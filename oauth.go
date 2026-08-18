package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// OAuthConfig holds all configuration for OAuth token management.
// All fields are loaded from environment variables.
type OAuthConfig struct {
	// AuthPath is the path to the auth.json file created by an external CLI tool.
	AuthPath string
	// TokenURL is the OAuth token refresh endpoint.
	TokenURL string
	// ClientID is the OAuth client ID sent in refresh requests.
	ClientID string
	// ProxyTargetURL optionally overrides PROXY_TARGET_URL when OAuth mode is enabled.
	ProxyTargetURL string
	// RefreshInterval is how often to check and refresh the token (0 = disabled).
	RefreshInterval time.Duration
	// EagerRefresh is how long before expiry to trigger a refresh (default: 5 min).
	EagerRefresh time.Duration
	// FieldAccess is the JSON key for the access token in auth.json (default: "access").
	FieldAccess string
	// FieldRefresh is the JSON key for the refresh token in auth.json (default: "refresh").
	FieldRefresh string
	// FieldExpires is the JSON key for the expiry timestamp in auth.json (default: "expires").
	FieldExpires string
}

// OAuthToken holds the current token state. Thread-safe via sync.RWMutex.
type OAuthToken struct {
	mu      sync.RWMutex
	access  string
	refresh string
	expires time.Time
}

// Access returns the current access token (thread-safe).
func (t *OAuthToken) Access() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.access
}

// Refresh returns the current refresh token (thread-safe).
func (t *OAuthToken) Refresh() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.refresh
}

// Expires returns the current token expiry (thread-safe).
func (t *OAuthToken) Expires() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.expires
}

// IsExpired returns true if the token is expired or will expire within the given buffer.
func (t *OAuthToken) IsExpired(buffer time.Duration) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return time.Now().Add(buffer).After(t.expires)
}

// update atomically replaces all token fields.
func (t *OAuthToken) update(access, refresh string, expires time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.access = access
	t.refresh = refresh
	t.expires = expires
}

// authFileRaw is the raw JSON structure of auth.json.
type authFileRaw struct {
	Type   string          `json:"type"`
	Fields json.RawMessage `json:"-"`
}

// LoadOAuthConfig reads OAuth configuration from environment variables.
// Returns nil if OAUTH_AUTH_PATH is not set (OAuth mode disabled).
func LoadOAuthConfig() *OAuthConfig {
	authPath := os.Getenv("OAUTH_AUTH_PATH")
	if authPath == "" {
		return nil
	}

	cfg := &OAuthConfig{
		AuthPath:    authPath,
		TokenURL:    os.Getenv("OAUTH_TOKEN_URL"),
		ClientID:    os.Getenv("OAUTH_CLIENT_ID"),
		ProxyTargetURL: os.Getenv("OAUTH_PROXY_TARGET_URL"),
		EagerRefresh:   300 * time.Second, // 5 min default
		FieldAccess:    "access",
		FieldRefresh:   "refresh",
		FieldExpires:   "expires",
	}

	if v := os.Getenv("OAUTH_REFRESH_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v + "m"); err == nil {
			cfg.RefreshInterval = d
		}
	}

	if v := os.Getenv("OAUTH_EAGER_REFRESH_SECONDS"); v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil {
			cfg.EagerRefresh = d
		}
	}

	if v := os.Getenv("OAUTH_FIELD_ACCESS"); v != "" {
		cfg.FieldAccess = v
	}
	if v := os.Getenv("OAUTH_FIELD_REFRESH"); v != "" {
		cfg.FieldRefresh = v
	}
	if v := os.Getenv("OAUTH_FIELD_EXPIRES"); v != "" {
		cfg.FieldExpires = v
	}

	return cfg
}

// ReadAuthFile reads and parses the auth.json file at the configured path.
// It uses the configured field names to extract access, refresh, and expiry values.
func ReadAuthFile(cfg *OAuthConfig) (*OAuthToken, error) {
	data, err := os.ReadFile(cfg.AuthPath)
	if err != nil {
		return nil, fmt.Errorf("reading auth file %s: %w", cfg.AuthPath, err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing auth file %s: %w", cfg.AuthPath, err)
	}

	access, err := extractStringField(raw, cfg.FieldAccess)
	if err != nil {
		return nil, fmt.Errorf("auth file missing %q field: %w", cfg.FieldAccess, err)
	}

	refresh, err := extractStringField(raw, cfg.FieldRefresh)
	if err != nil {
		return nil, fmt.Errorf("auth file missing %q field: %w", cfg.FieldRefresh, err)
	}

	expiresRaw, err := extractStringField(raw, cfg.FieldExpires)
	if err != nil {
		return nil, fmt.Errorf("auth file missing %q field: %w", cfg.FieldExpires, err)
	}

	expires, err := time.Parse(time.RFC3339, expiresRaw)
	if err != nil {
		// Try alternative formats
		for _, format := range []string{
			time.RFC3339Nano,
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02T15:04:05",
		} {
			if t, err2 := time.Parse(format, expiresRaw); err2 == nil {
				expires = t
				err = nil
				break
			}
		}
		if err != nil {
			return nil, fmt.Errorf("parsing expiry %q: %w", expiresRaw, err)
		}
	}

	return &OAuthToken{
		access:  access,
		refresh: refresh,
		expires: expires,
	}, nil
}

func extractStringField(raw map[string]json.RawMessage, key string) (string, error) {
	val, ok := raw[key]
	if !ok {
		return "", fmt.Errorf("field %q not found", key)
	}
	var s string
	if err := json.Unmarshal(val, &s); err != nil {
		return "", fmt.Errorf("field %q is not a string: %w", key, err)
	}
	return s, nil
}

// WriteAuthFile writes the token back to auth.json, preserving the existing
// file's structure but updating the access, refresh, and expiry fields.
func WriteAuthFile(cfg *OAuthConfig, token *OAuthToken) error {
	data, err := os.ReadFile(cfg.AuthPath)
	if err != nil {
		return fmt.Errorf("reading auth file for update: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parsing auth file for update: %w", err)
	}

	token.mu.RLock()
	access := token.access
	refresh := token.refresh
	expires := token.expires
	token.mu.RUnlock()

	raw[cfg.FieldAccess], _ = json.Marshal(access)
	raw[cfg.FieldRefresh], _ = json.Marshal(refresh)
	raw[cfg.FieldExpires], _ = json.Marshal(expires.Format(time.RFC3339))

	updated, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling updated auth file: %w", err)
	}

	if err := os.WriteFile(cfg.AuthPath, updated, 0600); err != nil {
		return fmt.Errorf("writing auth file: %w", err)
	}

	return nil
}

// tokenRefreshRequest is the request body for the OAuth token refresh endpoint.
type tokenRefreshRequest struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
}

// tokenRefreshResponse is the expected response from the OAuth token refresh endpoint.
type tokenRefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// RefreshToken calls the OAuth token endpoint to get a fresh access token.
// It uses the configured refresh token and client ID.
func RefreshToken(cfg *OAuthConfig, refreshTokenValue string) (*OAuthToken, error) {
	if cfg.TokenURL == "" {
		return nil, fmt.Errorf("OAUTH_TOKEN_URL not configured")
	}

	reqBody := tokenRefreshRequest{
		GrantType:    "refresh_token",
		RefreshToken: refreshTokenValue,
		ClientID:     cfg.ClientID,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling refresh request: %w", err)
	}

	resp, err := http.Post(cfg.TokenURL, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("posting refresh request to %s: %w", cfg.TokenURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp tokenRefreshResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing refresh response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("refresh response missing access_token")
	}

	// Use the new refresh token if provided, otherwise keep the old one
	newRefresh := refreshTokenValue
	if tokenResp.RefreshToken != "" {
		newRefresh = tokenResp.RefreshToken
	}

	expires := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return &OAuthToken{
		access:  tokenResp.AccessToken,
		refresh: newRefresh,
		expires: expires,
	}, nil
}

// StartRefreshLoop runs a background goroutine that periodically checks and
// refreshes the OAuth token. It stops when the provided stop channel is closed.
func StartRefreshLoop(cfg *OAuthConfig, token *OAuthToken, stop <-chan struct{}) {
	if cfg.RefreshInterval <= 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(cfg.RefreshInterval)
		defer ticker.Stop()

		log.Printf("[OAuth] Background refresh enabled, checking every %s", cfg.RefreshInterval)

		for {
			select {
			case <-stop:
				log.Printf("[OAuth] Background refresh stopped")
				return
			case <-ticker.C:
				if !token.IsExpired(cfg.EagerRefresh) {
					continue
				}

				log.Printf("[OAuth] Token expiring soon (in %s), refreshing...", time.Until(token.Expires()).Round(time.Second))

				currentRefresh := token.Refresh()
				newToken, err := RefreshToken(cfg, currentRefresh)
				if err != nil {
					log.Printf("[OAuth] ⚠️ Refresh failed: %v", err)
					continue
				}

				token.update(newToken.access, newToken.refresh, newToken.expires)

				if err := WriteAuthFile(cfg, token); err != nil {
					log.Printf("[OAuth] ⚠️ Failed to write refreshed token to auth file: %v", err)
				}

				log.Printf("[OAuth] ✅ Token refreshed, expires %s", token.Expires().Format(time.RFC3339))
			}
		}
	}()
}

// ReloadToken re-reads the auth.json file and updates the in-memory token.
// Used by SIGHUP handler. Returns true if the token was actually changed.
func ReloadToken(cfg *OAuthConfig, token *OAuthToken) (bool, error) {
	newToken, err := ReadAuthFile(cfg)
	if err != nil {
		return false, err
	}

	oldAccess := token.Access()
	oldExpires := token.Expires()

	token.update(newToken.access, newToken.refresh, newToken.expires)

	changed := newToken.access != oldAccess || !newToken.expires.Equal(oldExpires)
	return changed, nil
}
