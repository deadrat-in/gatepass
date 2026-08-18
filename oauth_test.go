package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestReadAuthFile(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		fields        *OAuthConfig
		wantAccess    string
		wantRefresh   string
		wantExpires   time.Time
		wantErr       bool
	}{
		{
			name:    "Default field names",
			content: `{"type":"oauth","access":"tok_abc123","refresh":"ref_xyz789","expires":"2026-12-31T23:59:59Z"}`,
			fields: &OAuthConfig{
				FieldAccess:  "access",
				FieldRefresh: "refresh",
				FieldExpires: "expires",
			},
			wantAccess:  "tok_abc123",
			wantRefresh: "ref_xyz789",
			wantExpires: time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
		},
		{
			name:    "Custom field names",
			content: `{"token":"my_token","refresh_token":"my_refresh","expiry":"2026-06-15T12:00:00Z"}`,
			fields: &OAuthConfig{
				FieldAccess:  "token",
				FieldRefresh: "refresh_token",
				FieldExpires: "expiry",
			},
			wantAccess:  "my_token",
			wantRefresh: "my_refresh",
			wantExpires: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
		},
		{
			name:    "Missing access field",
			content: `{"refresh":"ref_xyz","expires":"2026-12-31T23:59:59Z"}`,
			fields: &OAuthConfig{
				FieldAccess:  "access",
				FieldRefresh: "refresh",
				FieldExpires: "expires",
			},
			wantErr: true,
		},
		{
			name:    "Invalid JSON",
			content: `{not valid json`,
			fields: &OAuthConfig{
				FieldAccess:  "access",
				FieldRefresh: "refresh",
				FieldExpires: "expires",
			},
			wantErr: true,
		},
		{
			name:    "Invalid expiry format",
			content: `{"access":"tok","refresh":"ref","expires":"not-a-date"}`,
			fields: &OAuthConfig{
				FieldAccess:  "access",
				FieldRefresh: "refresh",
				FieldExpires: "expires",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			authFile := filepath.Join(tmpDir, "auth.json")
			if err := os.WriteFile(authFile, []byte(tt.content), 0600); err != nil {
				t.Fatal(err)
			}

			cfg := &OAuthConfig{AuthPath: authFile}
			if tt.fields != nil {
				cfg.FieldAccess = tt.fields.FieldAccess
				cfg.FieldRefresh = tt.fields.FieldRefresh
				cfg.FieldExpires = tt.fields.FieldExpires
			}

			token, err := ReadAuthFile(cfg)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if token.Access() != tt.wantAccess {
				t.Errorf("access = %q; want %q", token.Access(), tt.wantAccess)
			}
			if token.Refresh() != tt.wantRefresh {
				t.Errorf("refresh = %q; want %q", token.Refresh(), tt.wantRefresh)
			}
			if !token.Expires().Equal(tt.wantExpires) {
				t.Errorf("expires = %v; want %v", token.Expires(), tt.wantExpires)
			}
		})
	}
}

func TestReadAuthFile_NotFound(t *testing.T) {
	cfg := &OAuthConfig{
		AuthPath:    "/nonexistent/auth.json",
		FieldAccess: "access",
	}
	_, err := ReadAuthFile(cfg)
	if err == nil {
		t.Errorf("expected error for nonexistent file")
	}
}

func TestWriteAuthFile(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "auth.json")

	// Write initial file
	initial := `{"type":"oauth","access":"old_access","refresh":"old_refresh","expires":"2020-01-01T00:00:00Z"}`
	if err := os.WriteFile(authFile, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &OAuthConfig{
		AuthPath:    authFile,
		FieldAccess: "access",
		FieldRefresh: "refresh",
		FieldExpires: "expires",
	}

	newToken := &OAuthToken{
		access:  "new_access",
		refresh: "new_refresh",
		expires: time.Date(2027, 6, 15, 12, 0, 0, 0, time.UTC),
	}

	if err := WriteAuthFile(cfg, newToken); err != nil {
		t.Fatalf("WriteAuthFile failed: %v", err)
	}

	// Read back and verify
	data, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	var access, refresh, expires string
	json.Unmarshal(raw["access"], &access)
	json.Unmarshal(raw["refresh"], &refresh)
	json.Unmarshal(raw["expires"], &expires)

	if access != "new_access" {
		t.Errorf("access = %q; want %q", access, "new_access")
	}
	if refresh != "new_refresh" {
		t.Errorf("refresh = %q; want %q", refresh, "new_refresh")
	}
	if expires != "2027-06-15T12:00:00Z" {
		t.Errorf("expires = %q; want %q", expires, "2027-06-15T12:00:00Z")
	}

	// Verify "type" field is preserved
	var typ string
	json.Unmarshal(raw["type"], &typ)
	if typ != "oauth" {
		t.Errorf("type field lost, got %q; want %q", typ, "oauth")
	}
}

func TestWriteAuthFile_CustomFields(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "auth.json")

	initial := `{"token":"old","refresh_token":"old_ref","expiry":"2020-01-01T00:00:00Z"}`
	if err := os.WriteFile(authFile, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &OAuthConfig{
		AuthPath:    authFile,
		FieldAccess:  "token",
		FieldRefresh: "refresh_token",
		FieldExpires: "expiry",
	}

	newToken := &OAuthToken{
		access:  "new_tok",
		refresh: "new_ref",
		expires: time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	if err := WriteAuthFile(cfg, newToken); err != nil {
		t.Fatalf("WriteAuthFile failed: %v", err)
	}

	data, _ := os.ReadFile(authFile)
	var raw map[string]json.RawMessage
	json.Unmarshal(data, &raw)

	var token string
	json.Unmarshal(raw["token"], &token)
	if token != "new_tok" {
		t.Errorf("token = %q; want %q", token, "new_tok")
	}
}

func TestOAuthToken_IsExpired(t *testing.T) {
	token := &OAuthToken{
		expires: time.Now().Add(10 * time.Minute),
	}

	// Token expires in 10m. With 15m buffer, it IS expired (15m > 10m remaining)
	if !token.IsExpired(15 * time.Minute) {
		t.Error("expected expired with 15 min buffer (token has only 10m left)")
	}

	// Token expires in 10m. With 5m buffer, it is NOT expired (5m < 10m remaining)
	if token.IsExpired(5 * time.Minute) {
		t.Error("expected not expired with 5 min buffer (token has 10m left)")
	}

	// Already expired
	token.update("x", "y", time.Now().Add(-1*time.Hour))
	if !token.IsExpired(0) {
		t.Error("expected expired token")
	}
}

func TestOAuthToken_ConcurrentAccess(t *testing.T) {
	token := &OAuthToken{
		access:  "initial",
		refresh: "initial_refresh",
		expires: time.Now().Add(1 * time.Hour),
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = token.Access()
			_ = token.Refresh()
			_ = token.Expires()
			_ = token.IsExpired(0)
		}()
		go func(i int) {
			defer wg.Done()
			token.update("new_access", "new_refresh", time.Now().Add(time.Duration(i)*time.Minute))
		}(i)
	}
	wg.Wait()

	// Token should have some value (exact value depends on race)
	if token.Access() == "" {
		t.Error("access token should not be empty after concurrent updates")
	}
}

func TestRefreshToken(t *testing.T) {
	// Mock OAuth token endpoint
	var receivedBody tokenRefreshRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

	decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&receivedBody); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}

		resp := tokenRefreshResponse{
			AccessToken:  "new_access_token",
			RefreshToken: "new_refresh_token",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &OAuthConfig{
		TokenURL: server.URL,
		ClientID: "test-client",
	}

	token, err := RefreshToken(cfg, "old_refresh_token")
	if err != nil {
		t.Fatalf("RefreshToken failed: %v", err)
	}

	if receivedBody.GrantType != "refresh_token" {
		t.Errorf("grant_type = %q; want %q", receivedBody.GrantType, "refresh_token")
	}
	if receivedBody.RefreshToken != "old_refresh_token" {
		t.Errorf("refresh_token = %q; want %q", receivedBody.RefreshToken, "old_refresh_token")
	}
	if receivedBody.ClientID != "test-client" {
		t.Errorf("client_id = %q; want %q", receivedBody.ClientID, "test-client")
	}

	if token.Access() != "new_access_token" {
		t.Errorf("access = %q; want %q", token.Access(), "new_access_token")
	}
	if token.Refresh() != "new_refresh_token" {
		t.Errorf("refresh = %q; want %q", token.Refresh(), "new_refresh_token")
	}

	// Token should be valid for roughly 3600 seconds
	expectedExpiry := time.Now().Add(3600 * time.Second)
	if diff := token.Expires().Sub(expectedExpiry); diff > 5*time.Second || diff < -5*time.Second {
		t.Errorf("expires diff = %v; expected within 5s of %v", diff, expectedExpiry)
	}
}

func TestRefreshToken_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer server.Close()

	cfg := &OAuthConfig{
		TokenURL: server.URL,
		ClientID: "test-client",
	}

	_, err := RefreshToken(cfg, "bad_refresh")
	if err == nil {
		t.Error("expected error for 401 response")
	}
}

func TestRefreshToken_NoTokenURL(t *testing.T) {
	cfg := &OAuthConfig{ClientID: "test"}
	_, err := RefreshToken(cfg, "refresh")
	if err == nil {
		t.Error("expected error when TokenURL is empty")
	}
}

func TestRefreshToken_PreservesOldRefreshIfEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Response without refresh_token
		resp := tokenRefreshResponse{
			AccessToken: "new_access",
			ExpiresIn:   1800,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &OAuthConfig{
		TokenURL: server.URL,
		ClientID: "test",
	}

	token, err := RefreshToken(cfg, "original_refresh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token.Refresh() != "original_refresh" {
		t.Errorf("refresh = %q; want original_refresh preserved when server returns empty", token.Refresh())
	}
}

func TestReloadToken(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "auth.json")

	initial := `{"access":"old_token","refresh":"old_refresh","expires":"2020-01-01T00:00:00Z"}`
	os.WriteFile(authFile, []byte(initial), 0600)

	cfg := &OAuthConfig{
		AuthPath:    authFile,
		FieldAccess: "access",
		FieldRefresh: "refresh",
		FieldExpires: "expires",
	}

	token, _ := ReadAuthFile(cfg)
	if token.Access() != "old_token" {
		t.Fatalf("initial access = %q; want %q", token.Access(), "old_token")
	}

	// Update the file on disk
	updated := `{"access":"reloaded_token","refresh":"reloaded_refresh","expires":"2028-01-01T00:00:00Z"}`
	os.WriteFile(authFile, []byte(updated), 0600)

	changed, err := ReloadToken(cfg, token)
	if err != nil {
		t.Fatalf("ReloadToken failed: %v", err)
	}
	if !changed {
		t.Error("expected changed=true after file update")
	}
	if token.Access() != "reloaded_token" {
		t.Errorf("access after reload = %q; want %q", token.Access(), "reloaded_token")
	}
}

func TestReloadToken_NoChange(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "auth.json")

	content := `{"access":"same_token","refresh":"same_refresh","expires":"2026-01-01T00:00:00Z"}`
	os.WriteFile(authFile, []byte(content), 0600)

	cfg := &OAuthConfig{
		AuthPath:    authFile,
		FieldAccess: "access",
		FieldRefresh: "refresh",
		FieldExpires: "expires",
	}

	token, _ := ReadAuthFile(cfg)

	// Reload same file
	changed, err := ReloadToken(cfg, token)
	if err != nil {
		t.Fatalf("ReloadToken failed: %v", err)
	}
	if changed {
		t.Error("expected changed=false when file hasn't changed")
	}
}

func TestAtomicMap(t *testing.T) {
	m := newAtomicMap(map[string]string{"a": "1"})

	// Load
	loaded := m.Load()
	if loaded["a"] != "1" {
		t.Errorf("Load() a = %q; want %q", loaded["a"], "1")
	}

	// Store new map
	m.Store(map[string]string{"b": "2"})
	loaded = m.Load()
	if loaded["b"] != "2" {
		t.Errorf("Store/Load b = %q; want %q", loaded["b"], "2")
	}
	if _, ok := loaded["a"]; ok {
		t.Error("old key 'a' should not exist after Store")
	}
}

func TestLoadOAuthConfig(t *testing.T) {
	// Save and restore env
	origAuth := os.Getenv("OAUTH_AUTH_PATH")
	origToken := os.Getenv("OAUTH_TOKEN_URL")
	origClient := os.Getenv("OAUTH_CLIENT_ID")
	origTarget := os.Getenv("OAUTH_PROXY_TARGET_URL")
	origInterval := os.Getenv("OAUTH_REFRESH_INTERVAL")
	origEager := os.Getenv("OAUTH_EAGER_REFRESH_SECONDS")
	origFieldAccess := os.Getenv("OAUTH_FIELD_ACCESS")
	origFieldRefresh := os.Getenv("OAUTH_FIELD_REFRESH")
	origFieldExpires := os.Getenv("OAUTH_FIELD_EXPIRES")
	defer func() {
		os.Setenv("OAUTH_AUTH_PATH", origAuth)
		os.Setenv("OAUTH_TOKEN_URL", origToken)
		os.Setenv("OAUTH_CLIENT_ID", origClient)
		os.Setenv("OAUTH_PROXY_TARGET_URL", origTarget)
		os.Setenv("OAUTH_REFRESH_INTERVAL", origInterval)
		os.Setenv("OAUTH_EAGER_REFRESH_SECONDS", origEager)
		os.Setenv("OAUTH_FIELD_ACCESS", origFieldAccess)
		os.Setenv("OAUTH_FIELD_REFRESH", origFieldRefresh)
		os.Setenv("OAUTH_FIELD_EXPIRES", origFieldExpires)
	}()

	t.Run("Disabled when OAUTH_AUTH_PATH not set", func(t *testing.T) {
		os.Unsetenv("OAUTH_AUTH_PATH")
		cfg := LoadOAuthConfig()
		if cfg != nil {
			t.Error("expected nil config when OAUTH_AUTH_PATH not set")
		}
	})

	t.Run("All fields populated", func(t *testing.T) {
		os.Setenv("OAUTH_AUTH_PATH", "/tmp/auth.json")
		os.Setenv("OAUTH_TOKEN_URL", "https://example.com/token")
		os.Setenv("OAUTH_CLIENT_ID", "my-client")
		os.Setenv("OAUTH_PROXY_TARGET_URL", "https://example.com/zen/v1")
		os.Setenv("OAUTH_REFRESH_INTERVAL", "30")
		os.Setenv("OAUTH_EAGER_REFRESH_SECONDS", "600")
		os.Setenv("OAUTH_FIELD_ACCESS", "token")
		os.Setenv("OAUTH_FIELD_REFRESH", "refresh_token")
		os.Setenv("OAUTH_FIELD_EXPIRES", "expiry")

		cfg := LoadOAuthConfig()
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
		if cfg.AuthPath != "/tmp/auth.json" {
			t.Errorf("AuthPath = %q", cfg.AuthPath)
		}
		if cfg.TokenURL != "https://example.com/token" {
			t.Errorf("TokenURL = %q", cfg.TokenURL)
		}
		if cfg.ClientID != "my-client" {
			t.Errorf("ClientID = %q", cfg.ClientID)
		}
		if cfg.ProxyTargetURL != "https://example.com/zen/v1" {
			t.Errorf("ProxyTargetURL = %q", cfg.ProxyTargetURL)
		}
		if cfg.RefreshInterval != 30*time.Minute {
			t.Errorf("RefreshInterval = %v; want 30m", cfg.RefreshInterval)
		}
		if cfg.EagerRefresh != 600*time.Second {
			t.Errorf("EagerRefresh = %v; want 600s", cfg.EagerRefresh)
		}
		if cfg.FieldAccess != "token" {
			t.Errorf("FieldAccess = %q; want %q", cfg.FieldAccess, "token")
		}
		if cfg.FieldRefresh != "refresh_token" {
			t.Errorf("FieldRefresh = %q; want %q", cfg.FieldRefresh, "refresh_token")
		}
		if cfg.FieldExpires != "expiry" {
			t.Errorf("FieldExpires = %q; want %q", cfg.FieldExpires, "expiry")
		}
	})
}
