package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

// RateLimiter implements a thread-safe token-bucket rate limiter with queue reservation.
type RateLimiter struct {
	mu           sync.Mutex
	capacity     float64
	tokens       float64
	refillRate   float64 // tokens per second
	lastRefilled time.Time
	nextFree     time.Time
}

// NewRateLimiter creates a new RateLimiter.
func NewRateLimiter(capacity, refillRate float64) *RateLimiter {
	now := time.Now()
	return &RateLimiter{
		capacity:     capacity,
		tokens:       capacity,
		refillRate:   refillRate,
		lastRefilled: now,
		nextFree:     now,
	}
}

// Wait blocks until a token is available or the context is cancelled.
func (rl *RateLimiter) Wait(ctx context.Context) error {
	rl.mu.Lock()
	now := time.Now()

	// 1. Refill tokens
	elapsed := now.Sub(rl.lastRefilled).Seconds()
	rl.tokens += elapsed * rl.refillRate
	if rl.tokens > rl.capacity {
		rl.tokens = rl.capacity
	}
	rl.lastRefilled = now

	// 2. If nextFree is in the past, align it with now
	if rl.nextFree.Before(now) {
		rl.nextFree = now
	}

	// 3. If we have at least 1.0 token and no queue is active, consume it immediately
	if rl.tokens >= 1.0 && rl.nextFree.Equal(now) {
		rl.tokens -= 1.0
		rl.mu.Unlock()
		return nil
	}

	// 4. Otherwise, queue/reserve a slot
	var readyTime time.Time
	if rl.nextFree.After(now) {
		readyTime = rl.nextFree.Add(time.Duration((1.0 / rl.refillRate) * float64(time.Second)))
	} else {
		needed := 1.0 - rl.tokens
		readyTime = now.Add(time.Duration((needed / rl.refillRate) * float64(time.Second)))
	}

	sleepTime := readyTime.Sub(now)
	rl.nextFree = readyTime
	rl.tokens -= 1.0
	rl.mu.Unlock()

	if sleepTime <= 0 {
		return nil
	}

	log.Printf("[RateLimiter] ⏳ Queueing request. Estimated wait time: %.2fs", sleepTime.Seconds())

	timer := time.NewTimer(sleepTime)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		rl.refund()
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// refund restores one token to the bucket and adjusts the queue timing if a request is cancelled.
func (rl *RateLimiter) refund() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.tokens += 1.0
	if rl.tokens > rl.capacity {
		rl.tokens = rl.capacity
	}

	costDuration := time.Duration((1.0 / rl.refillRate) * float64(time.Second))
	if rl.nextFree.After(time.Now()) {
		rl.nextFree = rl.nextFree.Add(-costDuration)
		if rl.nextFree.Before(time.Now()) {
			rl.nextFree = time.Now()
		}
	}
	log.Printf("[RateLimiter] ↩️ Request cancelled. Token refunded and queue adjusted.")
}

// atomicMap provides thread-safe atomic reads and swaps for a string map.
type atomicMap struct {
	v atomic.Value
}

func newAtomicMap(m map[string]string) *atomicMap {
	a := &atomicMap{}
	a.v.Store(m)
	return a
}

func (a *atomicMap) Load() map[string]string {
	return a.v.Load().(map[string]string)
}

func (a *atomicMap) Store(m map[string]string) {
	a.v.Store(m)
}

func getEnvInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func rateLimitMiddleware(limiter *RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Printf("[Proxy] 📥 Incoming request: %s %s", req.Method, req.URL.Path)

		err := limiter.Wait(req.Context())
		if err != nil {
			log.Printf("[Proxy] ❌ Request %s %s cancelled/aborted in queue: %v", req.Method, req.URL.Path, err)
			http.Error(w, "Request cancelled or timed out in queue", http.StatusGatewayTimeout)
			return
		}

		log.Printf("[Proxy] 📤 Forwarding request: %s %s", req.Method, req.URL.Path)
		next.ServeHTTP(w, req)
	})
}

func main() {
	// 1. Load configuration
	targetURL := os.Getenv("PROXY_TARGET_URL")

	modelReplaceEnv := os.Getenv("MODEL_REPLACE")
	modelReplacements := parseModelReplacements(modelReplaceEnv)
	if len(modelReplacements) > 0 {
		log.Printf("🔄 Dynamic Model Replacement enabled:")
		for k, v := range modelReplacements {
			log.Printf("   - %s -> %s", k, v)
		}
	}

	apiKeyReplaceEnv := os.Getenv("API_KEY_REPLACE")
	apiKeyReplacements := parseModelReplacements(apiKeyReplaceEnv)
	if len(apiKeyReplacements) > 0 {
		log.Printf("🔄 Dynamic API Key Replacement enabled:")
		for k, v := range apiKeyReplacements {
			log.Printf("   - %s -> %s", maskKey(k), maskKey(v))
		}
	}

	// 1b. OAuth Token Management (optional)
	var oauthCfg *OAuthConfig
	var oauthToken *OAuthToken
	var oauthReplacements map[string]string

	oauthCfg = LoadOAuthConfig()
	if oauthCfg != nil {
		log.Printf("🔐 OAuth mode enabled (auth file: %s)", oauthCfg.AuthPath)

		var err error
		oauthToken, err = ReadAuthFile(oauthCfg)
		if err != nil {
			log.Fatalf("FATAL: Failed to read OAuth auth file: %v", err)
		}

		log.Printf("🔑 OAuth token loaded, expires %s", oauthToken.Expires().Format(time.RFC3339))

		// If token is already expired at startup, try to refresh immediately
		if oauthToken.IsExpired(0) {
			log.Printf("⚠️ OAuth token already expired, attempting refresh...")
			newToken, err := RefreshToken(oauthCfg, oauthToken.Refresh())
			if err != nil {
				log.Printf("⚠️ OAuth refresh failed: %v (will use expired token)", err)
			} else {
				oauthToken.update(newToken.access, newToken.refresh, newToken.expires)
				if err := WriteAuthFile(oauthCfg, oauthToken); err != nil {
					log.Printf("⚠️ Failed to write refreshed token: %v", err)
				}
				log.Printf("✅ OAuth token refreshed at startup, expires %s", oauthToken.Expires().Format(time.RFC3339))
			}
		}

		// Inject OAuth token as wildcard API key replacement
		oauthReplacements = map[string]string{
			"*": oauthToken.Access(),
		}
		log.Printf("🔑 OAuth token injected as wildcard API key")

		// Override PROXY_TARGET_URL if OAUTH_PROXY_TARGET_URL is set
		if oauthCfg.ProxyTargetURL != "" {
			targetURL = oauthCfg.ProxyTargetURL
			log.Printf("➡️ OAuth proxy target override: %s", targetURL)
		}
	}

	// Validate and parse target URL (may have been set by OAuth config)
	if targetURL == "" {
		log.Fatal("FATAL: PROXY_TARGET_URL or OAUTH_PROXY_TARGET_URL must be set.")
	}

	target, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("FATAL: Failed to parse target URL '%s': %v", targetURL, err)
	}

	// Merge OAuth replacements into apiKeyReplacements
	if len(oauthReplacements) > 0 {
		for k, v := range oauthReplacements {
			apiKeyReplacements[k] = v
		}
	}

	atomicKeyReplacements := newAtomicMap(apiKeyReplacements)

	// Initialize SQLite Database
	dbPath := os.Getenv("PROXY_LOGS_DB")
	if dbPath == "" {
		dbPath = "gatepass.db"
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatalf("FATAL: Failed to open SQLite DB: %v", err)
	}
	defer db.Close()

	// Create table if not exists
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS api_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			request_headers TEXT,
			request_body TEXT,
			response_status INTEGER,
			response_headers TEXT,
			response_body TEXT,
			error TEXT,
			duration_ms INTEGER
		);
	`)
	if err != nil {
		log.Fatalf("FATAL: Failed to create api_logs table: %v", err)
	}

	go startLogWorker(db)
	log.Printf("📂 SQLite Logging enabled. File: %s", dbPath)

	// 2. Parse headers to inject
	headersToInject := make(map[string]string)

	// A. Parse from environment variables starting with HEADER_
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]
		if strings.HasPrefix(key, "HEADER_") {
			headerName := strings.TrimPrefix(key, "HEADER_")
			headerName = strings.ReplaceAll(headerName, "_", "-")
			canonicalName := http.CanonicalHeaderKey(headerName)
			headersToInject[canonicalName] = val
		}
	}

	// B. Parse from structured JSON if provided
	headersJSON := os.Getenv("INJECT_HEADERS_JSON")
	if headersJSON != "" {
		var jsonHeaders map[string]string
		if err := json.Unmarshal([]byte(headersJSON), &jsonHeaders); err != nil {
			log.Fatalf("FATAL: Failed to parse INJECT_HEADERS_JSON: %v", err)
		}
		for k, v := range jsonHeaders {
			headersToInject[http.CanonicalHeaderKey(k)] = v
		}
	}

	// 3. Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Intercept and modify the request before it goes out
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Override Host header for proper SSL routing at the destination
		req.Host = target.Host

		// Inject headers
		for k, v := range headersToInject {
			req.Header.Set(k, v)
		}

		// Perform dynamic model replacements if configured
		if len(modelReplacements) > 0 {
			if req.URL != nil {
				req.URL.Path = replaceModelInPath(req.URL.Path, modelReplacements)
			}
			replaceModelInBody(req, modelReplacements)
		}

		// Perform dynamic API key replacements if configured
		if currentKeyReplacements := atomicKeyReplacements.Load(); len(currentKeyReplacements) > 0 {
			replaceAPIKeys(req, currentKeyReplacements)
		}
	}

	// Intercept and modify the response before returning to client
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Format response headers
		var respHeaders []string
		for k, v := range resp.Header {
			respHeaders = append(respHeaders, k+": "+strings.Join(v, ", "))
		}
		respHeadersStr := strings.Join(respHeaders, "\n")

		// Retrieve request details from context
		if details, ok := resp.Request.Context().Value(requestDetailsKey).(*RequestDetails); ok {
			// Wrap resp.Body so we log asynchronously when reading completes or closes
			resp.Body = &loggingReader{
				ReadCloser: resp.Body,
				onClose: func(respBodyBytes []byte) {
					duration := time.Since(details.StartTime)
					logChan <- &LogEntry{
						Timestamp:       details.StartTime,
						Method:          details.Method,
						Path:            details.Path,
						RequestHeaders:  details.Headers,
						RequestBody:     details.Body,
						ResponseStatus:  resp.StatusCode,
						ResponseHeaders: respHeadersStr,
						ResponseBody:    string(respBodyBytes),
						Error:           "",
						DurationMs:      duration.Milliseconds(),
					}
				},
			}
		}

		return nil
	}

	// Capture errors (e.g. backend down)
	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		log.Printf("[Proxy] ❌ Target error: %v", err)

		if details, ok := req.Context().Value(requestDetailsKey).(*RequestDetails); ok {
			duration := time.Since(details.StartTime)
			logChan <- &LogEntry{
				Timestamp:       details.StartTime,
				Method:          details.Method,
				Path:            details.Path,
				RequestHeaders:  details.Headers,
				RequestBody:     details.Body,
				ResponseStatus:  http.StatusBadGateway,
				ResponseHeaders: "",
				ResponseBody:    "",
				Error:           err.Error(),
				DurationMs:      duration.Milliseconds(),
			}
		}

		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	// 4. Rate Limiter configuration
	rpm := getEnvInt("RATE_LIMIT_RPM", 0) // Default to 0 (disabled)
	burst := getEnvInt("RATE_LIMIT_BURST", 0)

	// 5. Start the server
	port := os.Getenv("PROXY_PORT")
	if port == "" {
		port = ":8318"
	} else if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}

	log.Printf("🚀 Gatepass LLM Proxy running on http://localhost%s", port)
	log.Printf("➡️ Proxy Target URL: %s", targetURL)

	var handler http.Handler
	if rpm > 0 {
		if burst <= 0 {
			burst = 1 // Ensure we have at least 1 capacity if burst is omitted
		}
		refillRate := float64(rpm) / 60.0
		limiter := NewRateLimiter(float64(burst), refillRate)
		handler = loggingMiddleware(rateLimitMiddleware(limiter, proxy))
		log.Printf("➡️ Rate Limiting: ENABLED (%d RPM, Burst: %d)", rpm, burst)
	} else {
		handler = loggingMiddleware(proxy)
		log.Printf("➡️ Rate Limiting: DISABLED")
	}

	if len(headersToInject) > 0 {
		log.Printf("🔑 Injected headers:")
		for k := range headersToInject {
			log.Printf("   - %s", k)
		}
	} else {
		log.Printf("ℹ️ No headers configured to inject.")
	}

	// 6. OAuth background refresh + SIGHUP reload (if OAuth mode enabled)
	if oauthCfg != nil && oauthToken != nil {
		// Background refresh (optional, only if OAUTH_REFRESH_INTERVAL > 0)
		stopRefresh := make(chan struct{})
		StartRefreshLoop(oauthCfg, oauthToken, stopRefresh)
		defer close(stopRefresh)

		// SIGHUP handler for manual token reload
		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		go func() {
			for range sighup {
				log.Printf("[OAuth] 📥 SIGHUP received, reloading auth file...")
				changed, err := ReloadToken(oauthCfg, oauthToken)
				if err != nil {
					log.Printf("[OAuth] ⚠️ Reload failed: %v", err)
					continue
				}
				if changed {
					// Update the atomic map with the new token
					current := atomicKeyReplacements.Load()
					updated := make(map[string]string, len(current))
					for k, v := range current {
						updated[k] = v
					}
					updated["*"] = oauthToken.Access()
					atomicKeyReplacements.Store(updated)
					log.Printf("[OAuth] ✅ Token reloaded, expires %s", oauthToken.Expires().Format(time.RFC3339))
				} else {
					log.Printf("[OAuth] ℹ️ No changes detected in auth file")
				}
			}
		}()
		log.Printf("[OAuth] 💡 Send SIGHUP (kill -HUP <pid>) to reload token from auth file")
	}

	if err := http.ListenAndServe(port, handler); err != nil {
		log.Fatal("Server error:", err)
	}
}

type LogEntry struct {
	Timestamp       time.Time
	Method          string
	Path            string
	RequestHeaders  string
	RequestBody     string
	ResponseStatus  int
	ResponseHeaders string
	ResponseBody    string
	Error           string
	DurationMs      int64
}

var logChan = make(chan *LogEntry, 1000)

func startLogWorker(db *sql.DB) {
	for entry := range logChan {
		_, err := db.Exec(`
			INSERT INTO api_logs (
				timestamp, method, path, request_headers, request_body,
				response_status, response_headers, response_body, error, duration_ms
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.Timestamp.Format(time.RFC3339),
			entry.Method,
			entry.Path,
			entry.RequestHeaders,
			entry.RequestBody,
			entry.ResponseStatus,
			entry.ResponseHeaders,
			entry.ResponseBody,
			entry.Error,
			entry.DurationMs,
		)
		if err != nil {
			log.Printf("[Logger] ❌ Error writing log to DB: %v", err)
		}
	}
}

type contextKey string

const requestDetailsKey contextKey = "requestDetails"

type RequestDetails struct {
	StartTime time.Time
	Method    string
	Path      string
	Headers   string
	Body      string
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		startTime := time.Now()

		// Capture request headers
		var reqHeaders []string
		for k, v := range req.Header {
			reqHeaders = append(reqHeaders, k+": "+strings.Join(v, ", "))
		}
		reqHeadersStr := strings.Join(reqHeaders, "\n")

		// Capture request body (buffer it)
		var bodyBytes []byte
		if req.Body != nil {
			var err error
			bodyBytes, err = io.ReadAll(req.Body)
			if err != nil {
				log.Printf("[Logger] Error reading request body: %v", err)
			}
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		details := &RequestDetails{
			StartTime: startTime,
			Method:    req.Method,
			Path:      req.URL.Path,
			Headers:   reqHeadersStr,
			Body:      string(bodyBytes),
		}

		ctx := context.WithValue(req.Context(), requestDetailsKey, details)
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

type loggingReader struct {
	io.ReadCloser
	buf       bytes.Buffer
	onClose   func([]byte)
	closeOnce sync.Once
}

func (lr *loggingReader) Read(p []byte) (n int, err error) {
	n, err = lr.ReadCloser.Read(p)
	if n > 0 {
		lr.buf.Write(p[:n])
	}
	if err == io.EOF {
		lr.closeOnce.Do(func() {
			lr.onClose(lr.buf.Bytes())
		})
	}
	return n, err
}

func (lr *loggingReader) Close() error {
	err := lr.ReadCloser.Close()
	lr.closeOnce.Do(func() {
		lr.onClose(lr.buf.Bytes())
	})
	return err
}

func parseModelReplacements(val string) map[string]string {
	res := make(map[string]string)
	val = strings.TrimSpace(val)
	if val == "" {
		return res
	}

	// Try parsing as JSON first
	if strings.HasPrefix(val, "{") {
		var m map[string]string
		if err := json.Unmarshal([]byte(val), &m); err == nil {
			return m
		}
	}

	// Fallback to custom split by commas, taking quotes/whitespace into account
	parts := strings.Split(val, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"'`)
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			k := strings.TrimSpace(kv[0])
			k = strings.Trim(k, `"'`)
			v := strings.TrimSpace(kv[1])
			v = strings.Trim(v, `"'`)
			if k != "" && v != "" {
				res[k] = v
			}
		}
	}
	return res
}

func replaceModelInPath(path string, replacements map[string]string) string {
	segments := strings.Split(path, "/")
	modified := false
	for i, seg := range segments {
		baseSeg := seg
		suffix := ""
		if idx := strings.Index(seg, ":"); idx != -1 {
			baseSeg = seg[:idx]
			suffix = seg[idx:]
		}
		
		// Try exact match or wildcard match for the model segment
		if target, ok := replacements[baseSeg]; ok {
			segments[i] = target + suffix
			modified = true
		} else if i > 0 && segments[i-1] == "models" {
			if target, ok := replacements["*"]; ok {
				segments[i] = target + suffix
				modified = true
			} else if target, ok := replacements["default"]; ok {
				segments[i] = target + suffix
				modified = true
			}
		}
	}
	if modified {
		return strings.Join(segments, "/")
	}
	return path
}

func replaceModelInBody(req *http.Request, replacements map[string]string) {
	if req.Body == nil {
		return
	}
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil || len(bodyBytes) == 0 {
		return
	}

	// Make sure we always restore the body, even if modification fails or is skipped
	defer func() {
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		req.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	}()

	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	dec.UseNumber()
	var bodyMap map[string]interface{}
	if err := dec.Decode(&bodyMap); err != nil {
		return
	}

	modelVal, ok := bodyMap["model"]
	if !ok {
		return
	}
	modelStr, ok := modelVal.(string)
	if !ok {
		return
	}

	target, ok := resolveReplacement(modelStr, replacements)
	if !ok {
		return
	}

	bodyMap["model"] = target
	modifiedBytes, err := json.Marshal(bodyMap)
	if err != nil {
		return
	}
	bodyBytes = modifiedBytes
}

func maskKey(key string) string {
	if len(key) <= 8 {
		return "***"
	}
	return key[:3] + "..." + key[len(key)-4:]
}

func resolveReplacement(val string, replacements map[string]string) (string, bool) {
	if val == "" {
		return "", false
	}
	if target, ok := replacements[val]; ok {
		return target, true
	}
	if fallback, ok := replacements["*"]; ok {
		return fallback, true
	}
	if fallback, ok := replacements["default"]; ok {
		return fallback, true
	}
	return "", false
}

func replaceAPIKeys(req *http.Request, replacements map[string]string) {
	if req == nil {
		return
	}

	// 1. Replace in Headers
	// Authorization header
	if auth := req.Header.Get("Authorization"); auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 {
			token := strings.TrimSpace(parts[1])
			if replacement, ok := resolveReplacement(token, replacements); ok {
				req.Header.Set("Authorization", parts[0]+" "+replacement)
			}
		} else if len(parts) == 1 {
			token := strings.TrimSpace(parts[0])
			if replacement, ok := resolveReplacement(token, replacements); ok {
				req.Header.Set("Authorization", replacement)
			}
		}
	}

	// api-key header
	if apiKey := req.Header.Get("api-key"); apiKey != "" {
		if replacement, ok := resolveReplacement(apiKey, replacements); ok {
			req.Header.Set("api-key", replacement)
		}
	}

	// x-api-key header
	if xApiKey := req.Header.Get("x-api-key"); xApiKey != "" {
		if replacement, ok := resolveReplacement(xApiKey, replacements); ok {
			req.Header.Set("x-api-key", replacement)
		}
	}

	// 2. Replace in Query Parameters
	if req.URL != nil {
		query := req.URL.Query()
		modified := false
		keyParams := []string{"key", "api_key", "api-key"}
		for _, p := range keyParams {
			if values, ok := query[p]; ok {
				for i, val := range values {
					if replacement, ok := resolveReplacement(val, replacements); ok {
						query[p][i] = replacement
						modified = true
					}
				}
			}
		}
		if modified {
			req.URL.RawQuery = query.Encode()
		}
	}
}
