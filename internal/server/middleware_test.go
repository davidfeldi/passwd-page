package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSecurityHeaders(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	expected := map[string]string{
		"Content-Security-Policy": "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data:; connect-src 'self'; font-src 'self'; " +
			"base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
		"X-Dns-Prefetch-Control":    "off",
	}

	for header, want := range expected {
		got := rec.Header().Get(header)
		if got != want {
			t.Errorf("header %s = %q, want %q", header, got, want)
		}
	}
}

func TestRateLimit_UnderLimit(t *testing.T) {
	handler := RateLimit(10, 30, time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Send 5 GET requests — all should succeed.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: got status %d, want %d", i, rec.Code, http.StatusOK)
		}
	}

	// Verify rate limit headers are present.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-RateLimit-Limit") == "" {
		t.Error("missing X-RateLimit-Limit header")
	}
	if rec.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("missing X-RateLimit-Remaining header")
	}
	if rec.Header().Get("X-RateLimit-Reset") == "" {
		t.Error("missing X-RateLimit-Reset header")
	}
}

func TestRateLimit_ExceedsLimit(t *testing.T) {
	createLimit := 3
	handler := RateLimit(createLimit, 30, time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust the create limit with POST requests.
	for i := 0; i < createLimit; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = "10.0.0.1:9999"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: got status %d, want %d", i, rec.Code, http.StatusOK)
		}
	}

	// Next POST should be rate limited.
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "rate limit exceeded") {
		t.Errorf("response body = %q, want it to contain 'rate limit exceeded'", body)
	}

	if rec.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header on 429 response")
	}

	// GET requests from the same IP should still succeed (separate bucket).
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET after POST limit: got status %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRateLimit_XForwardedFor(t *testing.T) {
	createLimit := 2
	handler := RateLimit(createLimit, 30, time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Two requests from same X-Forwarded-For IP should exhaust limit.
	for i := 0; i < createLimit; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: got status %d, want %d", i, rec.Code, http.StatusOK)
		}
	}

	// Third should be blocked.
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
}

func TestMaxBodySize(t *testing.T) {
	maxBytes := int64(16)
	handler := MaxBodySize(maxBytes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Request within limit.
	small := strings.NewReader("hello")
	req := httptest.NewRequest(http.MethodPost, "/", small)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("small body: got status %d, want %d", rec.Code, http.StatusOK)
	}

	// Request exceeding limit.
	large := strings.NewReader(strings.Repeat("x", int(maxBytes+100)))
	req = httptest.NewRequest(http.MethodPost, "/", large)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body: got status %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestRequestLogger(t *testing.T) {
	handler := RequestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/secrets", nil)
	req.RemoteAddr = "192.168.1.1:8080"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify the inner handler's status code is preserved.
	if rec.Code != http.StatusCreated {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusCreated)
	}
}
