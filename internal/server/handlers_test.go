package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davidfeldi/passwd-page/internal/storage"
)

// newTestStore creates a temporary SQLite store for testing.
func newTestStore(t *testing.T) storage.Store {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	store, err := storage.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestCreateSecret_Success(t *testing.T) {
	store := newTestStore(t)
	handler := CreateSecret(store)

	plaintext := []byte("my secret data")
	ciphertext := base64.RawURLEncoding.EncodeToString(plaintext)
	body := `{"ciphertext":"` + ciphertext + `","expiresIn":"1h","burnAfterRead":true}`

	req := httptest.NewRequest(http.MethodPost, "/api/secrets", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp createResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.ID) != 32 {
		t.Errorf("expected 32-char hex ID, got %q (len %d)", resp.ID, len(resp.ID))
	}

	if resp.ExpiresAt == "" {
		t.Error("expected non-empty expiresAt")
	}
}

func TestCreateSecret_InvalidInput(t *testing.T) {
	store := newTestStore(t)
	handler := CreateSecret(store)

	ct := base64.RawURLEncoding.EncodeToString([]byte("x"))
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "missing ciphertext",
			body:       `{"expiresIn":"1h","burnAfterRead":true}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		{
			name:       "empty ciphertext",
			body:       `{"ciphertext":"","expiresIn":"1h","burnAfterRead":true}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		{
			name:       "invalid expiresIn (2h not in enum)",
			body:       `{"ciphertext":"` + ct + `","expiresIn":"2h","burnAfterRead":true}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_expiry",
		},
		{
			name:       "invalid expiresIn (garbage)",
			body:       `{"ciphertext":"` + ct + `","expiresIn":"foo","burnAfterRead":true}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_expiry",
		},
		{
			name:       "invalid expiresIn (60d not in enum)",
			body:       `{"ciphertext":"` + ct + `","expiresIn":"60d","burnAfterRead":true}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_expiry",
		},
		{
			name:       "missing expiresIn",
			body:       `{"ciphertext":"` + base64.RawURLEncoding.EncodeToString([]byte("x")) + `","burnAfterRead":true}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		{
			name:       "ciphertext too large",
			body:       `{"ciphertext":"` + base64.RawURLEncoding.EncodeToString(make([]byte, (1536*1024)+1)) + `","expiresIn":"1h","burnAfterRead":true}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "ciphertext_too_large",
		},
		{
			name:       "missing burnAfterRead",
			body:       `{"ciphertext":"` + base64.RawURLEncoding.EncodeToString([]byte("x")) + `","expiresIn":"1h"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/secrets", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatus, w.Code, w.Body.String())
			}

			var errResp errorResponse
			if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
				t.Fatalf("failed to decode error response: %v", err)
			}
			if errResp.Error.Code != tt.wantCode {
				t.Errorf("expected error code %q, got %q", tt.wantCode, errResp.Error.Code)
			}
		})
	}
}

// TestCreateSecret_AllValidTTLs verifies every value in the TTL enum is
// accepted and yields an HTTP 201.
func TestCreateSecret_AllValidTTLs(t *testing.T) {
	store := newTestStore(t)
	handler := CreateSecret(store)

	ct := base64.RawURLEncoding.EncodeToString([]byte("x"))
	ttls := []string{"5m", "15m", "1h", "24h", "7d", "30d"}
	for _, ttl := range ttls {
		t.Run(ttl, func(t *testing.T) {
			body := `{"ciphertext":"` + ct + `","expiresIn":"` + ttl + `","burnAfterRead":true}`
			req := httptest.NewRequest(http.MethodPost, "/api/secrets", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusCreated {
				t.Fatalf("expiresIn=%q: expected 201, got %d: %s", ttl, w.Code, w.Body.String())
			}
		})
	}
}

func TestGetSecret_Success(t *testing.T) {
	store := newTestStore(t)

	// Create a secret first.
	plaintext := []byte("secret payload")
	ciphertext := base64.RawURLEncoding.EncodeToString(plaintext)
	body := `{"ciphertext":"` + ciphertext + `","expiresIn":"1h","burnAfterRead":false}`

	createHandler := CreateSecret(store)
	req := httptest.NewRequest(http.MethodPost, "/api/secrets", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	createHandler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create failed: status %d: %s", w.Code, w.Body.String())
	}

	var created createResponse
	json.NewDecoder(w.Body).Decode(&created)

	// Now retrieve it.
	getHandler := GetSecret(store)
	req = httptest.NewRequest(http.MethodGet, "/api/secrets/"+created.ID, nil)
	w = httptest.NewRecorder()
	getHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp getResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Decode and compare ciphertext.
	decoded, err := base64.RawURLEncoding.DecodeString(resp.Ciphertext)
	if err != nil {
		t.Fatalf("failed to decode ciphertext: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Errorf("expected plaintext %q, got %q", plaintext, decoded)
	}
	if resp.BurnAfterRead != false {
		t.Error("expected burnAfterRead=false")
	}
}

func TestGetSecret_NotFound(t *testing.T) {
	store := newTestStore(t)
	handler := GetSecret(store)

	// Use a valid-format but nonexistent ID.
	req := httptest.NewRequest(http.MethodGet, "/api/secrets/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}

	var errResp errorResponse
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp.Error.Code != "not_found" {
		t.Errorf("expected error code 'not_found', got %q", errResp.Error.Code)
	}
}

// TestCreateSecret_LargeCiphertext verifies a ~500 KB ciphertext is accepted
// (within the 1.5 MiB cap, to support file uploads up to 1 MiB).
func TestCreateSecret_LargeCiphertext(t *testing.T) {
	store := newTestStore(t)
	handler := CreateSecret(store)

	// ~500 KB of ciphertext bytes.
	payload := make([]byte, 500*1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	ciphertext := base64.RawURLEncoding.EncodeToString(payload)
	body := `{"ciphertext":"` + ciphertext + `","expiresIn":"1h","burnAfterRead":true}`

	req := httptest.NewRequest(http.MethodPost, "/api/secrets", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for 500 KB ciphertext, got %d: %s", w.Code, w.Body.String())
	}
}

// TestMaxBodySize_RejectsOversized verifies that request bodies larger than
// 2 MiB are rejected by the MaxBodySize middleware.
func TestMaxBodySize_RejectsOversized(t *testing.T) {
	const limit = 2 * 1024 * 1024 // 2 MiB — must match server.go
	store := newTestStore(t)
	// Chain MaxBodySize around CreateSecret to mirror production.
	handler := MaxBodySize(limit)(CreateSecret(store))

	// Build a body larger than 2 MiB. Use raw base64 bytes; content is
	// irrelevant because MaxBodyReader caps reads.
	oversized := make([]byte, limit+2048)
	for i := range oversized {
		oversized[i] = 'a'
	}
	body := `{"ciphertext":"` + string(oversized) + `","expiresIn":"1h","burnAfterRead":true}`

	req := httptest.NewRequest(http.MethodPost, "/api/secrets", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// http.MaxBytesReader causes json.Decode to fail, which our handler
	// returns as 400 invalid_request. Accept 400 or 413 as valid rejection.
	if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 400 or 413 for oversized body, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCreateAndGetSecret_TypeRoundtrip verifies the optional `type` field is
// persisted on create and echoed back on retrieve.
func TestCreateAndGetSecret_TypeRoundtrip(t *testing.T) {
	store := newTestStore(t)

	plaintext := []byte("sk_live_xxx")
	ciphertext := base64.RawURLEncoding.EncodeToString(plaintext)
	body := `{"ciphertext":"` + ciphertext + `","expiresIn":"1h","burnAfterRead":false,"type":"api_key"}`

	createHandler := CreateSecret(store)
	req := httptest.NewRequest(http.MethodPost, "/api/secrets", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	createHandler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create failed: status %d: %s", w.Code, w.Body.String())
	}

	var created createResponse
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// Retrieve and verify type.
	getHandler := GetSecret(store)
	req = httptest.NewRequest(http.MethodGet, "/api/secrets/"+created.ID, nil)
	w = httptest.NewRecorder()
	getHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("get failed: status %d: %s", w.Code, w.Body.String())
	}

	var resp getResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if resp.Type != "api_key" {
		t.Errorf("expected type 'api_key', got %q", resp.Type)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(resp.Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Errorf("expected plaintext %q, got %q", plaintext, decoded)
	}
}

// TestCreateSecret_InvalidType ensures non-enum type values are rejected
// with a 400 at the API boundary.
func TestCreateSecret_InvalidType(t *testing.T) {
	store := newTestStore(t)
	handler := CreateSecret(store)

	ciphertext := base64.RawURLEncoding.EncodeToString([]byte("x"))
	body := `{"ciphertext":"` + ciphertext + `","expiresIn":"1h","burnAfterRead":true,"type":"bogus_type"}`

	req := httptest.NewRequest(http.MethodPost, "/api/secrets", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var errResp errorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if errResp.Error.Code != "invalid_type" {
		t.Errorf("expected error code 'invalid_type', got %q", errResp.Error.Code)
	}
}

// TestCreateSecret_DefaultType verifies omitting `type` defaults to "text".
func TestCreateSecret_DefaultType(t *testing.T) {
	store := newTestStore(t)

	ciphertext := base64.RawURLEncoding.EncodeToString([]byte("hello"))
	body := `{"ciphertext":"` + ciphertext + `","expiresIn":"1h","burnAfterRead":false}`

	createHandler := CreateSecret(store)
	req := httptest.NewRequest(http.MethodPost, "/api/secrets", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	createHandler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create failed: status %d: %s", w.Code, w.Body.String())
	}
	var created createResponse
	json.NewDecoder(w.Body).Decode(&created)

	getHandler := GetSecret(store)
	req = httptest.NewRequest(http.MethodGet, "/api/secrets/"+created.ID, nil)
	w = httptest.NewRecorder()
	getHandler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get failed: status %d: %s", w.Code, w.Body.String())
	}
	var resp getResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Type != "text" {
		t.Errorf("expected default type 'text', got %q", resp.Type)
	}
}

func TestHealthCheck(t *testing.T) {
	handler := HealthCheck()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp healthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.OK {
		t.Error("expected ok=true")
	}
}
