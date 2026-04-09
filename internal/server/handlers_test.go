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
			name:       "invalid expiresIn",
			body:       `{"ciphertext":"` + base64.RawURLEncoding.EncodeToString([]byte("x")) + `","expiresIn":"2h","burnAfterRead":true}`,
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
			body:       `{"ciphertext":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 65*1024)) + `","expiresIn":"1h","burnAfterRead":true}`,
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
