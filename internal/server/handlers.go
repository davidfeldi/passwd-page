package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/davidfeldi/passwd-page/internal/storage"
)

const maxCiphertextDecoded = 64 * 1024 // 64 KiB

// Metrics returns anonymous usage counters.
// Protected by METRICS_TOKEN env var — if set, requires ?token=<value> to access.
func Metrics(store storage.Store) http.Handler {
	token := os.Getenv("METRICS_TOKEN")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.URL.Query().Get("token") != token {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing token")
			return
		}
		stats, err := store.Stats(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "Failed to get metrics")
			return
		}
		writeJSON(w, http.StatusOK, stats)
	})
}

// errorResponse represents a structured API error.
type errorResponse struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// createRequest is the JSON body for POST /api/secrets.
type createRequest struct {
	Ciphertext    string `json:"ciphertext"`
	ExpiresIn     string `json:"expiresIn"`
	BurnAfterRead *bool  `json:"burnAfterRead"`
}

// createResponse is the JSON response for a successful secret creation.
type createResponse struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expiresAt"`
}

// getResponse is the JSON response for a successful secret retrieval.
type getResponse struct {
	Ciphertext    string `json:"ciphertext"`
	BurnAfterRead bool   `json:"burnAfterRead"`
}

// healthResponse is the JSON response for the health check endpoint.
type healthResponse struct {
	OK bool `json:"ok"`
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a structured error response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{
		Error: errorDetail{Code: code, Message: message},
	})
}

// parseExpiresIn converts an expiresIn string to a duration.
func parseExpiresIn(s string) (time.Duration, bool) {
	switch s {
	case "1h":
		return 1 * time.Hour, true
	case "24h":
		return 24 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

// CreateSecret returns an http.HandlerFunc for POST /api/secrets.
func CreateSecret(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed")
			return
		}

		var req createRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
			return
		}

		// Validate ciphertext is present.
		if req.Ciphertext == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "Field 'ciphertext' is required")
			return
		}

		// Decode base64 to check size. Try raw URL encoding (no padding) first,
		// then padded URL encoding, then standard base64 as fallback.
		decoded, err := base64.RawURLEncoding.DecodeString(req.Ciphertext)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(req.Ciphertext)
			if err != nil {
				decoded, err = base64.StdEncoding.DecodeString(req.Ciphertext)
				if err != nil {
					writeError(w, http.StatusBadRequest, "invalid_request", "Field 'ciphertext' must be valid base64")
					return
				}
			}
		}

		if len(decoded) > maxCiphertextDecoded {
			writeError(w, http.StatusBadRequest, "ciphertext_too_large",
				fmt.Sprintf("Ciphertext exceeds maximum size of %d bytes", maxCiphertextDecoded))
			return
		}

		// Validate expiresIn.
		if req.ExpiresIn == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "Field 'expiresIn' is required")
			return
		}
		duration, ok := parseExpiresIn(req.ExpiresIn)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_expiry", "expiresIn must be one of: 1h, 24h, 7d")
			return
		}

		// Validate burnAfterRead is present.
		if req.BurnAfterRead == nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "Field 'burnAfterRead' is required")
			return
		}

		expiresAt := time.Now().Add(duration)

		id, err := store.Create(r.Context(), storage.CreateParams{
			Ciphertext:    decoded,
			BurnAfterRead: *req.BurnAfterRead,
			ExpiresAt:     expiresAt,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to create secret")
			return
		}

		writeJSON(w, http.StatusCreated, createResponse{
			ID:        id,
			ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		})
	}
}

// GetSecret returns an http.HandlerFunc for GET /api/secrets/{id}.
func GetSecret(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed")
			return
		}

		// Extract ID from path: /api/secrets/{id}
		id := strings.TrimPrefix(r.URL.Path, "/api/secrets/")
		if id == "" || id == r.URL.Path {
			writeError(w, http.StatusBadRequest, "invalid_request", "Secret ID is required")
			return
		}

		// Validate ID format: 32 hex characters.
		if len(id) != 32 {
			writeError(w, http.StatusNotFound, "not_found", "Secret not found")
			return
		}
		if _, err := hex.DecodeString(id); err != nil {
			writeError(w, http.StatusNotFound, "not_found", "Secret not found")
			return
		}

		// Note: We use a direct database lookup rather than constant-time comparison
		// because secret IDs are 128-bit cryptographically random values (2^128 space).
		// Timing side-channels are not exploitable here — an attacker cannot
		// meaningfully narrow the search space via response-time observations.

		secret, err := store.Get(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to retrieve secret")
			return
		}
		if secret == nil {
			writeError(w, http.StatusNotFound, "not_found", "Secret not found")
			return
		}

		writeJSON(w, http.StatusOK, getResponse{
			Ciphertext:    base64.RawURLEncoding.EncodeToString(secret.Ciphertext),
			BurnAfterRead: secret.BurnAfterRead,
		})
	}
}

// HealthCheck returns an http.HandlerFunc for GET /health.
func HealthCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{OK: true})
	}
}

// generateID creates a 16-byte cryptographically random hex-encoded ID.
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
