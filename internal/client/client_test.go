package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateSecret_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/secrets" {
			t.Fatalf("expected /api/secrets, got %s", r.URL.Path)
		}
		if ua := r.Header.Get("User-Agent"); ua != userAgent {
			t.Fatalf("expected User-Agent %q, got %q", userAgent, ua)
		}

		var req createRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Ciphertext != "dGVzdA" {
			t.Fatalf("expected ciphertext 'dGVzdA', got %q", req.Ciphertext)
		}
		if req.ExpiresIn != "1h" {
			t.Fatalf("expected expiresIn '1h', got %q", req.ExpiresIn)
		}
		if !req.BurnAfterRead {
			t.Fatal("expected burnAfterRead true")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createResponse{
			ID:        "abcdef01234567890abcdef012345678",
			ExpiresAt: "2026-04-06T13:00:00Z",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	id, expiresAt, err := c.CreateSecret(context.Background(), "dGVzdA", "1h", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "abcdef01234567890abcdef012345678" {
		t.Fatalf("expected id 'abcdef01234567890abcdef012345678', got %q", id)
	}
	if expiresAt != "2026-04-06T13:00:00Z" {
		t.Fatalf("expected expiresAt '2026-04-06T13:00:00Z', got %q", expiresAt)
	}
}

func TestGetSecret_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/secrets/abcdef01234567890abcdef012345678" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if ua := r.Header.Get("User-Agent"); ua != userAgent {
			t.Fatalf("expected User-Agent %q, got %q", userAgent, ua)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getResponse{
			Ciphertext:    "dGVzdA",
			BurnAfterRead: true,
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	ct, bar, err := c.GetSecret(context.Background(), "abcdef01234567890abcdef012345678")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != "dGVzdA" {
		t.Fatalf("expected ciphertext 'dGVzdA', got %q", ct)
	}
	if !bar {
		t.Fatal("expected burnAfterRead true")
	}
}

func TestGetSecret_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":    "not_found",
				"message": "Secret not found",
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	_, _, err := c.GetSecret(context.Background(), "00000000000000000000000000000000")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDefaultServerURL(t *testing.T) {
	// With explicit URL
	c := NewClient("https://custom.example.com")
	if c.baseURL != "https://custom.example.com" {
		t.Fatalf("expected custom URL, got %q", c.baseURL)
	}

	// With env var override
	t.Setenv("PASSWD_SERVER", "https://env.example.com")
	c = NewClient("")
	if c.baseURL != "https://env.example.com" {
		t.Fatalf("expected env URL, got %q", c.baseURL)
	}

	// Default when nothing is set
	t.Setenv("PASSWD_SERVER", "")
	c = NewClient("")
	if c.baseURL != defaultServerURL {
		t.Fatalf("expected default URL %q, got %q", defaultServerURL, c.baseURL)
	}
}
