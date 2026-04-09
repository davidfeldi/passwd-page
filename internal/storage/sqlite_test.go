package storage

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestCreateAndGet(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	id, err := store.Create(ctx, CreateParams{
		Ciphertext:    []byte("encrypted-data"),
		BurnAfterRead: false,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(id) != 32 {
		t.Fatalf("expected 32-char ID, got %d: %s", len(id), id)
	}

	sec, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if sec == nil {
		t.Fatal("Get returned nil")
	}
	if string(sec.Ciphertext) != "encrypted-data" {
		t.Errorf("ciphertext = %q, want %q", sec.Ciphertext, "encrypted-data")
	}
	if sec.BurnAfterRead {
		t.Error("expected BurnAfterRead = false")
	}
	if sec.Views != 1 {
		t.Errorf("views = %d, want 1", sec.Views)
	}

	// Second get should increment views
	sec, err = store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get (2nd): %v", err)
	}
	if sec.Views != 2 {
		t.Errorf("views = %d, want 2", sec.Views)
	}
}

func TestBurnAfterRead(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	id, err := store.Create(ctx, CreateParams{
		Ciphertext:    []byte("burn-secret"),
		BurnAfterRead: true,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// First get should succeed
	sec, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if sec == nil {
		t.Fatal("Get returned nil")
	}
	if string(sec.Ciphertext) != "burn-secret" {
		t.Errorf("ciphertext = %q, want %q", sec.Ciphertext, "burn-secret")
	}

	// Second get should return nil (burned)
	sec, err = store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get (2nd): %v", err)
	}
	if sec != nil {
		t.Error("expected nil after burn-after-read, got secret")
	}
}

func TestExpiry(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	id, err := store.Create(ctx, CreateParams{
		Ciphertext:    []byte("expired-secret"),
		BurnAfterRead: false,
		ExpiresAt:     time.Now().Add(-1 * time.Hour), // already expired
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	sec, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if sec != nil {
		t.Error("expected nil for expired secret, got secret")
	}
}

func TestCleanup(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Create an expired secret
	_, err := store.Create(ctx, CreateParams{
		Ciphertext:    []byte("old-secret"),
		BurnAfterRead: false,
		ExpiresAt:     time.Now().Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Create (expired): %v", err)
	}

	// Create a valid secret
	validID, err := store.Create(ctx, CreateParams{
		Ciphertext:    []byte("valid-secret"),
		BurnAfterRead: false,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Create (valid): %v", err)
	}

	removed, err := store.Cleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}

	// Valid secret should still exist
	sec, err := store.Get(ctx, validID)
	if err != nil {
		t.Fatalf("Get valid: %v", err)
	}
	if sec == nil {
		t.Error("valid secret was cleaned up")
	}
}

func TestNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	sec, err := store.Get(ctx, "nonexistent0000000000000000000000")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if sec != nil {
		t.Error("expected nil for nonexistent secret")
	}
}

func TestDelete(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	id, err := store.Create(ctx, CreateParams{
		Ciphertext:    []byte("to-delete"),
		BurnAfterRead: false,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	err = store.Delete(ctx, id)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	sec, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if sec != nil {
		t.Error("expected nil after delete")
	}

	// Delete nonexistent should not error
	err = store.Delete(ctx, "nonexistent0000000000000000000000")
	if err != nil {
		t.Errorf("Delete nonexistent: %v", err)
	}
}

func TestStartCleanup(t *testing.T) {
	store := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())

	// Create an expired secret
	_, err := store.Create(ctx, CreateParams{
		Ciphertext:    []byte("cleanup-test"),
		BurnAfterRead: false,
		ExpiresAt:     time.Now().Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	go StartCleanup(ctx, store, 50*time.Millisecond, logger)

	// Wait for cleanup to run
	time.Sleep(200 * time.Millisecond)
	cancel()

	// Verify the expired secret was cleaned up
	removed, err := store.Cleanup(context.Background())
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if removed != 0 {
		t.Errorf("expected 0 remaining expired secrets, got %d", removed)
	}
}
