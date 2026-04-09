package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	createTableSQL = `
		CREATE TABLE IF NOT EXISTS secrets (
			id              TEXT PRIMARY KEY,
			ciphertext      BLOB NOT NULL,
			burn_after_read BOOLEAN NOT NULL DEFAULT FALSE,
			expires_at      DATETIME NOT NULL,
			created_at      DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			views           INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets(expires_at);
		CREATE TABLE IF NOT EXISTS counters (
			key   TEXT PRIMARY KEY,
			value INTEGER NOT NULL DEFAULT 0
		);
		INSERT OR IGNORE INTO counters (key, value) VALUES ('total_created', 0);
		INSERT OR IGNORE INTO counters (key, value) VALUES ('total_burned', 0);
		INSERT OR IGNORE INTO counters (key, value) VALUES ('total_expired', 0);
	`

	insertSQL = `INSERT INTO secrets (id, ciphertext, burn_after_read, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`

	getBurnSQL = `DELETE FROM secrets WHERE id = ? AND burn_after_read = 1 AND expires_at > ? RETURNING id, ciphertext, burn_after_read, expires_at, created_at, views`

	getNormalSQL = `UPDATE secrets SET views = views + 1 WHERE id = ? AND burn_after_read = 0 AND expires_at > ? RETURNING id, ciphertext, burn_after_read, expires_at, created_at, views`

	deleteSQL = `DELETE FROM secrets WHERE id = ?`

	cleanupSQL = `DELETE FROM secrets WHERE expires_at <= ?`
)

// SQLiteStore implements Store using SQLite.
type SQLiteStore struct {
	db          *sql.DB
	stmtInsert  *sql.Stmt
	stmtBurn    *sql.Stmt
	stmtNormal  *sql.Stmt
	stmtDelete  *sql.Stmt
	stmtCleanup *sql.Stmt
}

// NewSQLiteStore creates a new SQLite-backed store.
// The database file is created if it does not exist.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_foreign_keys=ON&cache=shared")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Set cache size (this also forces the file to be created on disk).
	if _, err := db.Exec("PRAGMA cache_size = -2000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set cache_size: %w", err)
	}

	// Restrict database file permissions to owner-only (rw-------).
	// This prevents other users on the system from reading secret data.
	if err := os.Chmod(dbPath, 0600); err != nil {
		db.Close()
		return nil, fmt.Errorf("chmod db: %w", err)
	}

	// Create table and index
	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("create table: %w", err)
	}

	s := &SQLiteStore{db: db}

	// Prepare statements
	s.stmtInsert, err = db.Prepare(insertSQL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("prepare insert: %w", err)
	}
	s.stmtBurn, err = db.Prepare(getBurnSQL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("prepare burn: %w", err)
	}
	s.stmtNormal, err = db.Prepare(getNormalSQL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("prepare normal: %w", err)
	}
	s.stmtDelete, err = db.Prepare(deleteSQL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("prepare delete: %w", err)
	}
	s.stmtCleanup, err = db.Prepare(cleanupSQL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("prepare cleanup: %w", err)
	}

	return s, nil
}

// generateID creates a 32-character hex string from 16 cryptographically random bytes.
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Create stores a new secret and returns its generated ID.
func (s *SQLiteStore) Create(ctx context.Context, params CreateParams) (string, error) {
	id, err := generateID()
	if err != nil {
		return "", err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	expiresAt := params.ExpiresAt.UTC().Format(time.RFC3339)

	_, err = s.stmtInsert.ExecContext(ctx, id, params.Ciphertext, params.BurnAfterRead, expiresAt, now)
	if err != nil {
		return "", fmt.Errorf("insert secret: %w", err)
	}

	s.db.ExecContext(ctx, `UPDATE counters SET value = value + 1 WHERE key = 'total_created'`)

	return id, nil
}

// scanSecret scans a row into a Secret struct.
func scanSecret(row *sql.Row) (*Secret, error) {
	var sec Secret
	var expiresAt, createdAt string

	err := row.Scan(&sec.ID, &sec.Ciphertext, &sec.BurnAfterRead, &expiresAt, &createdAt, &sec.Views)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan secret: %w", err)
	}

	sec.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}
	sec.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}

	return &sec, nil
}

// Get retrieves a secret by ID.
// For burn-after-read secrets, the secret is atomically deleted.
// For normal secrets, the view counter is incremented.
// Returns (nil, nil) if the secret does not exist or has expired.
func (s *SQLiteStore) Get(ctx context.Context, id string) (*Secret, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	// Try burn-after-read first (DELETE ... RETURNING)
	sec, err := scanSecret(s.stmtBurn.QueryRowContext(ctx, id, now))
	if err != nil {
		return nil, err
	}
	if sec != nil {
		s.db.ExecContext(ctx, `UPDATE counters SET value = value + 1 WHERE key = 'total_burned'`)
		return sec, nil
	}

	// Try normal get (UPDATE ... RETURNING)
	sec, err = scanSecret(s.stmtNormal.QueryRowContext(ctx, id, now))
	if err != nil {
		return nil, err
	}

	return sec, nil
}

// Delete removes a secret by ID. No error if it doesn't exist.
func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	_, err := s.stmtDelete.ExecContext(ctx, id)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	return nil
}

// Cleanup removes all expired secrets and returns the count deleted.
func (s *SQLiteStore) Cleanup(ctx context.Context) (int, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	result, err := s.stmtCleanup.ExecContext(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("cleanup secrets: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}

	if count > 0 {
		s.db.ExecContext(ctx, `UPDATE counters SET value = value + ? WHERE key = 'total_expired'`, count)
	}

	return int(count), nil
}

// Stats returns anonymous usage counters.
func (s *SQLiteStore) Stats(ctx context.Context) (*Stats, error) {
	stats := &Stats{}

	// Active secrets count
	row := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets WHERE expires_at > ?`, time.Now().UTC().Format(time.RFC3339))
	if err := row.Scan(&stats.ActiveSecrets); err != nil {
		return nil, fmt.Errorf("count active: %w", err)
	}

	// Counters
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM counters`)
	if err != nil {
		return nil, fmt.Errorf("query counters: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var key string
		var value int64
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("scan counter: %w", err)
		}
		switch key {
		case "total_created":
			stats.TotalCreated = value
		case "total_burned":
			stats.BurnedSecrets = value
		case "total_expired":
			stats.ExpiredCleaned = value
		}
	}

	return stats, nil
}

// Close releases all resources.
func (s *SQLiteStore) Close() error {
	s.stmtInsert.Close()
	s.stmtBurn.Close()
	s.stmtNormal.Close()
	s.stmtDelete.Close()
	s.stmtCleanup.Close()
	return s.db.Close()
}
