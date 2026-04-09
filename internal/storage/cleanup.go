package storage

import (
	"context"
	"log/slog"
	"time"
)

// StartCleanup runs a background goroutine that periodically removes expired secrets.
// It blocks until the context is cancelled. Typically called with `go StartCleanup(...)`.
func StartCleanup(ctx context.Context, store Store, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed, err := store.Cleanup(ctx)
			if err != nil {
				logger.Error("cleanup failed", "error", err)
				continue
			}
			if removed > 0 {
				logger.Info("cleanup completed", "removed", removed)
			}
		}
	}
}
