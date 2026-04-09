package main

import (
	"context"
	"flag"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	passwdpage "github.com/davidfeldi/passwd-page"
	"github.com/davidfeldi/passwd-page/internal/server"
	"github.com/davidfeldi/passwd-page/internal/storage"
)

func main() {
	port := flag.Int("port", 8080, "HTTP listen port")
	dbPath := flag.String("db", "passwd.db", "SQLite database path")
	flag.Parse()

	// Respect PORT env var (set by Render.com) if -port flag wasn't explicitly provided.
	if envPort := os.Getenv("PORT"); envPort != "" {
		portExplicit := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "port" {
				portExplicit = true
			}
		})
		if !portExplicit {
			if p, err := strconv.Atoi(envPort); err == nil {
				*port = p
			}
		}
	}

	// Initialize SQLite store.
	store, err := storage.NewSQLiteStore(*dbPath)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	// Start background cleanup goroutine.
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	defer cleanupCancel()
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				removed, err := store.Cleanup(context.Background())
				if err != nil {
					slog.Error("cleanup failed", "error", err)
				} else if removed > 0 {
					slog.Info("cleanup completed", "removed", removed)
				}
			case <-cleanupCtx.Done():
				return
			}
		}
	}()

	// Prepare embedded frontend filesystem (strip the "frontend/build" prefix).
	frontendFS, err := fs.Sub(passwdpage.FrontendFiles, "frontend/build")
	if err != nil {
		slog.Error("failed to prepare frontend filesystem", "error", err)
		os.Exit(1)
	}

	// Create and start server.
	srv := server.NewServer(store,
		server.WithPort(*port),
		server.WithFrontend(frontendFS),
	)

	slog.Info("passwd.page starting", "port", *port)

	// Start server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	// Wait for interrupt signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		slog.Info("received signal", "signal", sig)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}

	// Graceful shutdown with 10s timeout.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped")
}
