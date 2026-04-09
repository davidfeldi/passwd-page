package server

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"time"

	"github.com/davidfeldi/passwd-page/internal/storage"
)

// Server holds the HTTP server and its dependencies.
type Server struct {
	store      storage.Store
	mux        *http.ServeMux
	httpServer *http.Server
}

// Option configures the Server.
type Option func(*serverConfig)

type serverConfig struct {
	port         int
	readTimeout  time.Duration
	writeTimeout time.Duration
	frontend     fs.FS
}

func defaultConfig() serverConfig {
	return serverConfig{
		port:         8080,
		readTimeout:  5 * time.Second,
		writeTimeout: 10 * time.Second,
	}
}

// WithPort sets the listening port.
func WithPort(port int) Option {
	return func(c *serverConfig) {
		c.port = port
	}
}

// WithReadTimeout sets the HTTP read timeout.
func WithReadTimeout(d time.Duration) Option {
	return func(c *serverConfig) {
		c.readTimeout = d
	}
}

// WithWriteTimeout sets the HTTP write timeout.
func WithWriteTimeout(d time.Duration) Option {
	return func(c *serverConfig) {
		c.writeTimeout = d
	}
}

// WithFrontend sets the filesystem used to serve static frontend files.
func WithFrontend(f fs.FS) Option {
	return func(c *serverConfig) {
		c.frontend = f
	}
}

// NewServer creates a configured Server with routes and middleware wired up.
func NewServer(store storage.Store, opts ...Option) *Server {
	cfg := defaultConfig()
	for _, o := range opts {
		o(&cfg)
	}

	mux := http.NewServeMux()
	s := &Server{
		store: store,
		mux:   mux,
	}

	// Middleware chains: rate limiting only on API routes, not static assets.
	rateLimit := RateLimit(10, 60, 1*time.Minute)
	maxBody := MaxBodySize(128 * 1024) // 128 KiB

	apiChain := func(h http.Handler) http.Handler {
		return RequestLogger(SecurityHeaders(rateLimit(maxBody(h))))
	}
	staticChain := func(h http.Handler) http.Handler {
		return RequestLogger(SecurityHeaders(h))
	}

	// API routes (rate-limited).
	mux.Handle("POST /api/secrets", apiChain(CreateSecret(store)))
	mux.Handle("GET /api/secrets/", apiChain(GetSecret(store)))
	mux.Handle("GET /health", staticChain(HealthCheck()))
	mux.Handle("GET /metrics", staticChain(Metrics(store)))

	// Static frontend files with SPA fallback (no rate limit).
	if cfg.frontend != nil {
		mux.Handle("/", staticChain(spaHandler(cfg.frontend)))
	} else {
		mux.Handle("/", staticChain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "frontend not configured", http.StatusNotFound)
		})))
	}

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.port),
		Handler:      mux,
		ReadTimeout:  cfg.readTimeout,
		WriteTimeout: cfg.writeTimeout,
	}

	return s
}

// Start begins listening. It blocks until the server stops.
// Returns http.ErrServerClosed on graceful shutdown.
func (s *Server) Start() error {
	slog.Info("server starting", "addr", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("server shutting down")
	return s.httpServer.Shutdown(ctx)
}

// spaHandler serves static files from the embedded FS, falling back to
// index.html for paths that don't match a real file (SPA client-side routing).
func spaHandler(frontend fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clean the path; strip leading slash for fs.Open.
		p := path.Clean(r.URL.Path)
		if p == "/" {
			p = "index.html"
		} else {
			p = p[1:] // strip leading "/"
		}

		// Try to open the requested file.
		f, err := frontend.Open(p)
		if err != nil {
			// File not found — serve index.html for SPA routing.
			serveIndexHTML(w, r, frontend)
			return
		}
		defer f.Close()

		// If it's a directory, try <dir>/index.html, else SPA fallback.
		stat, err := f.Stat()
		if err != nil {
			serveIndexHTML(w, r, frontend)
			return
		}
		if stat.IsDir() {
			f.Close()
			indexPath := path.Join(p, "index.html")
			f2, err := frontend.Open(indexPath)
			if err != nil {
				serveIndexHTML(w, r, frontend)
				return
			}
			defer f2.Close()
			http.ServeContent(w, r, "index.html", stat.ModTime(), f2.(io.ReadSeeker))
			return
		}

		http.ServeContent(w, r, stat.Name(), stat.ModTime(), f.(io.ReadSeeker))
	})
}

// serveIndexHTML serves the root index.html as the SPA fallback.
func serveIndexHTML(w http.ResponseWriter, r *http.Request, frontend fs.FS) {
	f, err := frontend.Open("index.html")
	if err != nil {
		http.Error(w, "index.html not found", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "failed to stat index.html", http.StatusInternalServerError)
		return
	}

	http.ServeContent(w, r, "index.html", stat.ModTime(), f.(io.ReadSeeker))
}
