// Package server provides HTTP middleware for passwd.page.
package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SecurityHeaders sets all security-related HTTP headers on every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; connect-src 'self'; font-src 'self'; "+
				"base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

		h.Set("Strict-Transport-Security",
			"max-age=31536000; includeSubDomains; preload")

		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("X-DNS-Prefetch-Control", "off")

		// CORS is intentionally not enabled. The browser's same-origin policy
		// blocks cross-origin requests by default, which is the desired behavior
		// for this application. No Access-Control-Allow-Origin header is set.

		next.ServeHTTP(w, r)
	})
}

// rateLimiter tracks request counts per IP using a sliding window.
type rateLimiter struct {
	mu             sync.Mutex
	createWindows  map[string][]time.Time
	readWindows    map[string][]time.Time
	createLimit    int
	readLimit      int
	windowDuration time.Duration
	stopCleanup    chan struct{}
}

// newRateLimiter creates a rate limiter and starts its background cleanup goroutine.
func newRateLimiter(createLimit, readLimit int, windowDuration time.Duration) *rateLimiter {
	rl := &rateLimiter{
		createWindows:  make(map[string][]time.Time),
		readWindows:    make(map[string][]time.Time),
		createLimit:    createLimit,
		readLimit:      readLimit,
		windowDuration: windowDuration,
		stopCleanup:    make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// cleanup periodically removes stale entries from the rate limiter maps.
func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.evict()
		case <-rl.stopCleanup:
			return
		}
	}
}

// evict removes entries older than 2 minutes.
func (rl *rateLimiter) evict() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-2 * time.Minute)
	evictMap(rl.createWindows, cutoff)
	evictMap(rl.readWindows, cutoff)
}

func evictMap(m map[string][]time.Time, cutoff time.Time) {
	for ip, times := range m {
		valid := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(m, ip)
		} else {
			m[ip] = valid
		}
	}
}

// allow checks whether the given IP is within its rate limit for the specified
// window map and limit. It prunes expired entries and records the new request
// if allowed. Returns (allowed, remaining, resetTime).
func (rl *rateLimiter) allow(ip string, windows map[string][]time.Time, limit int) (bool, int, time.Time) {
	now := time.Now()
	windowStart := now.Add(-rl.windowDuration)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Prune expired entries for this IP.
	times := windows[ip]
	valid := times[:0]
	for _, t := range times {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}
	windows[ip] = valid

	if len(valid) >= limit {
		// Calculate when the oldest request in the window expires.
		resetAt := valid[0].Add(rl.windowDuration)
		return false, 0, resetAt
	}

	windows[ip] = append(valid, now)
	remaining := limit - len(valid) - 1
	resetAt := now.Add(rl.windowDuration)
	return true, remaining, resetAt
}

// clientIP extracts the client IP from the request, checking X-Forwarded-For first.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first (leftmost) IP — closest to client.
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RateLimit returns middleware that enforces per-IP rate limits using a sliding
// window. createLimit applies to POST requests, readLimit to GET requests.
func RateLimit(createLimit, readLimit int, windowDuration time.Duration) func(http.Handler) http.Handler {
	rl := newRateLimiter(createLimit, readLimit, windowDuration)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)

			var allowed bool
			var remaining int
			var resetAt time.Time
			var limit int

			switch r.Method {
			case http.MethodPost:
				limit = rl.createLimit
				allowed, remaining, resetAt = rl.allow(ip, rl.createWindows, limit)
			default:
				limit = rl.readLimit
				allowed, remaining, resetAt = rl.allow(ip, rl.readWindows, limit)
			}

			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetAt.Unix()))

			if !allowed {
				retryAfter := time.Until(resetAt).Seconds()
				if retryAfter < 1 {
					retryAfter = 1
				}
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter)))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]string{"error": "rate limit exceeded"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// MaxBodySize returns middleware that limits the request body to maxBytes.
// Returns 413 Request Entity Too Large if exceeded.
func MaxBodySize(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// responseRecorder wraps http.ResponseWriter to capture the status code.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	rr.ResponseWriter.WriteHeader(code)
}

// RequestLogger logs method, path, status code, and duration for every request.
// It NEVER logs request or response bodies.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rec := &responseRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(rec, r)

		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.statusCode,
			"duration", time.Since(start).String(),
			"ip", clientIP(r),
		)
	})
}
