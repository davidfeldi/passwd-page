# Security Headers Specification

## Overview

All HTTP responses from passwd.page include security headers to defend against XSS, clickjacking, MIME sniffing, and information leakage. Headers are applied via a single middleware function that wraps every handler.

---

## Header Definitions

### Content-Security-Policy

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

| Directive        | Value    | Rationale                                              |
|------------------|----------|--------------------------------------------------------|
| default-src      | 'none'   | Deny everything by default; whitelist explicitly       |
| script-src       | 'self'   | Only scripts from our origin (go:embed bundle)         |
| style-src        | 'self'   | Only stylesheets from our origin                       |
| img-src          | 'self'   | Only images from our origin (favicon, logo)            |
| connect-src      | 'self'   | Only XHR/fetch to our own API                          |
| font-src         | 'self'   | Only fonts from our origin (if any)                    |
| base-uri         | 'none'   | Prevent base tag injection                             |
| form-action      | 'self'   | Forms can only submit to our origin                    |
| frame-ancestors  | 'none'   | Prevent embedding in iframes (clickjacking)            |

**No `'unsafe-inline'` or `'unsafe-eval'`**: The Svelte build produces external JS/CSS files. No inline scripts or eval are needed.

### Strict-Transport-Security

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

- Forces HTTPS for 1 year (31536000 seconds)
- Applies to all subdomains
- Eligible for browser HSTS preload lists
- Only sent over HTTPS responses (middleware checks `r.TLS != nil` or `X-Forwarded-Proto: https`)

### X-Content-Type-Options

```
X-Content-Type-Options: nosniff
```

Prevents browsers from MIME-sniffing responses away from declared Content-Type. Ensures our JSON API responses are not reinterpreted as HTML.

### X-Frame-Options

```
X-Frame-Options: DENY
```

Legacy clickjacking protection (supplement to CSP frame-ancestors). Blocks all framing of the page.

### Referrer-Policy

```
Referrer-Policy: no-referrer
```

Prevents the browser from sending any Referer header when navigating away from passwd.page. Critical because:
- The URL contains the secret ID in the path
- Although the fragment (key) is never sent as Referer, the path `/s/{id}` would be
- `no-referrer` ensures not even the path leaks to external sites

### Permissions-Policy

```
Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()
```

Disables browser features not needed by the application:
- No camera/microphone/geolocation access
- Opts out of FLoC/Topics API tracking

### Cache-Control

```
Cache-Control: no-store
```

Applied to all API responses. Secrets must never be cached by browsers or intermediate proxies. Static assets (JS/CSS) may use cache headers with content hashing in filenames.

### X-Request-Id

```
X-Request-Id: <uuid>
```

Generated per-request UUID for log correlation. Useful for debugging without exposing internal state.

---

## Middleware Implementation

```go
func SecurityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        h := w.Header()

        h.Set("Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; "+
            "img-src 'self'; connect-src 'self'; font-src 'self'; "+
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

        h.Set("Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload")

        h.Set("X-Content-Type-Options", "nosniff")
        h.Set("X-Frame-Options", "DENY")
        h.Set("Referrer-Policy", "no-referrer")
        h.Set("Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), interest-cohort=()")
        h.Set("Cache-Control", "no-store")

        next.ServeHTTP(w, r)
    })
}
```

---

## Rate Limiting

### Algorithm

Sliding window counter per IP address, implemented in-memory using a map with periodic eviction.

### Limits

| Endpoint             | Limit              | Window |
|----------------------|--------------------|--------|
| POST /api/secrets    | 10 requests        | 1 min  |
| GET /api/secrets/{id}| 30 requests        | 1 min  |
| GET /health          | Exempt             | -      |
| All other routes     | 60 requests        | 1 min  |

### IP Extraction

```go
func clientIP(r *http.Request) string {
    // Trust X-Forwarded-For only behind a known reverse proxy
    // In direct mode, use r.RemoteAddr
    if trusted {
        if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
            // Take the first (leftmost) IP — closest to client
            return strings.TrimSpace(strings.Split(xff, ",")[0])
        }
    }
    host, _, _ := net.SplitHostPort(r.RemoteAddr)
    return host
}
```

### Configuration

| Parameter             | Default  | Env Var                  |
|-----------------------|----------|--------------------------|
| Create limit          | 10/min   | `PASSWD_RATE_CREATE`     |
| Read limit            | 30/min   | `PASSWD_RATE_READ`       |
| Trust proxy headers   | false    | `PASSWD_TRUST_PROXY`     |

### Response Headers

All responses include rate limit headers (see api-spec.md for details):

```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1680000000
```

### Eviction

The rate limiter's in-memory map is cleaned every 5 minutes, removing entries older than 2 minutes. This prevents unbounded memory growth.

---

## Additional Security Measures

### Request Body Limits
- Maximum request body: 128 KiB
- Enforced via `http.MaxBytesReader` on all POST handlers
- Returns `413 Request Entity Too Large` if exceeded

### Timeout Configuration
- Read timeout: 5 seconds
- Write timeout: 10 seconds
- Idle timeout: 120 seconds
- Read header timeout: 2 seconds

```go
server := &http.Server{
    Addr:              ":8080",
    Handler:           handler,
    ReadTimeout:       5 * time.Second,
    WriteTimeout:      10 * time.Second,
    IdleTimeout:       120 * time.Second,
    ReadHeaderTimeout: 2 * time.Second,
    MaxHeaderBytes:    1 << 15, // 32 KiB
}
```

### Logging
- Log request method, path, status code, duration, client IP, request ID
- NEVER log request/response bodies (may contain ciphertext)
- NEVER log URL fragments (not possible server-side, but stated for completeness)
- Use structured logging (`slog`) with JSON output in production
