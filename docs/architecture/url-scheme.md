# URL Structure and Encoding

## URL Format

```
https://passwd.page/s/{id}#{base64url(key)}
```

### Components

| Component          | Example                                    | Description                           |
|--------------------|--------------------------------------------|---------------------------------------|
| Origin             | `https://passwd.page`                      | HTTPS only                            |
| Path prefix        | `/s/`                                      | Short, memorable route for secrets    |
| Secret ID          | `a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`        | 32-char hex (16 random bytes)         |
| Fragment separator | `#`                                        | Starts the fragment; never sent to server |
| Encryption key     | `dGhpcyBpcyBhIHRlc3Qga2V5IGZvciBkZW1v`   | base64url-encoded 256-bit key (43 chars) |

### Full Example

```
https://passwd.page/s/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6#q7Z4xK9mN2pR5vW8yB3jF6hL0tS4uA1dC7eG9iM2kO
```

Total URL length: ~100 characters. Well within browser and system limits.

---

## ID Generation

### Requirements
- 16 bytes (128 bits) of cryptographic randomness
- Hex-encoded (32 characters)
- Generated server-side using Go's `crypto/rand`

### Implementation

```go
import (
    "crypto/rand"
    "encoding/hex"
)

func generateID() (string, error) {
    bytes := make([]byte, 16)
    if _, err := rand.Read(bytes); err != nil {
        return "", fmt.Errorf("generating secret ID: %w", err)
    }
    return hex.EncodeToString(bytes), nil
}
```

### Properties
- **Collision probability**: 2^128 space. At 1 billion secrets, collision probability is ~1.5 x 10^-20.
- **Not sequential**: Random IDs prevent enumeration attacks.
- **Not derived from content**: ID reveals nothing about the secret or key.
- **Case-insensitive**: Always stored and returned as lowercase hex. Server normalizes input to lowercase before lookup.

---

## Why the URL Fragment is Safe

### HTTP Specification (RFC 3986 Section 3.5)

> The fragment identifier component of a URI, if present, refers to a
> secondary resource... The fragment identifier is not used in the
> scheme-specific processing of a URI; instead, the fragment identifier
> is separated from the rest of the URI prior to a dereference.

The fragment (everything after `#`) is:
1. **Never included in HTTP requests** — the browser strips it before sending
2. **Never sent as Referer** — with `Referrer-Policy: no-referrer` we don't even send the path
3. **Not visible to the server** — `request.URL.Fragment` is always empty in Go HTTP handlers
4. **Not logged by web servers** — because it is never in the request
5. **Not visible to TLS-terminating proxies** — because it is never in the request

### What the server receives

When a user opens `https://passwd.page/s/abc123#secretkey`:

```
GET /s/abc123 HTTP/1.1
Host: passwd.page
```

The `#secretkey` portion is completely absent from the wire.

### JavaScript Access

The fragment IS accessible to client-side JavaScript:

```javascript
const key = window.location.hash.substring(1); // "secretkey"
```

This is by design — the Svelte frontend reads the key from the fragment to perform decryption.

---

## Fragment Limitations and Risks

### Services That Strip Fragments

Some services remove the fragment when processing or rendering URLs:

| Service/Context         | Behavior                                     | Impact     |
|-------------------------|----------------------------------------------|------------|
| URL shorteners (bit.ly) | Strip fragment entirely                     | Key lost   |
| Slack link previews     | May strip fragment in unfurled previews      | Key lost   |
| Jira descriptions       | Strip fragment when rendering links          | Key lost   |
| Some email clients      | Strip fragment in HTML email links           | Key lost   |
| HTTP redirects (302)    | Browser MAY preserve fragment (per RFC 7231) | Usually OK |
| QR code generators      | Preserve fragment (it is just text)          | Safe       |
| SMS                     | Preserve fragment (plain text)               | Safe       |

### Browser Extensions

Browser extensions with `tabs` or `webNavigation` permissions can read `window.location.hash`. This is an inherent risk of browser-based encryption. Users in high-security environments should use a clean browser profile.

### Copy-Paste Behavior

When a user copies a URL from the browser address bar, the fragment IS included. This is the intended sharing mechanism. The risk is that the clipboard may be monitored.

### UX Mitigations

The frontend should display warnings:

1. **On the share page** (after creating a secret):
   > "Copy the full link including everything after the # symbol. This is your encryption key. Without it, the secret cannot be decrypted."

2. **On the share page** (secondary notice):
   > "Do not use URL shorteners. Some services strip the # portion of links."

3. **On the retrieve page** (if no fragment is present):
   > "This link appears to be missing the decryption key. The key is the part after the # symbol in the URL. It may have been stripped by the service you used to share the link."

---

## Frontend Routing

The Svelte frontend uses client-side routing for the secret view page. The server must return the SPA's `index.html` for all `/s/*` paths.

### Server Route Configuration

```go
mux.HandleFunc("GET /s/{id}", spaHandler)   // Serve index.html; Svelte handles routing
mux.HandleFunc("POST /api/secrets", createHandler)
mux.HandleFunc("GET /api/secrets/{id}", getHandler)
mux.HandleFunc("GET /health", healthHandler)
mux.Handle("GET /", staticHandler)           // Serve embedded static files
```

The SPA handler returns `index.html` with appropriate cache headers. The Svelte router then:
1. Parses the path to extract the secret ID
2. Reads `window.location.hash` to extract the key
3. Fetches the ciphertext from `/api/secrets/{id}`
4. Decrypts and displays

### URL Encoding Notes

- The secret ID is hex-only (`[0-9a-f]`), no encoding needed
- The key is base64url (`[A-Za-z0-9_-]`), safe in fragments without percent-encoding
- No special characters appear in our URLs; no encoding edge cases
