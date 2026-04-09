# REST API Specification

## Base URL

```
https://passwd.page/api
```

All endpoints return `application/json`. All request bodies are `application/json`.

---

## Endpoints

### POST /api/secrets

Create a new encrypted secret.

**Request Body:**

```json
{
  "ciphertext": "string (base64url-encoded, required)",
  "expiresIn": "string (required, one of: '1h', '24h', '7d')",
  "burnAfterRead": "boolean (required)"
}
```

**Validation Rules:**

| Field          | Rule                                              |
|----------------|---------------------------------------------------|
| ciphertext     | Required. base64url-encoded. Max 64 KiB decoded.  |
| expiresIn      | Required. Must be one of: `1h`, `24h`, `7d`.      |
| burnAfterRead  | Required. Boolean.                                 |

**Success Response: `201 Created`**

```json
{
  "id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "expiresAt": "2026-04-07T12:00:00Z"
}
```

**Error Responses:**

| Status | Code                | Description                            |
|--------|---------------------|----------------------------------------|
| 400    | `invalid_request`   | Missing or malformed fields            |
| 400    | `ciphertext_too_large` | Ciphertext exceeds 64 KiB          |
| 400    | `invalid_expiry`    | expiresIn not one of allowed values    |
| 429    | `rate_limited`      | Too many create requests               |
| 500    | `internal_error`    | Server-side failure                    |

---

### GET /api/secrets/{id}

Retrieve an encrypted secret by ID.

**Path Parameters:**

| Parameter | Type   | Description                        |
|-----------|--------|------------------------------------|
| id        | string | 32-character hex string (16 bytes) |

**Success Response: `200 OK`**

```json
{
  "ciphertext": "string (base64url-encoded)",
  "burnAfterRead": true
}
```

If `burnAfterRead` is `true`, the secret is deleted from storage immediately after this response is sent. Subsequent requests for the same ID return 404.

**Error Responses:**

| Status | Code              | Description                              |
|--------|-------------------|------------------------------------------|
| 404    | `not_found`       | Secret does not exist or has expired      |
| 410    | `gone`            | Secret was burned after read (optional)   |
| 429    | `rate_limited`    | Too many read requests                    |
| 500    | `internal_error`  | Server-side failure                       |

**Design Decision — 404 vs 410:** The server returns `404` for all missing secrets regardless of reason (expired, burned, never existed). This prevents information leakage about whether a secret ID was ever valid. The `410 Gone` status is NOT used in production — an attacker should not be able to distinguish "never existed" from "was burned."

---

### GET /health

Health check endpoint for load balancers and monitoring.

**Success Response: `200 OK`**

```json
{
  "ok": true
}
```

This endpoint is exempt from rate limiting.

---

## Common Error Response Format

All error responses follow a consistent structure:

```json
{
  "error": {
    "code": "string",
    "message": "string (human-readable)"
  }
}
```

Example:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "Field 'ciphertext' is required"
  }
}
```

---

## Rate Limiting

Rate limits are applied per client IP address using a sliding window algorithm.

| Endpoint         | Limit            |
|------------------|------------------|
| POST /api/secrets | 10 requests/min |
| GET /api/secrets/{id} | 30 requests/min |
| GET /health      | Exempt           |

**Rate Limit Response Headers (included on ALL responses):**

```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1680000000
```

| Header                | Description                                    |
|-----------------------|------------------------------------------------|
| X-RateLimit-Limit     | Max requests allowed in the current window     |
| X-RateLimit-Remaining | Requests remaining in the current window       |
| X-RateLimit-Reset     | Unix timestamp when the window resets          |

When rate limited, the response includes:

```
Retry-After: 42
```

Where the value is seconds until the client may retry.

**429 Response Body:**

```json
{
  "error": {
    "code": "rate_limited",
    "message": "Too many requests. Try again in 42 seconds."
  }
}
```

---

## Request Size Limits

| Limit              | Value   |
|---------------------|---------|
| Max request body    | 128 KiB |
| Max ciphertext (decoded) | 64 KiB |
| Max URL path length | 2048 bytes |

---

## CORS

CORS is not required. The frontend is served from the same origin via `go:embed`. If CORS is needed in the future:

```
Access-Control-Allow-Origin: https://passwd.page
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type
Access-Control-Max-Age: 86400
```

---

## Content Negotiation

- Request `Content-Type` must be `application/json` for POST requests.
- Responses are always `application/json` with `charset=utf-8`.
- Requests with unsupported `Content-Type` receive `415 Unsupported Media Type`.

---

## ID Format

Secret IDs are 16 cryptographically random bytes, hex-encoded (32 characters). Generated server-side using `crypto/rand`.

Example: `a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`

IDs are case-insensitive but always returned lowercase.
