# Cryptographic Protocol Specification

## Overview

passwd.page uses client-side AES-256-GCM encryption via the Web Crypto API. The server never receives, stores, or processes decryption keys. All cryptographic operations occur exclusively in the browser.

## Primitives

| Parameter       | Value                          |
|-----------------|--------------------------------|
| Algorithm       | AES-256-GCM                    |
| Key size        | 256 bits (32 bytes)            |
| IV size         | 96 bits (12 bytes)             |
| Auth tag size   | 128 bits (appended by GCM)     |
| Key encoding    | base64url (RFC 4648 Section 5) |
| Ciphertext encoding | base64url                  |
| Key derivation  | None (raw random key)          |
| CSPRNG source   | `crypto.getRandomValues()`     |

## Encryption Flow (Client — Create Secret)

```
1. User enters plaintext secret in browser
2. Generate 256-bit random key:
     key = crypto.getRandomValues(new Uint8Array(32))
3. Generate 96-bit random IV:
     iv = crypto.getRandomValues(new Uint8Array(12))
4. Import key into Web Crypto API:
     cryptoKey = crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"])
5. Encrypt plaintext:
     ciphertext = crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, encode(plaintext))
     // GCM appends 128-bit auth tag to ciphertext automatically
6. Prepend IV to ciphertext:
     payload = iv || ciphertext   // 12 bytes IV + N bytes ciphertext + 16 bytes tag
7. Encode payload:
     encodedPayload = base64url(payload)
8. POST to server:
     POST /api/secrets { ciphertext: encodedPayload, expiresIn: "24h", burnAfterRead: true }
9. Server returns { id: "a1b2c3d4..." }
10. Construct shareable URL:
      passwd.page/s/{id}#base64url(key)
```

## Decryption Flow (Client — Retrieve Secret)

```
1. User opens URL: passwd.page/s/{id}#{encodedKey}
2. Browser extracts fragment (everything after #):
     encodedKey = window.location.hash.substring(1)
3. Decode key:
     key = base64urlDecode(encodedKey)
4. Fetch ciphertext from server:
     GET /api/secrets/{id} -> { ciphertext: encodedPayload, burnAfterRead: true }
5. Decode payload:
     payload = base64urlDecode(encodedPayload)
6. Split IV and ciphertext:
     iv = payload.slice(0, 12)
     ciphertext = payload.slice(12)
7. Import key:
     cryptoKey = crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"])
8. Decrypt:
     plaintext = crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ciphertext)
9. Display plaintext to user
10. Clear key material from memory (overwrite ArrayBuffers)
```

## Server Knowledge Boundary

### What the server stores
- Ciphertext (encrypted blob, semantically indistinguishable from random)
- Metadata: expiry time, burn-after-read flag, creation timestamp, view count
- Secret ID (random, not derived from content or key)

### What the server NEVER receives
- The decryption key (lives only in URL fragment)
- The plaintext secret
- Any key-derivation material

### Why this is safe
The URL fragment (everything after `#`) is defined by RFC 3986 Section 3.5 as client-only. Browsers MUST NOT include the fragment in HTTP requests. The server receives `GET /s/{id}` with no fragment. The key exists only in the browser's address bar and JavaScript runtime.

## base64url Encoding

Per RFC 4648 Section 5:
- Alphabet: `A-Za-z0-9-_` (replacing `+/` with `-_`)
- No padding (`=` characters stripped)
- Safe for URL fragments without percent-encoding

```javascript
function base64urlEncode(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64urlDecode(str) {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
```

## Memory Hygiene

After decryption and display:
1. Zero out the key `Uint8Array` by filling with 0x00
2. Zero out the IV and raw ciphertext buffers
3. Do NOT call `URL.createObjectURL` or store key material in any persistent API
4. The fragment remains in the address bar — warn users not to share browser history

Note: JavaScript does not guarantee memory zeroing due to GC and JIT. This is a best-effort mitigation. The primary security boundary is that the key never leaves the client.

## Threat Model — Fragment Limitations

The URL fragment is safe from the HTTP transport layer, but can leak through:

| Vector                     | Risk    | Mitigation                                      |
|----------------------------|---------|--------------------------------------------------|
| Browser history            | Medium  | Warn user; burn-after-read reduces window        |
| Browser extensions         | High    | Cannot mitigate; user responsibility             |
| Copy-paste to chat apps    | None    | Fragment is preserved in copy — this is intended |
| Slack/Teams link previews  | Medium  | Some services strip fragments; document this     |
| Corporate HTTP proxies     | None    | Fragment never sent over HTTP                    |
| JavaScript `document.referrer` | None | Referrer-Policy: no-referrer prevents leakage |
| Server-side logging        | None    | Fragment not in request; nothing to log          |
| TLS inspection proxies     | None    | Fragment not in TLS-layer request                |

## Services Known to Strip Fragments

The following services may strip the `#...` portion when sharing links:
- Slack (in some preview contexts)
- Jira (when rendering links in descriptions)
- Some email clients (Outlook, certain webmail)
- URL shorteners (bit.ly, etc.)

Users should be warned: "Copy the full URL including everything after the # symbol. Some services may strip this part, making the secret unrecoverable."
