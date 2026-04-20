```                                                                                                            
                                                         ▄▄                                                   
                                                         ██                                                   
 ██▄███▄    ▄█████▄  ▄▄█████▄  ▄▄█████▄ ██      ██  ▄███▄██            ██▄███▄    ▄█████▄   ▄███▄██   ▄████▄  
 ██▀  ▀██   ▀ ▄▄▄██  ██▄▄▄▄ ▀  ██▄▄▄▄ ▀ ▀█  ██  █▀ ██▀  ▀██            ██▀  ▀██   ▀ ▄▄▄██  ██▀  ▀██  ██▄▄▄▄██ 
 ██    ██  ▄██▀▀▀██   ▀▀▀▀██▄   ▀▀▀▀██▄  ██▄██▄██  ██    ██            ██    ██  ▄██▀▀▀██  ██    ██  ██▀▀▀▀▀▀ 
 ███▄▄██▀  ██▄▄▄███  █▄▄▄▄▄██  █▄▄▄▄▄██  ▀██  ██▀  ▀██▄▄███     ██     ███▄▄██▀  ██▄▄▄███  ▀██▄▄███  ▀██▄▄▄▄█ 
 ██ ▀▀▀     ▀▀▀▀ ▀▀   ▀▀▀▀▀▀    ▀▀▀▀▀▀    ▀▀  ▀▀     ▀▀▀ ▀▀     ▀▀     ██ ▀▀▀     ▀▀▀▀ ▀▀   ▄▀▀▀ ██    ▀▀▀▀▀  
 ██                                                                    ██                   ▀████▀▀           

    ┌──────┐   zero-knowledge secret sharing          ╭──────────────────╮
    │ ┌──┐ │   for humans & agents                    │  ████░░░░░░░░░   │
    │ │  │ │                                          │  encrypted       │
    │ └──┘ │   encrypted on your device               │  self-destruct   │
    │ ████ │   self-destructing after one read        │  one-time read   │
    │ ████ │   works from browser, cli, or any agent  │  ▓▓▓▓▓▓▓▓▓▓▓▓    │
    └──────┘                                          ╰──────────────────╯

```

# passwd.page
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/davidfeldi/passwd-page/ci.yml?branch=main)
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)


**Zero-knowledge secret sharing for humans and agents.**

[Go 1.22+](https://go.dev)
[Open Source](https://github.com/davidfeldi/passwd-page)

---

Your agents need secrets. Pasting them into prompts gets them logged, leaked, and stored in places you don't control. passwd.page is the zero-knowledge handoff -- encrypted on your device, self-destructing after one read, and accessible from a browser, CLI, or any AI agent via MCP.

## What's new (v3)
- **QR code** on share page -- scan to open on another device.
- **File sharing** -- drag-and-drop any file up to 1 MiB, encrypted client-side.
- **Optional passphrase** -- second factor via PBKDF2-SHA256 (600k iters) + AES-GCM key wrapping.
- **Secret types** -- `text`, `api_key`, `ssh_key`, `postgres_url`, `jwt`, `oauth_token`, `env_file`, `file`.
- **Custom TTLs** -- 5m / 15m / 1h / 24h / 7d / 30d.
- **Self-host polish** -- see [SELF_HOSTING.md](./SELF_HOSTING.md) (docker-compose / systemd unit).

## Features

- **Zero-knowledge** -- server never sees plaintext
- **End-to-end encrypted** -- AES-256-GCM, client-side
- **Burn-after-read** -- secret is atomically deleted on first retrieval
- **TTL expiry** -- unread secrets auto-expire (5m, 15m, 1h, 24h, 7d, or 30d)
- **Browser UI, CLI tool, MCP tool server** -- three interfaces, one protocol
- **Single binary, self-hostable** -- Go binary with embedded frontend (~7MB)
- **No accounts, no cookies, no tracking** -- stateless by design
- **Open source** -- MIT licensed

## How It Works

1. **Encrypt** -- your device generates a random AES-256-GCM key and encrypts the secret.
2. **Store** -- only the ciphertext is sent to the server. The key never leaves your device.
3. **Share** -- you get a URL where the key lives in the fragment, which is never sent over HTTP.

```
https://passwd.page/s/abc123#kG7xR2m...
                      ^^^^^^ ^^^^^^^^^
                 server sees  server NEVER sees
                   (per RFC 3986, fragments are client-only)
```

The server is physically unable to decrypt your secret. Even if compromised, stored data is useless without the keys.

## Architecture

```
User's machine                            Your server / passwd.page
─────────────────                         ─────────────────────────
Claude Code / Cursor / GPT
  ↕ stdio (JSON-RPC)
passwd-mcp (local binary)
  ↕ HTTPS (ciphertext only)
  └──────────────────────────────────────→ passwd-server
                                           (stores encrypted blobs)
Browser
  ↕ Web Crypto API (local encryption)
  └──────────────────────────────────────→ passwd-server

CLI
  ↕ pkg/crypto (local encryption)
  └──────────────────────────────────────→ passwd-server
```

**All encryption happens on the user's device.** The server only stores and serves ciphertext.

| Binary | Runs where | Purpose |
|--------|-----------|---------|
| `passwd-server` | Your server or Render/Docker | Hosted service — stores encrypted blobs, serves the web UI |
| `passwd-mcp` | User's machine | MCP tool server — Claude Code spawns it as a local subprocess |
| `passwd` | User's machine | CLI client — encrypt and share from the terminal |

The MCP binary is a thin local process: it encrypts locally, sends only ciphertext to the server over HTTPS, and returns a URL to the agent. Plaintext never leaves the user's machine.

## Quick Start

### Browser

Go to [passwd.page](https://passwd.page), paste a secret, get a one-time link.

### CLI

```bash
# Install
go install github.com/davidfeldi/passwd-page/cmd/passwd@latest

# Share a secret
passwd create "my-api-key" --ttl 1h
# https://passwd.page/s/abc123#kG7x...

# Retrieve (decrypts locally, prints to stdout)
passwd get "https://passwd.page/s/abc123#kG7x..."
# my-api-key

# From a file
passwd create --file .env --ttl 24h

# From stdin
echo "secret" | passwd create

# Disable burn-after-read (secret persists until TTL)
passwd create --no-burn "reusable secret" --ttl 7d
```

### AI Agent (MCP)

Install the MCP tool server:

```bash
go install github.com/davidfeldi/passwd-page/cmd/passwd-mcp@latest
```

Add to your Claude Code config (`settings.json` or `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "passwd": {
      "command": "passwd-mcp",
      "env": {
        "PASSWD_SERVER": "https://passwd.page"
      }
    }
  }
}
```

Then ask your agent: *"Share this API key securely"* or *"Retrieve the secret at this URL."*

The MCP server exposes three tools (all accept `type` and `ttl` params, enum-validated server-side):

- **`share_secret`** -- encrypt and upload a secret, returns a one-time URL
- **`share_file`** -- encrypt and upload a file (<= 1 MiB), returns a one-time URL
- **`retrieve_secret`** -- fetch and decrypt a secret from a passwd.page URL

## Use Cases

- **Human to Human** -- share a database password with a teammate
- **Human to Agent** -- give your AI agent the staging API key without pasting it into a prompt
- **Agent to Human** -- CI pipeline shares deploy credentials via a self-destructing link
- **Agent to Agent** -- service-to-service token handoff with zero trust

## API

### `POST /api/secrets`

Create a new encrypted secret.

```json
// Request
{
  "ciphertext": "<base64-encoded ciphertext>",
  "expiresIn": "5m" | "15m" | "1h" | "24h" | "7d" | "30d",
  "burnAfterRead": true,
  "type": "text"
}

// Response (201)
{
  "id": "<secret-id>",
  "expiresAt": "<ISO 8601 timestamp>"
}
```

File size limit: 1 MiB plaintext (client-side enforced). API body limit: 2 MiB.

### `GET /api/secrets/{id}`

Retrieve a secret. If burn-after-read is enabled, the secret is atomically deleted on read.

```json
// Response (200)
{
  "ciphertext": "<base64-encoded ciphertext>",
  "burnAfterRead": true,
  "type": "text"
}

// Response (404) -- expired, burned, or not found
{
  "error": { "code": "not_found", "message": "..." }
}
```

### `GET /health`

```json
{ "ok": true }
```

**Rate limits:** 10 creates/min, 60 reads/min per IP. Static assets are not rate-limited.

## Self-Hosting

### From Source

```bash
git clone https://github.com/davidfeldi/passwd-page
cd passwd.page

# Build the frontend
cd frontend && npm install && npm run build && cd ..

# Build and run the server
go build -o passwd-server ./cmd/passwd-server
./passwd-server -port 8080 -db /var/lib/passwd-page/data.db
```

### Docker

```bash
docker build -t passwd-page .
docker run -p 8080:8080 passwd-page
```

### Render.com (free tier)

Fork the repo, connect it to [Render](https://render.com), and it auto-deploys from the Dockerfile. The server reads the `PORT` environment variable that Render provides.

## Configuration


| Variable / Flag        | Default               | Used by  | Description                     |
| ---------------------- | --------------------- | -------- | ------------------------------- |
| `PASSWD_SERVER`        | `https://passwd.page` | CLI, MCP | Server URL                      |
| `PORT` or `-port`      | `8080`                | Server   | HTTP listen port                |
| `-db`                  | `passwd.db`           | Server   | SQLite database path            |
| `--ttl` / `-t`         | `24h`                 | CLI      | Secret TTL (`5m`, `15m`, `1h`, `24h`, `7d`, `30d`) |
| `--burn` / `--no-burn` | burn on               | CLI      | Burn after read toggle          |
| `--server` / `-s`      | (from env)            | CLI      | Override server URL per-command |
| `--file` / `-f`        |                       | CLI      | Read secret from a file         |


## Project Structure

```
passwd.page/
  cmd/passwd-server/     Web server with embedded frontend + SQLite
  cmd/passwd/            CLI client (create, get, version)
  cmd/passwd-mcp/        MCP tool server (JSON-RPC over stdio)
  pkg/crypto/            Shared AES-256-GCM encryption (Go)
  internal/server/       HTTP handlers, middleware (CSP, HSTS, rate limiting)
  internal/storage/      SQLite storage layer, TTL cleanup goroutine
  internal/client/       API client (used by CLI + MCP)
  frontend/              Svelte 5 SPA (SvelteKit, adapter-static)
  e2e/                   Playwright end-to-end tests
  docs/                  Architecture documentation
```

## Security Model

### Encryption

- **Algorithm:** AES-256-GCM with a 256-bit random key and 96-bit IV per encryption
- **Browser:** Web Crypto API (native, hardware-accelerated, no external crypto libs)
- **CLI / MCP:** Go `crypto/aes` + `crypto/cipher` via `pkg/crypto`
- **Encoding:** base64url for keys and ciphertext

### Key Distribution

The decryption key is placed in the URL fragment (`#`). Per [RFC 3986 Section 3.5](https://datatracker.ietf.org/doc/html/rfc3986#section-3.5), the fragment identifier is never sent to the server in HTTP requests. The server receives and stores only ciphertext -- it has no mechanism to decrypt secrets.

### Burn-After-Read

Implemented via atomic `DELETE...RETURNING` in SQLite. The secret is read and permanently deleted in a single transaction. There is no window where a second reader can retrieve the same secret.

### Server Hardening

- **Content Security Policy (CSP)** on all responses
- **HSTS** (HTTP Strict Transport Security)
- **Rate limiting** on API routes (10 creates/min, 60 reads/min per IP)
- **Request body size limits**
- **SQLite file permissions** hardened to `0600`
- **No cookies, no sessions, no auth state** -- access is by knowledge of ID + key

### Explicit Reveal

The recipient page requires clicking a "Reveal Secret" button before decryption occurs. This prevents preview bots, link unfurlers, and crawlers from accidentally burning secrets.

### Residual Risks

These are inherent to any browser-based secret sharing and are not unique to passwd.page:

- Browser extensions with page access can read URL fragments
- Clipboard managers may log copied secrets
- Browser history stores full URLs including fragments
- Screenshots and screen recording

### Audit

- OWASP score: 91/100 (no high-severity findings)
- STRIDE threat model: 11 threats analyzed, all mitigated or accepted with documented rationale
- Dependencies: 1 Go dependency (`go-sqlite3`), 0 frontend runtime dependencies

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run the tests:

```bash
# Go unit tests
go test ./...

# Frontend crypto tests
cd frontend && npx vitest run

# E2E tests (requires a running server)
go run ./cmd/passwd-server -port 9876 -db /tmp/test.db &
cd e2e && npx playwright test
```

1. Submit a pull request

Code style: `gofmt` for Go, standard Prettier for TypeScript/Svelte. Keep external dependencies to a minimum.

## Tech Stack


| Layer            | Technology                           |
| ---------------- | ------------------------------------ |
| Backend          | Go (stdlib `net/http`)               |
| Frontend         | Svelte 5 (SvelteKit, adapter-static) |
| Database         | SQLite (WAL mode, `go-sqlite3`)      |
| Crypto (browser) | Web Crypto API (AES-256-GCM)         |
| Crypto (Go)      | `pkg/crypto` (AES-256-GCM)           |
| Deployment       | Single binary via `go:embed`         |


## License

```
MIT License -- Copyright (c) 2026 passwd.page contributors
```

See [LICENSE](LICENSE) for the full text.

---

Built for the age of agents. [passwd.page](https://passwd.page)