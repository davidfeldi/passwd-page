# Self-Hosting passwd.page

Two supported paths: Docker Compose (fastest) or bare-metal systemd.

---

## A. Docker Compose (60-second path)

### Prerequisites

- Docker Engine 20.10+
- Docker Compose v2 (`docker compose ...`, not the legacy `docker-compose`)

### Run

```sh
git clone https://github.com/davidfeldi/passwd-page
cd passwd-page
docker compose up -d
```

Verify:

```sh
curl http://localhost:8080/health
# → {"ok":true}
```

Then open <http://localhost:8080>.

### Persistence

The named volume `passwd-data` is mounted at `/var/lib/passwd-page` inside the
container and holds `data.db` (SQLite + WAL). It survives `docker compose
down` and container rebuilds. To wipe state: `docker compose down -v`.

### Upgrade

```sh
git pull && docker compose build --no-cache && docker compose up -d
```

### TLS

The container speaks plain HTTP on `:8080`. Terminate TLS with a reverse
proxy (Caddy, nginx, Traefik). Caddy snippet in section B.

---

## B. Bare-metal systemd

### Prerequisites

- Linux (systemd)
- Go 1.22+
- Node.js 20+
- GCC and libc headers (CGO is required for `mattn/go-sqlite3`)

### Build

```sh
cd frontend && npm ci && npm run build && cd ..
go build -o passwd-server ./cmd/passwd-server
sudo install -m 0755 passwd-server /usr/local/bin/passwd-server
```

### Create system user and data directory

```sh
sudo useradd --system --home-dir /var/lib/passwd-page --shell /usr/sbin/nologin passwd
sudo mkdir -p /var/lib/passwd-page
sudo chown passwd:passwd /var/lib/passwd-page
sudo chmod 0750 /var/lib/passwd-page
```

### Install the unit

```sh
sudo cp deploy/passwd-page.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now passwd-page
sudo systemctl status passwd-page
```

The unit is hardened: `NoNewPrivileges`, `ProtectSystem=strict`,
`MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_INET AF_INET6`.
Only `/var/lib/passwd-page` is writable.

### Logs

```sh
journalctl -u passwd-page -f
```

### Reverse proxy

**Caddy** (`/etc/caddy/Caddyfile`) — handles ACME automatically:

```caddy
passwd.example.com {
    encode gzip
    reverse_proxy 127.0.0.1:8080
}
```

**nginx** (`/etc/nginx/sites-available/passwd-page`) — pair with certbot:

```nginx
server {
    listen 443 ssl http2;
    server_name passwd.example.com;

    ssl_certificate     /etc/letsencrypt/live/passwd.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/passwd.example.com/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

### Upgrade

```sh
git pull && (cd frontend && npm ci && npm run build)
go build -o passwd-server ./cmd/passwd-server
sudo systemctl stop passwd-page
sudo install -m 0755 passwd-server /usr/local/bin/passwd-server
sudo systemctl start passwd-page
```

---

## Configuration reference

| Flag  | Default          | Description          |
| ----- | ---------------- | -------------------- |
| -port | 8080             | HTTP listen port     |
| -db   | passwd.db (cwd)  | SQLite database path |

Rate limits (10 creates/min, 60 reads/min per IP) are hard-coded; patch
`internal/server/middleware.go` to change them.
