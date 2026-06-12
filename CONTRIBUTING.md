# Contributing to passwd.page

Thanks for your interest! passwd.page is a small, dependency-light project and
contributions are welcome — bug fixes, features, docs, and security reports.

## Ground rules

- **Keep dependencies minimal.** 1 Go dependency (`go-sqlite3`), 0 frontend
  runtime deps. New deps need a strong justification.
- **Never weaken the zero-knowledge model.** The server must never see plaintext
  or keys. If a change could let the server decrypt secrets, it won't be merged.
- **Match the surrounding style.** `gofmt` for Go, Prettier defaults for
  TypeScript/Svelte.

## Local setup

Requires **Go 1.22+** and **Node 18+**.

```bash
git clone https://github.com/davidfeldi/passwd-page
cd passwd-page

# Build the frontend (required before building/running the server)
cd frontend && npm install && npm run build && cd ..

# Run the server with the embedded frontend
go run ./cmd/passwd-server -port 8080 -db /tmp/passwd-dev.db
```

The CLI and MCP server build independently:

```bash
go build ./cmd/passwd
go build ./cmd/passwd-mcp
```

## Running the tests

```bash
# Go unit tests
go test ./...

# Frontend crypto tests (vitest)
cd frontend && npx vitest run && cd ..

# End-to-end tests (Playwright; needs a running server)
go run ./cmd/passwd-server -port 9876 -db /tmp/test.db &
cd e2e && npm install && npx playwright test
```

Please make sure `go test ./...` and `vitest` pass before opening a PR.

## Pull request workflow

1. Fork the repo and create a feature branch off `main`
   (`git checkout -b fix/some-thing`).
2. Make your change with tests where it makes sense.
3. Run `gofmt -w` and the test suites above.
4. Open a PR describing **what** changed and **why**. Link any related issue.

Keep PRs focused — one logical change per PR is much easier to review.

## Reporting security issues

Please do **not** open a public issue for a vulnerability that could expose
secrets. Email the maintainer (see the GitHub profile) with details and a repro,
and allow reasonable time to patch before disclosure.

## Reporting bugs / requesting features

Use the issue templates. Include your OS, the binary and version
(`passwd-page version`), and exact steps to reproduce.
