<!-- Thanks for contributing! Keep PRs focused — one logical change each. -->

## What & why

<!-- What does this change, and what problem does it solve? Link issues with #123. -->

## How to test

<!-- Commands / steps a reviewer can run to verify the change. -->

## Checklist

- [ ] `go test ./...` passes
- [ ] `cd frontend && npx vitest run` passes (if frontend touched)
- [ ] `gofmt`-clean Go / Prettier-clean TS/Svelte
- [ ] Does **not** weaken the zero-knowledge model (server never sees plaintext or keys)
- [ ] Docs updated if behavior/flags changed
