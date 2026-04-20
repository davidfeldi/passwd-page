# passwd.page — build + test targets
# Usage: make [target]. See `make help`.

BINARIES := passwd-server passwd passwd-mcp
FRONTEND_BUILD := frontend/build

GO ?= go
NPM ?= npm

# Ad-hoc codesign is required on Apple Silicon macOS to avoid SIGKILL on
# freshly-built CGO binaries. No-op on Linux.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  CODESIGN = codesign --force --sign - $(1)
else
  CODESIGN = true
endif

.PHONY: all help build frontend backend test test-go test-frontend \
        run clean install-deps e2e fmt vet

all: build

help:
	@echo "passwd.page build targets:"
	@echo "  make build          — frontend + all 3 Go binaries (codesigned on macOS)"
	@echo "  make frontend       — frontend only"
	@echo "  make backend        — Go binaries only (assumes frontend already built)"
	@echo "  make test           — go test + vitest"
	@echo "  make test-go        — go test ./..."
	@echo "  make test-frontend  — frontend vitest"
	@echo "  make e2e            — playwright e2e (needs server running)"
	@echo "  make run            — build + run passwd-server on :8080"
	@echo "  make clean          — remove binaries and frontend build"
	@echo "  make install-deps   — npm install in frontend/"
	@echo "  make fmt            — gofmt"
	@echo "  make vet            — go vet"

build: frontend backend

frontend: $(FRONTEND_BUILD)

$(FRONTEND_BUILD):
	cd frontend && $(NPM) install && $(NPM) run build

backend: $(BINARIES)

passwd-server: $(FRONTEND_BUILD)
	$(GO) build -o $@ ./cmd/passwd-server
	@$(call CODESIGN,$@)

passwd:
	$(GO) build -o $@ ./cmd/passwd
	@$(call CODESIGN,$@)

passwd-mcp:
	$(GO) build -o $@ ./cmd/passwd-mcp
	@$(call CODESIGN,$@)

test: test-go test-frontend

test-go:
	$(GO) test ./...

test-frontend:
	cd frontend && npx vitest run

e2e: build
	@echo "Start passwd-server in another terminal, then run:"
	@echo "  cd e2e && npx playwright test"

run: build
	./passwd-server -port 8080 -db passwd.db

install-deps:
	cd frontend && $(NPM) install

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

clean:
	rm -f $(BINARIES)
	rm -rf $(FRONTEND_BUILD) frontend/.svelte-kit
