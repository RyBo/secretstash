VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/rybo/secretstash/internal/version.Version=$(VERSION)
IMAGE   := secretstash

# Platforms for the `dist` cross-compile target (GOOS/GOARCH pairs).
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.DEFAULT_GOAL := help
.PHONY: help build test test-js vet fmt check run-dev dist docker-build docker-run clean

help: ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary into bin/
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/secretstash .

test: ## Run tests with the race detector
	go test -race ./...

test-js: ## Run the browser shamir.js tests (requires node 20+)
	node --test internal/web/static/*.test.mjs

vet: ## Run go vet
	go vet ./...

fmt: ## Format all Go sources
	go fmt ./...

check: vet test ## Vet, govulncheck + shamir.js tests (if installed), and test
	@command -v govulncheck >/dev/null 2>&1 && govulncheck ./... || echo "govulncheck not installed; skipping (go install golang.org/x/vuln/cmd/govulncheck@latest)"
	@command -v node >/dev/null 2>&1 && node --test internal/web/static/*.test.mjs || echo "node not installed; skipping shamir.js tests"

run-dev: ## Run a plain-HTTP dev server
	go run . server --dev

dist: ## Cross-compile static binaries into dist/
	@rm -rf dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		out=dist/secretstash-$$os-$$arch; \
		[ "$$os" = windows ] && out=$$out.exe; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -trimpath -ldflags "$(LDFLAGS)" -o $$out . || exit 1; \
	done

docker-build: ## Build the Docker image (tagged with VERSION and latest)
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

docker-run: docker-build ## Build and run the image (ephemeral self-signed TLS)
	docker run --rm -p 8200:8200 $(IMAGE):latest

clean: ## Remove build outputs
	rm -rf bin/ dist/
