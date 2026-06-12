VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/rybo/secretstash/internal/version.Version=$(VERSION)

.PHONY: build test vet check run-dev clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/secretstash .

test:
	go test -race ./...

vet:
	go vet ./...

check: vet test
	@command -v govulncheck >/dev/null 2>&1 && govulncheck ./... || echo "govulncheck not installed; skipping (go install golang.org/x/vuln/cmd/govulncheck@latest)"

run-dev:
	go run . server --dev

clean:
	rm -rf bin/
