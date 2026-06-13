# syntax=docker/dockerfile:1

# --- build stage -------------------------------------------------------------
# Pinned to the Go version in go.mod. stdlib-only, so the build needs no
# network access beyond the base image itself.
FROM golang:1.26 AS build

WORKDIR /src

# go.mod first for layer caching (there is no go.sum: stdlib-only).
COPY go.mod ./
COPY main.go ./
COPY internal ./internal

# Version is passed in by the Makefile's docker-build target, since .git is not
# part of the build context (see .dockerignore).
ARG VERSION=dev

# CGO disabled produces a fully static binary that runs on distroless/scratch.
# Flags mirror the Makefile: -trimpath plus -s -w to strip the symbol table.
RUN CGO_ENABLED=0 GOOS=linux go build \
	-trimpath \
	-ldflags "-s -w -X github.com/rybo/secretstash/internal/version.Version=${VERSION}" \
	-o /out/secretstash .

# --- final stage -------------------------------------------------------------
# distroless static: no shell, no package manager, ships CA certs, runs nonroot.
FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/secretstash /secretstash

EXPOSE 8200

# Listen on all interfaces so the container is reachable; non-loopback is
# allowed because this is not --dev mode. Append --tls-cert/--tls-key (or other
# flags) after the image name to override or extend this default command.
ENTRYPOINT ["/secretstash"]
CMD ["server", "--listen", "0.0.0.0:8200"]
