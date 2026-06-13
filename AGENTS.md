# AGENTS.md

Guidance for AI agents working in this repository.

## What this is

`secretstash` shares secrets via one-time, self-destructing links (Vault
cubbyhole style). A secret is wrapped into a single-use token; unwrapping
consumes a read and burns it after N reads or a TTL. Storage is **in-memory
only, by design**: nothing touches disk, and a restart destroys all secrets.

## Build, test, run

```sh
make build     # build the binary (version stamped from git via -ldflags)
make test      # go test -race ./...
make vet       # go vet ./...
make check     # vet + govulncheck (if installed) + tests; run before committing
make run-dev   # plain-HTTP dev server on 127.0.0.1:8200
make clean
```

There is no `go.sum`: the project depends only on the Go standard library.

## Architecture

Entry point is `main.go`, which calls `cli.Run`. Everything else is under
`internal/`:

- `cli/`     — command-line interface: the `server` subcommand and the client
               commands (`wrap`, `unwrap`, `peek`, `revoke`, `status`). Flag parsing lives here.
- `server/`  — wires API + web UI + TLS + lifecycle; builds the root mux and
               applies server-wide middleware (`SecurityHeaders`, `Recover`).
- `api/`     — the REST API: handlers, request/response shapes, middleware
               (rate limiting, max-bytes, no-store), audit logging, and `/metrics`.
- `store/`   — the in-memory secret store: burn-after-N-reads, lazy TTL expiry,
               tamper-evident tombstones, and a background janitor. Concurrency
               via a single `sync.Mutex` (every read path mutates state).
- `crypto/`  — token generation and AES-GCM seal/open; best-effort memory wiping.
- `web/`     — the embedded web UI (static assets via `embed`).
- `version/` — the `Version` string, stamped at build time.

Routes: API endpoints are registered in `api.Routes()` (`internal/api/api.go`)
under `/v1/`. The unauthenticated `/metrics` endpoint is registered separately
on the root mux in `server.Run` so scrapers bypass the per-IP rate limiter.

## Conventions

- **Standard library only.** Do not add third-party dependencies without a
  strong reason; the zero-dependency, single-static-binary property is a
  feature. Prometheus exposition, for example, is hand-rolled in
  `internal/api/metrics.go` rather than pulling in a client library.
- **JSON API with a stable error shape.** Errors are `apiError{code, message}`
  (plus an optional `consumed_at` for tamper evidence). Use the `writeJSON` /
  `writeError` helpers in `internal/api/api.go`.
- **Security posture is load-bearing.** Tokens travel in the `X-Stash-Token`
  header or a URL fragment, never a query string (URLs leak into logs). Audit
  events go through `slog` and log only a token-hash prefix, never the token or
  plaintext. A failed unwrap against a consumed secret is the operator-facing
  tamper alarm and is logged at WARN. Reject out-of-range input rather than
  silently clamping it.
- **No em-dashes in prose or UI copy.** Use commas, parentheses, or rewrites.
- New config knobs flow as: a flag in `cli.cmdServer` -> a field on
  `server.Config` (or `api.Config` / `store.Limits`) -> consumed where needed.
  Default-on features take a `--no-<feature>` flag, mirroring `--no-ui`.

## Testing

Handlers are tested against a real `httptest.Server` via the `testEnv` helper
in `internal/api/api_test.go` (`newEnv`, `wrap`, `do`, `decode`). Logs are
captured into a `bytes.Buffer` so tests can assert audit events. The store uses
a `fakeClock` (`internal/store/store_test.go`) to drive TTL/expiry
deterministically. Mirror these patterns; always run `make test` (race
detector) before finishing.
