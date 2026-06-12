# secretstash

Share secrets via one-time, self-destructing links — a standalone take on
HashiCorp Vault's cubbyhole + response wrapping. One static binary, zero
dependencies, runs the server, the REST API, the web UI, and the client CLI.

This is a secret **sharing** utility, not a password manager: wrap a secret,
hand the recipient a token or link, and the secret destroys itself after
it's read (or after its TTL). If someone intercepted the link and read it
first, the real recipient finds out — that's the point.

## Quick start

```sh
make build

# Terminal 1: run the server (TLS with an ephemeral self-signed cert by default)
./bin/secretstash server

# Terminal 2: share a secret
export SECRETSTASH_ADDR=https://127.0.0.1:8200
printf 'db password: hunter2' | ./bin/secretstash wrap --tls-skip-verify --ttl 30m
# token:     ss.kKx9_2fP…
# share url: https://127.0.0.1:8200/s#ss.kKx9_2fP…

# Recipient (exactly once):
./bin/secretstash unwrap --tls-skip-verify ss.kKx9_2fP…
```

Or use the web UI at `https://127.0.0.1:8200`, or plain curl:

```sh
curl -sk -X POST https://127.0.0.1:8200/v1/wrap \
  -d '{"secret":"hunter2","ttl":"30m","reads":1}'

curl -sk -X POST https://127.0.0.1:8200/v1/unwrap \
  -H "X-Stash-Token: ss.kKx9_2fP…"
```

For local development, `secretstash server --dev` serves plain HTTP on
loopback (refused on non-loopback addresses unless you add
`--dev-allow-remote`).

## How it works

- **Wrap**: the server generates a 256-bit random token, derives an
  encryption key from it (HKDF-SHA256 with a per-secret salt), encrypts the
  secret with AES-256-GCM, and stores only the ciphertext, salt, nonce, and
  SHA-256 hash of the token. The token is returned once and never stored.
- **Zero knowledge**: nothing the server retains can decrypt a secret. A
  memory dump yields ciphertext. Decryption requires the token the
  recipient holds.
- **Unwrap**: presenting the token consumes one read. When reads hit zero
  (default: 1) the entry is deleted and its ciphertext zeroed, leaving only
  a hash-keyed tombstone.
- **Tamper evidence**: a second unwrap returns `410 {"code":"consumed",
  "consumed_at":…}` — if that wasn't you, your secret was intercepted;
  rotate it. The CLI exits with code 3 so scripts can branch on it, and the
  server logs the event at WARN.
- **In-memory only, on purpose**: nothing ever touches disk. Restarting the
  server destroys all secrets. Deploy it long-term as a sharing service or
  spin it up for a single handoff.
- **Share links carry the token in the URL fragment** (`/s#ss.…`), which
  browsers never send to any server — nothing leaks into access logs or
  link-preview fetchers. Revealing in the browser requires an explicit
  click; page load never consumes a read.

## REST API

| Endpoint | Auth | Description |
|---|---|---|
| `POST /v1/wrap` | — | `{secret, ttl?, reads?}` → `{token, expires_at, reads, share_url}` |
| `POST /v1/unwrap` | `X-Stash-Token` | consume a read → `{secret, reads_remaining, created_at}` |
| `GET /v1/peek` | `X-Stash-Token` | metadata without consuming a read |
| `DELETE /v1/secret` | `X-Stash-Token` | revoke before it's read |
| `GET /v1/sys/health` | — | health/version |

Errors: `404 not_found` (never existed), `410 consumed|expired|revoked`
(with timestamps — the tamper signal), `400` invalid input, `413` too
large, `429` rate-limited, `507` store full.

## CLI

```
secretstash server   [--listen 127.0.0.1:8200] [--tls-cert F --tls-key F | --dev]
                     [--max-secret-size 65536] [--max-secrets 10000]
                     [--default-ttl 24h] [--max-ttl 168h] [--max-reads 100]
                     [--trust-proxy] [--no-ui] [--share-base-url URL]
secretstash wrap     [--ttl 30m] [--reads 1] [secret]     # or pipe via stdin
secretstash unwrap   <token>     # secret → stdout, metadata → stderr (pipe-safe)
secretstash peek     <token>     # metadata, does not consume a read
secretstash revoke   <token>
secretstash status
```

Client flags: `--addr` / `SECRETSTASH_ADDR`, `--tls-skip-verify`, `--json`.
Exit codes: `0` ok, `1` error, `2` usage, `3` consumed/expired/revoked,
`4` not found.

## Security model, honestly

- The wrap token is the secret's only key. Anyone holding it can read the
  secret (once). Transmit share links over channels you trust.
- Tokens have 256 bits of `crypto/rand` entropy; brute force is the
  security boundary, per-IP rate limiting is defense in depth.
- TLS is on by default. The auto-generated cert is self-signed and
  ephemeral; its SHA-256 fingerprint is printed at startup for pinning. Use
  `--tls-cert`/`--tls-key` with a real cert in production.
- Key material and plaintext buffers are zeroed after use, but Go's garbage
  collector can move and copy memory — wiping is best-effort hardening, not
  a guarantee. The actual guarantee is that the server only ever *retains*
  ciphertext and token hashes.
- Failed and repeated unwrap attempts are rate limited per IP and logged as
  structured audit events (token hash prefix only, never the token).

## Development

```sh
make test    # go test -race ./...
make check   # vet + govulncheck (if installed) + tests
make run-dev # plain-HTTP dev server
```
