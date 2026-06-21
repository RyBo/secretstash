```text
                       __      __           __
  ___ ___ ___________ / /____ / /____ ____ / /
 (_-</ -_) __/ __/ -_) __(_-</ __/ _ `(_-</ _ \
/___/\__/\__/_/  \__/\__/___/\__/\_,_/___/_//_/
```

**One-time self-destructing secret links, with tamper evidence built in.**

> ⚠️ **Heads up: this project was completely vibe coded** in one sitting. A
> language model wrote it while a human nodded along and said "looks good".
> It has tests, the crypto is boring stdlib AES-GCM, and it still owes you
> zero guarantees: nobody with a security badge has audited a single line.
> Use at your own risk, ideally for secrets that wouldn't ruin your week if
> they leaked.

---

- [What is secretstash?](#what-is-secretstash)
- [Is secretstash right for you?](#is-secretstash-right-for-you)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [REST API](#rest-api)
- [CLI](#cli)
- [Security model](#security-model)
- [Deployment](#deployment)
- [Development](#development)

## What is secretstash?

A secret sharing utility in the spirit of HashiCorp Vault's cubbyhole and
response wrapping. A single static binary with no external dependencies
runs the server, the REST API, the web UI, and the client CLI.

Wrap a secret, send someone the link, and the secret deletes itself after
it gets read or when it expires. If somebody intercepted the link and read
it before your recipient did, the recipient sees exactly when that happened
instead of silently getting nothing.

## Is secretstash right for you?

Good fits:

- Handing a coworker a credential without leaving it in chat history
  forever.
- Sending API keys, certificates, or connection strings to someone on
  another team.
- A long-running internal sharing service, or a throwaway instance you
  spin up for a single handoff and kill afterwards.
- Scripts that need to pass a secret across a trust boundary and verify
  nobody else grabbed it first (the CLI exits 3 on tamper evidence).

Bad fits:

- A password manager. Nothing here is meant to be stored; everything is
  meant to be read once and disappear.
- Secrets that must survive a restart. Storage is memory only, on purpose.
  Restart the server and everything in it is gone.
- Audited, compliance-grade secret management. That's what actual Vault
  is for.
- Production anything. See the notice at the top.

## Quick start

```sh
make build

# Terminal 1: run the server (TLS with an ephemeral self-signed cert by default)
./bin/secretstash server

# Terminal 2: share a secret
export SECRETSTASH_ADDR=https://127.0.0.1:8200
printf 'db password: hunter2' | ./bin/secretstash wrap --tls-skip-verify --ttl 30m
# token:     ss.kKx9_2fP...
# share url: https://127.0.0.1:8200/s#ss.kKx9_2fP...

# Recipient (exactly once):
./bin/secretstash unwrap --tls-skip-verify ss.kKx9_2fP...
```

Or use the web UI at `https://127.0.0.1:8200`, or plain curl:

```sh
curl -sk -X POST https://127.0.0.1:8200/v1/wrap \
  -d '{"secret":"hunter2","ttl":"30m","reads":1}'

curl -sk -X POST https://127.0.0.1:8200/v1/unwrap \
  -H "X-Stash-Token: ss.kKx9_2fP..."
```

For local development, `secretstash server --dev` serves plain HTTP on
loopback. It refuses to do that on a non-loopback address unless you also
pass `--dev-allow-remote`.

## How it works

When you wrap a secret, the server generates a 256-bit random token,
derives an encryption key from it (HKDF-SHA256 with a per-secret salt),
encrypts the secret with AES-256-GCM, and stores only the ciphertext, salt,
nonce, and a SHA-256 hash of the token. The token itself is returned once
and never stored. Nothing the server keeps can decrypt a secret, so a
memory dump yields ciphertext and decryption requires the token the
recipient is holding.

Presenting the token consumes one read. When reads hit zero (default: 1)
the entry is deleted and its ciphertext zeroed, leaving a hash-keyed
tombstone behind. A second unwrap attempt gets `410 {"code":"consumed",
"consumed_at":...}`. If that wasn't you, your secret was intercepted and
you should rotate it. The CLI exits with code 3 in that case so scripts can
branch on it, and the server logs the event at WARN.

Storage is in-memory only, on purpose: nothing ever touches disk, and
restarting the server destroys all secrets. Deploy it long-term as a
sharing service or spin it up for a single handoff.

Share links carry the token in the URL fragment (`/s#ss....`), which
browsers never send to any server, so nothing leaks into access logs or
link-preview fetchers. Revealing a secret in the browser requires an
explicit click; loading the page never consumes a read.

## REST API

| Endpoint | Auth | Description |
|---|---|---|
| `POST /v1/wrap` | none | `{secret, ttl?, reads?}` returns `{token, expires_at, reads, share_url}` |
| `POST /v1/unwrap` | `X-Stash-Token` | consume a read, returns `{secret, reads_remaining, created_at}` |
| `GET /v1/peek` | `X-Stash-Token` | metadata without consuming a read |
| `DELETE /v1/secret` | `X-Stash-Token` | revoke before it's read |
| `GET /v1/sys/health` | none | health/version |
| `GET /metrics` | none | Prometheus metrics (on by default; see below) |

Errors: `404 not_found` (never existed), `410 consumed|expired|revoked`
(with timestamps, which is the tamper signal), `400` invalid input, `413`
too large, `429` rate-limited, `507` store full.

The `/metrics` endpoint exposes operational counters and gauges in Prometheus
text format: wrap/unwrap/peek/revoke totals, unwrap failures by reason
(including the tamper signal), store-full and rate-limited counts, plus live
secret and tombstone gauges. It is unauthenticated and not rate limited, so
restrict it at the network level (firewall, reverse proxy, or NetworkPolicy).
Disable it entirely with `--no-metrics`.

## CLI

```
secretstash server   [--listen 127.0.0.1:8200] [--tls-cert F --tls-key F | --dev]
                     [--max-secret-size 65536] [--max-secrets 10000]
                     [--default-ttl 24h] [--max-ttl 168h] [--max-reads 100]
                     [--real-ip-header NAME] [--no-ui] [--no-metrics] [--share-base-url URL]
secretstash wrap     [--ttl 30m] [--reads 1] [secret]     # or pipe via stdin
secretstash unwrap   <token>     # secret to stdout, metadata to stderr (pipe-safe)
secretstash peek     <token>     # metadata, does not consume a read
secretstash revoke   <token>
secretstash status
```

Client flags: `--addr` / `SECRETSTASH_ADDR`, `--tls-skip-verify`, `--json`.
Exit codes: `0` ok, `1` error, `2` usage, `3` consumed/expired/revoked,
`4` not found.

## Security model

- The wrap token is the secret's only key. Anyone holding it can read the
  secret (once). Send share links over channels you trust.
- Tokens have 256 bits of `crypto/rand` entropy. Brute force is the actual
  security boundary; per-IP rate limiting is defense in depth.
- TLS is on by default. The auto-generated cert is self-signed and
  ephemeral, and its SHA-256 fingerprint is printed at startup for pinning.
  Use `--tls-cert`/`--tls-key` with a real cert in production.
- Key material and plaintext buffers are zeroed after use, but Go's garbage
  collector can move and copy memory, so wiping is best-effort hardening
  rather than a guarantee. The actual guarantee is that the server only
  ever retains ciphertext and token hashes.
- Failed and repeated unwrap attempts are rate limited per IP and logged as
  structured audit events containing a token-hash prefix, never the token.
- Behind a reverse proxy or tunnel every request arrives from the proxy's
  address, which would collapse per-IP rate limiting into one shared bucket
  (one fumbled link could lock everyone out). Set `--real-ip-header` to the
  header your proxy populates with the real client IP (`CF-Connecting-IP` for
  Cloudflare, `X-Forwarded-For` for Caddy/nginx) so each client is limited
  independently. Only enable it when the origin is reachable *solely* through
  that proxy: otherwise a client could forge the header. secretstash trusts the
  rightmost address in the header, the hop your proxy appends, so a
  client-supplied value cannot spoof it.

## Deployment

A reminder before you read on: the notice at the top of this file still
applies. None of the steps below turn an unaudited toy into production-grade
infrastructure. They just describe how to run it with real certificates if you
have decided the trade-offs are acceptable for your use.

### Running behind a reverse proxy or tunnel

Whenever something sits in front of secretstash (a reverse proxy, load balancer,
or tunnel), every request arrives from that intermediary's address rather than
the visitor's. Per-IP rate limiting then collapses into a single shared bucket,
so one person fumbling a link can lock everyone out. Set `--real-ip-header` to
the header your proxy populates with the real client IP and each client is
limited independently. secretstash trusts the rightmost address in that header
(the hop the nearest proxy appends), so a client-supplied value cannot spoof it.

This is only safe when the origin is reachable *solely* through that proxy. If
anyone can connect to secretstash directly, they can forge the header and defeat
rate limiting (or frame another client). So with `--real-ip-header` set:

- Bind the origin to loopback (`--listen 127.0.0.1:8200`) or an internal-only
  network, and never publish the port to the host or the internet.
- Make sure the proxy itself overwrites or appends the header rather than
  passing a client-supplied one through untouched.

Without `--real-ip-header`, secretstash always uses the connection's socket
address and ignores forwarding headers entirely, which is the safe default when
nothing trusted sits in front of it. The vendor-specific sections below show
which header name to use for each setup.

For example, behind a Cloudflare Tunnel (Cloudflare overwrites `CF-Connecting-IP`
on every request, and `cloudflared` reaches the origin over loopback only):

```sh
secretstash server --listen 127.0.0.1:8200 --real-ip-header CF-Connecting-IP
```

The same shape applies to other front ends, just with their header: Caddy or
nginx append `X-Forwarded-For`, so you would use `--real-ip-header X-Forwarded-For`.
See [Cloudflare Tunnel](#cloudflare-tunnel) and
[Reverse proxy with automatic certificates (Caddy)](#reverse-proxy-with-automatic-certificates-caddy)
below for the full recipes.

### Docker

```sh
make docker-build                       # builds secretstash:latest (and :VERSION)
docker run --rm -p 8200:8200 secretstash:latest   # ephemeral self-signed TLS
```

The image is a `distroless/static:nonroot` base over a static binary (no shell,
no package manager). It listens on `0.0.0.0:8200` inside the container; map the
port with `-p`. Append flags after the image name to override the defaults, for
example `docker run ... secretstash:latest server --listen 0.0.0.0:8200 --no-metrics`.

### Production with real certificates (native TLS)

secretstash can terminate TLS itself. Point it at a real certificate and key and
it serves trusted HTTPS directly, no proxy required.

1. Obtain a certificate. With [certbot](https://certbot.eff.org/) and a public
   DNS name:

   ```sh
   certbot certonly --standalone -d secrets.example.com
   # writes /etc/letsencrypt/live/secrets.example.com/{fullchain,privkey}.pem
   ```

2. Make the cert and key available to the container and start it. The included
   `docker-compose.yml` mounts `./certs` read-only and passes the flags for you:

   ```sh
   mkdir certs
   cp /etc/letsencrypt/live/secrets.example.com/fullchain.pem certs/
   cp /etc/letsencrypt/live/secrets.example.com/privkey.pem   certs/
   docker compose up -d
   ```

   The startup banner should read `TLS enabled with /certs/fullchain.pem`.

   Equivalent without compose:

   ```sh
   docker run -d -p 443:8200 -v "$PWD/certs:/certs:ro" secretstash:latest \
     server --listen 0.0.0.0:8200 \
     --tls-cert /certs/fullchain.pem --tls-key /certs/privkey.pem
   ```

   Or run the bare binary on a host with `--tls-cert`/`--tls-key`.

**Renewal.** secretstash reads the certificate once at startup, so a renewed
cert only takes effect after a restart. Add a certbot deploy hook to copy the
new files and bounce the container:

```sh
certbot renew --deploy-hook 'cp /etc/letsencrypt/live/secrets.example.com/*.pem /srv/secretstash/certs/ && docker compose -f /srv/secretstash/docker-compose.yml restart secretstash'
```

A restart wipes all live secrets, which is true of every restart here: storage
is in-memory by design (see [How it works](#how-it-works)), so renewal causes no
extra data loss.

### Reverse proxy with automatic certificates (Caddy)

If you would rather have the proxy manage certs (automatic issuance and
renewal), put [Caddy](https://caddyserver.com/) in front. Keep secretstash in
its normal TLS mode (the ephemeral self-signed cert) so the internal hop stays
encrypted, and tell Caddy to skip verification on that hop.

`docker-compose.yml`:

```yaml
services:
  secretstash:
    image: secretstash:latest
    command: [server, --listen=0.0.0.0:8200, --real-ip-header=X-Forwarded-For]
    expose: ["8200"]            # internal only; not published to the host

  caddy:
    image: caddy:2
    ports: ["80:80", "443:443"]
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data        # persists issued certificates

volumes:
  caddy_data:
```

`Caddyfile`:

```caddyfile
secrets.example.com {
	reverse_proxy https://secretstash:8200 {
		transport http {
			tls_insecure_skip_verify
		}
	}
}
```

`--real-ip-header=X-Forwarded-For` makes secretstash read the real client
address from the header Caddy appends, so per-IP rate limiting and audit logs
reflect real clients rather than the proxy. Because Caddy is the only thing that
can reach the `expose`d port, the header cannot be forged. Caddy obtains and
renews the public certificate automatically. (`--trust-proxy` is a deprecated
alias for `--real-ip-header=X-Forwarded-For`.)

### Cloudflare Tunnel

A [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
is the easiest way to share secretstash with friends and family: Cloudflare
issues and renews the public certificate, terminates TLS at its edge, and
reaches your origin through an outbound-only `cloudflared` connection, so you
never open a port to the internet.

Because `cloudflared` dials the origin over localhost, every request reaches
secretstash from `127.0.0.1`. Set `--real-ip-header=CF-Connecting-IP` so per-IP
rate limiting keys on the real visitor (Cloudflare overwrites that header on
every request, so clients cannot forge it) rather than collapsing every visitor
into one shared bucket.

Run the origin bound to loopback and never publish the port. Loopback-only is
exactly what keeps `CF-Connecting-IP` trustworthy: if the origin were reachable
directly, an attacker could send the header themselves.

```sh
secretstash server --listen 127.0.0.1:8200 --dev --real-ip-header CF-Connecting-IP --no-metrics
```

`--no-metrics` keeps the unauthenticated `/metrics` endpoint off the public
hostname (see [A note on /metrics](#a-note-on-metrics); alternatively block the
path with a Cloudflare WAF rule). `--dev` serves plain HTTP on loopback (Cloudflare provides the public HTTPS).
secretstash refuses `--dev` on a non-loopback address, which is the guard that
keeps you from accidentally exposing plaintext. To keep the localhost hop
encrypted instead, drop `--dev` (secretstash serves its ephemeral self-signed
cert) and add `originRequest.noTLSVerify: true` to the ingress rule below.

Minimal `cloudflared` `config.yml`:

```yaml
tunnel: <your-tunnel-id>
credentials-file: /root/.cloudflared/<your-tunnel-id>.json

ingress:
  - hostname: secrets.example.com
    service: http://127.0.0.1:8200    # https:// + noTLSVerify if not using --dev
  - service: http_status:404
```

```sh
cloudflared tunnel route dns <your-tunnel-id> secrets.example.com
cloudflared tunnel run <your-tunnel-id>
```

**Edge rate limiting (defense in depth).** Add a Cloudflare *Rate Limiting* rule
on the hostname (Security -> WAF -> Rate limiting rules) so abuse is dropped at
the edge before it reaches the tunnel, for example matching
`http.request.uri.path contains "/v1/"` and limiting to ~30 requests/minute per
client IP. This complements, and does not replace, the app-level limiter.

A reminder that applies to every deployment here: storage is in-memory by
design, so restarting `secretstash` (updates, host reboots) destroys all live
secrets.

### A note on /metrics

The `/metrics` endpoint is unauthenticated and not rate limited. In any
internet-facing deployment, block it at the firewall or proxy (Caddy: a
`@metrics path /metrics` matcher returning `respond 403`), or disable it with
`--no-metrics`.

## Development

```sh
make help    # list all targets
make test    # go test -race ./...
make check   # vet + govulncheck (if installed) + tests
make run-dev # plain-HTTP dev server
```
