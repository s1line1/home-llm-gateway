<p align="center"><a href="README.md">中文</a> | <b>English</b></p>

# home-llm-gateway

**Run a local LLM at home, use a cloud server as the public relay, and access your home model service from anywhere via an OpenAI-compatible API.**

Implemented in Rust with zero external proxy components (no frp / ngrok / nginx). Tunnel protocol: **QUIC** with **mutual TLS**. SSE streaming passthrough, multi-agent load balancing.

```
Client (anywhere)
   │  HTTPS + OpenAI-compatible API (incl. SSE streaming)
   ▼
cloud-gateway (public)     axum entry: API-key auth → rate limit → routing → tunnel frames
   │  QUIC (UDP, mTLS, multiplexed single connection, no head-of-line blocking)
   ▼
edge-agent (LLM host)      dials out + heartbeat + auto-reconnect, proxies to local LLM
   │  HTTP
   ▼
Local LLM (Ollama / vLLM / llama.cpp / mock-llm)
```

## Features

- **QUIC tunnel + mTLS**: the agent dials an outbound long-lived connection, naturally punching through NAT / dynamic IPs; two-way certificate authentication keeps unregistered agents out
- **Streaming-first**: SSE chunks are forwarded as they arrive (typewriter effect); client disconnect / timeout sends `Cancel` upstream so you never pay for abandoned tokens; per-frame idle timeout never kills long streams
- **Native public HTTPS**: rustls directly on port 443 — no nginx/caddy needed
- **Security & governance**: API-key auth (constant-time compare), per-key token-bucket rate limiting, per-agent concurrency admission control (429 when full)
- **Multi-agent least-loaded routing**: automatically balances across multiple LLM machines; stale agents are evicted
- **Observability**: `/metrics` in Prometheus text format, structured request logs (`request_id` / status / latency), `/healthz` probe
- **Multi-platform deployment**: single static binary (Linux / macOS), cross-compile script + systemd units

## Layout

```
crates/
├── proto/      tunnel frame protocol (Register/Heartbeat/ProxyRequest/Response*/Cancel/Error)
├── gateway/    cloud-gateway binary (axum + quinn server)
├── agent/      edge-agent binary (quinn client + reqwest)
└── mock-llm/   fake OpenAI-compatible LLM (to bring up the full chain without a real model)
certs/          dev certificate script
deploy/         systemd units (gateway.service / agent.service)
scripts/        multi-platform release packaging script
```

## Quick Start (fully local, no real LLM required)

> `cargo run` below is only for local development convenience (debug builds). **For production, run the compiled release binaries directly** — no Rust toolchain needed on the server, see [`DEPLOY.md`](DEPLOY.md).

### Prerequisites

- Rust stable (1.75+ recommended)
- `openssl` CLI (only needed by the certificate script)

### 1. Generate certificates

```bash
certs/gen-dev.sh        # outputs to certs/out/ (CA + server + client)
```

### 2. Start the mock LLM (pretend it is your home model)

```bash
cargo run -p mock-llm -- --addr 127.0.0.1:11435
```

### 3. Start edge-agent (on the machine next to your LLM)

```bash
cargo run -p agent -- \
  --cloud-addr 127.0.0.1:4433 \
  --ca certs/out/ca.crt \
  --cert certs/out/client.crt \
  --key certs/out/client.key \
  --agent-id home-1 \
  --upstream http://127.0.0.1:11435
```

### 4. Start cloud-gateway (on the cloud server)

All gateway settings live in a **YAML config file** (`gateway --config config.yml`, see `config.example.yml`). A minimal dev config:

```bash
cat > config.yml <<'EOF'
listen_addr: "0.0.0.0:8080"
quic_addr: "0.0.0.0:4433"
cert: certs/out/server.crt
key: certs/out/server.key
ca: certs/out/ca.crt
api_keys: [dev-key]
EOF
cargo run -p gateway -- --config config.yml
```

### 5. Access from "anywhere"

```bash
curl -H "Authorization: Bearer dev-key" http://127.0.0.1:8080/v1/models
curl -H "Authorization: Bearer dev-key" \
  http://127.0.0.1:8080/v1/chat/completions \
  -d '{"model":"mock-llm","messages":[{"role":"user","content":"hello"}]}'
```

Seeing the mock echo means the full chain (HTTP → auth → QUIC tunnel → agent → upstream) is up.

**SSE streaming** (a typewriter effect once you connect a real model):

```bash
curl -N -H "Authorization: Bearer dev-key" \
  http://127.0.0.1:8080/v1/chat/completions \
  -d '{"model":"mock-llm","stream":true,"messages":[{"role":"user","content":"hello"}]}'
```

### 6. Tests

```bash
cargo test    # proto roundtrip + end-to-end integration tests (in-memory certs, no external services)
```

## Connecting a Real LLM

Point the agent's `--upstream` at your real service — nothing else changes:

| Service | Command |
|---|---|
| Ollama | `--upstream http://127.0.0.1:11434` |
| vLLM | `--upstream http://127.0.0.1:8000` |
| llama.cpp server | `--upstream http://127.0.0.1:8080` |

## Production Deployment (Alibaba Cloud / public Internet)

> Full step-by-step deployment guide (certificates, security groups, systemd, verification, troubleshooting): [`DEPLOY.md`](DEPLOY.md). Key points below.

1. **Gateway on a public server**: open **UDP 4433** (QUIC tunnel) and **TCP 8443** (HTTPS API) in the security group / firewall. The gateway speaks HTTPS natively — no reverse proxy required (a reverse proxy couldn't handle the QUIC tunnel anyway, since it is a private frame protocol). If you later want a domain + automatic certificate renewal, add caddy (nginx needs `proxy_buffering off` or SSE streaming breaks).
2. **Agent next to the LLM**: `--cloud-addr <PUBLIC_IP>:4433`, and set `--server-name` to a domain present in the certificate SAN (a domain + DNS SAN certificate is recommended so an IP change never breaks the connection).
3. **mTLS is the key security line**: keep the CA private key yourself; issue a separate client certificate for every agent.
4. **UDP caveat**: QUIC runs over UDP — make sure it is not blocked; as a last resort you can downgrade the transport to TCP+TLS (the frame protocol stays the same, see `DESIGN.md` §10).

### Enabling HTTPS + rate limiting

Enable TLS and rate limiting in `config.yml`:

```yaml
listen_addr: "0.0.0.0:8443"
quic_addr: "0.0.0.0:4433"
cert: certs/out/server.crt
key: certs/out/server.key
ca: certs/out/ca.crt
api_keys: [dev-key]
tls_cert: certs/out/server.crt   # enables HTTPS on the public entry
tls_key: certs/out/server.key
rate_limit_per_min: 60            # per API key per minute (0 = unlimited)
```

```bash
cargo run -p gateway -- --config config.yml
```

Clients now use `https://`; for self-signed certificates either install `ca.crt` into the system trust store (or temporarily use `curl -k`).

### Agent concurrency cap (admission control)

```bash
cargo run -p agent -- ... --max-concurrency 2   # advertise at most 2 concurrent requests
```

The gateway reserves concurrency slots according to the advertised cap and returns 429 when full, so your home GPU is never overwhelmed.

### Multiple agents (multiple LLM machines)

Point several agents at the same gateway; it routes by **least load** (fewest in-flight requests):

```bash
# machine 1 (home)
cargo run -p agent -- ... --agent-id home-1 --upstream http://127.0.0.1:11434 --max-concurrency 2
# machine 2 (another box / cloud)
cargo run -p agent -- ... --agent-id home-2 --upstream http://127.0.0.1:8000 --max-concurrency 4
```

- Issue a separate client certificate per agent; `agent_id` distinguishes them
- Agents that miss heartbeats for `--agent-stale-secs` (default 15s) are evicted automatically
- When every agent is at capacity, the gateway returns 429

### Observability

- **`GET /metrics`**: Prometheus text format (per-status counters, in-flight requests, online agents, bytes forwarded, cumulative latency) — scrapable by Prometheus/Grafana
- **Structured logs**: `tracing` with `request_id` / status / latency per request (`tower-http` TraceLayer)
- **`/healthz`**: liveness probe

> Note: `/metrics` has no auth; on a public deployment, restrict it to your monitoring network via the security group.

### Multi-platform packaging & auto-start

```bash
scripts/build-release.sh          # build release binaries for every installed target into dist/
rustup target add aarch64-unknown-linux-gnu   # install cross targets when needed
```

Artifacts: `dist/home-llm-gateway-<version>-<platform>.tar.gz` (gateway / agent / mock-llm binaries).
Cross-compilation notes (macOS → Linux) are in the script header; musl targets are recommended for static binaries.

systemd units: `deploy/gateway.service` (cloud server) and `deploy/agent.service` (LLM machine). Adjust the parameters, then `systemctl enable --now` for auto-start on boot.

## API Key Management (Admin API)

The gateway ships a lightweight admin interface to **issue / revoke keys at runtime — no restart needed**:

- **Web admin page**: open `http://<gateway-addr>/` in a browser — enter the admin token and **create / revoke / list keys** right from the page
- Config `admin_token` (`config.yml`): admin password (independent of API keys); enables `/admin/*` and the page's management features when provided
- Config `keys_file`: SQLite database file for dynamic keys (default `keys.db`); keys survive restarts
- Static keys from `api_keys` are not affected by the Admin API; both kinds work on `/v1/*`

```bash
# Create a key (returns the plaintext secret, shown only once)
curl -X POST http://127.0.0.1:8080/admin/keys \
  -H "Authorization: Bearer <admin-token>" -H "Content-Type: application/json" \
  -d '{"name":"dsh-client"}'
# → {"id":"ab99de40","key":"sk-…","name":"dsh-client","created_at":…,"enabled":true}

# List keys (masked — only a prefix, never the full secret)
curl http://127.0.0.1:8080/admin/keys -H "Authorization: Bearer <admin-token>"

# Revoke a key (takes effect immediately)
curl -X DELETE http://127.0.0.1:8080/admin/keys/<id> -H "Authorization: Bearer <admin-token>"
```

> Security: use a strong random value for `admin_token` (`openssl rand -hex 32`); `keys.db` (SQLite) holds plaintext secrets and is git-ignored; in production, restrict `/admin/*` to your management network via the security group.

## Security Model

| Surface | Measure |
|---|---|
| Public entry | TLS 1.3, API-key auth (constant-time compare), token-bucket rate limiting, request body size cap |
| Tunnel | QUIC built-in TLS 1.3 + mTLS (agent certs issued by your CA); unregistered agents cannot connect |
| Concurrency | Atomic slot reservation against the agent's `max_concurrency`; 429 when full |
| Secrets | The CA private key never leaves your hands; a separate client cert per agent; `certs/out/` is git-ignored |

## Design Document

Architecture, frame protocol details and milestones live in [`DESIGN.md`](DESIGN.md).
