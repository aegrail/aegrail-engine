# Engine proxy design — v0.1.0

This document captures the design for the v0.1.0 HTTP forward proxy
that replaces the current `cmd/aegrail-engine/main.go` placeholder.
Reviewers and contributors: this is the contract the implementation
has to satisfy; deviations need a separate ADR in `docs/adr/`.

## Goal

A single Go binary that runs as a per-pod sidecar (or cluster-shared
Deployment) and intercepts an agent container's outbound HTTP traffic.
It enforces a deny-by-default egress allowlist, writes a SHA-256
chained audit log compatible with the
[`aegrail`](https://github.com/arpitcoder/aegrail) Python library's
JSONL format, and exposes liveness/readiness endpoints for K8s.

## Non-goals for v0.1.0

- Identity-aware enforcement (per-agent-identity policy decisions).
  Deferred to v0.2.0; v0.1.0 enforces a single allowlist per engine
  instance.
- Hot-reload of the allowlist policy. v0.1.0 reads the policy once
  at startup; the Helm chart's `ConfigMap`-checksum annotation
  triggers a pod reroll on policy change (already validated by the
  kind test).
- TLS interception (man-in-the-middle decryption). The proxy
  observes the SNI host on `CONNECT` and decides allow/deny, but
  does not decrypt the tunneled traffic.
- gRPC API for SDK→engine policy push. SDKs read the same
  `ConfigMap` for v0.1.0; the SDK→engine gRPC channel is v0.2.0
  scope.
- Approval gates for irreversible actions. v0.4.x.

## Module layout

```
aegrail-engine/
  cmd/aegrail-engine/main.go    # entry, flag parsing, signal handling, server wiring
  internal/policy/              # allowlist policy + host matching
    policy.go                   #   Policy struct, Allows() method
    policy_test.go              #   table-driven matcher tests
    loader.go                   #   load policy from YAML / ConfigMap mount
    loader_test.go
  internal/audit/               # JSONL audit chain compatible with aegrail-py
    event.go                    #   Event type + JSON serialization
    chain.go                    #   SHA-256 chain link computation + verification
    chain_test.go               #   chain invariants + cross-lang compat tests
    sink.go                     #   Sink interface
    sink_stdout.go              #   StdoutSink (line-buffered, mutex-protected)
    sink_file.go                #   FileSink (append-only, chain recovery on open)
    sink_test.go
  internal/proxy/               # HTTP + HTTPS forward proxy
    proxy.go                    #   Proxy struct + ServeHTTP dispatch
    http.go                     #   plain HTTP request handling
    connect.go                  #   HTTPS via CONNECT tunneling
    proxy_test.go               #   integration tests with httptest.Server
  internal/server/              # server bootstrap (HTTP listener, /healthz, /readyz)
    server.go
```

This mirrors the package boundaries the Python library uses
(`aegrail/policy.py`, `aegrail/audit.py`, etc.) so contributors
familiar with one can read the other.

## Wire / API contracts

### Allowlist policy format

YAML file mounted from a `ConfigMap`:

```yaml
# /etc/aegrail/allowlist.yaml
allow:
  - api.openai.com
  - api.anthropic.com
  - "*.openai.com"
  - generativelanguage.googleapis.com
```

`allow:` is a list of host patterns. Wildcards use the same
fnmatch-style semantics as `aegrail-py`:

- `*` matches any sequence of characters except `.` (so
  `*.openai.com` matches `api.openai.com` but not `openai.com`)
- `?` matches a single character
- No braces, no character classes — keep the grammar small

An empty list means deny-all. A missing file means deny-all (fail
secure). A file that can't be parsed at startup means the engine
fails to start with a clear error (also fail secure).

Implementation: use stdlib `path.Match` for the wildcard matching
(deterministic `/`-separator semantics regardless of OS; hosts don't
contain `/` so we get fnmatch-equivalent behavior with no extra
deps).

### Audit log format

JSONL, one event per line. Same `AuditEvent` schema as `aegrail-py`,
so a downstream consumer can verify chains across both producers
with one `verify_chain()` call:

```json
{"ts":"2026-05-15T09:42:11.123Z","session_id":"sess_engine_...","agent_identity":"egress-proxy/v1","invoking_user":null,"principal":"egress-proxy/v1@sess_engine_...","event":"egress_allowed","payload":{"host":"api.openai.com","method":"POST","path":"/v1/chat/completions"},"budget":{},"prev_hash":"...","event_hash":"..."}
```

Event types emitted by the engine in v0.1.0:

- `engine_start` — emitted once when the engine boots, captures
  policy hash and version. Genesis event for the chain.
- `egress_allowed` — an outbound request matched the allowlist and
  was forwarded. Payload: `{host, method, path}`.
- `egress_denied` — an outbound request did not match the
  allowlist and was rejected. Payload: `{host, method, path,
  reason: "not_in_allowlist"}`. Engine returns HTTP 403 to the
  client.
- `engine_shutdown` — emitted on graceful shutdown.

Notes:

- For `CONNECT` (HTTPS), `method` is `"CONNECT"` and `path` is the
  target host:port; the engine cannot see the actual HTTP path
  inside the tunnel.
- `invoking_user` is `null` in v0.1.0 (no identity attribution
  yet). The field exists for forward-compat with v0.2.0's
  header-based attribution.
- `budget` is `{}` in v0.1.0 (no budget tracking at the proxy
  layer; that's the Python library's job).
- Chain hash algorithm: identical to `aegrail.audit.compute_event_hash`
  in the Python library. Re-implementation must be byte-equivalent
  to satisfy `aegrail-py`'s `verify_chain()` on engine-produced
  logs. We have a cross-language test for this (see Testing below).

### HTTP request handling

For an incoming `GET http://example.com/foo`:

1. Extract `Host` (from URL or `Host` header)
2. `policy.Allows(host)` → True / False
3. If True: forward the request to the upstream, emit `egress_allowed`,
   stream the response back to the client.
4. If False: emit `egress_denied`, respond `403 Forbidden` with a
   clear plaintext body identifying the rejection reason.

Implementation: `httputil.ReverseProxy` for the forwarding path,
hand-rolled denial response for the rejection path.

### HTTPS request handling (CONNECT)

For `CONNECT example.com:443 HTTP/1.1`:

1. Extract host from the `CONNECT` target
2. `policy.Allows(host)` → True / False
3. If True: respond `200 Connection Established`, hijack the
   connection, open a TCP socket to the upstream, copy bytes in
   both directions until either side closes. Emit `egress_allowed`.
4. If False: respond `403 Forbidden`. Emit `egress_denied`.

Implementation: `http.Hijacker` to take over the TCP connection;
`io.Copy` in both directions with a `errgroup.Group` for the goroutines.

### Configuration

CLI flags (also settable via env via `kingpin`-style binding):

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--listen` | `AEGRAIL_LISTEN` | `:8080` | listen address |
| `--allowlist` | `AEGRAIL_ALLOWLIST` | `/etc/aegrail/allowlist.yaml` | path to policy file |
| `--audit-mode` | `AEGRAIL_AUDIT_MODE` | `stdout` | `stdout` or `file` |
| `--audit-file` | `AEGRAIL_AUDIT_FILE` | `/var/log/aegrail/audit.jsonl` | when `--audit-mode=file` |
| `--shutdown-timeout` | `AEGRAIL_SHUTDOWN_TIMEOUT` | `10s` | grace period on SIGTERM |
| `--version` | — | — | print version, exit |

## Failure modes & their behaviour

| Condition | Engine behaviour |
|---|---|
| Allowlist file missing on startup | Refuse to start; exit 2 with stderr message. Fail secure. |
| Allowlist file malformed YAML | Refuse to start; exit 2 with the parse error. Fail secure. |
| Allowlist file empty (`allow: []`) | Start; deny every request. |
| Upstream connection error (post-allowlist) | Respond `502 Bad Gateway` to client; emit `egress_error` event with the upstream error. |
| Audit sink write error | Log to stderr; continue serving. Audit pipeline failure must never break the data plane. |
| SIGTERM received | Stop accepting new connections; finish in-flight requests up to `--shutdown-timeout`; emit `engine_shutdown`; exit 0. |

## Testing strategy

1. **Unit tests** per package:
   - `internal/policy` — table-driven matcher tests (allow/deny,
     wildcards, empty lists, edge cases like IPv4 addresses)
   - `internal/audit` — chain computation determinism, tamper
     detection, sink concurrency
   - `internal/proxy` — `httptest.Server` upstream, in-process
     client; verify allow/deny, response shape, audit emissions

2. **Cross-language audit-chain compat test:**
   - Engine produces a JSONL audit log against a test scenario
   - The aegrail Python library's `verify_chain()` runs over the
     produced events
   - MUST validate end-to-end. Implemented as a Go test that
     shells out to `python -c "..."` with the right path setup,
     OR as a separate `tests/compat/` script invoked from CI.

3. **kind-cluster integration test** (already in
   `tests/kind/run.sh`):
   - Expand the 7-scenario test to cover the real proxy:
     - Pod with HTTP_PROXY set to engine service → allowed host
       returns 200 (or upstream's actual status), denied host
       returns 403
     - Verify `egress_allowed` and `egress_denied` events land in
       the audit log
     - Verify chain validates with the Python library

## Open questions to settle before / during implementation

1. **Should the engine emit events for connections it didn't see?**
   E.g., if the agent bypasses the proxy entirely (talks directly
   to the network), the engine has no record. The answer is "no,
   because we can't" — but should the engine emit a periodic
   heartbeat so consumers can detect engine outages? Probably
   yes, as a `engine_heartbeat` event every 60s. Decide before
   coding.

2. **How does the engine handle large request/response bodies?**
   The current plan streams via `httputil.ReverseProxy` which is
   constant-memory. For `CONNECT` tunneling, bidirectional `io.Copy`
   is also constant-memory. No specific limit configured; let the
   client and upstream negotiate.

3. **Logging vs audit:** the engine has two streams — operational
   logs (engine startup messages, errors) and the audit chain (the
   forensic record). Operational logs go to stderr; the audit
   chain goes to stdout (or file). This matters because k8s log
   shippers usually grab both streams; the consumer needs to be
   able to separate them. Mark audit log lines with a stable
   prefix or use a separate stream entirely. **Recommendation:
   separate streams.** Engine logs to stderr; audit JSONL to
   stdout. Log shipper config can route them differently.

## Approximate sizing

- `internal/policy/`: ~200 LOC + ~150 LOC tests
- `internal/audit/`: ~400 LOC + ~300 LOC tests
- `internal/proxy/`: ~500 LOC + ~400 LOC tests
- `internal/server/`: ~150 LOC
- `cmd/aegrail-engine/main.go`: ~150 LOC (already partly written)
- Total: ~1500 LOC + ~850 LOC tests for v0.1.0 MVP

At 10–20 hrs/week, expect 6–8 weeks elapsed to land all of the
above with kind validation and CI green.
