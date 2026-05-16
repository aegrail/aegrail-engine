# Changelog

All notable changes to `aegrail-engine` are documented in this file.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] — 2026-05-16

### Added — pod-label-driven agent identity (K8s downward API)

The engine's `agent_identity` can now be bound to a pod label via
the K8s downward API. Set `agentIdentityFromLabel` in the Helm
values, label your pod, and every audit event the engine emits
carries the label's value as `agent_identity`.

```yaml
# values.yaml
agentIdentityFromLabel: "aegrail.io/identity"
```

```yaml
# the pod manifest (or, soon, the auto-injection webhook in v0.2.0)
metadata:
  labels:
    aegrail.io/identity: "support-bot/v1"
```

The Helm chart renders a direct `env` entry that reads
`metadata.labels['<key>']` via `valueFrom.fieldRef`. K8s applies
direct `env` entries after `envFrom`, so the label wins over the
static ConfigMap value. Existing deployments without
`agentIdentityFromLabel` set are unaffected — the static
`agentIdentity` continues to flow through the ConfigMap as before.

This is the foundation for the v0.2.0 mutating admission webhook,
where the webhook will stamp `aegrail.io/identity` on agent pods
when it auto-injects the engine sidecar. The agent author writes
zero code; the operator labels a namespace; every audit event is
correctly identified.

### Why this is its own release

Three reasons:

1. The webhook in v0.2.0 depends on this — best to ship and
   exercise the label path on its own first.
2. Operators running the engine as a sidecar today can adopt the
   pattern manually before the webhook ships.
3. The change is chart-only (engine binary is unchanged in
   behavior); shipping it standalone gives platform teams a clean
   release boundary to track.

## [0.1.0-rc] — 2026-05-15

First release candidate. Ships the egress proxy and the Helm chart
that the deployment guides in the aegrail repo reference.

### Added — egress proxy

- **HTTP forward path.** The proxy parses the destination host from
  the incoming request, consults the allowlist, and either forwards
  via `httputil.ReverseProxy` (emitting `egress_allowed` with status
  code, duration, host, method, path) or denies with 403 plus an
  `X-Aegrail-Decision: denied` header (emitting `egress_denied` with
  reason `not_in_allowlist`). Upstream failures surface as 502 plus
  `egress_error` with the error string.
- **HTTPS CONNECT tunneling** following RFC 7231. The proxy dials
  upstream first so dial failures fail closed with 502 before the
  client commits to a tunnel; then hijacks the client connection,
  writes `HTTP/1.1 200 Connection Established`, and performs
  bidirectional `io.Copy` with per-direction byte counters. On
  tunnel close, emits `egress_allowed` with `bytes_to_upstream`,
  `bytes_from_upstream`, and `duration_ms`.
- **Allowlist policy** with fnmatch-style host pattern matching
  (`*` greedy across dots; only `/` is a separator). Identical
  semantics to the aegrail Python library's egress allowlist so the
  same patterns work in both halves of the stack.
- **Refuses to start with an empty allowlist.** Empty input is
  treated as a deployment error rather than as a deny-all default;
  operators have to be explicit.

### Added — audit

- **SHA-256 audit chain** byte-equivalent to aegrail-py. Each event
  carries `prev_hash` plus `event_hash`. The five engine event
  types are `engine_start`, `engine_shutdown`, `egress_allowed`,
  `egress_denied`, `egress_error`.
- **StdoutSink** — mutex-protected JSONL to stdout (default).
- **FileSink with chain recovery on open** — reads the last line
  of an existing audit file and continues the chain from its
  `event_hash`. Matches aegrail-py's `FileAuditSink` semantics so a
  single file written across many process lifetimes remains one
  verifiable chain.

### Added — packaging

- **Helm chart** with env-driven configuration. ConfigMap renders
  `AEGRAIL_ENGINE_ALLOWLIST`, `_AGENT_IDENTITY`, `_AUDIT_FILE` /
  `_AUDIT_STDOUT`, `_LISTEN` and the Deployment consumes them via
  `envFrom`. ConfigMap content hash drives pod re-roll on policy
  change. Optional `emptyDir` mount for the file-sink audit log.
- **Container image** at `ghcr.io/arpitcoder/aegrail-engine:0.1.0-rc`
  for `linux/amd64` and `linux/arm64`. Distroless nonroot base.

### Validated

- **13-scenario kind + Ollama gate.** Helm lint, template, image
  build + load, install, health probes, HTTP forward to the host's
  Ollama returning a real `llama3.2:3b` completion, HTTP denial,
  HTTPS CONNECT to `example.com` succeeding, HTTPS CONNECT to a
  disallowed host failing with curl exit 56, Python `verify_chain`
  over the engine-produced JSONL returning `(True, -1)`, helm
  upgrade re-rolling on ConfigMap change, helm uninstall removing
  every chart-managed resource.
- **Cross-language audit chain.** A chain produced by the Go engine
  is byte-identical to one produced by the Python library and
  validates with a single Python `verify_chain` call.

### Compatibility

Audit JSONL format compatible with the `aegrail` Python library at
v0.2.7 or later. Earlier SDK versions reject the new engine event
types via Pydantic literal validation.

This is the v0.3.0 milestone of the broader aegrail project. See
[ARCHITECTURE.md](https://github.com/arpitcoder/aegrail/blob/main/ARCHITECTURE.md)
in the aegrail repo for context on how this fits with the Python
library.
