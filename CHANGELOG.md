# Changelog

All notable changes to `aegrail-engine` are documented in this file.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.2] — 2026-05-16

### Changed — repository moved to `aegrail` GitHub organisation

Metadata-only release. Both `aegrail-engine` and the companion
`aegrail` Python SDK now live under the dedicated `aegrail`
GitHub organisation:

- Source: `github.com/arpitcoder/aegrail-engine` →
  `github.com/aegrail/aegrail-engine` (GitHub redirects from the
  old URL indefinitely).
- Go module path: `github.com/arpitcoder/aegrail-engine` →
  `github.com/aegrail/aegrail-engine`. Anyone importing the
  internal packages needs to update their `go.mod` and imports.
- Container image: `ghcr.io/arpitcoder/aegrail-engine:*` images
  remain accessible (immutable). New images from v0.4.2 onward
  publish under `ghcr.io/aegrail/aegrail-engine:*`.
- Helm chart: published to `https://aegrail.github.io/aegrail-engine`
  from v0.4.2's CI run. The old `https://arpitcoder.github.io/...`
  URL becomes a 404 (GitHub Pages is owner-anchored — no redirect
  for Pages itself). Users running `helm repo add` need to update
  the URL.

No behaviour change. No new features. Existing tagged releases
(0.1.0-rc through 0.4.1) under the old paths continue to work for
anyone who pinned them.

### Why the move

Credibility for adopters (security-adjacent OSS reads as "real
project" under a dedicated org), optionality for future co-
maintainers / contributors, and canonical artifact URLs that
match the project name rather than the author's personal handle.

## [0.4.1] — 2026-05-16

### Added — webhook auto-injects the MITM CA trust into agent containers

Closes the loop on v0.4.0. When both the mutating webhook and MITM
are enabled and the operator has placed the CA Secret in the
labeled namespace, the webhook now adds:

- A `volumes` entry referencing the CA Secret on the pod
- A `volumeMounts` entry on every user container, mounting the
  CA dir read-only
- Three env vars on every user container:
  - `SSL_CERT_FILE=/etc/aegrail/mitm-ca/ca.crt`
  - `REQUESTS_CA_BUNDLE=/etc/aegrail/mitm-ca/ca.crt`
  - `NODE_EXTRA_CA_CERTS=/etc/aegrail/mitm-ca/ca.crt`

This covers the trust stores of every major HTTP library:
- Python `requests` (REQUESTS_CA_BUNDLE)
- Python `httpx` (SSL_CERT_FILE)
- Node.js (NODE_EXTRA_CA_CERTS appends to system trust)
- OpenSSL-based clients (SSL_CERT_FILE)
- Go's net/http (reads SSL_CERT_FILE on Linux as a fallback)

End-to-end pattern: agent dev writes zero aegrail code, platform
team labels the namespace, every pod gets the engine sidecar +
proxy env vars + MITM CA trust. Every HTTPS call to a MITM'd
provider gets token-accounted at the network layer.

### Webhook Config / env

New webhook config fields surfaced via env on the webhook
deployment:

- `AEGRAIL_WEBHOOK_MITM_CA_SECRET_NAME` — required to enable trust
  injection. Set automatically by Helm when `mitm.caSecretName` is
  configured.
- `AEGRAIL_WEBHOOK_MITM_CA_CERT_KEY` — optional, defaults to `tls.crt`.
- `AEGRAIL_WEBHOOK_MITM_CA_MOUNT_PATH` — optional, defaults to
  `/etc/aegrail/mitm-ca/ca.crt`.

### Cross-namespace caveat (intentional)

K8s does not allow Pod Secret mounts to reference Secrets in other
namespaces. The webhook does NOT create per-namespace copies of
the CA Secret — that would be a Kubernetes controller, not a
mutating webhook. For v0.4.1 the operator pre-creates the Secret
in each labeled namespace (typical pattern: a post-install Helm
hook or a one-liner `kubectl get secret ... -o yaml | sed
s/namespace:.*/namespace: target/ | kubectl apply -f -`).

A first-class controller that watches namespaces and replicates
the CA Secret is planned for v0.5.0.

### Tests

2 new tests in `internal/webhook/mutator_test.go`:
- `TestBuildPatch_MITMCAInjectsVolumeAndTrustEnv` — verifies the
  patch includes all three env vars + the volume mount + the pod-
  level Secret-backed volume declaration when MITMCASecretName is
  set.
- `TestBuildPatch_NoMITMCAMeansNoTrustInjection` — regression: with
  no MITM CA configured, none of the env vars or the volume
  reference appear in the patch.

Total webhook tests: 11. All engine + webhook + parser tests still
green.

## [0.4.0] — 2026-05-16

### Added — HTTPS MITM mode for token enforcement on direct provider TLS

The last gap in the engine-side coverage story. When the operator
opts into `mitm.hosts`, the engine terminates TLS for CONNECT
requests whose destination matches one of the configured patterns,
parses the decrypted response for tokens via the v0.3.x llmparse
machinery, and re-encrypts to the real upstream. This is the only
way to enforce token budgets on direct HTTPS traffic to public
provider endpoints (api.openai.com, api.anthropic.com, Bedrock,
Vertex) when the agent never imported the SDK.

#### New components

- **`internal/mitm/`** — CA + leaf cert factory.
  `NewAuthority(validity)` mints a self-signed CA at engine startup
  (useful for dev / kind). `LoadAuthority(certPath, keyPath)` loads
  an operator-pinned CA from PEM files (production). Per-upstream
  leaf certs are signed on demand, cached for 24h. 5 unit tests
  covering CA generation, leaf signing + verification, host-based
  caching, regional Bedrock hostnames, and tls.Config integration.

- **`internal/proxy/mitm.go`** — TLS-terminating CONNECT handler.
  When `MITMConfig.shouldMITM(host)` is true, the proxy:
  1. Mints a leaf cert for the destination host.
  2. Hijacks the client connection, writes 200 Connection
     Established, performs TLS handshake using the leaf cert.
  3. Reads HTTP requests off the TLS-terminated client conn.
  4. Forwards each to the real upstream over TLS using system
     trust to verify the provider's real cert.
  5. Parses the response body via `llmparse`, augments the audit
     event with `llm_model` / `tokens_in` / `tokens_out` / `mitm:
     true`, and writes the response back to the client.
  6. Accumulates against the TokenBudget if configured.

- **End-to-end test** (`internal/proxy/mitm_test.go`,
  `TestMITM_EndToEnd_OpenAIChatCompletions`): real TLS upstream
  serving an OpenAI-shaped response, engine MITM'ing with a fresh
  CA, client trusting that CA, request flows end-to-end. Verifies
  body integrity, audit event, token parsing, and budget
  accumulation. Plus a regression test that hosts NOT in the MITM
  patterns continue to tunnel opaquely.

#### New env vars

- `AEGRAIL_ENGINE_MITM_HOSTS` — comma-separated host patterns
  (fnmatch). Empty = MITM disabled (default).
- `AEGRAIL_ENGINE_MITM_CA_CERT_FILE` /
  `AEGRAIL_ENGINE_MITM_CA_KEY_FILE` — optional CA PEM files. If
  unset, the engine generates a fresh CA at startup and logs the
  PEM (look at the engine pod's logs to capture it).

#### Helm chart

New `mitm.hosts` and `mitm.caSecretName` values. When `caSecretName`
is set, the chart mounts the named Secret at `/etc/aegrail/mitm-ca`
and sets `AEGRAIL_ENGINE_MITM_CA_CERT_FILE` /
`AEGRAIL_ENGINE_MITM_CA_KEY_FILE` accordingly. Off by default;
existing deployments unaffected.

#### Parser relaxation

URL recognition for OpenAI Chat Completions, Responses, and
Anthropic Messages is now **path-based** instead of host-anchored.
Coverage now includes Azure OpenAI proxies, litellm, vLLM, and
any gateway exposing the standard paths. Bedrock and Vertex stay
host-anchored because their path shapes are otherwise generic.

#### What's NOT in v0.4.0 (deferred to v0.4.1)

**CA trust distribution into agent containers.** The engine-side
MITM machinery works, but for HTTPS traffic from the agent to
reach the engine without TLS verification failures, the engine's
CA must be in the agent container's trust store. In v0.4.0 the
operator does this manually:

1. Capture the CA PEM from the engine pod's logs (or pre-create
   it as a Secret and point `mitm.caSecretName` at it).
2. Mount the CA into the agent container.
3. Set `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`
   env vars on the agent container pointing at the CA file.

The v0.4.1 webhook will inject all four automatically on labeled
namespaces. The deferral is scope discipline — engine-side MITM
is a self-contained, testable unit; the webhook-side distribution
is its own well-understood feature.

### Limitation acknowledged

HTTP/1.1 only on the MITM path. HTTP/2 keep-alive over the
terminated connection is not handled in v0.4.0 — each request
opens a fresh CONNECT. Modern clients usually do this anyway; we'll
revisit if a design partner reports throughput issues.

## [0.3.1] — 2026-05-16

### Added — Anthropic, Bedrock, Vertex AI / Gemini parsers

The token-parsing surface from v0.3.0 now covers the major
commercial LLM providers beyond OpenAI and Ollama:

- **Anthropic Messages** — `api.anthropic.com/v1/messages`
  parses `usage.input_tokens` + `usage.output_tokens` from the
  response body. Also reads `cache_creation_input_tokens` and
  `cache_read_input_tokens` for prompt-cache attribution
  (carried through into the audit event in a later release).
- **AWS Bedrock Runtime** — `bedrock-runtime.<region>.amazonaws.com/
  model/<id>/invoke` (and the streaming + Converse variants). Token
  counts come from the response **headers**
  `X-Amzn-Bedrock-Input-Token-Count` /
  `X-Amzn-Bedrock-Output-Token-Count`, not the body — Bedrock is
  the only major provider that reports out-of-band, so the
  parser's signature was extended to accept response headers. The
  model id is extracted from the URL path.
- **Google Vertex AI / Gemini API** —
  `*-aiplatform.googleapis.com/*/models/*:generateContent` (or
  `:streamGenerateContent` / `:predict`) and
  `generativelanguage.googleapis.com/*/models/*:generateContent`
  (Gemini AI Studio). Reads `usageMetadata.promptTokenCount` +
  `candidatesTokenCount`.

### API change (internal)

`llmparse.ParseResponse` signature is now
`ParseResponse(url, body, headers http.Header)` to support
providers that report usage in headers. The proxy passes
`resp.Header` through automatically. Callers outside the engine
that wired against the v0.3.0 signature need to update.

### Tests

`internal/llmparse/parse_test.go` gains 4 new tests covering each
new provider's response shape. Total package: 11 tests.
`internal/proxy/proxy_test.go` unchanged — the new headers
parameter is passed transparently.

### Coverage matrix after this release

| Provider | URL recognition | Usage parsing | Streaming |
|---|---|---|---|
| OpenAI Chat Completions | ✅ | ✅ | ⚠️ (body buffered; OK for non-stream) |
| OpenAI Responses API | ✅ | ✅ | ⚠️ |
| Anthropic Messages | ✅ | ✅ | ⚠️ |
| AWS Bedrock Invoke / Converse | ✅ | ✅ (header-based) | ⚠️ |
| Google Vertex / Gemini | ✅ | ✅ | ⚠️ |
| Ollama generate / chat | ✅ | ✅ | ⚠️ |

(Streaming responses still pass through unparsed — usage frames
are split across SSE chunks; v0.3.x fast-follow.)

### Same v0.3.0 HTTPS caveat applies

Plain-HTTP forward path only. Direct HTTPS traffic to public
provider endpoints stays opaque via CONNECT tunnels; that needs
the v0.4.x MITM mode.

## [0.3.0] — 2026-05-16

### Added — LLM response token parsing + network-layer token budget

The "agent never imported the SDK and the platform still wants USD
guardrails" piece. The engine now recognises known LLM endpoint URL
shapes on the **plain-HTTP forward path**, parses their response
bodies to extract token usage, and enforces a cumulative token
budget at the network layer.

**Recognised URL patterns:**

- `api.openai.com/v1/chat/completions` (OpenAI Chat Completions)
- `api.openai.com/v1/responses` (OpenAI Responses API)
- `*/api/generate` and `*/api/chat` (Ollama — matches any host so
  in-cluster Service DNS, localhost, sidecar, all work)

**Each parsed response augments the `egress_allowed` audit event:**

```json
{
  "event": "egress_allowed",
  "payload": {
    "host": "host.docker.internal",
    "method": "POST",
    "path": "/api/generate",
    "status_code": 200,
    "duration_ms": 1843,
    "llm_model": "llama3.2:3b",
    "tokens_in": 33,
    "tokens_out": 5,
    "tokens_total": 38
  }
}
```

`tokens_total` is the running cumulative since engine boot.

**New env var:** `AEGRAIL_ENGINE_MAX_TOKENS` — hard cap on cumulative
LLM tokens (input + output). Once the running total crosses this
value, the next request is denied with `egress_denied` reason
`token_budget_exceeded` and HTTP 429. The current in-flight call
always finishes accounting — we never lose already-consumed work.
The webhook injector propagates this env var to auto-injected
sidecars.

**Helm values:** new `limits.maxTokens` (0 = unlimited).

### Important limitation

**HTTPS CONNECT tunnels are opaque** to the parser — TLS is end-to-
end between agent and provider. Token enforcement on `api.openai.com`
HTTPS traffic requires either:

1. Terminating TLS upstream of aegrail (an in-cluster reverse proxy)
   so the engine sees plain HTTP, OR
2. The future v0.4.x MITM mode that injects a CA cert into agent
   pods and terminates TLS at the engine.

For self-hosted models (Ollama, vLLM, TGI) and in-cluster gateways,
the v0.3.0 plain-HTTP coverage is complete.

### Files added

- `internal/llmparse/` — URL recognition + body parsers for OpenAI
  (Chat Completions and Responses) and Ollama. 8 unit tests.
- `internal/limits/` gains `TokenBudget` (atomic cumulative counter
  with cap). 4 new unit tests.
- `internal/proxy/http.go` reads response bodies for recognised
  LLM URLs via the `ModifyResponse` hook, extracts usage, augments
  the audit event, and accumulates against the budget.

### Validated

- `tests/kind/run.sh` extended: the audit-chain scenario now also
  asserts that the Ollama call's `egress_allowed` event carries
  non-zero `tokens_in`, `tokens_out`, and a populated `llm_model`
  field — proving end-to-end real-Ollama → engine → response-parse
  → audit-event.
- Existing 13 scenarios + webhook gate still green. Backward compat
  verified (token enforcement off by default).

## [0.2.0] — 2026-05-16

### Added — mutating admission webhook (auto-injection)

The "platform team enables it, dev team does nothing" release. When
`webhook.enabled=true` in Helm values:

1. The chart deploys an admission webhook server alongside the
   engine — TLS-protected, with self-signed cert generated at
   install time via Helm's `genCA` / `genSignedCert` (no cert-
   manager dependency).
2. A `MutatingWebhookConfiguration` registers the webhook for Pod
   CREATE events in namespaces labeled `aegrail.io/inject=enabled`.
3. For each labeled-namespace pod creation, the webhook returns a
   JSON Patch that:
   - Adds the engine sidecar container to the pod.
   - Adds `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` env vars to
     every user container so outbound traffic routes through the
     engine on `localhost:8080`.
   - Defaults the `aegrail.io/identity` label so the engine's
     downward-API binding has a value to read.
4. The engine container reads `agent_identity` from the
   `aegrail.io/identity` pod label via the downward API (from
   v0.1.1), so audit events stamp the actual agent's identity, not
   the engine's hardcoded default.

Agent dev writes zero aegrail code. Their Dockerfile is unchanged.
The platform team flips a Helm value and labels a namespace; every
new pod in that namespace gets the runtime governance layer.

### New components

- `cmd/aegrail-webhook/` — webhook HTTP server binary (~250 LOC).
- `internal/webhook/` — admission mutation logic, `BuildPatch`
  (~200 LOC) + 9 unit tests covering injection, idempotency, env
  array creation vs append, label defaulting, optional limits, and
  file-audit mode.
- Helm templates: `webhook/secret.yaml`, `webhook/deployment.yaml`,
  `webhook/service.yaml`, `webhook/mutating-config.yaml`. All
  wrapped in `{{- if .Values.webhook.enabled -}}` so default
  behavior is unchanged for existing v0.1.x deployments.

### Dockerfile

Now builds **two** binaries — `/aegrail-engine` and
`/aegrail-webhook` — into the same distroless image. The engine
`Deployment` keeps the default `ENTRYPOINT`; the webhook
`Deployment` overrides `command: ["/aegrail-webhook"]`.

### Validated

End-to-end on a fresh kind cluster
(`tests/kind/run-webhook.sh`, 9 scenarios):

1. helm install with webhook.enabled=true — both Deployments Ready
2. Test namespace labeled `aegrail.io/inject=enabled`
3. Apply single-container test pod
4. Pod becomes Ready with **2 containers** (user + injected engine)
5. `HTTP_PROXY` / `HTTPS_PROXY` set to `http://localhost:8080` on
   the user container
6. `aegrail.io/identity` label defaulted on the pod
7. Engine sidecar container reaches Ready inside the pod

Plus the existing 14-scenario engine gate (`tests/kind/run.sh`)
still passes — backward compatibility verified.

### Operational notes

- `failurePolicy: Ignore` on the MutatingWebhookConfiguration so
  webhook outages do not block cluster-wide pod creation. The
  engine itself still fails-closed at the proxy layer (deny-by-
  default allowlist).
- K8s label values cannot contain `/`. The default
  `webhook.defaultIdentity` is `auto-injected-v1`; use dashes or
  dots for version segments (e.g. `support-bot-v1`,
  `research-agent.v2.1`).
- The self-signed CA regenerates on every `helm upgrade`. For
  production environments where short-lived cert rotation is
  desired this is correct. For pinned-CA setups, integrate
  cert-manager (future enhancement).

## [0.1.2] — 2026-05-16

### Added — network-layer request budgets

Two new primitives let the engine enforce cost-bounded behavior
**without inspecting response bodies** — the case where an agent
never imported the aegrail SDK but the platform team still wants
a hard cap.

- **`AEGRAIL_ENGINE_MAX_REQUESTS`** — total requests served over
  the engine's process lifetime. Denials return HTTP 429 with
  `X-Aegrail-Decision: denied`, `X-Aegrail-Reason: request_count_exceeded`,
  and an `egress_denied` audit event whose payload includes
  `reason`, `total`, `max`, `host`, and `method`. 0 (default) means
  unlimited.
- **`AEGRAIL_ENGINE_RATE_LIMIT`** — token-bucket rate limit, format
  `<n>/<unit>` where unit is `sec`, `min`, or `hour`. Burst equals n.
  Denials return HTTP 429 with `X-Aegrail-Reason: rate_limited`.
  Empty (default) means unlimited.

Both checks fire **before** the per-host allowlist policy so a
runaway agent burns the budget once, not once per allowlisted
destination. Both are no-ops when their value is empty/zero, so
the change is fully backward compatible.

### New internal package

`internal/limits` — `RequestCounter` (atomic counter with cap) and
`RateLimiter` (single-bucket token bucket, no external deps).
`ParseRateSpec` parses the rate-string format. 10 new unit tests.

### Proxy + tests

`Proxy` struct gains `Counter` and `Limiter` fields. The proxy's
pre-flight in `ServeHTTP` checks both before dispatching to plain-
HTTP or CONNECT paths. 2 new proxy tests exercise the request-count
and rate-limit denial paths end-to-end via httptest.

### Helm chart

New `values.yaml` block:

```yaml
limits:
  maxRequests: 0    # 0 = unlimited
  rate: ""          # e.g. "10/sec", "1000/min"
```

ConfigMap renders the corresponding env vars only when set. Default
behavior unchanged for existing deployments.

### Why this is its own release

The webhook in v0.2.0 will let platform teams enable engine-side
enforcement on a labeled namespace without dev-team cooperation.
Shipping the network-layer budgets first means the auto-injected
engine arrives already capable of enforcing a hard cap — instead
of being an audit-only proxy until later.

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
- **Container image** at `ghcr.io/aegrail/aegrail-engine:0.1.0-rc`
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
[ARCHITECTURE.md](https://github.com/aegrail/aegrail/blob/main/ARCHITECTURE.md)
in the aegrail repo for context on how this fits with the Python
library.
