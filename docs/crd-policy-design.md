# CRD-based policy — v0.5.0 design

This document captures the design for the v0.5.0 milestone that
introduces Kubernetes Custom Resource Definitions (CRDs) as the
canonical mechanism for declaring agent governance policy in a
cluster. Reviewers and contributors: this is the contract the
implementation has to satisfy; deviations need a separate ADR in
`docs/adr/`.

## Goal

Operators declare aegrail policy — budgets, tool allowlists, egress
allowlists, audit sinks, MITM config — as Kubernetes resources
(`aegrail.io/v1alpha1` `ClusterAgentPolicy` and `AgentPolicy`). The
admission webhook reads matching policy at pod-creation time and
configures the injected engine sidecar accordingly. Policy is
versioned by the cluster, audited via the K8s audit log, RBAC-gated
via standard K8s RBAC, and observable via `kubectl get / describe`.

This brings aegrail in line with the Kyverno / Gatekeeper / Crossplane
pattern for declarative cluster-scoped policy. The aegrail-engine
becomes the data plane; CRDs become the control plane. No external
hosted control plane required.

## Why CRDs, not just Helm values

The Helm chart values that exist today (`policy.allowlist`,
`limits.maxRequests`, `mitm.hosts`, etc.) are cluster-wide constants
baked into the engine Deployment at install time. They don't compose
with the per-pod-identity model the webhook enables.

CRDs let one cluster express:

- "All agents labeled `aegrail.io/identity: support-bot/v1` get a $5
  budget and may call `lookup_order` and `issue_refund`."
- "All agents labeled `aegrail.io/identity: research-agent/v2` get a
  $50 budget, full web egress, but no write-tool permissions."
- "All agents in namespace `agents-prod` get audit-to-webhook; agents
  in `agents-staging` get audit-to-stdout."

Helm values can't express this. A CRD per agent-role can.

This is the same evolution every CNCF security/policy project has
gone through: Gatekeeper started as a Helm-installed admission
controller and now ships `ConstraintTemplate` + `Constraint` CRDs.
Kyverno ships `ClusterPolicy` and `Policy`. Falco ships `FalcoRule`
(in their newer K8s-native mode). aegrail v0.5.0 follows the same
arc.

## Non-goals for v0.5.0

- **Per-resource RBAC on tool predicates.** A `ClusterAgentPolicy`
  can be edited by any user with `cluster-admin` on the CRD group;
  fine-grained RBAC per-policy-field is v0.6.
- **Policy mutation while pods are running.** Policy changes apply
  to newly-created pods. Operators reroll deployments to pick up
  new policy. A controller-driven pod-reroll feature is v0.6.
- **Cross-cluster policy federation.** Each cluster has its own
  CRDs; cross-cluster aggregation is hosted-control-plane scope
  (out of OSS).
- **CEL expressions in tool predicates beyond a small validated
  subset.** v0.5.0 supports `args.X op constant` and conjunctions;
  full CEL surface is v0.6.
- **A separate controller binary.** The existing webhook reads
  CRDs directly via the K8s API at admission time. A dedicated
  controller for status reporting is v0.6.
- **Policy validation webhook.** The CRD's OpenAPI v3 schema
  catches the common errors at `kubectl apply` time. A separate
  ValidatingAdmissionWebhook for cross-field invariants is v0.6.

## CRD API surface

Two kinds, mirroring Kyverno's `ClusterPolicy` / `Policy` split.

### `ClusterAgentPolicy` (cluster-scoped)

```yaml
apiVersion: aegrail.io/v1alpha1
kind: ClusterAgentPolicy
metadata:
  name: production-support-agents
spec:
  # Which pods this policy applies to. Standard K8s LabelSelector.
  # Required. Pods matching no policy get the engine's default
  # allowlist from Helm values (deny-by-default).
  selector:
    matchLabels:
      aegrail.io/identity: "support-bot/v1"

  # Optional: restrict to specific namespaces. If omitted, applies
  # cluster-wide. Use the namespace-scoped AgentPolicy kind below
  # for per-namespace ownership.
  namespaceSelector:
    matchLabels:
      aegrail.io/inject: "enabled"

  # All five Budget fields from the SDK. Each becomes an env var
  # on the engine sidecar.
  budget:
    usdLimit: "5.00"          # AEGRAIL_ENGINE_USD_LIMIT
    tokenLimit: 100000        # AEGRAIL_ENGINE_TOKEN_LIMIT (a.k.a. MAX_TOKENS)
    wallSecondsLimit: 600     # AEGRAIL_ENGINE_WALL_SECONDS_LIMIT
    maxRecursion: 5           # (SDK-only; not enforced at sidecar)
    maxToolCalls: 500         # AEGRAIL_ENGINE_MAX_REQUESTS (sidecar-mapped)

  # Tool allowlist. Tool *names* gate at the sidecar level (a
  # request whose URL or LLM-call shape names a non-allowed tool
  # is denied). Argument-level predicates remain in-process in
  # the SDK; CRD-side predicates are CEL-validated for the small
  # subset documented under "Predicate subset" below.
  tools:
    allowed:
      - name: lookup_order
      - name: issue_refund
        when: "args.amount <= 100 && args.currency == 'USD'"
        # Redact specific keys from the audit log argument summary.
        redactKeys: ["payment_method_token"]
      - name: search_orders

  # Egress allowlist applied at the sidecar's L7 boundary. Same
  # semantics as the existing Helm `policy.allowlist`.
  egress:
    allowed:
      - api.openai.com
      - api.anthropic.com
      - "*.bedrock-runtime.*.amazonaws.com"

  # Audit sink config. Routed to AEGRAIL_ENGINE_AUDIT_MODE +
  # AEGRAIL_ENGINE_AUDIT_FILE on the sidecar; additional sinks
  # become a composite-sink config via a generated ConfigMap.
  audit:
    mode: "file"
    file: "/var/log/aegrail/audit.jsonl"
    additionalSinks:
      - type: webhook
        url: "https://siem.example.com/aegrail-events"
        headersSecretRef:
          name: siem-webhook-headers

  # MITM config (engine v0.4.3+). Same shape as Helm's `mitm`
  # values.
  mitm:
    enabled: true
    hosts: "api.openai.com,api.anthropic.com"
    caSecretRef:
      name: aegrail-mitm-ca
      certKey: tls.crt
      keyKey: tls.key
      mountDir: /etc/aegrail/mitm-ca

status:
  # Populated by the webhook on each admission. Operators read
  # this for observability ("how many pods have this policy
  # currently applied?").
  matchedPods: 12
  lastAppliedTime: "2026-05-21T14:30:00Z"
  lastError: ""
```

### `AgentPolicy` (namespace-scoped)

Identical schema to `ClusterAgentPolicy`, scoped to a single
namespace. Used when a namespace owner wants to declare policy
without `cluster-admin` rights. Where both a cluster-scoped and
namespace-scoped policy match a pod, the **namespace-scoped policy
wins** (least-privilege-friendly default; explicit namespace owner
intent overrides cluster baseline).

## Conflict resolution between multiple matching policies

When N policies match a pod (because selectors overlap), the
webhook applies these rules in order:

1. **Tool allowlist**: **intersection**. A tool must appear in
   every matching policy's `tools.allowed` to be permitted. This
   is least-privilege; adding a more-permissive policy never
   widens an existing pod's tool surface.
2. **Egress allowlist**: **intersection**. Same reasoning.
3. **Budgets**: **minimum**. Most-restrictive limit wins.
4. **Audit sinks**: **union**. Events go to every configured
   sink (no policy can remove audit coverage that another policy
   added).
5. **MITM**: **enabled if any policy enables**. Hosts list is
   the **union** of `hosts` across matching policies.
6. **CRD scope precedence**: namespace-scoped `AgentPolicy` wins
   over cluster-scoped `ClusterAgentPolicy` on **non-additive**
   fields where there's a direct conflict. (e.g., the
   namespace-scoped policy's `mitm.caSecretRef` overrides the
   cluster-scoped one; but the additive fields like audit sinks
   still union.)

Examples will be in `docs/adr/0001-crd-conflict-resolution.md`
once that's written.

## Module layout

```
aegrail-engine/
  api/v1alpha1/
    types.go                    # ClusterAgentPolicy, AgentPolicy Go structs
    zz_generated_deepcopy.go    # controller-gen output
  config/crd/bases/             # YAML CRD manifests (controller-gen output)
    aegrail.io_clusteragentpolicies.yaml
    aegrail.io_agentpolicies.yaml
  internal/webhook/
    policy_resolver.go          # NEW: walk matching CRDs, merge per rules above
    policy_resolver_test.go     # NEW: conflict-resolution table tests
    mutator.go                  # CHANGED: resolve policy before BuildPatch
  cmd/aegrail-webhook/main.go   # CHANGED: instantiate controller-runtime
                                # client, wire policy resolver
  internal/cel/
    predicate.go                # NEW: CEL-subset evaluator for `when:`
    predicate_test.go
```

`api/v1alpha1/types.go` follows the standard controller-gen
markers. `make manifests` regenerates the CRD YAML and DeepCopy
boilerplate.

## How it integrates with the existing webhook

The current webhook (`internal/webhook/mutator.go`) reads its
config from env vars set on the webhook Deployment, applies one
config to every matched pod. v0.5.0 changes this:

1. Webhook startup: instantiate a `controller-runtime` client
   for `aegrail.io/v1alpha1` resources. No new binary; embedded
   in `cmd/aegrail-webhook`.
2. On each `AdmissionReview`: the webhook resolves matching
   `ClusterAgentPolicy` + `AgentPolicy` for the pod's labels and
   namespace, applies the conflict-resolution rules, builds a
   merged `webhook.Config`, and calls `BuildPatch(pod, config)`.
3. Pod-not-matching-any-policy fallback: the webhook's existing
   env-var defaults still apply (cluster baseline). Existing
   v0.4.x Helm installs continue to work unchanged.
4. CRD status update: the webhook PATCHes the matched
   ClusterAgentPolicy's `.status.matchedPods` count + last-applied
   timestamp. Fire-and-forget; failure to update status never
   blocks pod admission (audit log records the status-update
   failure for the operator).

The mutator code from v0.4.3 (`buildEngineContainer`,
`mitmCAVolumeOp`, etc.) is unchanged. The policy resolution
happens *before* `BuildPatch` is called. Single seam to test
(the resolver), no rewrite of the mutation logic.

## Predicate subset for `when:` expressions

Full CEL is overkill for v0.5.0 alpha. The subset:

- Identifiers: `args` (a `map[string]any` of the tool's
  arguments), `principal` (the agent identity string),
  `invoker` (the invoking user string)
- Operators: `==`, `!=`, `<`, `<=`, `>`, `>=`, `&&`, `||`, `!`,
  `in`
- Literals: strings, numbers, booleans, lists, the `args.X`
  index expression
- Functions: `size(...)`, `string.startsWith(...)`,
  `string.endsWith(...)`, `string.matches(...)` (regex)

This covers ~90% of real-world predicates. Anything more
complex stays as a Python callable on the in-process `Tool`
declaration. Full CEL is a v0.6 graduation item.

## SDK ↔ engine ↔ CRD relationship

| Layer | Source of truth |
|---|---|
| In-process `Tool` with arbitrary Python `when` lambda | Always wins; the SDK never reads CRDs |
| Sidecar tool-name allowlist | CRD-derived |
| Sidecar egress allowlist | CRD-derived |
| Sidecar budget (token, request count) | CRD-derived |
| Sidecar MITM config | CRD-derived |
| Audit sink config | CRD-derived (additive union with Helm config) |
| Per-tool CEL `when:` predicate | CRD-derived, enforced at sidecar admission to outbound HTTP |
| Recursion depth, USD-precision arithmetic | Always SDK-only |

This is intentional: the SDK has more expressive power than the
sidecar (full Python lambdas) and remains the in-process source
of truth. The CRDs give the *operator* a declarative way to
constrain *what the SDK gets to do* — they don't replace the SDK.

## Helm chart changes

A new top-level `crd` block in `values.yaml`:

```yaml
crd:
  # Install the aegrail.io CRDs as part of the chart install.
  # Set to false if you manage CRDs out-of-band (operator
  # pattern, ArgoCD-managed CRDs, etc.).
  install: true
  # If install:false, the chart's manifests still reference the
  # CRDs but assume they're already present.
```

CRD YAML lives under `deploy/helm/crds/` (Helm's special
directory that installs CRDs before any templated resources).

## Migration from v0.4.x

Operators on v0.4.x continue to work unchanged. The existing
`policy.allowlist`, `limits.*`, `mitm.*` Helm values still
apply as the cluster baseline.

Adopting CRDs is an opt-in upgrade: install one
`ClusterAgentPolicy` matching your `aegrail.io/identity` label,
verify it's matched (`kubectl get clusteragentpolicy
production-support-agents -o yaml` → check
`.status.matchedPods`), gradually move per-agent config from
Helm values into CRDs.

No breaking changes to the v0.4.x Helm chart shape.

## Test plan

| Test type | Path | What it covers |
|---|---|---|
| Unit | `internal/webhook/policy_resolver_test.go` | Conflict-resolution rules table |
| Unit | `internal/cel/predicate_test.go` | CEL subset evaluation against `args` |
| Unit | `internal/webhook/mutator_test.go` | (Extended) policy-derived sidecar env vars |
| Kind integration | `tests/kind/run-crd-policy.sh` | Apply a `ClusterAgentPolicy`, label namespace, deploy pod, assert sidecar env matches CRD; modify CRD, redeploy pod, assert new env reflects change |
| Kind integration | `tests/kind/run-crd-conflict.sh` | Two overlapping policies (cluster + namespace), assert intersection of tool allowlists |

Both kind tests follow the v0.4.3 pattern: full helm install +
agent pod exec, not just unit tests. Per the v0.4.3 lesson, the
integrated path is the test that matters.

## Open questions (for ADRs)

1. **CEL evaluator choice.** `google/cel-go` is the canonical
   choice but pulls in a sizable dep tree. Alternative: a
   hand-rolled subset evaluator (~500 LOC) that we control
   entirely. Recommendation: hand-rolled for v0.5.0; switch to
   cel-go in v0.6 if we need the full surface.
2. **Status-update mechanism.** PATCH from the webhook hot path
   adds latency to every admission. Alternative: a tiny
   asynchronous goroutine batch-updates status every N seconds.
   Recommendation: batch update, accept stale-by-N-seconds
   `matchedPods` count.
3. **Should `AgentPolicy` (namespace-scoped) be the primary
   recommendation, with `ClusterAgentPolicy` reserved for the
   platform team?** Likely yes — it matches the K8s RBAC norm
   that namespace owners declare their workload's policy. ADR
   to follow.

## Timeline

| Week | Work |
|---|---|
| 1 | `api/v1alpha1/types.go`, controller-gen integration, CRD YAML manifests, `crd-policy-design.md` doc (this doc) |
| 1 | `internal/cel/predicate.go` — hand-rolled CEL subset evaluator + tests |
| 2 | `internal/webhook/policy_resolver.go` + conflict resolution tests |
| 2 | Webhook integration — resolver wired into mutator flow |
| 2 | `tests/kind/run-crd-policy.sh` + `tests/kind/run-crd-conflict.sh` |
| 2 | Helm chart updates, CHANGELOG, v0.5.0 release ritual |

Two weeks to v0.5.0 alpha if scope holds. Tag as
`v0.5.0-alpha.1` initially; promote to `v0.5.0` after one design
partner has it working in a real cluster.

## Marketing / narrative ties

This work is structurally complete; it ships regardless of the
narrative. But the narrative writes itself given the May 2026
acquisition wave:

> Palo Alto paid $130M for an AI gateway.
> Check Point paid $300M for a prompt firewall.
> Cisco paid for a model-security platform.
>
> None of them shipped a Kubernetes-native, declarative
> runtime contract for AI agents. aegrail v0.5.0 does. Apache 2.0.
> `kubectl apply -f my-aegrail-policy.yaml`.

The "Kyverno of AI agents" framing maps cleanly to the existing
Falco/Kyverno community surface. CNCF Slack post + Medium piece
+ X thread, in the v0.5.0 release window.
