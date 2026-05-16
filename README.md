<div align="center">

<img src=".assets/logo.svg" alt="aegrail-engine" width="140">

# aegrail-engine

**The Kubernetes-deployable enforcement engine for `aegrail`.**

[![Release](https://img.shields.io/github/v/release/aegrail/aegrail-engine?style=flat-square&label=Release&color=2DD4BF&labelColor=0F172A)](https://github.com/aegrail/aegrail-engine/releases)
[![Image](https://img.shields.io/badge/ghcr.io-aegrail/aegrail--engine-2DD4BF?style=flat-square&labelColor=0F172A&logo=docker&logoColor=white)](https://github.com/aegrail/aegrail-engine/pkgs/container/aegrail-engine)
[![Helm](https://img.shields.io/badge/helm-chart-2DD4BF?style=flat-square&labelColor=0F172A&logo=helm&logoColor=white)](https://aegrail.github.io/aegrail-engine)
[![License](https://img.shields.io/badge/license-Apache%202.0-2DD4BF?style=flat-square&labelColor=0F172A)](LICENSE)
[![SDK](https://img.shields.io/pypi/v/aegrail?style=flat-square&label=SDK&color=2DD4BF&labelColor=0F172A&logo=python&logoColor=white)](https://pypi.org/project/aegrail/)

</div>

A Go sidecar that enforces aegrail's runtime contract for AI agents at
the network egress boundary — outside the agent process, in any
language. Pairs with the [`aegrail`](https://github.com/aegrail/aegrail)
Python library to provide defense-in-depth: the library enforces tool
ACLs in-process; the engine enforces egress + audit at the pod level.

---

## Why this exists

The `aegrail` Python library is application-level: it works for
Python agents that route their tool calls through `session.call_tool(...)`.
That covers the L7 capability boundary inside a Python process.

It does **not** cover:

- Agents written in other languages (TypeScript, Go, Rust, JVM)
- A Python developer who calls `requests.post(...)` directly,
  bypassing the library
- Anything that ends up at a TCP socket regardless of what library
  opened it

`aegrail-engine` closes that gap by being a **separate process** that
sits between the agent's container and the outside world. It enforces
egress policy at the network boundary, where it doesn't matter what
language the agent is written in or what library it used.

This is the same pattern Envoy uses for service-mesh policy and
[oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) uses for
HTTP auth — push the policy boundary out of the application, into a
sidecar where it's enforced once and language-agnostic.

---

## Status

**Pre-release. v0.1.0 is the first milestone (egress proxy MVP).**

This repo was created on 2026-05-14. Engineering is sequenced after
`aegrail` v0.2.4 ships its in-Python interceptors. See
[ARCHITECTURE.md](ARCHITECTURE.md) in the [`aegrail`](https://github.com/aegrail/aegrail/blob/main/ARCHITECTURE.md)
repo for how the engine fits into the broader project.

Track the v0.1.0 milestone for what's planned and current progress.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ Pod                                                              │
│                                                                  │
│   ┌────────────────────┐    HTTP_PROXY    ┌───────────────────┐  │
│   │ Agent container    │ ────────────────▶│ aegrail-engine    │  │
│   │  - Python / Node / │   to localhost   │ sidecar           │  │
│   │    Go / etc.       │       :8080      │  - Go binary      │  │
│   │  - any aegrail SDK │                  │  - allowlist      │  │
│   │    or none         │                  │  - audit chain    │  │
│   └────────────────────┘                  │  - JSONL log      │  │
│             ▲                             └───────────────────┘  │
│             │                                       │            │
│             │                                       ▼            │
│             │      ┌──────────────────────────────────────────┐  │
│             │      │  Network egress (allowed hosts only)     │  │
│             │      └──────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

**What it enforces** that the Python library can't:

- All outbound HTTP from the agent container, regardless of language
  or library
- Allowlist policy applied at request time
- Audit chain (SHA-256, same format as the Python library's audit log)
- Denials recorded as `egress_denied` events with the requested
  destination

**What it does NOT do:**

- Non-HTTP traffic (use NetworkPolicy / Cilium for L3/L4)
- In-process enforcement (use the `aegrail` Python library for that)
- Process / syscall isolation (use containers, gVisor, Firecracker)

See [ARCHITECTURE.md](https://github.com/aegrail/aegrail/blob/main/ARCHITECTURE.md)
in the aegrail repo for the layered defense-in-depth model.

---

## Quickstart (when v0.1.0 ships)

```bash
# Add the Helm repository
helm repo add aegrail https://aegrail.github.io/aegrail-engine
helm repo update

# Install with default allowlist (deny-by-default)
helm install aegrail-engine aegrail/aegrail-engine \
  --set policy.allowlist[0]=api.openai.com \
  --set policy.allowlist[1]=api.anthropic.com
```

Or for sidecar injection in an existing agent pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-agent
  annotations:
    aegrail.io/inject: "true"
spec:
  containers:
    - name: agent
      image: my-agent:latest
      env:
        - name: HTTP_PROXY
          value: "http://localhost:8080"
        - name: HTTPS_PROXY
          value: "http://localhost:8080"
```

---

## Roadmap

- **v0.1.0** — HTTP forward proxy, allowlist policy from ConfigMap,
  audit chain JSONL, Helm chart, single-pod sidecar deployment
- **v0.2.0** — gRPC policy sync from the agent's `Tool` registry
  (no ConfigMap duplication)
- **v0.3.0** — mutating admission webhook for automatic sidecar
  injection across the cluster
- **v0.4.0** — approval gates: irreversible actions pause on the
  sidecar and require human confirmation before the request is
  forwarded
- **v1.0** — hosted control plane integration; multi-tenant policy
  management

The roadmap-discipline rules in
[`CLAUDE.md`](https://github.com/aegrail/aegrail/blob/main/CLAUDE.md)
of the aegrail repo govern when structural and feature work proceeds.

---

## Contributing

Contributions welcome via PR. See [CONTRIBUTING.md](CONTRIBUTING.md)
for the workflow. The contribution model mirrors the aegrail Python
repo: small reviewable PRs against `main`, tests required, Apache
2.0 license.

Security issues: please report privately per [SECURITY.md](SECURITY.md).
Do not open public issues for vulnerabilities.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for full terms.

Copyright © 2026 [Arpit Nigam](https://github.com/aegrail).
