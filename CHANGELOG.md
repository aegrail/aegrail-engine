# Changelog

All notable changes to `aegrail-engine` are documented in this file.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned for v0.1.0

- HTTP forward proxy enforcing a configurable allowlist of egress
  destinations
- Audit log JSONL output with SHA-256 chain (format compatible with
  the `aegrail` Python library at v0.2.3+)
- Helm chart for K8s sidecar deployment (deny-by-default, allowlist
  configured via ConfigMap or Helm values)
- Single-pod sidecar deployment pattern (agent + engine in one pod,
  agent uses `HTTP_PROXY=http://localhost:8080`)
- Docker image (multi-arch: `linux/amd64`, `linux/arm64`)
- Documentation: deployment guide, allowlist configuration,
  troubleshooting

This is the v0.3.0 milestone of the broader aegrail project. See
[ARCHITECTURE.md](https://github.com/arpitcoder/aegrail/blob/main/ARCHITECTURE.md)
in the aegrail repo for context on how this fits with the Python
library.
