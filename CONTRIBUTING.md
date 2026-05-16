# Contributing to aegrail-engine

Thanks for considering a contribution. This repo is the Kubernetes
enforcement engine that pairs with the [`aegrail`](https://github.com/aegrail/aegrail)
Python library; contributions to either repo are welcomed under the
same model.

## How to contribute

1. **Open an issue first** for anything beyond a typo fix or one-line
   change. This is to make sure we agree the work fits the project's
   scope (see roadmap-discipline rules in
   [`CLAUDE.md`](https://github.com/aegrail/aegrail/blob/main/CLAUDE.md)
   of the aegrail repo) before you sink time into it.
2. **Fork + branch**: branch from `main`, work in your fork.
3. **Small, reviewable PRs.** One change per PR; explain the *why*
   in the PR body, not just the *what*.
4. **Tests required.** New code paths must have Go tests. Use the
   table-driven test pattern where it fits. Run `go test ./...`
   locally before pushing.
5. **Pass CI.** Lint (`golangci-lint run`), test (`go test ./...`),
   build (`go build ./cmd/aegrail-engine`) must all be green.
6. **No new runtime dependencies** without explicit discussion in
   the issue. The engine aims for a minimal dependency tree to keep
   the binary small and the supply-chain surface narrow.

## Scope

This repo holds the **Kubernetes deployment artifact** for
aegrail: the Go sidecar, Helm chart, and related K8s configuration.
The Python library lives in [`aegrail/aegrail`](https://github.com/aegrail/aegrail);
cross-cutting changes (e.g. new event types) need a PR in both repos.

What's in scope here:
- Go code for the engine binary (HTTP proxy, allowlist, audit chain)
- Helm chart and K8s manifests
- Engine-specific documentation
- Engine CI

What's out of scope here (belongs in the `aegrail` repo):
- Python SDK code
- The audit log JSONL format itself (defined by the Python library,
  consumed here)
- General architecture / compliance documentation

## Development setup

```bash
# Clone
git clone https://github.com/aegrail/aegrail-engine
cd aegrail-engine

# Build
go build ./cmd/aegrail-engine

# Test
go test ./...

# Lint
golangci-lint run

# Local run (when implementation lands)
./aegrail-engine --listen :8080 --allowlist api.openai.com,api.anthropic.com
```

## Release discipline (mirrors the aegrail Python repo)

When a release is cut:

1. Tests, lint, build all pass in CI
2. The built container image is tested in a real (or kind/minikube)
   K8s cluster with a sample agent pod
3. `git tag vX.Y.Z` on `main`
4. `git push origin main && git push origin vX.Y.Z`
5. GitHub release created with notes
6. Helm chart published to the GitHub Pages repo
7. Container image published to the registry (TBD which registry)

PyPI doesn't apply here — the artifact is a container image plus a
Helm chart. The discipline is the same: **the deployment must have
been exercised end-to-end against a real workload before the tag is
pushed.**

## License

By contributing, you agree your contributions are licensed under
Apache License 2.0 (the project's license).

## Code of conduct

Be respectful. Disagree with ideas, not people. Assume good faith.
This is a small project; we're all building it together.
