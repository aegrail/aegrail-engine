# Release discipline

This file is the engine repo's equivalent of the release rule in
[`CLAUDE.md`](https://github.com/aegrail/aegrail/blob/main/CLAUDE.md)
on the Python repo. It documents the gate every tagged release has to
pass *before* the tag is pushed.

## The hard rule

**No version is tagged on this repo until the built container image
has been deployed to a real (or `kind` / `minikube`) Kubernetes
cluster, alongside a sample agent pod, and the egress proxy has
been observed:**

1. Allowing a request to a host on the allowlist
2. Denying a request to a host not on the allowlist
3. Writing both events to the audit log
4. Producing an audit chain that `verify_chain()` (from the aegrail
   Python library) validates as intact

If the cluster test fails or wasn't run, no tag, no Helm release, no
container image push.

## Why

The whole point of the engine is to enforce policy in K8s. A release
that only passes Go unit tests but hasn't been observed running in
K8s is a release that hasn't been tested for its actual job. CI
unit tests are necessary but not sufficient.

Same principle as the Python repo, restated for the deployment
artifact: *for a security-adjacent product, the bar is "would a
customer running this in K8s hit anything we missed?" — which only
an actual K8s deployment can answer.*

## Standard release sequence

1. Code + tests + lint all green in CI
2. `git log` clean, version bumped in `cmd/aegrail-engine/main.go`
   (`Version` var) and in `deploy/helm/Chart.yaml` (`version` and
   `appVersion`)
3. `CHANGELOG.md` entry promoted from `[Unreleased]` to the new
   `[X.Y.Z]` block with date
4. Container image built locally:
   `docker build -t aegrail-engine:vX.Y.Z -f deploy/docker/Dockerfile .`
5. **Kind cluster smoke test** — see next section
6. `git commit -am "vX.Y.Z: ..."`
7. `git tag vX.Y.Z`
8. `git push origin main && git push origin vX.Y.Z`
9. Container image pushed to the registry:
   `docker push ghcr.io/aegrail/aegrail-engine:vX.Y.Z`
10. Helm chart packaged and uploaded to the chart repository
11. `gh release create vX.Y.Z --notes-from-tag`

## Kind cluster smoke test (the gate)

```bash
# Create a fresh cluster
kind create cluster --name aegrail-test

# Load the local image into the cluster
kind load docker-image aegrail-engine:vX.Y.Z --name aegrail-test

# Install the Helm chart against the local image
helm install aegrail-engine ./deploy/helm \
  --set image.tag=vX.Y.Z \
  --set image.pullPolicy=Never \
  --set policy.allowlist[0]=httpbin.org

# Apply a sample agent pod that uses the sidecar
kubectl apply -f docs/examples/sample-agent-pod.yaml

# Wait for the pod to be Ready
kubectl wait --for=condition=Ready pod/sample-agent --timeout=60s

# Verify the egress policy in both directions:
kubectl exec sample-agent -c agent -- curl -s -o /dev/null -w "%{http_code}\n" http://httpbin.org/get
# Expected: 200

kubectl exec sample-agent -c agent -- curl -s -o /dev/null -w "%{http_code}\n" http://api.example.com/forbidden
# Expected: 403 (or whatever the engine returns for denied egress)

# Pull the audit log from the sidecar
kubectl exec sample-agent -c aegrail-engine -- cat /var/log/aegrail/audit.jsonl > /tmp/audit.jsonl

# Verify the audit chain end-to-end using the aegrail Python library
uv run --no-project --isolated --python 3.12 --with aegrail python -c "
import json
from aegrail import AuditEvent
from aegrail.audit import verify_chain
events = [AuditEvent(**json.loads(line)) for line in open('/tmp/audit.jsonl')]
valid, bad = verify_chain(events)
assert valid, f'chain broken at event {bad}'
print(f'PASS — {len(events)} events, chain valid')
"

# Cleanup
kind delete cluster --name aegrail-test
```

If every step passes, the release gate is met. If any step fails,
the tag does not get pushed.

## When this rule was introduced

2026-05-14, alongside the initial repo skeleton. The
[`aegrail`](https://github.com/aegrail/aegrail) Python repo already
had an equivalent gate (real-LLM battle-test before PyPI upload) that
caught issues before users saw them. This is the K8s-side equivalent.
