# Deployment guide

> **Status:** placeholder for the v0.1.0 milestone. The full guide
> lands when the proxy implementation ships. The shape below is the
> intended structure so contributors and early-adopting operators can
> see where deployment documentation will live.

## Quick install (planned)

```bash
helm repo add aegrail https://arpitcoder.github.io/aegrail-engine
helm repo update
helm install aegrail-engine aegrail/aegrail-engine \
  --set policy.allowlist[0]=api.openai.com \
  --set policy.allowlist[1]=api.anthropic.com
```

## Manual sidecar injection

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-agent
spec:
  containers:
    - name: agent
      image: my-agent:latest
      env:
        - name: HTTP_PROXY
          value: "http://localhost:8080"
        - name: HTTPS_PROXY
          value: "http://localhost:8080"
        - name: NO_PROXY
          value: "localhost,127.0.0.1"
    - name: aegrail-engine
      image: ghcr.io/arpitcoder/aegrail-engine:0.1.0
      args:
        - --listen=:8080
        - --allowlist-configmap=aegrail-allowlist
      ports:
        - name: proxy
          containerPort: 8080
```

## Allowlist configuration

The allowlist lives in a ConfigMap, mounted by the sidecar:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aegrail-allowlist
data:
  allowlist.yaml: |
    allow:
      - api.openai.com
      - api.anthropic.com
      - generativelanguage.googleapis.com
```

## Audit log

By default the sidecar writes the audit JSONL to stdout, where the
cluster's log shipper (Fluent Bit, Vector, Promtail, etc.) picks it
up. To write to a file instead, set `audit.mode=file` in the Helm
values; the sidecar will write to `/var/log/aegrail/audit.jsonl`
inside an emptyDir volume that operators can mount.

The audit format is identical to the
[`aegrail`](https://github.com/arpitcoder/aegrail) Python library's
audit log. Events from the engine and the library can be merged into
a single chain when collected by the same log pipeline.

## Verifying the audit chain

(See [`COMPLIANCE.md`](https://github.com/arpitcoder/aegrail/blob/main/COMPLIANCE.md)
in the aegrail repo. The same `verify_chain()` function works on
engine-produced logs.)

## Troubleshooting

(Lands with v0.1.0.)
