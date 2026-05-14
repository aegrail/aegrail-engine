---
name: Bug report
about: Something doesn't work as documented
labels: bug
---

## What happened

(A concise description of the actual behavior.)

## What you expected

(What the documentation / common sense suggests should happen.)

## Reproduction

Smallest possible reproduction:

```
# commands / config / manifests
```

## Environment

- aegrail-engine version: (e.g. v0.1.0 or git SHA)
- Kubernetes version: (e.g. 1.30.2)
- Helm version (if installed via chart): (e.g. 3.16.0)
- Container runtime: (e.g. containerd 1.7)
- OS / arch: (e.g. linux/amd64)

## Logs

Relevant log output from the sidecar (`kubectl logs <pod> -c aegrail-engine`)
and / or audit log JSONL excerpt:

```
(paste)
```

## Anything else

(Other context, hypotheses, related issues.)
