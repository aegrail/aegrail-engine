# Security policy

## Reporting a vulnerability

If you believe you've found a security vulnerability in `aegrail-engine`,
**please do not open a public issue.** Instead, report it privately
via GitHub's vulnerability reporting:

https://github.com/aegrail/aegrail-engine/security/advisories/new

We aim to acknowledge reports within 72 hours and resolve verified
issues within 14 days for critical severities, longer for lower
severities.

## What's in scope

- Bypasses of the egress allowlist (requests reaching destinations
  not in the allowlist)
- Tamper attacks on the audit chain that aren't detected by
  `verify_chain()`
- Information leakage in audit logs (PII, credentials, tokens)
- Container escape or privilege escalation from the engine sidecar
- Denial of service against the proxy that crashes or hangs the
  agent pod

## What's out of scope

- Issues in the agent container itself (those belong to the agent's
  owner)
- Issues in the audit log JSONL format (report those in the
  [`aegrail`](https://github.com/aegrail/aegrail) repo)
- Issues in dependencies (report upstream); we'll bump our
  dependency version once a fix is released
- Configuration errors (open allowlist by mistake — that's an
  operator issue, not a vulnerability)
- Pre-v0.1.0 releases (the project is pre-release; no security
  guarantees yet)

## Disclosure

We coordinate disclosure with the reporter. Once a fix is released,
we publish a GitHub Security Advisory describing the issue, the fix,
and the affected versions. Credit the reporter unless they request
otherwise.
