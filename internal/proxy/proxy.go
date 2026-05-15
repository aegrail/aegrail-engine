// Package proxy is the HTTP + HTTPS forward proxy at the heart of
// the aegrail engine. It accepts an agent container's outbound
// HTTP traffic (typically via HTTP_PROXY / HTTPS_PROXY env vars),
// consults the configured Policy to decide allow/deny, and either
// forwards to the upstream or returns a 403 with an audit event
// emitted in either case.
//
// IMPLEMENTATION OUTLINE FOR v0.1.0
//
// Two code paths, dispatched by HTTP method:
//
//   Plain HTTP (GET / POST / PUT / etc.):
//     - parse the request, extract Host (URL or Host header)
//     - Policy.Allows(host)
//       - true  -> forward via httputil.ReverseProxy
//                  emit TypeEgressAllowed
//       - false -> respond 403 with plaintext body
//                  emit TypeEgressDenied
//
//   HTTPS (CONNECT method):
//     - parse the CONNECT target (host:port)
//     - Policy.Allows(host)
//       - true  -> respond 200 Connection Established
//                  hijack the connection
//                  dial upstream
//                  bidirectional io.Copy
//                  emit TypeEgressAllowed
//       - false -> respond 403
//                  emit TypeEgressDenied
//
// Upstream errors (network failure, DNS failure) on the allowed
// path emit TypeEgressError and return 502 to the client.
//
// Placeholder for now — the full handler implementation lands as
// the v0.1.0 milestone work.

package proxy

import (
	"net/http"

	"github.com/arpitcoder/aegrail-engine/internal/audit"
	"github.com/arpitcoder/aegrail-engine/internal/policy"
)

// Proxy is the HTTP handler that enforces the egress allowlist and
// emits audit events for every decision.
type Proxy struct {
	Policy *policy.Policy
	Sink   audit.Sink

	// AgentIdentity is the value emitted in the AgentIdentity field
	// of every audit event the proxy produces. Defaults to
	// "egress-proxy/v1"; can be overridden via CLI flag.
	AgentIdentity string
}

// ServeHTTP is the entry point for every request the proxy handles.
// It dispatches to handleConnect (HTTPS) or handleHTTP (plain) based
// on the request method.
//
// PLACEHOLDER: responds 501 Not Implemented. The real implementation
// lands as part of the v0.1.0 milestone.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Aegrail-Status", "proxy-not-yet-implemented")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte("aegrail-engine proxy: not yet implemented (v0.1.0 milestone)\n"))
}
