// Package proxy is the HTTP + HTTPS forward proxy at the heart of
// the aegrail engine. It accepts an agent container's outbound HTTP
// traffic (typically via HTTP_PROXY / HTTPS_PROXY env vars on the
// agent), consults the configured Policy to allow or deny, and
// either forwards to the upstream or returns 403, emitting one
// audit event for every decision.
//
// Two code paths, dispatched on HTTP method:
//
//	Plain HTTP (any method except CONNECT):
//	  - parse the request, extract the destination host
//	  - Policy.Allows(host)
//	      true  -> forward via httputil.ReverseProxy, emit egress_allowed
//	      false -> 403 plain text, emit egress_denied
//	  - upstream error -> 502, emit egress_error
//
//	HTTPS (CONNECT method):
//	  - parse the CONNECT target (host:port)
//	  - Policy.Allows(host without port)
//	      true  -> 200 Connection Established, hijack, dial upstream,
//	               bidirectional io.Copy, emit egress_allowed at close
//	      false -> 403, emit egress_denied
//	  - upstream dial / hijack failure -> 502, emit egress_error

package proxy

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/arpitcoder/aegrail-engine/internal/audit"
	"github.com/arpitcoder/aegrail-engine/internal/limits"
	"github.com/arpitcoder/aegrail-engine/internal/policy"
)

// Proxy is the HTTP handler that enforces the egress allowlist and
// emits audit events for every decision. It is safe for concurrent
// use; the embedded Sink and Policy own their own synchronisation.
type Proxy struct {
	Policy  *policy.Policy
	Sink    audit.Sink
	Session *Session

	// Counter caps total requests served over the engine's lifetime.
	// Nil = unlimited. When the cap is exceeded, the call is denied
	// with reason="request_count_exceeded" and HTTP 429.
	Counter *limits.RequestCounter

	// Limiter caps requests per unit time (token bucket). Nil =
	// unlimited. When no token is available, the call is denied
	// with reason="rate_limited" and HTTP 429.
	Limiter *limits.RateLimiter

	// TokenBudget caps cumulative LLM tokens (input + output) over
	// the engine's lifetime, parsed from known LLM response shapes
	// (v0.3.0+). Nil = unlimited. When the budget is over before a
	// request, the call is denied with reason="token_budget_exceeded"
	// and HTTP 429. HTTPS CONNECT tunnels are opaque to the parser
	// so token enforcement only fires on plain-HTTP forwards — unless
	// MITM is enabled for the destination host.
	TokenBudget *limits.TokenBudget

	// MITM, when set, enables TLS termination on CONNECT requests
	// whose target host matches one of the configured patterns
	// (v0.4.0+). Without trust distribution to the agent
	// container, MITM'd connections will fail TLS verification on
	// the client side — this is opt-in and the operator is
	// responsible for ensuring the CA is trusted.
	MITM *MITMConfig

	// DialTimeout caps how long the proxy waits when establishing a
	// CONNECT tunnel to upstream. Zero defaults to 10s.
	DialTimeout time.Duration

	// ForwardTimeout caps the total time for a plain-HTTP forward.
	// Zero defaults to 30s.
	ForwardTimeout time.Duration
}

// ServeHTTP dispatches to the HTTPS CONNECT or plain HTTP path,
// after applying the network-layer request budgets (if any) that
// don't require body inspection.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.Policy == nil || p.Sink == nil || p.Session == nil {
		http.Error(w, "aegrail-engine: proxy not configured", http.StatusInternalServerError)
		return
	}

	// Pre-flight: request-count budget. Fires before any per-host
	// policy decision so a runaway agent burns budget once, not once
	// per allowlisted destination.
	if p.Counter != nil {
		if ok, total := p.Counter.Allow(); !ok {
			p.denyRateOrCount(w, r, "request_count_exceeded", map[string]any{
				"total":  total,
				"max":    p.Counter.Max(),
				"host":   hostFromRequest(r),
				"method": r.Method,
			})
			return
		}
	}

	// Pre-flight: token-bucket rate limiter.
	if p.Limiter != nil && !p.Limiter.Allow() {
		p.denyRateOrCount(w, r, "rate_limited", map[string]any{
			"rate_per_sec": p.Limiter.Rate(),
			"burst":        p.Limiter.Burst(),
			"host":         hostFromRequest(r),
			"method":       r.Method,
		})
		return
	}

	// Pre-flight: LLM token budget. Refuses traffic once the
	// running token total has crossed the cap — the next request
	// can't restart accounting.
	if p.TokenBudget != nil && p.TokenBudget.OverBudget() {
		p.denyRateOrCount(w, r, "token_budget_exceeded", map[string]any{
			"tokens_used": p.TokenBudget.Used(),
			"tokens_max":  p.TokenBudget.Max(),
			"host":        hostFromRequest(r),
			"method":      r.Method,
		})
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// denyRateOrCount writes a 429 to the client and emits an
// egress_denied audit event with the given reason and payload.
func (p *Proxy) denyRateOrCount(
	w http.ResponseWriter,
	_ *http.Request,
	reason string,
	payload map[string]any,
) {
	payload["reason"] = reason
	p.emit(audit.TypeEgressDenied, payload)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Aegrail-Decision", "denied")
	w.Header().Set("X-Aegrail-Reason", reason)
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte("aegrail-engine: " + reason + "\n"))
}

// hostFromRequest extracts the destination host for use in audit
// payloads — works for both plain-HTTP proxy requests (host in URL)
// and CONNECT (host in r.Host).
func hostFromRequest(r *http.Request) string {
	if r.URL != nil && r.URL.Host != "" {
		return hostWithoutPort(r.URL.Host)
	}
	if r.Host != "" {
		return hostWithoutPort(r.Host)
	}
	return ""
}

// emit writes one audit event through the sink, logging — never
// surfacing — any sink failure. The proxy must not propagate sink
// errors to the agent; the load-bearing invariant is "the audit
// pipeline never breaks the wrapped workload."
func (p *Proxy) emit(eventType string, payload map[string]any) {
	event := audit.Event{
		Ts:            time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		SessionID:     p.Session.SessionID,
		AgentIdentity: p.Session.AgentIdentity,
		InvokingUser:  nil,
		Principal:     p.Session.Principal(),
		EventType:     eventType,
		Payload:       payload,
		Budget:        map[string]any{},
	}
	if err := p.Sink.Emit(event); err != nil {
		log.Printf("aegrail-engine: audit sink emit failed (event=%s): %v", eventType, err)
	}
}

// dialTimeout returns the configured CONNECT-dial timeout or its
// default.
func (p *Proxy) dialTimeout() time.Duration {
	if p.DialTimeout > 0 {
		return p.DialTimeout
	}
	return 10 * time.Second
}

// forwardTimeout returns the configured plain-HTTP timeout or its
// default.
func (p *Proxy) forwardTimeout() time.Duration {
	if p.ForwardTimeout > 0 {
		return p.ForwardTimeout
	}
	return 30 * time.Second
}

// emitEngineStart emits a single engine_start event so the chain
// has a stable genesis (or continuation) record on process boot.
func (p *Proxy) EmitEngineStart(version string) {
	p.emit(audit.TypeEngineStart, map[string]any{
		"version":  version,
		"patterns": p.Policy.Patterns(),
	})
}

// EmitEngineShutdown emits one event on clean shutdown so the chain
// has a recognisable terminator.
func (p *Proxy) EmitEngineShutdown(reason string) {
	p.emit(audit.TypeEngineShutdown, map[string]any{"reason": reason})
}

// deniedBodyForHost is the plaintext we send to denied callers.
// Format is intentionally machine-parseable so client code can
// react to "aegrail denied" specifically.
func deniedBodyForHost(host string) string {
	return fmt.Sprintf("aegrail-engine: egress to %q is not in the allowlist\n", host)
}
