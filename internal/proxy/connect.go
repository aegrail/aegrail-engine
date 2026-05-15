// connect.go: HTTPS CONNECT tunneling.
//
// Modern HTTP clients (Go's net/http, Python's requests, curl, etc.)
// issue a CONNECT request to the forward proxy for HTTPS URLs. The
// proxy is supposed to:
//   1. Verify policy on the destination host (TLS is end-to-end, we
//      can't inspect anything inside the tunnel).
//   2. Reply "200 Connection Established" with no body.
//   3. Hijack the underlying TCP connection from the HTTP server.
//   4. Dial the upstream "host:port".
//   5. io.Copy bytes bidirectionally until either side closes.
//
// Audit event semantics:
//   - egress_denied at decision time, no tunnel established.
//   - egress_error if dial/hijack fails after decision.
//   - egress_allowed on tunnel close (or shutdown), with byte counts
//     and duration in the payload.

package proxy

import (
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Host
	if target == "" {
		target = r.Host
	}
	host := hostWithoutPort(target)
	if host == "" {
		p.emit("egress_error", map[string]any{
			"method": http.MethodConnect,
			"error":  "no CONNECT target",
		})
		http.Error(w, "aegrail-engine: missing CONNECT target", http.StatusBadRequest)
		return
	}

	if !p.Policy.Allows(host) {
		p.emit("egress_denied", map[string]any{
			"host":   host,
			"target": target,
			"method": http.MethodConnect,
			"reason": "not_in_allowlist",
		})
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Aegrail-Decision", "denied")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(deniedBodyForHost(host)))
		return
	}

	// Dial upstream BEFORE acknowledging the tunnel so we can fail
	// cleanly with 502 if the destination is unreachable. The
	// alternative (200 then dial) leaves the client connected to
	// a tunnel that immediately closes, which is harder to debug.
	dialer := &net.Dialer{Timeout: p.dialTimeout()}
	upstream, err := dialer.Dial("tcp", target)
	if err != nil {
		p.emit("egress_error", map[string]any{
			"host":   host,
			"target": target,
			"method": http.MethodConnect,
			"error":  err.Error(),
		})
		w.Header().Set("X-Aegrail-Decision", "error")
		http.Error(w, "aegrail-engine: dial upstream: "+err.Error(), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		p.emit("egress_error", map[string]any{
			"host":   host,
			"target": target,
			"method": http.MethodConnect,
			"error":  "response writer does not support hijack",
		})
		http.Error(w, "aegrail-engine: server does not support tunneling", http.StatusInternalServerError)
		return
	}

	// Hijack BEFORE writing the response. Writing through the
	// ResponseWriter and then hijacking can interleave the server's
	// auto-headers with the bytes we then write, which manifests
	// to the client as "CONNECT tunnel failed, response 301" or
	// similar parser confusion. The RFC-7231 pattern is: take
	// over the connection, then write "HTTP/1.1 200 Connection
	// Established\r\n\r\n" directly to the raw conn.
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		p.emit("egress_error", map[string]any{
			"host":   host,
			"target": target,
			"method": http.MethodConnect,
			"error":  "hijack: " + err.Error(),
		})
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = clientConn.Close()
		_ = upstream.Close()
		p.emit("egress_error", map[string]any{
			"host":   host,
			"target": target,
			"method": http.MethodConnect,
			"error":  "write 200: " + err.Error(),
		})
		return
	}

	start := time.Now()
	var bytesToUpstream, bytesFromUpstream atomic.Int64
	go relay(clientConn, upstream, &bytesToUpstream)
	relay(upstream, clientConn, &bytesFromUpstream)
	// relay returns when one side EOFs / errors. Both connections
	// are closed by the relay deferred Close(); waiting on the
	// remaining direction here would hang in the common case.
	duration := time.Since(start)

	p.emit("egress_allowed", map[string]any{
		"host":                host,
		"target":              target,
		"method":              http.MethodConnect,
		"bytes_to_upstream":   bytesToUpstream.Load(),
		"bytes_from_upstream": bytesFromUpstream.Load(),
		"duration_ms":         duration.Milliseconds(),
	})
}

// relay copies src -> dst, recording bytes via the atomic counter,
// closing both connections on exit. Idempotent close protected by
// a sync.Once on each direction (callers pass distinct counters
// for each direction so the relay calls don't race).
//
// The pattern intentionally closes BOTH ends from each direction so
// that an EOF on one side causes the partner read to unblock and
// return promptly.
func relay(dst io.WriteCloser, src io.ReadCloser, counter *atomic.Int64) {
	defer once(dst).close()
	defer once(src).close()
	n, err := io.Copy(dst, src)
	counter.Store(n)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		// Tunnel-close errors are normal; log only at debug level
		// if we had one. For now, silently swallow.
		_ = err
	}
}

// onceCloser wraps a Closer so Close is called at most once.
type onceCloser struct {
	c    io.Closer
	once sync.Once
}

func once(c io.Closer) *onceCloser { return &onceCloser{c: c} }

func (o *onceCloser) close() {
	o.once.Do(func() { _ = o.c.Close() })
}
