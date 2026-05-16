// mitm.go: TLS-terminating CONNECT handler.
//
// When the operator enables MITM for specific hosts via
// AEGRAIL_ENGINE_MITM_HOSTS, the engine no longer tunnels those
// CONNECT requests opaquely. Instead it:
//
//   1. Verifies the destination host is on the egress allowlist.
//   2. Mints a leaf cert for the destination (signed by the
//      engine's CA via internal/mitm.Authority).
//   3. Hijacks the client connection, writes 200 Connection
//      Established, and performs a TLS handshake with the client
//      using the minted leaf cert.
//   4. Dials the real upstream over TLS.
//   5. Reads HTTP/1 requests off the client TLS conn, forwards
//      them to upstream over real TLS, reads each response,
//      passes it through llmparse for token extraction, and
//      writes the response back to the client.
//
// HTTPS clients in the agent container must trust the engine's
// CA, or the TLS handshake on step 3 fails. The webhook (v0.4.0+)
// distributes the CA and sets SSL_CERT_FILE / REQUESTS_CA_BUNDLE /
// NODE_EXTRA_CA_CERTS in agent pods.

package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/aegrail/aegrail-engine/internal/audit"
	"github.com/aegrail/aegrail-engine/internal/llmparse"
	"github.com/aegrail/aegrail-engine/internal/mitm"
)

// MITMConfig is the runtime configuration for TLS termination.
// nil means MITM is disabled; the proxy falls back to opaque
// tunneling for every CONNECT.
type MITMConfig struct {
	Authority *mitm.Authority
	// HostPatterns are fnmatch-style patterns (same semantics as
	// the egress allowlist). A CONNECT target whose host matches
	// any of these patterns is MITM'd; everything else tunnels.
	HostPatterns []string
	// UpstreamTLS overrides the TLS config the engine uses when
	// dialing the real upstream. Production: leave nil to use
	// system trust. Tests use this to trust httptest-generated
	// upstream certs.
	UpstreamTLS *tls.Config
}

// shouldMITM reports whether the given destination host falls
// under the MITM configuration. nil receiver / empty patterns =>
// false.
func (m *MITMConfig) shouldMITM(host string) bool {
	if m == nil || len(m.HostPatterns) == 0 {
		return false
	}
	for _, p := range m.HostPatterns {
		if ok, _ := path.Match(p, host); ok {
			return true
		}
	}
	return false
}

// handleMITM is invoked from handleConnect when shouldMITM(host) is
// true. It performs TLS termination + body inspection + re-encryption.
func (p *Proxy) handleMITM(w http.ResponseWriter, r *http.Request, target, host string) {
	mc := p.MITM
	leaf, err := mc.Authority.LeafFor(host)
	if err != nil {
		p.emit(audit.TypeEgressError, map[string]any{
			"host":   host,
			"target": target,
			"method": http.MethodConnect,
			"mitm":   true,
			"error":  "leaf cert: " + err.Error(),
		})
		http.Error(w, "aegrail-engine: mint leaf: "+err.Error(), http.StatusInternalServerError)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.emit(audit.TypeEgressError, map[string]any{
			"host":   host,
			"method": http.MethodConnect,
			"mitm":   true,
			"error":  "response writer does not support hijack",
		})
		http.Error(w, "aegrail-engine: server does not support tunneling", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.emit(audit.TypeEgressError, map[string]any{
			"host":   host,
			"method": http.MethodConnect,
			"mitm":   true,
			"error":  "hijack: " + err.Error(),
		})
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		p.emit(audit.TypeEgressError, map[string]any{
			"host":   host,
			"method": http.MethodConnect,
			"mitm":   true,
			"error":  "write 200: " + err.Error(),
		})
		return
	}

	// TLS-terminate on the client side.
	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	defer tlsClient.Close()
	if err := tlsClient.Handshake(); err != nil {
		p.emit(audit.TypeEgressError, map[string]any{
			"host":   host,
			"method": http.MethodConnect,
			"mitm":   true,
			"error":  "client TLS handshake: " + err.Error(),
		})
		return
	}

	// Loop: read HTTP requests off the TLS-terminated client conn,
	// forward each to upstream, parse the response, write back.
	clientReader := bufio.NewReader(tlsClient)
	for {
		_ = tlsClient.SetReadDeadline(time.Now().Add(p.forwardTimeout()))
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			// Connection closed by client or read timeout — normal.
			return
		}

		// Rewrite request URL so http.Client can forward it.
		req.URL.Scheme = "https"
		req.URL.Host = target
		req.Host = target
		req.RequestURI = "" // required for outbound use
		// Strip hop-by-hop headers
		req.Header.Del("Proxy-Connection")
		req.Header.Del("Proxy-Authorization")

		p.forwardMITMRequest(tlsClient, req, host, target)
	}
}

// forwardMITMRequest sends one decrypted HTTP request to the real
// upstream over TLS, parses the response for LLM tokens, writes the
// response back to the client, and emits the audit event.
func (p *Proxy) forwardMITMRequest(clientConn net.Conn, req *http.Request, host, target string) {
	start := time.Now()
	method := req.Method
	urlPath := req.URL.Path
	upstreamTLS := &tls.Config{MinVersion: tls.VersionTLS12}
	if p.MITM != nil && p.MITM.UpstreamTLS != nil {
		upstreamTLS = p.MITM.UpstreamTLS.Clone()
	}
	upstreamClient := &http.Client{
		Timeout: p.forwardTimeout(),
		Transport: &http.Transport{
			// Production: system trust verifies the upstream's real
			// certificate (we trust the real providers). Tests inject
			// UpstreamTLS to trust an httptest-generated cert.
			TLSClientConfig: upstreamTLS,
		},
	}

	resp, err := upstreamClient.Do(req)
	if err != nil {
		p.emit(audit.TypeEgressError, map[string]any{
			"host":        host,
			"target":      target,
			"method":      method,
			"path":        urlPath,
			"mitm":        true,
			"error":       err.Error(),
			"duration_ms": time.Since(start).Milliseconds(),
		})
		_ = writeMITMError(clientConn, http.StatusBadGateway,
			"aegrail-engine: upstream error: "+err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		p.emit(audit.TypeEgressError, map[string]any{
			"host":        host,
			"target":      target,
			"method":      method,
			"path":        urlPath,
			"mitm":        true,
			"error":       "read upstream body: " + err.Error(),
			"duration_ms": time.Since(start).Milliseconds(),
		})
		return
	}

	// Parse for LLM token usage if URL is recognised.
	usage := llmparse.ParseResponse(req.URL, body, resp.Header)

	// Restore body for the client write.
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	// Write response back to client through the TLS-terminated conn.
	if err := resp.Write(clientConn); err != nil {
		p.emit(audit.TypeEgressError, map[string]any{
			"host":   host,
			"target": target,
			"method": method,
			"mitm":   true,
			"error":  "write response to client: " + err.Error(),
		})
		return
	}

	payload := map[string]any{
		"host":        host,
		"target":      target,
		"method":      method,
		"path":        urlPath,
		"status_code": resp.StatusCode,
		"duration_ms": time.Since(start).Milliseconds(),
		"mitm":        true,
	}
	if usage.Recognised {
		payload["llm_model"] = usage.Model
		payload["tokens_in"] = usage.TokensIn
		payload["tokens_out"] = usage.TokensOut
		if p.TokenBudget != nil {
			_, total := p.TokenBudget.Add(int64(usage.TokensIn + usage.TokensOut))
			payload["tokens_total"] = total
		}
	}
	p.emit(audit.TypeEgressAllowed, payload)
}

// writeMITMError writes a minimal HTTP/1.1 error response to the
// TLS-terminated client connection. Used when the upstream call
// fails after TLS termination has already completed.
func writeMITMError(c net.Conn, statusCode int, body string) error {
	statusText := http.StatusText(statusCode)
	_, err := fmt.Fprintf(c,
		"HTTP/1.1 %d %s\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"X-Aegrail-Decision: error\r\n"+
			"\r\n"+
			"%s",
		statusCode, statusText, len(body), body,
	)
	return err
}
