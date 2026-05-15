// http.go: plain HTTP forwarding path.
//
// For non-CONNECT requests, the agent has set HTTP_PROXY=engine and
// is talking to us as a forward proxy. We extract the destination
// from req.URL.Host, consult the policy, and either forward via
// httputil.ReverseProxy or refuse with a 403.
//
// HTTPS over plain forwarding (i.e. req.URL.Scheme == "https" on a
// non-CONNECT request) does not occur in modern Go HTTP clients —
// they always issue CONNECT for https URLs through an HTTP_PROXY.
// We still handle it as a graceful fallback.

package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := requestHost(r)
	if host == "" {
		p.emit("egress_error", map[string]any{
			"method": r.Method,
			"error":  "no destination host in request",
		})
		http.Error(w, "aegrail-engine: missing destination host", http.StatusBadRequest)
		return
	}

	method := r.Method
	path := r.URL.Path

	if !p.Policy.Allows(host) {
		p.emit("egress_denied", map[string]any{
			"host":   host,
			"method": method,
			"path":   path,
			"reason": "not_in_allowlist",
		})
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Aegrail-Decision", "denied")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(deniedBodyForHost(host)))
		return
	}

	// Forward via httputil.ReverseProxy. The proxy's Director
	// rewrites the request URL to the absolute upstream form;
	// ReverseProxy then handles connection reuse and streaming.
	target := upstreamURLForRequest(r)
	if target == nil {
		p.emit("egress_error", map[string]any{
			"host":   host,
			"method": method,
			"path":   path,
			"error":  "could not construct upstream URL",
		})
		http.Error(w, "aegrail-engine: bad upstream URL", http.StatusBadRequest)
		return
	}

	start := time.Now()
	statusCode := 0
	var forwardErr error

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			// Strip hop-by-hop and proxy-specific headers
			req.Header.Del("Proxy-Connection")
			req.Header.Del("Proxy-Authorization")
		},
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, err error) {
			forwardErr = err
			rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			rw.Header().Set("X-Aegrail-Decision", "error")
			rw.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprintf(rw, "aegrail-engine: upstream error: %v\n", err)
		},
		ModifyResponse: func(resp *http.Response) error {
			statusCode = resp.StatusCode
			return nil
		},
	}

	ctx, cancel := context.WithTimeout(r.Context(), p.forwardTimeout())
	defer cancel()
	rp.ServeHTTP(w, r.WithContext(ctx))

	duration := time.Since(start)
	if forwardErr != nil {
		p.emit("egress_error", map[string]any{
			"host":        host,
			"method":      method,
			"path":        path,
			"error":       forwardErr.Error(),
			"duration_ms": duration.Milliseconds(),
		})
		return
	}
	p.emit("egress_allowed", map[string]any{
		"host":        host,
		"method":      method,
		"path":        path,
		"status_code": statusCode,
		"duration_ms": duration.Milliseconds(),
	})
}

// requestHost extracts the destination host for a non-CONNECT
// request. Forward-proxy clients populate req.URL.Host (absolute-form
// URI); some clients only populate req.Host. We try both.
func requestHost(r *http.Request) string {
	if r.URL != nil && r.URL.Host != "" {
		return hostWithoutPort(r.URL.Host)
	}
	if r.Host != "" {
		return hostWithoutPort(r.Host)
	}
	return ""
}

// upstreamURLForRequest builds the absolute URL to forward to,
// based on the incoming proxy request.
func upstreamURLForRequest(r *http.Request) *url.URL {
	if r.URL == nil {
		return nil
	}
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if host == "" {
		return nil
	}
	return &url.URL{
		Scheme: scheme,
		Host:   host,
	}
}

// hostWithoutPort returns "host" from "host:port"; passes through
// otherwise. Handles bracketed IPv6 ("[::1]:8080" -> "[::1]").
func hostWithoutPort(s string) string {
	if i := strings.LastIndex(s, ":"); i > 0 {
		// Avoid stripping the port-like segment when s is an IPv6
		// address without brackets — Go's URL parser usually
		// normalizes those, but be defensive.
		if strings.HasPrefix(s, "[") {
			if end := strings.LastIndex(s, "]"); end != -1 {
				return s[:end+1]
			}
		}
		return s[:i]
	}
	return s
}
