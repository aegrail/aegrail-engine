package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aegrail/aegrail-engine/internal/audit"
	"github.com/aegrail/aegrail-engine/internal/limits"
	"github.com/aegrail/aegrail-engine/internal/policy"
)

func limitsCounter(max int64) *limits.RequestCounter {
	return limits.NewRequestCounter(max)
}

func limitsRate(perSec, burst float64) *limits.RateLimiter {
	return limits.NewRateLimiter(perSec, burst)
}

// memorySink is an audit.Sink that captures emitted events in
// memory for assertions. It still does the prev_hash / event_hash
// chaining work so chain-related tests are exercising the real path.
type memorySink struct {
	mu       sync.Mutex
	events   []audit.Event
	lastHash *string
}

func newMemorySink() *memorySink { return &memorySink{} }

func (s *memorySink) Emit(event audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	event.PrevHash = s.lastHash
	h, err := audit.ComputeEventHash(event, s.lastHash)
	if err != nil {
		return err
	}
	event.EventHash = h
	s.events = append(s.events, event)
	s.lastHash = &h
	return nil
}

func (s *memorySink) Close() error { return nil }

func (s *memorySink) eventsOfType(t string) []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]audit.Event, 0)
	for _, e := range s.events {
		if e.EventType == t {
			out = append(out, e)
		}
	}
	return out
}

func mustNewProxy(t *testing.T, patterns []string) (*Proxy, *memorySink) {
	t.Helper()
	pol, err := policy.New(patterns)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	sink := newMemorySink()
	session, err := NewSession("egress-proxy-test/v1")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return &Proxy{
		Policy:         pol,
		Sink:           sink,
		Session:        session,
		DialTimeout:    2 * time.Second,
		ForwardTimeout: 5 * time.Second,
	}, sink
}

// proxiedClient builds an http.Client that routes everything through
// the given proxy server. DisableKeepAlives is set so the underlying
// TCP connection closes when the response body is closed — that's
// what trips the proxy's CONNECT relay to EOF and emit its
// egress_allowed audit event.
func proxiedClient(proxyURL string) *http.Client {
	u, _ := url.Parse(proxyURL)
	return &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(u),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}
}

// -- Plain HTTP --------------------------------------------------

func TestProxy_HTTP_Allowed_Forwards(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-body"))
	}))
	defer upstream.Close()

	upstreamHost := mustHost(t, upstream.URL)
	proxyHandler, sink := mustNewProxy(t, []string{upstreamHost})
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	client := proxiedClient(proxyServer.URL)

	resp, err := client.Get(upstream.URL + "/hello")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if string(body) != "upstream-body" {
		t.Errorf("body: got %q, want %q", body, "upstream-body")
	}
	if got := resp.Header.Get("X-Upstream-Path"); got != "/hello" {
		t.Errorf("X-Upstream-Path: got %q, want /hello", got)
	}

	allowed := sink.eventsOfType(audit.TypeEgressAllowed)
	if len(allowed) != 1 {
		t.Fatalf("egress_allowed events: got %d, want 1", len(allowed))
	}
	if allowed[0].Payload["host"] != upstreamHost {
		t.Errorf("payload.host: got %v, want %s", allowed[0].Payload["host"], upstreamHost)
	}
	if allowed[0].Payload["method"] != "GET" {
		t.Errorf("payload.method: got %v, want GET", allowed[0].Payload["method"])
	}
	if allowed[0].Payload["status_code"].(int) != 200 {
		t.Errorf("payload.status_code: got %v, want 200", allowed[0].Payload["status_code"])
	}
}

func TestProxy_HTTP_Denied_Returns403_AndEmitsDenied(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("should-not-be-reached"))
	}))
	defer upstream.Close()

	proxyHandler, sink := mustNewProxy(t, []string{"some-other-host.example"})
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	client := proxiedClient(proxyServer.URL)

	resp, err := client.Get(upstream.URL + "/should-be-denied")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", resp.StatusCode)
	}
	if !strings.Contains(string(body), "not in the allowlist") {
		t.Errorf("body: got %q, want phrase 'not in the allowlist'", body)
	}
	if got := resp.Header.Get("X-Aegrail-Decision"); got != "denied" {
		t.Errorf("X-Aegrail-Decision: got %q, want 'denied'", got)
	}

	denied := sink.eventsOfType(audit.TypeEgressDenied)
	if len(denied) != 1 {
		t.Fatalf("egress_denied events: got %d, want 1", len(denied))
	}
	if denied[0].Payload["reason"] != "not_in_allowlist" {
		t.Errorf("payload.reason: got %v, want not_in_allowlist", denied[0].Payload["reason"])
	}
	if got := len(sink.eventsOfType(audit.TypeEgressAllowed)); got != 0 {
		t.Errorf("egress_allowed events: got %d, want 0", got)
	}
}

func TestProxy_HTTP_UpstreamError_Returns502_AndEmitsError(t *testing.T) {
	t.Parallel()

	proxyHandler, sink := mustNewProxy(t, []string{"127.0.0.1"})
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	client := proxiedClient(proxyServer.URL)

	// 127.0.0.1:1 is a closed port — connection refused
	resp, err := client.Get("http://127.0.0.1:1/")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status: got %d, want 502", resp.StatusCode)
	}

	errs := sink.eventsOfType(audit.TypeEgressError)
	if len(errs) != 1 {
		t.Fatalf("egress_error events: got %d, want 1", len(errs))
	}
	if errs[0].Payload["host"] != "127.0.0.1" {
		t.Errorf("payload.host: got %v, want 127.0.0.1", errs[0].Payload["host"])
	}
	errStr, _ := errs[0].Payload["error"].(string)
	if errStr == "" {
		t.Error("payload.error: got empty, want non-empty error message")
	}
}

// -- HTTPS CONNECT -----------------------------------------------

func TestProxy_CONNECT_Allowed_TunnelsHTTPS(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tunneled-body"))
	}))
	defer upstream.Close()

	upstreamHost := mustHost(t, upstream.URL)
	proxyHandler, sink := mustNewProxy(t, []string{upstreamHost})
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	client := proxiedClient(proxyServer.URL)

	resp, err := client.Get(upstream.URL + "/tunnel-me")
	if err != nil {
		t.Fatalf("client.Get https: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if string(body) != "tunneled-body" {
		t.Errorf("body: got %q, want %q", body, "tunneled-body")
	}

	// Give relay goroutines a beat to settle and emit egress_allowed
	deadline := time.Now().Add(2 * time.Second)
	var allowed []audit.Event
	for time.Now().Before(deadline) {
		allowed = sink.eventsOfType(audit.TypeEgressAllowed)
		if len(allowed) == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(allowed) != 1 {
		t.Fatalf("egress_allowed events: got %d, want 1", len(allowed))
	}
	if allowed[0].Payload["method"] != "CONNECT" {
		t.Errorf("payload.method: got %v, want CONNECT", allowed[0].Payload["method"])
	}
	if allowed[0].Payload["host"] != upstreamHost {
		t.Errorf("payload.host: got %v, want %s", allowed[0].Payload["host"], upstreamHost)
	}
}

func TestProxy_CONNECT_Denied_Returns403(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("should-not-be-reached"))
	}))
	defer upstream.Close()

	proxyHandler, sink := mustNewProxy(t, []string{"different-host.example"})
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	client := proxiedClient(proxyServer.URL)

	_, err := client.Get(upstream.URL + "/blocked")
	if err == nil {
		t.Fatal("client.Get: expected error from denied CONNECT, got nil")
	}

	denied := sink.eventsOfType(audit.TypeEgressDenied)
	if len(denied) != 1 {
		t.Fatalf("egress_denied events: got %d, want 1", len(denied))
	}
	if denied[0].Payload["method"] != "CONNECT" {
		t.Errorf("payload.method: got %v, want CONNECT", denied[0].Payload["method"])
	}
}

// -- Engine lifecycle events -----------------------------------

func TestProxy_EngineStartEmitsEvent(t *testing.T) {
	t.Parallel()
	proxyHandler, sink := mustNewProxy(t, []string{"api.example.com"})
	proxyHandler.EmitEngineStart("0.1.0-test")

	starts := sink.eventsOfType(audit.TypeEngineStart)
	if len(starts) != 1 {
		t.Fatalf("engine_start events: got %d, want 1", len(starts))
	}
	if starts[0].Payload["version"] != "0.1.0-test" {
		t.Errorf("payload.version: got %v, want 0.1.0-test", starts[0].Payload["version"])
	}
}

func TestProxy_EngineShutdownEmitsEvent(t *testing.T) {
	t.Parallel()
	proxyHandler, sink := mustNewProxy(t, []string{"api.example.com"})
	proxyHandler.EmitEngineShutdown("sigterm")

	shutdowns := sink.eventsOfType(audit.TypeEngineShutdown)
	if len(shutdowns) != 1 {
		t.Fatalf("engine_shutdown events: got %d, want 1", len(shutdowns))
	}
	if shutdowns[0].Payload["reason"] != "sigterm" {
		t.Errorf("payload.reason: got %v, want sigterm", shutdowns[0].Payload["reason"])
	}
}

// -- Network-layer budgets (v0.1.2) ----------------------------

func TestProxy_RequestCounter_ExhaustsAfterMax(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	upstreamHost := mustHost(t, upstream.URL)

	proxyHandler, sink := mustNewProxy(t, []string{upstreamHost})
	proxyHandler.Counter = limitsCounter(2)
	server := httptest.NewServer(proxyHandler)
	defer server.Close()
	client := proxiedClient(server.URL)

	// First two calls succeed
	for i := 1; i <= 2; i++ {
		resp, err := client.Get(upstream.URL + "/")
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("call %d: status %d, want 200", i, resp.StatusCode)
		}
	}

	// Third call denied with 429
	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("third call: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("third call: status %d, want 429", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Aegrail-Reason"); got != "request_count_exceeded" {
		t.Errorf("X-Aegrail-Reason: got %q, want request_count_exceeded", got)
	}

	denied := sink.eventsOfType(audit.TypeEgressDenied)
	if len(denied) != 1 {
		t.Fatalf("egress_denied events: got %d, want 1", len(denied))
	}
	if denied[0].Payload["reason"] != "request_count_exceeded" {
		t.Errorf("payload.reason: got %v, want request_count_exceeded", denied[0].Payload["reason"])
	}
}

func TestProxy_RateLimiter_DeniesWhenBucketEmpty(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamHost := mustHost(t, upstream.URL)

	proxyHandler, sink := mustNewProxy(t, []string{upstreamHost})
	// Burst of 1, refill rate so slow the second call is denied
	proxyHandler.Limiter = limitsRate(0.01, 1.0)
	server := httptest.NewServer(proxyHandler)
	defer server.Close()
	client := proxiedClient(server.URL)

	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("first call: status %d, want 200", resp.StatusCode)
	}

	resp, err = client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("second call: status %d, want 429 (rate)", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Aegrail-Reason"); got != "rate_limited" {
		t.Errorf("X-Aegrail-Reason: got %q, want rate_limited", got)
	}

	denied := sink.eventsOfType(audit.TypeEgressDenied)
	if len(denied) != 1 {
		t.Fatalf("egress_denied events: got %d, want 1", len(denied))
	}
	if denied[0].Payload["reason"] != "rate_limited" {
		t.Errorf("payload.reason: got %v, want rate_limited", denied[0].Payload["reason"])
	}
}

// -- Helpers ---------------------------------------------------

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u.Hostname()
}
