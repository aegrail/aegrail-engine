package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/arpitcoder/aegrail-engine/internal/audit"
	"github.com/arpitcoder/aegrail-engine/internal/limits"
	"github.com/arpitcoder/aegrail-engine/internal/mitm"
	"github.com/arpitcoder/aegrail-engine/internal/policy"
)

// TestMITM_EndToEnd is the v0.4.0 gate. It spins up:
//
//  1. A TLS upstream that serves an OpenAI-shaped chat-completions
//     response.
//  2. The engine, configured with MITM for the upstream's host,
//     using a fresh CA whose cert the test trusts via the http.Client
//     used to make the request.
//  3. A client that issues a CONNECT to the engine (forward-proxy
//     form), expecting HTTPS to api.openai.com.
//
// The proof: the response body reaches the client unchanged, the
// engine emits an egress_allowed audit event with tokens_in /
// tokens_out parsed from the body, and the TokenBudget receives the
// accumulated count.
func TestMITM_EndToEnd_OpenAIChatCompletions(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl-test",
			"object":"chat.completion",
			"model":"gpt-4o-mini",
			"usage":{"prompt_tokens":42,"completion_tokens":77,"total_tokens":119}
		}`))
	}))
	defer upstream.Close()
	upstreamHost := mustHost(t, upstream.URL)

	// Engine setup: CA that the client will trust; MITM enabled for
	// the upstream's host; upstream TLS config trusts the httptest
	// server's self-signed cert.
	authority, err := mitm.NewAuthority(1 * time.Hour)
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	upstreamCertPool := x509.NewCertPool()
	upstreamCertPool.AddCert(upstream.Certificate())

	pol, _ := policy.New([]string{upstreamHost})
	sink := newMemorySink()
	session, _ := NewSession("egress-proxy-test/v1")
	proxyHandler := &Proxy{
		Policy:         pol,
		Sink:           sink,
		Session:        session,
		DialTimeout:    2 * time.Second,
		ForwardTimeout: 5 * time.Second,
		TokenBudget:    limits.NewTokenBudget(10_000),
		MITM: &MITMConfig{
			Authority:    authority,
			HostPatterns: []string{upstreamHost},
			UpstreamTLS:  &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamCertPool},
		},
	}
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	// Client setup: trust our CA so the MITM-presented leaf cert is
	// accepted. Disable keep-alives so the connection closes after
	// one request and the audit emit happens before we inspect.
	clientCAs := x509.NewCertPool()
	block, _ := pem.Decode(authority.CAPEM())
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse our CA: %v", err)
	}
	clientCAs.AddCert(caCert)

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    clientCAs,
			},
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}

	// Issue a request using the upstream host's URL. The TLS SNI
	// will match the leaf cert minted by our CA.
	resp, err := client.Get(upstream.URL + "/v1/chat/completions")
	if err != nil {
		t.Fatalf("client.Get via MITM proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}

	// Verify body reaches client unchanged (upstream payload is
	// preserved through the MITM)
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("client body not JSON: %v\n%s", err, body)
	}
	if parsed["model"] != "gpt-4o-mini" {
		t.Errorf("client received body but model field wrong: %v", parsed["model"])
	}

	// Verify audit event for MITM'd traffic
	allowed := sink.eventsOfType(audit.TypeEgressAllowed)
	if len(allowed) != 1 {
		t.Fatalf("egress_allowed events: got %d, want 1\nall events: %d", len(allowed), len(sink.events))
	}
	payload := allowed[0].Payload
	if payload["mitm"] != true {
		t.Errorf("event payload should mark mitm=true, got %v", payload["mitm"])
	}
	if payload["host"] != upstreamHost {
		t.Errorf("event host: got %v, want %v", payload["host"], upstreamHost)
	}
	if payload["status_code"].(int) != 200 {
		t.Errorf("event status_code: got %v, want 200", payload["status_code"])
	}
	if payload["llm_model"] != "gpt-4o-mini" {
		t.Errorf("event llm_model: got %v, want gpt-4o-mini", payload["llm_model"])
	}
	if payload["tokens_in"].(int) != 42 {
		t.Errorf("event tokens_in: got %v, want 42", payload["tokens_in"])
	}
	if payload["tokens_out"].(int) != 77 {
		t.Errorf("event tokens_out: got %v, want 77", payload["tokens_out"])
	}
	if proxyHandler.TokenBudget.Used() != 42+77 {
		t.Errorf("token budget used: got %d, want 119", proxyHandler.TokenBudget.Used())
	}
}

func TestMITM_HostNotInPatternsTunnelsOpaquely(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tunneled":true}`))
	}))
	defer upstream.Close()
	upstreamHost := mustHost(t, upstream.URL)

	authority, _ := mitm.NewAuthority(1 * time.Hour)
	pol, _ := policy.New([]string{upstreamHost})
	sink := newMemorySink()
	session, _ := NewSession("egress-proxy-test/v1")

	proxyHandler := &Proxy{
		Policy:         pol,
		Sink:           sink,
		Session:        session,
		DialTimeout:    2 * time.Second,
		ForwardTimeout: 5 * time.Second,
		MITM: &MITMConfig{
			Authority:    authority,
			HostPatterns: []string{"other-host.example"}, // NOT the upstream
		},
	}
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	client := proxiedClient(proxyServer.URL)
	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	_ = resp.Body.Close()

	allowed := sink.eventsOfType(audit.TypeEgressAllowed)
	if len(allowed) != 1 {
		t.Fatalf("egress_allowed events: got %d, want 1", len(allowed))
	}
	if mitmField, ok := allowed[0].Payload["mitm"]; ok && mitmField == true {
		t.Error("opaque-tunneled connection should NOT have mitm=true in audit payload")
	}
}

func TestMITM_DisabledMeansNoTermination(t *testing.T) {
	t.Parallel()

	// MITM is nil — all CONNECTs tunnel.
	var m *MITMConfig
	if m.shouldMITM("api.openai.com") {
		t.Error("nil MITMConfig should never MITM")
	}
}

// helper from proxy_test.go is re-used here. Add an import-only line
// to silence unused-import linters when this file compiles alone.
var _ = strings.Builder{}
