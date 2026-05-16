package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestNewAuthority_ProducesUsableCA(t *testing.T) {
	t.Parallel()
	a, err := NewAuthority(365 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	if len(a.CAPEM()) == 0 {
		t.Fatal("CAPEM should not be empty")
	}
	if a.caCert == nil || a.caKey == nil {
		t.Fatal("CA cert/key not populated")
	}
	if !a.caCert.IsCA {
		t.Error("generated CA must have IsCA=true")
	}
}

func TestLeafFor_MintsCertSignedByCA(t *testing.T) {
	t.Parallel()
	a, err := NewAuthority(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := a.LeafFor("api.openai.com")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if cert.Subject.CommonName != "api.openai.com" {
		t.Errorf("CN: got %q, want api.openai.com", cert.Subject.CommonName)
	}
	if cert.IsCA {
		t.Error("leaf cert must not be a CA")
	}
	// Verify the leaf is signed by our CA
	pool := x509.NewCertPool()
	pool.AddCert(a.caCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		DNSName:     "api.openai.com",
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("leaf does not verify against CA: %v", err)
	}
}

func TestLeafFor_CachesPerHost(t *testing.T) {
	t.Parallel()
	a, err := NewAuthority(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := a.LeafFor("api.openai.com")
	second, _ := a.LeafFor("api.openai.com")
	if first != second {
		t.Error("expected cached leaf to be returned on second call")
	}
	different, _ := a.LeafFor("api.anthropic.com")
	if different == first {
		t.Error("different hosts should get different leaves")
	}
}

func TestLeafFor_BedrockRegionalHost(t *testing.T) {
	t.Parallel()
	a, err := NewAuthority(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := a.LeafFor("bedrock-runtime.us-east-1.amazonaws.com")
	if err != nil {
		t.Fatalf("LeafFor regional host: %v", err)
	}
	cert, _ := x509.ParseCertificate(leaf.Certificate[0])
	found := false
	for _, dnsName := range cert.DNSNames {
		if dnsName == "bedrock-runtime.us-east-1.amazonaws.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("leaf SAN missing host; DNSNames=%v", cert.DNSNames)
	}
}

func TestLeafFor_TLSServerConfigUsesCert(t *testing.T) {
	t.Parallel()
	a, err := NewAuthority(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := a.LeafFor("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	// Just verify the cert is usable in a tls.Config
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{*leaf}}
	if len(tlsCfg.Certificates) != 1 {
		t.Error("tls.Config should hold one cert")
	}
}
