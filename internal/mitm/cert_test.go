package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
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
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{*leaf}}
	if len(tlsCfg.Certificates) != 1 {
		t.Error("tls.Config should hold one cert")
	}
}

// TestLoadAuthority_AcceptsRSAAndECDSA guards the bug found during
// v0.4.3 kind testing: the engine rejected an openssl-generated
// ECDSA CA with "CA key is not RSA", forcing operators back to
// RSA-only CAs. cert-manager and openssl both default to ECDSA, so
// rejecting non-RSA broke the integrated webhook+MITM path on any
// modern cluster.
func TestLoadAuthority_AcceptsRSAAndECDSA(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		gen  func(t *testing.T) (certPEM, keyPEM []byte)
	}{
		{"RSA-PKCS1", genRSACA},
		{"RSA-PKCS8", genRSACAPKCS8},
		{"ECDSA-P256-PKCS8", genECDSACA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, keyPEM := tc.gen(t)
			dir := t.TempDir()
			certPath := filepath.Join(dir, "ca.crt")
			keyPath := filepath.Join(dir, "ca.key")
			if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
				t.Fatal(err)
			}
			a, err := LoadAuthority(certPath, keyPath)
			if err != nil {
				t.Fatalf("LoadAuthority: %v", err)
			}
			leaf, err := a.LeafFor("example.com")
			if err != nil {
				t.Fatalf("LeafFor after loading %s CA: %v", tc.name, err)
			}
			if len(leaf.Certificate) == 0 {
				t.Errorf("%s: leaf had no certificate bytes", tc.name)
			}
		})
	}
}

func genRSACA(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := signCATemplate(t, &key.PublicKey, key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return certPEM, keyPEM
}

func genRSACAPKCS8(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := signCATemplate(t, &key.PublicKey, key)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return certPEM, keyPEM
}

func genECDSACA(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := signCATemplate(t, &key.PublicKey, key)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return certPEM, keyPEM
}

func signCATemplate(t *testing.T, pub any, signer any) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "aegrail test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
