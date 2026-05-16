// Package mitm generates the CA and per-upstream leaf certificates
// the engine uses when terminating TLS to inspect HTTPS traffic.
//
// One CA is generated (or loaded) per engine process. Leaf certs
// are minted on demand per upstream host, signed by that CA, and
// cached so subsequent connections to the same host reuse the
// same cert.
//
// The CA must be trusted by the agent container's HTTP clients for
// the MITM to be transparent. The webhook (v0.4.0+) mounts the CA
// file into agent containers and sets SSL_CERT_FILE /
// REQUESTS_CA_BUNDLE / NODE_EXTRA_CA_CERTS pointing at it.
//
// Without trust distribution, MITM'd connections will fail TLS
// verification on the client side. That's an opt-in feature, off
// by default — operators have to explicitly enable MITM hosts AND
// distribute the CA before any traffic is intercepted.

package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// Authority holds the engine's CA cert + private key and the leaf
// cert cache. Construct with NewAuthority or LoadAuthority.
type Authority struct {
	caCert  *x509.Certificate
	caKey   *rsa.PrivateKey
	caPEM   []byte
	leafTTL time.Duration

	mu        sync.Mutex
	leafCache map[string]*cachedLeaf
}

type cachedLeaf struct {
	cert    *tls.Certificate
	expires time.Time
}

// NewAuthority generates a fresh CA cert + key valid for `validity`.
// Use this when the operator hasn't supplied a CA — convenient for
// dev / kind, less so for production where you want a stable CA
// that survives engine restarts so already-distributed trust roots
// remain valid.
func NewAuthority(validity time.Duration) (*Authority, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("mitm: generate CA key: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "aegrail-engine MITM CA",
			Organization: []string{"aegrail"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("mitm: create CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse CA cert: %w", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &Authority{
		caCert:    caCert,
		caKey:     key,
		caPEM:     caPEM,
		leafTTL:   24 * time.Hour,
		leafCache: make(map[string]*cachedLeaf),
	}, nil
}

// LoadAuthority reads a CA cert + key pair from the given file
// paths (PEM). Use this when the operator wants a stable CA
// across engine restarts.
func LoadAuthority(certPath, keyPath string) (*Authority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("mitm: read CA cert %q: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("mitm: read CA key %q: %w", keyPath, err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("mitm: %q is not PEM-encoded", certPath)
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("mitm: %q is not PEM-encoded", keyPath)
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// PKCS#8 fallback
		anyKey, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("mitm: parse CA key: %w (PKCS#8 fallback also failed)", err)
		}
		rsaKey, ok := anyKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("mitm: CA key is not RSA")
		}
		caKey = rsaKey
	}
	return &Authority{
		caCert:    caCert,
		caKey:     caKey,
		caPEM:     certPEM,
		leafTTL:   24 * time.Hour,
		leafCache: make(map[string]*cachedLeaf),
	}, nil
}

// CAPEM returns the PEM-encoded CA certificate (for distribution
// to clients).
func (a *Authority) CAPEM() []byte {
	out := make([]byte, len(a.caPEM))
	copy(out, a.caPEM)
	return out
}

// LeafFor returns a TLS server certificate valid for the given
// host. Cached for `leafTTL` and re-minted on cache miss or
// expiry.
func (a *Authority) LeafFor(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if cached, ok := a.leafCache[host]; ok && time.Now().Before(cached.expires) {
		return cached.cert, nil
	}
	leaf, err := a.mintLeaf(host)
	if err != nil {
		return nil, err
	}
	a.leafCache[host] = &cachedLeaf{
		cert:    leaf,
		expires: time.Now().Add(a.leafTTL),
	}
	return leaf, nil
}

func (a *Authority) mintLeaf(host string) (*tls.Certificate, error) {
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("mitm: generate leaf key: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.caCert, &leafKey.PublicKey, a.caKey)
	if err != nil {
		return nil, fmt.Errorf("mitm: sign leaf cert: %w", err)
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der, a.caCert.Raw},
		PrivateKey:  leafKey,
	}
	return cert, nil
}
