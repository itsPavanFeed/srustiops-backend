// Package link is the tenant link: an outbound-only tunnel from a tenant plane
// to the central plane's gateway, modelled on Databricks secure cluster
// connectivity. The tenant dials out; nothing dials in.
//
//	enrol   agent → gateway   POST /v1/link/enroll   one-time token + CSR → short-lived certificate
//	renew   agent → gateway   POST /v1/link/renew    current certificate + CSR → next certificate
//	reenrol agent → gateway   POST /v1/link/reenroll after an offline expiry: CSR by the bound key
//	connect agent → gateway   GET  /v1/link/connect  Upgrade: srustiops-link/1, then a yamux session
//
// The tunnel is a yamux session: the gateway opens a stream for each request
// central makes to the tenant, and the agent pipes it to one fixed target, the
// tenant API. Central runs its usual mTLS session to the tenant API inside the
// stream, so the agent forwards bytes it can neither read nor alter. The agent
// opens a control stream (hello, health, clock; drain from the gateway) and,
// when it relays for the tenant's identity provider, egress streams.
package link

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// Proto is the Upgrade token of a tenant tunnel.
	Proto = "srustiops-link/1"
	// RelayProto is the Upgrade token a gateway replica uses to reach a tunnel
	// held by another replica.
	RelayProto = "srustiops-relay/1"
	// CertTTL is a link certificate's lifetime; agents renew at two thirds.
	CertTTL = 24 * time.Hour
	// EnrollTTL is how long a one-time enrolment token stays valid.
	EnrollTTL = time.Hour
)

var slugRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

// TenantID is the SPIFFE ID in a tenant's link certificate.
func TenantID(slug string) string { return "spiffe://srustiops/tenant/" + slug + "/link" }

// ReplicaID is the SPIFFE ID gateway replicas present to each other.
const ReplicaID = "spiffe://srustiops/central/replica"

// TenantOf returns the tenant a link certificate was issued to.
func TenantOf(c *x509.Certificate) (string, bool) {
	for _, u := range c.URIs {
		s := u.String()
		if rest, ok := strings.CutPrefix(s, "spiffe://srustiops/tenant/"); ok {
			if slug, ok := strings.CutSuffix(rest, "/link"); ok && slugRe.MatchString(slug) {
				return slug, true
			}
		}
	}
	return "", false
}

// IsReplica reports whether c names a gateway replica.
func IsReplica(c *x509.Certificate) bool {
	for _, u := range c.URIs {
		if u.String() == ReplicaID {
			return true
		}
	}
	return false
}

// Serial is a certificate serial as stored and shown (hex).
func Serial(c *x509.Certificate) string { return hex.EncodeToString(c.SerialNumber.Bytes()) }

// Fingerprint is the SHA-256 of a certificate's public key, so a renewed
// certificate for the same key keeps its fingerprint.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return "SHA256:" + hex.EncodeToString(sum[:])
}

// ---- the link CA (held by central, sealed in its database) ----

type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
	PEM  []byte
}

// NewCA creates the link CA and returns it with its key in PEM, for sealing.
func NewCA() (*CA, []byte, error) { return NewNamedCA("SrustiOps tenant link CA") }

// NewNamedCA creates a CA with the given common name.
func NewNamedCA(cn string) (*CA, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})...)
	ca, err := LoadCA(bundle)
	return ca, bundle, err
}

// LoadCA reads a CA certificate and key from one PEM bundle.
func LoadCA(bundle []byte) (*CA, error) {
	var ca CA
	for rest := bundle; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, err
			}
			ca.Cert, ca.PEM = c, pem.EncodeToMemory(b)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
			if err != nil {
				return nil, err
			}
			ek, ok := k.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.New("link CA key is not ECDSA")
			}
			ca.key = ek
		}
	}
	if ca.Cert == nil || ca.key == nil {
		return nil, errors.New("link CA bundle needs a certificate and a key")
	}
	return &ca, nil
}

// Pool is a certificate pool holding only this CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// Sign issues a client certificate for the CSR's key, naming id.
func (ca *CA) Sign(csr *x509.CertificateRequest, id string, ttl time.Duration) (*x509.Certificate, []byte, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("certificate request signature: %w", err)
	}
	if _, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok {
		return nil, nil, errors.New("certificate request must use an ECDSA key")
	}
	u, err := url.Parse(id)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(), Subject: pkix.Name{CommonName: id},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(ttl),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), err
}

// InternalName is the TLS name a bootstrapped tenant API serves: central
// dials it through the tunnel, so it never needs to resolve in DNS.
func InternalName(slug string) string { return slug + ".tenant.srustiops.internal" }

// SignServer issues a server certificate for the CSR's key, naming dns.
func (ca *CA) SignServer(csr *x509.CertificateRequest, dns string, ttl time.Duration, also ...string) (*x509.Certificate, []byte, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("certificate request signature: %w", err)
	}
	if _, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok {
		return nil, nil, errors.New("certificate request must use an ECDSA key")
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(), Subject: pkix.Name{CommonName: dns}, DNSNames: append([]string{dns}, also...),
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(ttl),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), err
}

// Verify checks a client certificate chains to this CA and is in date.
func (ca *CA) Verify(c *x509.Certificate) error {
	_, err := c.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}

func randSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n.Add(n, big.NewInt(1))
}

// NewKeyAndCSR makes a P-256 key and a certificate request for it.
func NewKeyAndCSR(cn string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		return nil, nil, err
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// ParseCSR reads one PEM certificate request.
func ParseCSR(p []byte) (*x509.CertificateRequest, error) {
	b, _ := pem.Decode(p)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("csr must be a PEM CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(b.Bytes)
}

// ---- streams ----

// BufConn reads first from a buffered reader that may already hold bytes
// read past an HTTP/1.1 upgrade, then from the connection.
type BufConn struct {
	net.Conn
	R *bufio.Reader
}

func (c *BufConn) Read(p []byte) (int, error) { return c.R.Read(p) }

// Pipe copies both ways until either side ends, then closes both.
func Pipe(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) { io.Copy(dst, src); done <- struct{}{} }
	go cp(a, b)
	go cp(b, a)
	<-done
	a.Close()
	b.Close()
}

// KeyFingerprint names a public key (its DER SubjectPublicKeyInfo) as
// "SHA256:<hex>", the form central pins and lists keys by.
func KeyFingerprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return "SHA256:" + hex.EncodeToString(sum[:])
}
