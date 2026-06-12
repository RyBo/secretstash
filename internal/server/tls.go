package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"time"
)

// loadTLS returns the TLS config for the configured mode, plus a
// human-readable description for the startup banner. nil config means
// plain HTTP (--dev).
func (c Config) loadTLS() (*tls.Config, string, error) {
	if c.Dev {
		return nil, "TLS DISABLED (--dev mode): traffic is plaintext", nil
	}
	if c.TLSCert != "" || c.TLSKey != "" {
		if c.TLSCert == "" || c.TLSKey == "" {
			return nil, "", fmt.Errorf("--tls-cert and --tls-key must be set together")
		}
		cert, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			return nil, "", fmt.Errorf("loading TLS keypair: %w", err)
		}
		return tlsConfig(cert), "TLS enabled with " + c.TLSCert, nil
	}

	cert, fingerprint, err := selfSignedCert(c.Listen)
	if err != nil {
		return nil, "", err
	}
	desc := "TLS enabled with ephemeral self-signed certificate (never written to disk)\n" +
		"  certificate SHA-256 fingerprint: " + fingerprint + "\n" +
		"  clients: use --tls-skip-verify or pin the fingerprint above"
	return tlsConfig(cert), desc, nil
}

func tlsConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

// selfSignedCert generates an in-memory ECDSA P-256 certificate valid for
// 90 days, with SANs for localhost and the listen host.
func selfSignedCert(listen string) (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}

	dnsNames := []string{"localhost"}
	ips := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	if host, _, err := net.SplitHostPort(listen); err == nil && host != "" {
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "secretstash"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	sum := sha256.Sum256(der)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return cert, hex.EncodeToString(sum[:]), nil
}
