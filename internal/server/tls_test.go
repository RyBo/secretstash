package server

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSelfSignedCertServes(t *testing.T) {
	cert, fingerprint, err := selfSignedCert("127.0.0.1:8200")
	if err != nil {
		t.Fatal(err)
	}
	if len(fingerprint) != 64 {
		t.Fatalf("want 64 hex char fingerprint, got %q", fingerprint)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	srv.TLS = tlsConfig(cert)
	srv.StartTLS()
	defer srv.Close()

	// Pin the generated cert: a client trusting exactly this certificate
	// must connect successfully.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"},
	}}

	// httptest server URL uses 127.0.0.1; dial it but verify against SAN.
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestDevModeRefusesNonLoopback(t *testing.T) {
	err := Run(Config{Listen: "0.0.0.0:8200", Dev: true})
	if err == nil {
		t.Fatal("want refusal for --dev on non-loopback listen")
	}
}

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8200": true,
		"localhost:8200": true,
		"[::1]:8200":     true,
		"0.0.0.0:8200":   false,
		"10.0.0.5:8200":  false,
		"example.com:80": false,
	} {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestCertAndKeyMustBeTogether(t *testing.T) {
	_, _, err := Config{TLSCert: "cert.pem"}.loadTLS()
	if err == nil {
		t.Fatal("want error for cert without key")
	}
}
