package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- test PKI helpers --------------------------------------------------------

type testPKI struct {
	dir        string
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	caPEM      []byte
	serverCert tls.Certificate
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	p := &testPKI{dir: t.TempDir()}
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p.caKey = caKey
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Meridian Test CA", Organization: []string{"meridian-test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	p.caCert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	p.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(p.dir, "ca.pem"), p.caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	p.serverCert = p.issue(t, "enclave-gateway", x509.ExtKeyUsageServerAuth, "server")
	return p
}

func (p *testPKI) issue(t *testing.T, cn string, usage x509.ExtKeyUsage, name string) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"meridian-test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if name != "" {
		_ = os.WriteFile(filepath.Join(p.dir, name+".crt"), certPEM, 0o644)
		_ = os.WriteFile(filepath.Join(p.dir, name+".key"), keyPEM, 0o600)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// --- mTLS: require-and-verify client certs -----------------------------------

func TestMTLSRequireAndVerifyClientCert(t *testing.T) {
	pki := newTestPKI(t)
	cfg := loadConfig()
	cfg.DataRoot = t.TempDir()
	cfg.AuthMode = "dev"
	cfg.TLSCertFile = filepath.Join(pki.dir, "server.crt")
	cfg.TLSKeyFile = filepath.Join(pki.dir, "server.key")
	cfg.MTLSCAFile = filepath.Join(pki.dir, "ca.pem")
	cfg.RequireClientCert = true

	tlsCfg, err := serverTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("expected RequireAndVerifyClientCert")
	}
	_, h := newTestServer(t)

	srv := httptest.NewUnstartedServer(h)
	srv.TLS = tlsCfg
	srv.StartTLS()
	defer srv.Close()

	caPool := x509.NewCertPool()
	caPool.AddCert(pki.caCert)

	// (a) No client certificate -> handshake must fail.
	noCertClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12}}}
	if _, err := noCertClient.Get(srv.URL + "/healthz"); err == nil {
		t.Fatal("handshake without client cert must fail when GATEWAY_REQUIRE_CLIENT_CERT=true")
	}

	// (b) Valid client certificate -> request succeeds.
	clientCert := pki.issue(t, "svc-market-einvoicing", x509.ExtKeyUsageClientAuth, "")
	mtlsClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS12}}}
	resp, err := mtlsClient.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("mTLS handshake with valid client cert: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz over mTLS: %d", resp.StatusCode)
	}
}

// --- caller identity stamping -------------------------------------------------

func TestCallerStampedFromVerifiedCertCN(t *testing.T) {
	// Capture the forwarded X-Meridian-Caller at the enclave consumer.
	var gotCaller string
	consumer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCaller = r.Header.Get("X-Meridian-Caller")
		w.WriteHeader(http.StatusOK)
	}))
	defer consumer.Close()

	cfg := loadConfig()
	cfg.DataRoot = t.TempDir()
	cfg.AuthMode = "dev"
	cfg.F1ConsumerURL = consumer.URL
	worm, local, err := newWORMStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: cfg, authn: newAuthenticator(cfg), http: http.DefaultClient, worm: worm, localWorm: local}

	// Fabricate a verified mTLS connection state (sovereign caller cert CN).
	clientCert := &x509.Certificate{Subject: pkix.Name{CommonName: "sovereign-jrb"}}
	req := httptest.NewRequest("POST", "/flows/f1/ubl-preclearance-invoices",
		strings.NewReader(`{"invoice_id":"INV-mtls","supplier_tin":"t","issue_date":"d","lines":[],"total_kobo":1}`))
	req.Header.Set("X-Dev-Role", "operator")
	req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{clientCert}}}
	rec := httptest.NewRecorder()
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		s.pipeline(w, r, s.flows()["F1"])
	})(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("pipeline over mTLS: %d body=%s", rec.Code, rec.Body)
	}
	if gotCaller != "mtls:sovereign-jrb" {
		t.Fatalf("X-Meridian-Caller = %q, want mtls:sovereign-jrb", gotCaller)
	}
}

func TestCallerStampedFromJWTSubWhenNoClientCert(t *testing.T) {
	var gotCaller string
	consumer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCaller = r.Header.Get("X-Meridian-Caller")
		w.WriteHeader(http.StatusOK)
	}))
	defer consumer.Close()

	cfg := loadConfig()
	cfg.DataRoot = t.TempDir()
	cfg.AuthMode = "dev"
	cfg.F1ConsumerURL = consumer.URL
	worm, local, err := newWORMStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: cfg, authn: newAuthenticator(cfg), http: http.DefaultClient, worm: worm, localWorm: local}

	req := httptest.NewRequest("POST", "/flows/f1/ubl-preclearance-invoices",
		strings.NewReader(`{"invoice_id":"INV-jwt","supplier_tin":"t","issue_date":"d","lines":[],"total_kobo":1}`))
	req.Header.Set("X-Dev-Role", "operator")
	rec := httptest.NewRecorder()
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		s.pipeline(w, r, s.flows()["F1"])
	})(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("pipeline: %d body=%s", rec.Code, rec.Body)
	}
	if gotCaller != "jwt:dev-operator" {
		t.Fatalf("X-Meridian-Caller = %q, want jwt:dev-operator", gotCaller)
	}
}

// --- F9/F10 deny-by-construction ----------------------------------------------

// TestForbiddenFlowsDenied proves F9/F10 are forbidden by construction: the
// mux has NO matching route (any method) and the deny middleware rejects every
// forbidden path shape with 403 before routing.
func TestForbiddenFlowsDenied(t *testing.T) {
	_, h := newTestServer(t)
	paths := []string{
		"/flows/f9", "/flows/f9/", "/flows/f9/direct-market-access",
		"/flows/f10", "/flows/f10/", "/flows/f10/unaudited-export",
		"/FLOWS/F9/anything", // case-insensitive denial
	}
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, path := range paths {
		for _, m := range methods {
			rec := do(t, h, m, path, `{"x":1}`, "admin")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %s: got %d, want 403 (F9/F10 must be denied by construction)", m, path, rec.Code)
			}
			body, _ := io.ReadAll(rec.Result().Body)
			var prob map[string]any
			if json.Unmarshal(body, &prob) == nil {
				if !strings.Contains(prob["detail"].(string), "forbidden by construction") {
					t.Fatalf("%s %s: unexpected detail %v", m, path, prob)
				}
			}
		}
	}
	// Accepted flows still route (F1 exists and is NOT caught by the deny rule).
	rec := do(t, h, "POST", "/flows/f1/ubl-preclearance-invoices",
		`{"invoice_id":"INV-ok","supplier_tin":"t","issue_date":"d","lines":[],"total_kobo":1}`, "operator")
	if rec.Code == http.StatusForbidden {
		t.Fatal("F1 must not be denied by the F9/F10 middleware")
	}
}
