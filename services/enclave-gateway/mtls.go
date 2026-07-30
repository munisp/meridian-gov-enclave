package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
)

// mtls.go — sovereign<->market transport security (HARDENING H5).
//
// Server TLS is enabled when TLS_CERT_FILE/TLS_KEY_FILE are set. When
// GATEWAY_REQUIRE_CLIENT_CERT=true the gateway requires AND verifies client
// certificates against the CA pool in GATEWAY_MTLS_CA_FILE: any sovereign or
// market caller must present a PKI-issued certificate, and the verified
// certificate CN becomes the caller identity stamped on X-Meridian-Caller
// before forwarding to enclave consumers.

// serverTLSConfig builds the tls.Config for the gateway listener. Returns nil
// (plain HTTP dev profile) when no cert pair is configured. Startup NEVER
// fails because the prod vars are missing.
func serverTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		log.Printf("profile=dev component=enclave-gateway tls=plain-http")
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS_CERT_FILE/TLS_KEY_FILE: %w", err)
	}
	tc := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if cfg.RequireClientCert {
		if cfg.MTLSCAFile == "" {
			return nil, fmt.Errorf("GATEWAY_REQUIRE_CLIENT_CERT=true requires GATEWAY_MTLS_CA_FILE")
		}
		pemBytes, err := os.ReadFile(cfg.MTLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read GATEWAY_MTLS_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("GATEWAY_MTLS_CA_FILE contains no usable CA certificates")
		}
		tc.ClientAuth = tls.RequireAndVerifyClientCert
		tc.ClientCAs = pool
		log.Printf("profile=prod component=enclave-gateway mtls=require-and-verify-client-cert ca=%s", cfg.MTLSCAFile)
	} else {
		log.Printf("profile=prod component=enclave-gateway tls=server-only mtls=off")
	}
	return tc, nil
}

// callerIdentity derives the caller identity to stamp on X-Meridian-Caller:
// the verified client-certificate CN when mTLS authenticated the connection,
// otherwise the JWT sub.
func callerIdentity(r *http.Request, p *Principal) string {
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 &&
		len(r.TLS.VerifiedChains[0]) > 0 {
		if cn := r.TLS.VerifiedChains[0][0].Subject.CommonName; cn != "" {
			return "mtls:" + cn
		}
	}
	return "jwt:" + p.Sub
}

// stampCaller sets the X-Meridian-Caller header on the inbound request so the
// audited pipeline and consumer dispatch propagate a verified identity.
func stampCaller(r *http.Request, p *Principal) string {
	caller := callerIdentity(r, p)
	r.Header.Set("X-Meridian-Caller", caller)
	return caller
}
