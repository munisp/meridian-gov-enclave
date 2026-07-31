package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Config holds env-driven settings with sane localhost defaults (SPEC 1.3).
type Config struct {
	ServiceName       string
	Version           string
	Port              string
	AuthMode          string // dev | prod
	JWTSecret         string
	DataRoot          string
	AuditEvidenceURL  string // core audit-evidence API; empty -> local WORM fallback
	F1ConsumerURL     string // enclave consumer APIs per flow; empty -> local dispatch
	F2ConsumerURL     string
	F3ConsumerURL     string
	F4ConsumerURL     string
	F5ConsumerURL     string
	JRBURL            string // for F7 signed attribution feeds
	WHTReconURL       string // for F8 WHT credit recon source
	InternalFlowToken string // F6 enclave-internal shared token (dev)
	// H1/H5 TLS & mTLS (prod profile):
	TLSCertFile       string // TLS_CERT_FILE: server certificate (empty -> plain HTTP dev)
	TLSKeyFile        string // TLS_KEY_FILE: server key
	MTLSCAFile        string // GATEWAY_MTLS_CA_FILE: CA pool verifying client certs
	RequireClientCert bool   // GATEWAY_REQUIRE_CLIENT_CERT=true -> require-and-verify
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadConfig() Config {
	cwd, _ := os.Getwd()
	return Config{
		ServiceName:       "enclave-gateway",
		Version:           "0.1.0",
		Port:              getenv("PORT", "8400"),
		AuthMode:          getenv("AUTH_MODE", "dev"),
		JWTSecret:         getenv("MERIDIAN_DEV_JWT_SECRET", "meridian-dev-secret"),
		DataRoot:          getenv("GATEWAY_DATA_ROOT", filepath.Join(cwd, "data")),
		AuditEvidenceURL:  os.Getenv("AUDIT_EVIDENCE_URL"),
		F1ConsumerURL:     os.Getenv("F1_CONSUMER_URL"),
		F2ConsumerURL:     os.Getenv("F2_CONSUMER_URL"),
		F3ConsumerURL:     os.Getenv("F3_CONSUMER_URL"),
		F4ConsumerURL:     os.Getenv("F4_CONSUMER_URL"),
		F5ConsumerURL:     os.Getenv("F5_CONSUMER_URL"),
		JRBURL:            os.Getenv("JRB_URL"),
		WHTReconURL:       os.Getenv("WHT_RECON_URL"),
			InternalFlowToken: getenv("INTERNAL_FLOW_TOKEN", ""),
		TLSCertFile:       os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:        os.Getenv("TLS_KEY_FILE"),
		MTLSCAFile:        os.Getenv("GATEWAY_MTLS_CA_FILE"),
		RequireClientCert: os.Getenv("GATEWAY_REQUIRE_CLIENT_CERT") == "true",
	}
}

// applyDevDefaults fills dev-only conveniences (never in prod).
func (c *Config) applyDevDefaults() {
	if (c.AuthMode == "dev" || c.AuthMode == "") && c.InternalFlowToken == "" {
		c.InternalFlowToken = "dev-internal-token"
	}
}

// Validate enforces the prod fail-closed contract (audit HIGH #7: dev auth
// was the default and never failed closed). In any non-dev AUTH_MODE the
// gateway must have server TLS, an explicit internal flow token and must not
// be using the public dev JWT secret.
func (c Config) Validate() error {
	if c.AuthMode == "dev" || c.AuthMode == "" {
		return nil
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		return fmt.Errorf("AUTH_MODE=%s requires TLS_CERT_FILE/TLS_KEY_FILE (plain HTTP is dev-only)", c.AuthMode)
	}
	if c.InternalFlowToken == "" || c.InternalFlowToken == "dev-internal-token" {
		return fmt.Errorf("AUTH_MODE=%s requires an explicit INTERNAL_FLOW_TOKEN (the dev default is forbidden)", c.AuthMode)
	}
	if c.AuthMode == "dev-jwt" && (c.JWTSecret == "" || c.JWTSecret == "meridian-dev-secret") {
		return fmt.Errorf("AUTH_MODE=%s requires MERIDIAN_DEV_JWT_SECRET to be set to a non-default value", c.AuthMode)
	}
	return nil
}
