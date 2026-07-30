package main

import (
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
		InternalFlowToken: getenv("INTERNAL_FLOW_TOKEN", "dev-internal-token"),
	}
}
