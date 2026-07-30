package main

import (
	"os"
	"path/filepath"
)

// Config holds env-driven settings with sane localhost defaults (SPEC 1.3 +
// HARDENING H1).
type Config struct {
	ServiceName       string
	Version           string
	Port              string
	AuthMode          string // dev | keycloak
	JWTSecret         string
	DataRoot          string
	EnclaveGatewayURL string // for cross-zone sends (F6); empty -> simulated receipt
	InternalFlowToken string // F6 shared token (dev); mTLS in prod profile
	PacksDir          string // rp-* fallback packs
	DatabaseURL       string // DATABASE_URL: postgres path (H3); empty -> JSON files
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
		ServiceName:       "jrb",
		Version:           "0.1.0",
		Port:              getenv("PORT", "8402"),
		AuthMode:          getenv("AUTH_MODE", "dev"),
		JWTSecret:         getenv("MERIDIAN_DEV_JWT_SECRET", "meridian-dev-secret"),
		DataRoot:          getenv("JRB_DATA_ROOT", filepath.Join(cwd, "data")),
		EnclaveGatewayURL: os.Getenv("ENCLAVE_GATEWAY_URL"),
		InternalFlowToken: getenv("INTERNAL_FLOW_TOKEN", "dev-internal-token"),
		PacksDir:          getenv("PACKS_DIR", "packs"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
	}
}
