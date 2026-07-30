package main

import (
	"os"
	"path/filepath"
)

type Config struct {
	ServiceName       string
	Version           string
	Port              string
	AuthMode          string
	JWTSecret         string
	DataRoot          string
	EnclaveGatewayURL string // cross-zone sends only via enclave-gateway
	InternalFlowToken string
	PacksDir          string
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
		EnclaveGatewayURL: getenv("ENCLAVE_GATEWAY_URL", ""), // empty -> local receipt capture
		InternalFlowToken: getenv("INTERNAL_FLOW_TOKEN", "dev-internal-token"),
		PacksDir:          getenv("PACKS_DIR", "packs"),
	}
}
