package main

import (
	"encoding/json"
	"net/http"

	"github.com/munisp/meridian-gov-enclave/packages/authx"
)

// Principal is the authenticated caller (shared authx implementation; H2:
// AUTH_MODE=dev keeps HS256 + X-Dev-Role, AUTH_MODE=keycloak verifies RS256
// against the Keycloak JWKS).
type Principal = authx.Principal

// newAuthenticator builds the env-selected authenticator for this service.
func newAuthenticator(cfg Config) *authx.Authenticator {
	ac := authx.ConfigFromEnv()
	// Service-level env wins if set explicitly; otherwise shared contract.
	if cfg.AuthMode != "" {
		ac.Mode = cfg.AuthMode
	}
	if cfg.JWTSecret != "" {
		ac.DevSecret = cfg.JWTSecret
	}
	return authx.New(ac, cfg.ServiceName)
}

// writeProblem emits RFC7807 problem+json (SPEC 1.3).
func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "about:blank", "title": title, "status": status, "detail": detail,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
