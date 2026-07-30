package main

import (
	"encoding/json"
	"net/http"

	"github.com/munisp/meridian-gov-enclave/packages/authx"
)

// Principal is the authenticated caller (shared authx implementation; H2:
// AUTH_MODE=dev keeps HS256 + X-Dev-Role, AUTH_MODE=keycloak verifies RS256
// against the Keycloak JWKS with iss/aud enforcement).
type Principal = authx.Principal

// newAuthenticator builds the env-selected authenticator for the gateway. In
// keycloak mode the audience defaults to meridian-services (service-to-service
// client-credentials tokens, HARDENING H2) when KEYCLOAK_AUDIENCE is unset.
func newAuthenticator(cfg Config) *authx.Authenticator {
	ac := authx.ConfigFromEnv()
	if cfg.AuthMode != "" {
		ac.Mode = cfg.AuthMode
	}
	if cfg.JWTSecret != "" {
		ac.DevSecret = cfg.JWTSecret
	}
	if ac.Mode == "keycloak" && ac.Audience == "" {
		ac.Audience = "meridian-services"
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
