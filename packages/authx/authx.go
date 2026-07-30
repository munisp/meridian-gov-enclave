// Package authx is the compact shared auth middleware for meridian-gov-enclave
// Go services (HARDENING H2). AUTH_MODE selects the verifier:
//
//	dev      (default): HS256 JWT against MERIDIAN_DEV_JWT_SECRET + X-Dev-Role header
//	keycloak          : RS256 JWT verified against Keycloak JWKS (issuer/audience enforced)
//
// The same Authenticator API backs both modes so services switch via env only.
package authx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Principal is the authenticated caller.
type Principal struct {
	Sub      string
	Roles    []string
	TenantID string
}

// HasRole reports whether the principal carries role r.
func (p *Principal) HasRole(r string) bool {
	for _, x := range p.Roles {
		if x == r {
			return true
		}
	}
	return false
}

// Config mirrors the H1 env contract.
type Config struct {
	Mode       string // dev | keycloak
	DevSecret  string
	Issuer     string
	Audience   string
	JWKSURL    string // derived from Issuer when empty
	DevRoleHdr bool   // accept X-Dev-Role in dev mode
}

// ConfigFromEnv builds Config from the H1 environment contract.
func ConfigFromEnv() Config {
	issuer := os.Getenv("KEYCLOAK_ISSUER")
	jwks := os.Getenv("KEYCLOAK_JWKS_URL")
	if jwks == "" && issuer != "" {
		jwks = strings.TrimSuffix(issuer, "/") + "/protocol/openid-connect/certs"
	}
	return Config{
		Mode:       getenv("AUTH_MODE", "dev"),
		DevSecret:  getenv("MERIDIAN_DEV_JWT_SECRET", "meridian-dev-secret"),
		Issuer:     issuer,
		Audience:   os.Getenv("KEYCLOAK_AUDIENCE"),
		JWKSURL:    jwks,
		DevRoleHdr: true,
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Authenticator authenticates requests in either profile.
type Authenticator struct {
	cfg  Config
	jwks *jwksCache // keycloak mode only
}

// New builds an Authenticator. Startup never fails: keycloak mode without an
// issuer logs a warning and simply rejects Bearer tokens until configured.
func New(cfg Config, component string) *Authenticator {
	a := &Authenticator{cfg: cfg}
	if cfg.Mode == "keycloak" {
		if cfg.JWKSURL == "" {
			log.Printf("profile=prod component=%s auth=keycloak WARNING: KEYCLOAK_ISSUER unset; Bearer tokens will be rejected", component)
		} else {
			a.jwks = newJWKSCache(cfg.JWKSURL, 5*time.Minute)
			log.Printf("profile=prod component=%s auth=keycloak jwks=%s aud=%s", component, cfg.JWKSURL, cfg.Audience)
		}
	} else {
		log.Printf("profile=dev component=%s auth=dev", component)
	}
	return a
}

// PrincipalFrom authenticates the request; nil when unauthenticated.
func (a *Authenticator) PrincipalFrom(r *http.Request) *Principal {
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		tok := strings.TrimSpace(authz[7:])
		var claims map[string]any
		var ok bool
		if a.cfg.Mode == "keycloak" {
			claims, ok = a.verifyRS256(tok)
		} else {
			claims, ok = VerifyHS256(tok, a.cfg.DevSecret)
		}
		if ok {
			return principalFromClaims(claims)
		}
	}
	if a.cfg.Mode != "keycloak" && a.cfg.DevRoleHdr {
		switch role := r.Header.Get("X-Dev-Role"); role {
		case "admin", "operator", "auditor":
			return &Principal{Sub: "dev-" + role, Roles: []string{role}, TenantID: "dev"}
		}
	}
	return nil
}

func principalFromClaims(claims map[string]any) *Principal {
	p := &Principal{Sub: "unknown"}
	if s, ok := claims["sub"].(string); ok && s != "" {
		p.Sub = s
	}
	if t, ok := claims["tenant_id"].(string); ok {
		p.TenantID = t
	}
	p.Roles = append(p.Roles, stringList(claims["roles"])...)
	// Keycloak realm roles -> roles claim (H2).
	if ra, ok := claims["realm_access"].(map[string]any); ok {
		p.Roles = append(p.Roles, stringList(ra["roles"])...)
	}
	return p
}

func stringList(v any) []string {
	var out []string
	switch vv := v.(type) {
	case string:
		if vv != "" {
			out = append(out, vv)
		}
	case []any:
		for _, x := range vv {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// B64urlDecode decodes unpadded base64url.
func B64urlDecode(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

func b64urlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// VerifyHS256 validates a HS256 JWT (dev contract, SPEC 1.3).
func VerifyHS256(token, secret string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := B64urlDecode(parts[2])
	if err != nil || !hmac.Equal(mac.Sum(nil), sig) {
		return nil, false
	}
	payload, err := B64urlDecode(parts[1])
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, false
	}
	if exp, ok := claims["exp"].(float64); ok && int64(exp) < time.Now().Unix() {
		return nil, false
	}
	return claims, true
}

// MintHS256 issues a dev HS256 JWT (used by tests and dev tooling).
func MintHS256(secret string, claims map[string]any) string {
	if claims == nil {
		claims = map[string]any{}
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(8 * time.Hour).Unix()
	}
	hdr, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	pl, _ := json.Marshal(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(b64urlEncode(hdr) + "." + b64urlEncode(pl)))
	return b64urlEncode(hdr) + "." + b64urlEncode(pl) + "." + b64urlEncode(mac.Sum(nil))
}
