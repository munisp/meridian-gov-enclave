package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Principal is the authenticated caller.
type Principal struct {
	Sub      string
	Roles    []string
	TenantID string
}

func (p Principal) HasRole(r string) bool {
	for _, x := range p.Roles {
		if x == r {
			return true
		}
	}
	return false
}

func b64urlDecode(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

// decodeHS256 validates a HS256 JWT and returns its claims (SPEC 1.3).
func decodeHS256(token, secret string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := b64urlDecode(parts[2])
	if err != nil || !hmac.Equal(mac.Sum(nil), sig) {
		return nil, false
	}
	payload, err := b64urlDecode(parts[1])
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

func principalFrom(r *http.Request, cfg Config) *Principal {
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		if claims, ok := decodeHS256(strings.TrimSpace(authz[7:]), cfg.JWTSecret); ok {
			p := &Principal{Sub: "unknown"}
			if s, ok := claims["sub"].(string); ok {
				p.Sub = s
			}
			if t, ok := claims["tenant_id"].(string); ok {
				p.TenantID = t
			}
			switch roles := claims["roles"].(type) {
			case string:
				p.Roles = []string{roles}
			case []any:
				for _, x := range roles {
					if s, ok := x.(string); ok {
						p.Roles = append(p.Roles, s)
					}
				}
			}
			return p
		}
	}
	if cfg.AuthMode == "dev" {
		role := r.Header.Get("X-Dev-Role")
		switch role {
		case "admin", "operator", "auditor":
			return &Principal{Sub: "dev-" + role, Roles: []string{role}, TenantID: "dev"}
		}
	}
	return nil
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
