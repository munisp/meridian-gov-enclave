package authx

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDevHS256AndDevRole(t *testing.T) {
	a := New(Config{Mode: "dev", DevSecret: "s3cret", DevRoleHdr: true}, "test")
	tok := MintHS256("s3cret", map[string]any{"sub": "alice", "roles": []string{"operator"}})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	p := a.PrincipalFrom(req)
	if p == nil || p.Sub != "alice" || !p.HasRole("operator") {
		t.Fatalf("hs256 principal: %+v", p)
	}
	// Wrong secret rejected.
	bad := MintHS256("wrong", map[string]any{"sub": "mallory"})
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", "Bearer "+bad)
	if a.PrincipalFrom(req2) != nil {
		t.Fatal("bad secret must be rejected")
	}
	// X-Dev-Role fallback in dev mode only.
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.Header.Set("X-Dev-Role", "auditor")
	if p := a.PrincipalFrom(req3); p == nil || !p.HasRole("auditor") {
		t.Fatal("dev role fallback")
	}
	// Expired token rejected.
	exp := MintHS256("s3cret", map[string]any{"sub": "x", "exp": time.Now().Add(-time.Hour).Unix()})
	req4 := httptest.NewRequest("GET", "/", nil)
	req4.Header.Set("Authorization", "Bearer "+exp)
	if a.PrincipalFrom(req4) != nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestKeycloakRS256JWKS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Serve a JWKS document.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := b64urlEncode(key.PublicKey.N.Bytes())
		e := b64urlEncode(big.NewInt(int64(key.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": n, "e": e}},
		})
	}))
	defer srv.Close()

	issuer := "https://keycloak:8443/realms/meridian"
	a := New(Config{Mode: "keycloak", Issuer: issuer, Audience: "meridian-services", JWKSURL: srv.URL}, "test")

	sign := func(claims map[string]any) string {
		hdr, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"})
		pl, _ := json.Marshal(claims)
		sum := sha256.Sum256([]byte(b64urlEncode(hdr) + "." + b64urlEncode(pl)))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		return b64urlEncode(hdr) + "." + b64urlEncode(pl) + "." + b64urlEncode(sig)
	}
	good := sign(map[string]any{
		"sub": "svc-jrb", "iss": issuer, "aud": "meridian-services",
		"exp": time.Now().Add(time.Hour).Unix(),
		"realm_access": map[string]any{"roles": []string{"operator"}},
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+good)
	p := a.PrincipalFrom(req)
	if p == nil || p.Sub != "svc-jrb" || !p.HasRole("operator") {
		t.Fatalf("rs256 principal: %+v", p)
	}

	cases := map[string]map[string]any{
		"wrong iss": {"sub": "x", "iss": "https://evil", "aud": "meridian-services", "exp": time.Now().Add(time.Hour).Unix()},
		"wrong aud": {"sub": "x", "iss": issuer, "aud": "other", "exp": time.Now().Add(time.Hour).Unix()},
		"expired":   {"sub": "x", "iss": issuer, "aud": "meridian-services", "exp": time.Now().Add(-time.Hour).Unix()},
	}
	for name, claims := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+sign(claims))
		if a.PrincipalFrom(req) != nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
	// No X-Dev-Role fallback in keycloak mode.
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Dev-Role", "admin")
	if a.PrincipalFrom(req2) != nil {
		t.Fatal("X-Dev-Role must not be honoured in keycloak mode")
	}
}
