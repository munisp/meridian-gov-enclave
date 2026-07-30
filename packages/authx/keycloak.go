package authx

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwksCache caches a Keycloak JWKS for 5 minutes and refreshes on unknown kid
// (HARDENING H2).
type jwksCache struct {
	url     string
	ttl     time.Duration
	client  *http.Client
	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

func newJWKSCache(url string, ttl time.Duration) *jwksCache {
	return &jwksCache{url: url, ttl: ttl, client: &http.Client{Timeout: 5 * time.Second},
		keys: map[string]*rsa.PublicKey{}}
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (c *jwksCache) refresh() error {
	resp, err := c.client.Get(c.url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nb, err := B64urlDecode(k.N)
		if err != nil {
			continue
		}
		eb, err := B64urlDecode(k.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
	}
	c.mu.Lock()
	c.keys = keys
	c.fetched = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *jwksCache) key(kid string) (*rsa.PublicKey, bool) {
	c.mu.RLock()
	stale := time.Since(c.fetched) > c.ttl
	k, ok := c.keys[kid]
	c.mu.RUnlock()
	if stale || !ok {
		// refresh on TTL expiry or unknown kid.
		_ = c.refresh()
		c.mu.RLock()
		k, ok = c.keys[kid]
		c.mu.RUnlock()
	}
	return k, ok
}

// verifyRS256 validates an RS256 Bearer token against the Keycloak JWKS and
// enforces iss/exp/aud per the H1 contract.
func (a *Authenticator) verifyRS256(token string) (map[string]any, bool) {
	if a.jwks == nil {
		return nil, false
	}
	headerB64, payloadB64, sigB64, ok := splitToken(token)
	if !ok {
		return nil, false
	}
	hdrBytes, err := B64urlDecode(headerB64)
	if err != nil {
		return nil, false
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil || hdr.Alg != "RS256" {
		return nil, false
	}
	pub, ok := a.jwks.key(hdr.Kid)
	if !ok {
		return nil, false
	}
	sig, err := B64urlDecode(sigB64)
	if err != nil {
		return nil, false
	}
	sum := sha256.Sum256([]byte(headerB64 + "." + payloadB64))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, false
	}
	payload, err := B64urlDecode(payloadB64)
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, false
	}
	now := time.Now().Unix()
	if exp, ok := claims["exp"].(float64); !ok || int64(exp) < now {
		return nil, false
	}
	if nbf, ok := claims["nbf"].(float64); ok && int64(nbf) > now {
		return nil, false
	}
	if a.cfg.Issuer != "" {
		if iss, _ := claims["iss"].(string); iss != a.cfg.Issuer {
			return nil, false
		}
	}
	if a.cfg.Audience != "" && !audContains(claims["aud"], a.cfg.Audience) {
		return nil, false
	}
	return claims, true
}

func splitToken(tok string) (h, p, s string, ok bool) {
	var parts []string
	for start, i := 0, 0; ; i++ {
		if i == len(tok) || tok[i] == '.' {
			parts = append(parts, tok[start:i])
			if i == len(tok) {
				break
			}
			start = i + 1
		}
	}
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func audContains(v any, want string) bool {
	switch vv := v.(type) {
	case string:
		return vv == want
	case []any:
		for _, x := range vv {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
