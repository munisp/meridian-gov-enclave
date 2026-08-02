// permify.go — P0: centralized authorization via the Permify server.
//
// Env-selected like the other middleware (HARDENING H1/H3):
//   - PERMIFY_URL set   -> live Permify Check API (POST
//     /v1/tenants/{tenant}/permissions/check); scope "flow:f1:send" becomes
//     entity flow:f1 permission send; "receipts:read" becomes entity
//     receipts:gateway permission read.
//   - PERMIFY_URL unset -> existing dev role->scope map, honest log.
//   - AUTH_MODE != dev + PERMIFY_URL unset -> startup FAILS CLOSED (same
//     contract as TLS/INTERNAL_FLOW_TOKEN in Config.Validate): no silent
//     decentralized authz in prod.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// PermifyClient is a thin stdlib client for the Permify Check API v1.
type PermifyClient struct {
	base    string
	tenant  string
	hc      *http.Client
	timeout time.Duration
}

// NewPermifyClient builds a client for the server at baseURL.
func NewPermifyClient(baseURL, tenant string) *PermifyClient {
	if tenant == "" {
		tenant = "t1"
	}
	return &PermifyClient{
		base:    strings.TrimRight(baseURL, "/"),
		tenant:  tenant,
		hc:      &http.Client{},
		timeout: 2 * time.Second,
	}
}

type permifyRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func splitPermifyRef(s string) (permifyRef, error) {
	i := strings.Index(s, ":")
	if i <= 0 || i == len(s)-1 {
		return permifyRef{}, fmt.Errorf("permify reference %q must be type:id", s)
	}
	return permifyRef{Type: s[:i], ID: s[i+1:]}, nil
}

// Check reports whether subject holds entity#permission. One retry on 5xx,
// 2s timeout, failures are circuit-logged and returned as errors (callers
// fail closed).
func (c *PermifyClient) Check(ctx context.Context, entity, permission, subject string) (bool, error) {
	ent, err := splitPermifyRef(entity)
	if err != nil {
		return false, err
	}
	sub, err := splitPermifyRef(subject)
	if err != nil {
		return false, err
	}
	body, _ := json.Marshal(map[string]any{
		"entity": ent, "permission": permission, "subject": sub,
	})
	url := c.base + "/v1/tenants/" + c.tenant + "/permissions/check"

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		allowed, retryable, err := c.do(ctx, url, body)
		if err == nil {
			return allowed, nil
		}
		lastErr = err
		log.Printf("component=permify circuit: check %s#%s@%s attempt %d failed: %v",
			entity, permission, subject, attempt+1, err)
		if !retryable {
			break
		}
	}
	return false, lastErr
}

func (c *PermifyClient) do(ctx context.Context, url string, body []byte) (allowed, retryable bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return false, false, fmt.Errorf("permify check transport: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 500 {
		return false, true, fmt.Errorf("permify check status %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return false, false, fmt.Errorf("permify check status %d", resp.StatusCode)
	}
	var out struct {
		Can     string `json:"can"`
		Allowed *bool  `json:"allowed"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return false, false, fmt.Errorf("permify check decode: %w", err)
	}
	if out.Allowed != nil {
		return *out.Allowed, false, nil
	}
	return out.Can == "RESULT_ALLOWED", false, nil
}

// scopeToRef maps a gateway scope to a Permify entity + permission:
//   - "flow:f1:send"  -> entity flow:f1, permission send
//   - "receipts:read" -> entity receipts:gateway, permission read
func scopeToRef(scope string) (entity, permission string, err error) {
	parts := strings.Split(scope, ":")
	switch len(parts) {
	case 3:
		return parts[0] + ":" + parts[1], parts[2], nil
	case 2:
		return parts[0] + ":gateway", parts[1], nil
	}
	return "", "", fmt.Errorf("malformed scope %q", scope)
}

// permifyFromEnv wires the client; error only for the prod fail-closed case
// (main log.Fatals, mirroring Config.Validate's contract).
func permifyFromEnv(cfg Config) (*PermifyClient, error) {
	if base := os.Getenv("PERMIFY_URL"); base != "" {
		log.Printf("component=enclave-gateway permify=live url=%s tenant=%s",
			base, getenv("PERMIFY_TENANT", "t1"))
		return NewPermifyClient(base, os.Getenv("PERMIFY_TENANT")), nil
	}
	if cfg.AuthMode != "dev" && cfg.AuthMode != "" {
		return nil, fmt.Errorf("AUTH_MODE=%s requires PERMIFY_URL (centralized authz fail-closed; refusing the dev role-scope map)", cfg.AuthMode)
	}
	log.Printf("profile=dev component=enclave-gateway WARNING: PERMIFY_URL unset; using dev role->scope map (Permify not consulted)")
	return nil, nil
}

// scopeCheckAuthz routes the scope decision: live Permify when wired, else
// the dev role->scope map. Permify errors fail closed (deny).
func (s *Server) scopeCheckAuthz(r *http.Request, p *Principal, scope string) bool {
	if s.perm == nil {
		return scopeCheck(p, scope)
	}
	entity, permission, err := scopeToRef(scope)
	if err != nil {
		log.Printf("component=enclave-gateway %v; denying", err)
		return false
	}
	subject := "user:" + p.Sub
	allowed, err := s.perm.Check(r.Context(), entity, permission, subject)
	if err != nil {
		log.Printf("component=enclave-gateway permify check failed (%v); request denied (fail-closed)", err)
		return false
	}
	return allowed
}
