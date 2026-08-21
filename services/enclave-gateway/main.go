// Command enclave-gateway is THE audited API gateway for the Meridian sovereign
// zone: the sole north-south path for cross-zone flows F1-F8 (SPEC 5).
//
// F9/F10 are FORBIDDEN BY CONSTRUCTION: no routes are registered and deny
// middleware rejects any matching path before it can reach a handler.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/munisp/meridian-gov-enclave/packages/authx"
	"github.com/munisp/meridian-gov-enclave/packages/httpx"
	"github.com/munisp/meridian-gov-enclave/packages/keyx/provider"
)

type ctxKey string

const (
	ctxPrincipal ctxKey = "principal"
	ctxCaller    ctxKey = "caller"
)

type Server struct {
	cfg       Config
	authn     *authx.Authenticator
	http      *http.Client
	worm      WORMStore
	localWorm *LocalWORMStore
	mu        sync.Mutex
	receipts  []*EvidenceReceipt // in-memory receipt log (admin console)
	perm      *PermifyClient     // non-nil when PERMIFY_URL selects live authz (P0)
}

func main() {
	cfg := loadConfig()
	cfg.applyDevDefaults()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("config invalid (fail closed): %v", err)
	}
	worm, local, err := newWORMStore(cfg)
	if err != nil {
		log.Fatalf("worm store: %v", err)
	}
	// Key provider abstraction (KEY_PROVIDER): dev default is a software
	// receipt key under <dataRoot>/signing; hsm|pkcs11|cloud-kms route
	// receipt signing to the HSM/KMS. Configured-but-unavailable provider is
	// a hard startup failure (fail-closed — no silent software fallback).
	keyProv, err := provider.NewFromEnv()
	if err != nil {
		log.Fatalf("key provider: %v", err)
	}
	receiptSigner, err := NewReceiptSigner(cfg.DataRoot, keyProv)
	if err != nil {
		log.Fatalf("receipt signer: %v", err)
	}
	if local != nil {
		local.SetReceiptSigner(receiptSigner)
	} else if api, ok := worm.(*APIWORMStore); ok {
		api.SetReceiptSigner(receiptSigner)
	}
	log.Printf("key provider: mode=%s (evidence receipt signing)", keyProv.Mode())
	// P0: Permify centralized authz — fail-closed in non-dev AUTH_MODE
	// without PERMIFY_URL (permify.go).
	perm, err := permifyFromEnv(cfg)
	if err != nil {
		log.Fatalf("permify authz (fail closed): %v", err)
	}
	s := &Server{cfg: cfg, authn: newAuthenticator(cfg),
		http: &http.Client{Timeout: 10 * time.Second}, worm: worm, localWorm: local, perm: perm}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)

	// Accepted flows F1-F5 (north-south ingress), F6 enclave-internal.
	for id, f := range s.flows() {
		flow := f
		mux.HandleFunc("POST /flows/"+strings.ToLower(id)+"/"+flow.Name,
			s.withAuth(func(w http.ResponseWriter, r *http.Request) { s.pipeline(w, r, flow) }))
	}
	// F7: serve signed attribution feeds. F8: WHT credit recon (pseudonymised,
	// every read logged).
	mux.HandleFunc("GET /flows/f7/attribution-feeds/{state}", s.withAuth(s.handleF7))
	mux.HandleFunc("GET /flows/f8/wht-credit-recon", s.withAuth(s.handleF8))
	// Receipt log for the admin console.
	mux.HandleFunc("GET /v1/receipts", s.withAuth(s.handleReceipts))
	// I19: sovereign audit-ledger cross-anchoring
	mux.HandleFunc("POST /v1/audit/anchors", s.withAuth(s.handleCreateAnchor))
	mux.HandleFunc("GET /v1/audit/anchors/verify", s.withAuth(s.handleVerifyAnchor))
	// I20: NDPA consent-receipt data-sharing gateway
	mux.HandleFunc("POST /v1/share/disclose", s.withAuth(s.handleDisclose))
	mux.HandleFunc("GET /v1/share/disclosures", s.withAuth(s.handleDisclosureLog))

	// NOTE: F9 and F10 have NO routes. Deny middleware below rejects their
	// paths explicitly; there is no code path that can dispatch them.
	handler := s.denyForbiddenFlows(s.logRequests(mux))

	addr := ":" + cfg.Port
	tlsCfg, err := serverTLSConfig(cfg)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}
	srv := httpx.NewServer(addr, handler)
	srv.TLSConfig = tlsCfg
	if tlsCfg != nil {
		log.Printf("enclave-gateway %s listening on %s TLS (worm=%s auth=%s mtls=%v)",
			cfg.Version, addr, worm.Mode(), cfg.AuthMode, cfg.RequireClientCert)
		log.Fatal(httpx.ServeTLS(srv, "", ""))
	}
	log.Printf("enclave-gateway %s listening on %s (worm=%s auth=%s)",
		cfg.Version, addr, worm.Mode(), cfg.AuthMode)
	log.Fatal(httpx.Serve(srv))
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "service": s.cfg.ServiceName, "version": s.cfg.Version})
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "worm_mode": s.worm.Mode()})
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := s.authn.PrincipalFrom(r)
		if p == nil {
			writeProblem(w, http.StatusUnauthorized, "Unauthorized",
				"Bearer JWT or X-Dev-Role (dev) required")
			return
		}
		// Stamp the verified caller identity (mTLS cert CN or JWT sub) BEFORE
		// anything is processed or forwarded (HARDENING H2/H5).
		caller := stampCaller(r, p)
		ctx := context.WithValue(r.Context(), ctxPrincipal, p)
		ctx = context.WithValue(ctx, ctxCaller, caller)
		next(w, r.WithContext(ctx))
	}
}

// denyForbiddenFlows rejects F9/F10 by construction (SPEC 5): any request whose
// path targets a forbidden flow is denied before routing.
func (s *Server) denyForbiddenFlows(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.ToLower(r.URL.Path)
		if strings.HasPrefix(p, "/flows/f9") || strings.HasPrefix(p, "/flows/f10") {
			writeProblem(w, http.StatusForbidden, "Forbidden flow",
				"flows F9/F10 are forbidden by construction: no code path exists to process them")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// upstreamGet forwards a read to an enclave-internal source with the verified
// caller identity stamped (X-Meridian-Caller).
func (s *Server) upstreamGet(r *http.Request, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if caller, ok := r.Context().Value(ctxCaller).(string); ok && caller != "" {
		req.Header.Set("X-Meridian-Caller", caller)
	}
	return s.http.Do(req)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

func (s *Server) logReceipt(rc *EvidenceReceipt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receipts = append([]*EvidenceReceipt{rc}, s.receipts...)
	if len(s.receipts) > 500 {
		s.receipts = s.receipts[:500]
	}
}

func (s *Server) handleReceipts(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(ctxPrincipal).(*Principal)
	if !s.scopeCheckAuthz(r, p, "receipts:read") {
		writeProblem(w, http.StatusForbidden, "Forbidden", "scope receipts:read required")
		return
	}
	s.mu.Lock()
	mem := make([]*EvidenceReceipt, len(s.receipts))
	copy(mem, s.receipts)
	s.mu.Unlock()
	var manifest []map[string]string
	if s.localWorm != nil {
		manifest = s.localWorm.ListReceipts(200)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"worm_mode": s.worm.Mode(), "receipts": mem, "manifest": manifest,
	})
}

// handleF7 serves signed JRB attribution feeds (F7). Feeds are produced by the
// jrb service and ed25519-signed; the gateway verifies the signature before
// serving. Dev fallback: local feed store under <data>/feeds/.
func (s *Server) handleF7(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(ctxPrincipal).(*Principal)
	if !s.scopeCheckAuthz(r, p, "flow:f7:read") {
		writeProblem(w, http.StatusForbidden, "Forbidden", "scope flow:f7:read required")
		return
	}
	state := r.PathValue("state")
	var feed []byte
	if s.cfg.JRBURL != "" {
		resp, err := s.upstreamGet(r, s.cfg.JRBURL+"/v1/attribution/feeds/"+state+"/latest")
		if err != nil {
			writeProblem(w, http.StatusBadGateway, "JRB unreachable", err.Error())
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			writeProblem(w, resp.StatusCode, "Feed unavailable", "jrb returned "+resp.Status)
			return
		}
		feed, _ = io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	} else {
		data, err := os.ReadFile(filepath.Join(s.cfg.DataRoot, "feeds", state+".json"))
		if err != nil {
			writeProblem(w, http.StatusNotFound, "Feed not found",
				"no signed attribution feed for state "+state)
			return
		}
		feed = data
	}
	var doc struct {
		Feed      json.RawMessage `json:"feed"`
		Signature string          `json:"signature"`
		PublicKey string          `json:"public_key"`
	}
	if err := json.Unmarshal(feed, &doc); err != nil || doc.Signature == "" || doc.PublicKey == "" {
		writeProblem(w, http.StatusBadGateway, "Malformed feed", "feed lacks ed25519 signature block")
		return
	}
	pub, err := hex.DecodeString(doc.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		writeProblem(w, http.StatusBadGateway, "Malformed feed", "invalid public key")
		return
	}
	sig, err := hex.DecodeString(doc.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), doc.Feed, sig) {
		writeProblem(w, http.StatusBadGateway, "Signature verification failed",
			"attribution feed signature invalid; refusing to serve")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(feed)
}

// handleF8 answers WHT credit reconciliation queries (F8). Responses are
// pseudonymised (pseudo_tin only) and EVERY read is logged to the read-audit log.
func (s *Server) handleF8(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(ctxPrincipal).(*Principal)
	if !s.scopeCheckAuthz(r, p, "flow:f8:read") {
		writeProblem(w, http.StatusForbidden, "Forbidden", "scope flow:f8:read required")
		return
	}
	pseudo := r.URL.Query().Get("pseudo_tin")
	if !strings.HasPrefix(pseudo, "ptin_") {
		writeProblem(w, http.StatusBadRequest, "Bad request",
			"pseudo_tin query param required (ptin_...); raw TINs are never accepted")
		return
	}
	s.logRead(p, pseudo)

	var entry map[string]any
	if s.cfg.WHTReconURL != "" {
		resp, err := s.upstreamGet(r, s.cfg.WHTReconURL+"/v1/wht/credits/"+pseudo)
		if err != nil {
			writeProblem(w, http.StatusBadGateway, "WHT service unreachable", err.Error())
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			writeProblem(w, http.StatusNotFound, "No credits", "no WHT credits for "+pseudo)
			return
		}
		_ = json.NewDecoder(resp.Body).Decode(&entry)
	} else {
		entry = s.localRecon(pseudo)
		if entry == nil {
			writeProblem(w, http.StatusNotFound, "No credits", "no WHT credits for "+pseudo)
			return
		}
	}
	// Defence in depth: strip anything that is not pseudonymised.
	delete(entry, "tin")
	delete(entry, "vendor_tin")
	delete(entry, "legal_name")
	writeJSON(w, http.StatusOK, map[string]any{
		"pseudo_tin": pseudo, "credits": entry, "disclosure": "pseudonymised response; read logged",
	})
}

func (s *Server) localRecon(pseudo string) map[string]any {
	data, err := os.ReadFile(filepath.Join(s.cfg.DataRoot, "wht_recon.json"))
	if err != nil {
		return nil
	}
	var store map[string]map[string]any
	if err := json.Unmarshal(data, &store); err != nil {
		return nil
	}
	return store[pseudo]
}

func (s *Server) logRead(p *Principal, pseudo string) {
	dir := s.cfg.DataRoot
	_ = os.MkdirAll(dir, 0o755)
	f, err := os.OpenFile(filepath.Join(dir, "read-audit.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	line, _ := json.Marshal(map[string]any{
		"time": time.Now().UTC().Format(time.RFC3339), "flow": "F8",
		"principal": p.Sub, "roles": p.Roles, "pseudo_tin": pseudo,
	})
	_, _ = f.Write(append(line, '\n'))
}
