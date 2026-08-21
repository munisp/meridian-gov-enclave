// Command ombud implements the Tax Ombud institutional service (T13i): case
// registry with lifecycle + deadlines, 20% appeal deposit holds on ledger 500,
// WORM evidence packs, rp-procedure-* / rp-ntaa-penalties / rp-deposit-20pct
// pack loading (embedded fallback), registry/clerk/member roles,
// privilege-filtered search, and an activation gate on Ombud rules.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/munisp/meridian-gov-enclave/packages/authx"
	"github.com/munisp/meridian-gov-enclave/packages/eventx"
	"github.com/munisp/meridian-gov-enclave/packages/httpx"
	"github.com/munisp/meridian-gov-enclave/packages/storex"
)

type ctxKey string

const ctxPrincipal ctxKey = "principal"

// Ombud roles: registry (admin), clerk (intake/processing), member (decisions).
const (
	RoleRegistry = "registry"
	RoleClerk    = "clerk"
	RoleMember   = "member"
)

type Server struct {
	cfg        Config
	authn      *authx.Authenticator
	cases      *CaseStore
	ledger     LedgerClient
	worm       WORMStore
	gate       GateClient
	localGate  *LocalGateClient
	depositBps int
	emitter    eventx.Emitter
}

func main() {
	cfg := loadConfig()
	// Pack parameters (embedded fallback packs; production: rp-registry pins).
	ackDays := packInt(cfg.PacksDir, "rp-procedure-ombud", "days", 7)
	decideDays := 90
	depositBps := packInt(cfg.PacksDir, "rp-deposit-20pct", "rate_bps", 2000)

	pg, err := storex.Open(context.Background(), cfg.DatabaseURL, "ombud",
		storex.DocTableDDL(CasesTable))
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer pg.Close()
	cases, err := NewCaseStore(cfg.DataRoot, ackDays, decideDays, pg)
	if err != nil {
		log.Fatal(err)
	}
	worm, _, err := newWORMStore(cfg)
	if err != nil {
		log.Fatal(err)
	}
	gate, localGate := newGateClient(cfg)
	emitter := eventx.New("ombud", cfg.DataRoot)
	defer emitter.Close()
	s := &Server{cfg: cfg, authn: newAuthenticator(cfg), cases: cases, ledger: newLedgerClient(cfg), worm: worm,
		gate: gate, localGate: localGate, depositBps: depositBps, emitter: emitter}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("POST /v1/cases", s.withAuth(s.intakeCase))
	mux.HandleFunc("GET /v1/cases", s.withAuth(s.listCases))
	mux.HandleFunc("GET /v1/cases/{id}", s.withAuth(s.getCase))
	mux.HandleFunc("POST /v1/cases/{id}/transition", s.withAuth(s.transitionCase))
	mux.HandleFunc("POST /v1/cases/{id}/deposit", s.withAuth(s.placeDeposit))
	mux.HandleFunc("POST /v1/cases/{id}/deposit/release", s.withAuth(s.releaseDeposit))
	mux.HandleFunc("POST /v1/cases/{id}/deposit/settle", s.withAuth(s.settleDeposit))
	mux.HandleFunc("POST /v1/cases/{id}/documents", s.withAuth(s.addDocument))
	mux.HandleFunc("POST /v1/cases/{id}/evidence-pack", s.withAuth(s.buildEvidencePack))
	mux.HandleFunc("GET /v1/search", s.withAuth(s.search))
	mux.HandleFunc("GET /v1/gate", s.withAuth(s.getGate))
	mux.HandleFunc("POST /v1/gate/flip", s.withAuth(s.flipGate))
	mux.HandleFunc("GET /v1/packs", s.withAuth(s.listPacks))

	log.Printf("ombud %s listening on :%s (ledger=%s worm=%s gate=%s)",
		cfg.Version, cfg.Port, s.ledger.Mode(), worm.Mode(), gate.Mode())
	log.Fatal(httpx.ListenAndServe(":"+cfg.Port, mux))
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": s.cfg.ServiceName, "version": s.cfg.Version})
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	active, mode, _ := s.gate.Active("ombud.rules_active")
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "ledger_mode": s.ledger.Mode(),
		"worm_mode": s.worm.Mode(), "gate_mode": mode, "ombud_rules_active": active})
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := s.authn.PrincipalFrom(r)
		if p == nil {
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Bearer JWT or X-Dev-Role (dev) required")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxPrincipal, p)))
	}
}

// roleOf maps principal roles onto ombud institutional roles. The
// X-Ombud-Role header selects the institutional role explicitly in DEV mode
// only (audit fix H-2): in keycloak mode the header is ignored and the role
// derives solely from the verified token claims.
func (s *Server) roleOf(r *http.Request, p *Principal) string {
	if s.authn.DevMode() {
		if v := r.Header.Get("X-Ombud-Role"); v == RoleRegistry || v == RoleClerk || v == RoleMember {
			return v
		}
	}
	if p.HasRole("admin") {
		return RoleRegistry
	}
	if p.HasRole("operator") {
		return RoleClerk
	}
	return RoleMember
}

// requireGate refuses rule-governed actions while the activation gate is off.
func (s *Server) requireGate(w http.ResponseWriter) bool {
	active, mode, err := s.gate.Active("ombud.rules_active")
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "Gate check failed", err.Error())
		return false
	}
	if !active {
		writeProblem(w, http.StatusServiceUnavailable, "Ombud rules not activated",
			"gate ombud.rules_active is OFF ("+mode+"); board activation required")
		return false
	}
	return true
}

// ------------------------------------------------------------------ cases
func (s *Server) intakeCase(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(ctxPrincipal).(*Principal)
	role := s.roleOf(r, p)
	if role == RoleMember {
		writeProblem(w, http.StatusForbidden, "Forbidden", "members do not intake cases (clerk/registry)")
		return
	}
	var c Case
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&c); err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	out, err := s.cases.Intake(p.Sub, &c)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	if s.emitter != nil {
		_ = s.emitter.Emit(r.Context(), "nrs.dispute.ombud.v1", eventx.Envelope{
			Type: "nrs.dispute.ombud.v1",
			Data: map[string]any{"case_id": out.ID, "state": out.State,
				"appellant_pseudo_tin": out.AppellantPseudoTIN, "tax_type": out.TaxType},
		})
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) listCases(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(ctxPrincipal).(*Principal)
	role := s.roleOf(r, p)
	priv := role == RoleRegistry || role == RoleMember
	writeJSON(w, http.StatusOK, map[string]any{"cases": s.cases.Search("", priv)})
}

func (s *Server) getCase(w http.ResponseWriter, r *http.Request) {
	c, ok := s.cases.Get(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusNotFound, "Not found", "unknown case")
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) transitionCase(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(ctxPrincipal).(*Principal)
	role := s.roleOf(r, p)
	var body struct {
		Action  string `json:"action"`
		Detail  string `json:"detail"`
		Outcome string `json:"outcome"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	if body.Action == "decide" || body.Action == "close" {
		if role != RoleMember && role != RoleRegistry {
			writeProblem(w, http.StatusForbidden, "Forbidden", "only members may decide/close")
			return
		}
		if !s.requireGate(w) {
			return
		}
	}
	c, err := s.cases.Transition(p.Sub, r.PathValue("id"), body.Action, body.Detail)
	if err != nil {
		writeProblem(w, http.StatusConflict, "Transition failed", err.Error())
		return
	}
	if body.Outcome != "" {
		c.Outcome = body.Outcome
	}
	writeJSON(w, http.StatusOK, c)
}

// ------------------------------------------------------------------ deposits (ledger 500)
func (s *Server) placeDeposit(w http.ResponseWriter, r *http.Request) {
	if !s.requireGate(w) {
		return
	}
	c, ok := s.cases.Get(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusNotFound, "Not found", "unknown case")
		return
	}
	if c.Deposit != nil && c.Deposit.Status == "held" {
		writeProblem(w, http.StatusConflict, "Conflict", "active deposit hold already exists")
		return
	}
	// rp-deposit-20pct: 20% of disputed amount (rate_bps from pack).
	amount := c.DisputedAmountKobo * int64(s.depositBps) / 10000
	var serial uint64
	fmt.Sscanf(c.ID, "OMB-%06d", &serial)
	hold, err := s.ledger.Hold(c.ID, serial, amount)
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "Ledger error", err.Error())
		return
	}
	if err := s.cases.AttachDeposit(c.ID, hold); err != nil {
		writeProblem(w, http.StatusInternalServerError, "Store error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"deposit": hold,
		"rule": "rp-deposit-20pct: 20% of disputed amount, ledger 500 hold (code 6)"})
}

func (s *Server) releaseDeposit(w http.ResponseWriter, r *http.Request) {
	s.resolveDeposit(w, r, false)
}

func (s *Server) settleDeposit(w http.ResponseWriter, r *http.Request) {
	s.resolveDeposit(w, r, true)
}

func (s *Server) resolveDeposit(w http.ResponseWriter, r *http.Request, settle bool) {
	if !s.requireGate(w) {
		return
	}
	c, ok := s.cases.Get(r.PathValue("id"))
	if !ok || c.Deposit == nil {
		writeProblem(w, http.StatusNotFound, "Not found", "no deposit hold on case")
		return
	}
	var err error
	if settle {
		err = s.ledger.Settle(c.Deposit.HoldID) // code 5/7 per rp-deposit-20pct outcome rule
	} else {
		err = s.ledger.Release(c.Deposit.HoldID)
	}
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "Ledger error", err.Error())
		return
	}
	verb := "released (code 7) to appellant"
	if settle {
		verb = "settled (code 5) to revenue"
	}
	writeJSON(w, http.StatusOK, map[string]any{"hold_id": c.Deposit.HoldID, "result": verb})
}

// ------------------------------------------------------------------ documents & evidence packs
func (s *Server) addDocument(w http.ResponseWriter, r *http.Request) {
	var doc CaseDoc
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&doc); err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	if doc.DocID == "" || doc.Title == "" {
		writeProblem(w, http.StatusBadRequest, "Bad request", "doc_id and title required")
		return
	}
	if err := s.cases.AddDocument(r.PathValue("id"), doc); err != nil {
		writeProblem(w, http.StatusNotFound, "Not found", "unknown case")
		return
	}
	writeJSON(w, http.StatusCreated, doc)
}

func (s *Server) buildEvidencePack(w http.ResponseWriter, r *http.Request) {
	c, ok := s.cases.Get(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusNotFound, "Not found", "unknown case")
		return
	}
	// Evidence pack: canonical JSON of the case file -> WORM store.
	payload, _ := json.Marshal(map[string]any{
		"kind": "ombud-evidence-pack", "case": c,
		"assembled_at": time.Now().UTC().Format(time.RFC3339),
		"rule_packs": []string{"rp-procedure-ombud@1.0.0", "rp-procedure-tat@1.0.0",
			"rp-ntaa-penalties@1.0.0", "rp-deposit-20pct@1.0.0"},
	})
	rc, err := s.worm.Store("ombud", c.ID, payload)
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "WORM store error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"evidence_receipt": rc})
}

// ------------------------------------------------------------------ search (privilege-filtered)
func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(ctxPrincipal).(*Principal)
	role := s.roleOf(r, p)
	priv := role == RoleRegistry || role == RoleMember
	q := r.URL.Query().Get("q")
	writeJSON(w, http.StatusOK, map[string]any{"q": q, "role": role,
		"privileged_visible": priv, "results": s.cases.Search(q, priv),
		"index": "dev in-process index (OpenSearch wired in prod)"})
}

// ------------------------------------------------------------------ gate & packs
func (s *Server) getGate(w http.ResponseWriter, _ *http.Request) {
	active, mode, _ := s.gate.Active("ombud.rules_active")
	writeJSON(w, http.StatusOK, map[string]any{"gate": "ombud.rules_active",
		"active": active, "mode": mode})
}

func (s *Server) flipGate(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(ctxPrincipal).(*Principal)
	if s.roleOf(r, p) != RoleRegistry {
		writeProblem(w, http.StatusForbidden, "Forbidden", "registry role required to flip gates")
		return
	}
	if s.localGate == nil {
		writeProblem(w, http.StatusConflict, "Conflict",
			"gate managed by reg-watch API; flip there (board-authorized)")
		return
	}
	var body struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	if err := s.localGate.Flip("ombud.rules_active", body.Active); err != nil {
		writeProblem(w, http.StatusInternalServerError, "Gate error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"gate": "ombud.rules_active", "active": body.Active})
}

func (s *Server) listPacks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"packs": []string{
		"rp-procedure-ombud@1.0.0", "rp-procedure-tat@1.0.0",
		"rp-ntaa-penalties@1.0.0", "rp-deposit-20pct@1.0.0"},
		"source":           "embedded fallback packs; production pins from rp-registry",
		"deposit_rate_bps": s.depositBps,
	})
}
