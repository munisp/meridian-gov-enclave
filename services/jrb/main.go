// Command jrb implements the Joint Revenue Board service (T11): authority
// registry, authority onboarding, EOI with four-party visibility, per-state
// adapter framework, NTAA attribution feed builder (ed25519-signed), and
// wf-jrb-* workflows. Cross-zone sends go ONLY via enclave-gateway with WORM
// receipt capture.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/munisp/meridian-gov-enclave/packages/authx"
	"github.com/munisp/meridian-gov-enclave/packages/eventx"
	"github.com/munisp/meridian-gov-enclave/packages/storex"
)

type ctxKey string

const ctxPrincipal ctxKey = "principal"

type Server struct {
	cfg       Config
	authn     *authx.Authenticator
	auth      *AuthorityStore
	eoi       *EOIStore
	adapters  *AdapterRegistry
	formula   *AttributionFormula
	signer    *FeedSigner
	runner    *WorkflowRunner
	gateway   *GatewayClient
	emitter   eventx.Emitter
	http      *http.Client
}

func main() {
	cfg := loadConfig()
	pg, err := storex.Open(context.Background(), cfg.DatabaseURL, "jrb",
		storex.DocTableDDL(AuthoritiesTable), storex.DocTableDDL(EOITable))
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer pg.Close()
	auth, err := NewAuthorityStore(cfg.DataRoot, pg)
	if err != nil {
		log.Fatal(err)
	}
	eoiStore, err := NewEOIStore(cfg.DataRoot, pg)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := NewFeedSigner(cfg.DataRoot)
	if err != nil {
		log.Fatal(err)
	}
	emitter := eventx.New("jrb", cfg.DataRoot)
	defer emitter.Close()
	s := &Server{
		cfg: cfg, authn: newAuthenticator(cfg), auth: auth, eoi: eoiStore, adapters: NewAdapterRegistry(),
		formula: LoadAttributionFormula(cfg.PacksDir), signer: signer,
		runner: NewWorkflowRunner(), http: &http.Client{Timeout: 10 * time.Second},
		emitter: emitter,
		gateway: &GatewayClient{base: cfg.EnclaveGatewayURL, token: cfg.InternalFlowToken,
			http: &http.Client{Timeout: 10 * time.Second}},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /v1/authorities", s.withAuth(s.listAuthorities))
	mux.HandleFunc("POST /v1/authorities", s.withAuth(s.upsertAuthority))
	mux.HandleFunc("GET /v1/authorities/{id}", s.withAuth(s.getAuthority))
	mux.HandleFunc("PUT /v1/authorities/{id}", s.withAuth(s.upsertAuthority))
	mux.HandleFunc("DELETE /v1/authorities/{id}", s.withAuth(s.deleteAuthority))
	mux.HandleFunc("POST /v1/authorities/{id}/onboard", s.withAuth(s.onboardAuthority))
	mux.HandleFunc("POST /v1/eoi", s.withAuth(s.createEOI))
	mux.HandleFunc("GET /v1/eoi", s.withAuth(s.listEOI))
	mux.HandleFunc("GET /v1/eoi/{id}", s.withAuth(s.getEOI))
	mux.HandleFunc("POST /v1/eoi/{id}/answer", s.withAuth(s.answerEOI))
	mux.HandleFunc("GET /v1/adapters", s.withAuth(s.listAdapters))
	mux.HandleFunc("POST /v1/adapters/{state}/pull-filings", s.withAuth(s.pullFilings))
	mux.HandleFunc("POST /v1/attribution/feeds", s.withAuth(s.buildFeed))
	mux.HandleFunc("GET /v1/attribution/feeds/{state}/latest", s.latestFeed) // gateway F7 source; signature-verified by gateway
	mux.HandleFunc("GET /v1/workflows", s.withAuth(s.listWorkflows))
	mux.HandleFunc("POST /v1/workflows/{name}/run", s.withAuth(s.runWorkflow))
	mux.HandleFunc("GET /v1/workflows/runs", s.withAuth(s.listRuns))

	log.Printf("jrb %s listening on :%s (gateway=%q)", cfg.Version, cfg.Port, cfg.EnclaveGatewayURL)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, mux))
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": s.cfg.ServiceName, "version": s.cfg.Version})
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready",
		"authorities": len(s.auth.List()), "reference_adapters": s.adapters.ReferenceAdapters()})
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

// ------------------------------------------------------------------ authorities
func (s *Server) listAuthorities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"authorities": s.auth.List()})
}

func (s *Server) getAuthority(w http.ResponseWriter, r *http.Request) {
	a, ok := s.auth.Get(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusNotFound, "Not found", "unknown authority")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) upsertAuthority(w http.ResponseWriter, r *http.Request) {
	var a Authority
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&a); err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	if id := r.PathValue("id"); id != "" {
		a.ID = id
	}
	if a.ID == "" || a.Name == "" || a.Kind == "" {
		writeProblem(w, http.StatusBadRequest, "Bad request", "id, name, kind required")
		return
	}
	if a.Status == "" {
		a.Status = "seeded"
	}
	if err := s.auth.Upsert(&a); err != nil {
		writeProblem(w, http.StatusInternalServerError, "Store error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) deleteAuthority(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "NRS" || id == "JRB-SEC" {
		writeProblem(w, http.StatusConflict, "Conflict", "NRS and JRB-SEC cannot be deleted")
		return
	}
	if err := s.auth.Delete(id); err != nil {
		writeProblem(w, http.StatusInternalServerError, "Store error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) onboardAuthority(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CertPEM string `json:"cert_pem"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	a, err := s.auth.Onboard(r.PathValue("id"), body.CertPEM)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "Onboarding failed", err.Error())
		return
	}
	if s.emitter != nil {
		_ = s.emitter.Emit(r.Context(), "nrs.jrb.onboard.v1", eventx.Envelope{
			Type: "nrs.jrb.onboard.v1",
			Data: map[string]any{"authority_id": a.ID, "kind": a.Kind, "status": a.Status,
				"cert_fingerprint": a.CertFingerprint},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"authority": a,
		"note": "dev profile: cert upload + SHA-256 fingerprint; prod profile: mTLS both directions + OIDC"})
}

// ------------------------------------------------------------------ EOI
func callerAuthority(r *http.Request) (string, bool) {
	id := r.Header.Get("X-Authority-Id")
	if id == "" {
		id = r.URL.Query().Get("authority_id")
	}
	return id, id == "JRB-SEC"
}

func (s *Server) createEOI(w http.ResponseWriter, r *http.Request) {
	var req EOI
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	e, err := s.eoi.Create(&req)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	// Cross-zone send ONLY via enclave-gateway; capture WORM receipt.
	payload, _ := json.Marshal(map[string]any{
		"eoi_id": e.ID, "requester_state": e.RequesterID, "responder_state": e.ResponderID,
		"subject_pseudo_tin": e.SubjectPseudoTIN, "purpose": e.Purpose, "request": e.Request,
	})
	res, err := s.gateway.SendF6EOI(payload)
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "Gateway send failed", err.Error())
		return
	}
	s.eoi.MarkSent(e.ID, res.ReceiptID)
	e, _ = s.eoi.GetFor(e.ID, e.RequesterID, false)
	writeJSON(w, http.StatusCreated, map[string]any{"eoi": e, "gateway_receipt": res,
		"visibility": "requester + responder + secretariat; fourth party hard-denied"})
}

func (s *Server) listEOI(w http.ResponseWriter, r *http.Request) {
	authID, isSec := callerAuthority(r)
	if authID == "" {
		writeProblem(w, http.StatusBadRequest, "Bad request", "X-Authority-Id header required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authority": authID, "is_secretariat": isSec,
		"visibility_banner": "You see only exchanges where you are requester, responder, or the JRB secretariat.",
		"items":             s.eoi.ListFor(authID, isSec),
	})
}

func (s *Server) getEOI(w http.ResponseWriter, r *http.Request) {
	authID, isSec := callerAuthority(r)
	e, err := s.eoi.GetFor(r.PathValue("id"), authID, isSec)
	if errors.Is(err, errNotFound) {
		writeProblem(w, http.StatusNotFound, "Not found", "unknown EOI")
		return
	}
	if errors.Is(err, errForbidden) {
		writeProblem(w, http.StatusForbidden, "Forbidden",
			"four-party visibility: only requester, responder and secretariat may view this exchange")
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) answerEOI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AuthorityID string `json:"authority_id"`
		Response    string `json:"response"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	e, err := s.eoi.Answer(r.PathValue("id"), body.AuthorityID, body.Response)
	if errors.Is(err, errNotFound) {
		writeProblem(w, http.StatusNotFound, "Not found", "unknown EOI")
		return
	}
	if errors.Is(err, errForbidden) {
		writeProblem(w, http.StatusForbidden, "Forbidden", "only the responder authority may answer")
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// ------------------------------------------------------------------ adapters
func (s *Server) listAdapters(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"reference_adapters": s.adapters.ReferenceAdapters(),
		"framework":          "StateAdapter interface; unregistered states use generic simulated adapter",
		"honesty":            "SIMULATED adapters in dev",
	})
}

func (s *Server) pullFilings(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = time.Now().UTC().Format("2006-01")
	}
	filings, err := s.adapters.For(r.PathValue("state")).PullFilings(period)
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "Adapter error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": r.PathValue("state"),
		"period": period, "filings": filings, "honesty": "SIMULATED adapter data"})
}

// ------------------------------------------------------------------ attribution
func (s *Server) buildFeed(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Period   string                  `json:"period"`
		PoolKobo int64                   `json:"pool_kobo"`
		Inputs   []StateConsumptionInput `json:"inputs"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	feed, err := s.formula.BuildAttributionFeed(body.Period, body.PoolKobo, body.Inputs)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	doc, err := s.signer.Sign(feed)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "Signing failed", err.Error())
		return
	}
	if err := s.saveFeed(body.Period, doc); err != nil {
		writeProblem(w, http.StatusInternalServerError, "Store error", err.Error())
		return
	}
	if s.emitter != nil {
		_ = s.emitter.Emit(r.Context(), "nrs.jrb.attribution.v1", eventx.Envelope{
			Type: "nrs.jrb.attribution.v1",
			Data: map[string]any{"period": body.Period, "pool_kobo": body.PoolKobo,
				"formula_pack": s.formula.PackRef},
		})
	}
	writeJSON(w, http.StatusCreated, map[string]any{"feed": feed, "signature": doc.Signature,
		"public_key": doc.PublicKey, "formula_pack": s.formula.PackRef,
		"verify": "gateway F7 verifies ed25519 signature before serving"})
}

func (s *Server) saveFeed(period string, doc *SignedFeedDoc) error {
	dir := filepath.Join(s.cfg.DataRoot, "feeds")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, period+".json"), data, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "latest.json"), data, 0o644)
}

// latestFeed serves the latest signed feed. The path carries a state segment to
// match the gateway F7 contract; the signed document covers all states and the
// gateway/state portal extracts its own row.
func (s *Server) latestFeed(w http.ResponseWriter, _ *http.Request) {
	data, err := os.ReadFile(filepath.Join(s.cfg.DataRoot, "feeds", "latest.json"))
	if err != nil {
		writeProblem(w, http.StatusNotFound, "No feed", "no attribution feed published yet")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// ------------------------------------------------------------------ workflows
func (s *Server) listWorkflows(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"workflows": WorkflowNames,
		"runner": "inproc (Temporal fallback)"})
}

func (s *Server) listRuns(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"runs": s.runner.List()})
}

func (s *Server) runWorkflow(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var params map[string]any
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&params)
	if params == nil {
		params = map[string]any{}
	}
	run, prob := s.dispatchWorkflow(name, params)
	if prob != nil {
		writeProblem(w, http.StatusNotFound, "Unknown workflow", *prob)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) dispatchWorkflow(name string, p map[string]any) (*WorkflowRun, *string) {
	str := func(k string) string { v, _ := p[k].(string); return v }
	switch name {
	case "wf-jrb-onboard":
		return s.runner.Execute(name, []struct {
			Name string
			Fn   func() (any, error)
		}{
			{"onboard-authority", func() (any, error) {
				a, err := s.auth.Onboard(str("authority_id"), str("cert_pem"))
				if err != nil {
					return nil, err
				}
				return map[string]any{"authority": a.ID, "fingerprint": a.CertFingerprint}, nil
			}},
		}), nil
	case "wf-jrb-route":
		return s.runner.Execute(name, []struct {
			Name string
			Fn   func() (any, error)
		}{
			{"push-assessment", func() (any, error) {
				ack, err := s.adapters.For(str("state")).PushAssessment(AssessmentNotice{
					NoticeID: str("notice_id"), PseudoTIN: str("pseudo_tin"),
					TaxType: str("tax_type"), IssuedAt: time.Now().UTC().Format(time.RFC3339),
				})
				if err != nil {
					return nil, err
				}
				return map[string]any{"ack": ack}, nil
			}},
		}), nil
	case "wf-jrb-reconcile":
		return s.runner.Execute(name, []struct {
			Name string
			Fn   func() (any, error)
		}{
			{"pull-reference-filings", func() (any, error) {
				period := str("period")
				if period == "" {
					period = time.Now().UTC().Format("2006-01")
				}
				total := 0
				for _, code := range s.adapters.ReferenceAdapters() {
					f, err := s.adapters.For(code).PullFilings(period)
					if err != nil {
						return nil, err
					}
					total += len(f)
				}
				return map[string]any{"period": period, "filings_seen": total}, nil
			}},
		}), nil
	case "wf-jrb-eoi":
		return s.runner.Execute(name, []struct {
			Name string
			Fn   func() (any, error)
		}{
			{"create-and-send", func() (any, error) {
				e, err := s.eoi.Create(&EOI{RequesterID: str("requester_id"),
					ResponderID: str("responder_id"), SubjectPseudoTIN: str("subject_pseudo_tin"),
					Purpose: str("purpose"), Request: str("request")})
				if err != nil {
					return nil, err
				}
				payload, _ := json.Marshal(map[string]any{
					"eoi_id": e.ID, "requester_state": e.RequesterID,
					"responder_state": e.ResponderID, "subject_pseudo_tin": e.SubjectPseudoTIN})
				res, err := s.gateway.SendF6EOI(payload)
				if err != nil {
					return nil, err
				}
				s.eoi.MarkSent(e.ID, res.ReceiptID)
				return map[string]any{"eoi_id": e.ID, "receipt": res}, nil
			}},
		}), nil
	case "wf-jrb-joint-audit":
		return s.runner.Execute(name, []struct {
			Name string
			Fn   func() (any, error)
		}{
			{"assemble-plan", func() (any, error) {
				var active []string
				for _, a := range s.auth.List() {
					if a.Status == "active" {
						active = append(active, a.ID)
					}
				}
				return map[string]any{"subject_pseudo_tin": str("subject_pseudo_tin"),
					"participating_authorities": active,
					"plan":                      "joint audit plan assembled; notices via wf-jrb-route"}, nil
			}},
		}), nil
	case "wf-jrb-cert-rotate":
		return s.runner.Execute(name, []struct {
			Name string
			Fn   func() (any, error)
		}{
			{"rotate", func() (any, error) {
				a, old, err := s.auth.RotateCert(str("authority_id"), str("cert_pem"))
				if err != nil {
					return nil, err
				}
				return map[string]any{"authority": a.ID, "old_fingerprint_revoked": old,
					"new_fingerprint": a.CertFingerprint}, nil
			}},
		}), nil
	case "wf-jrb-single-filing":
		return s.runner.Execute(name, []struct {
			Name string
			Fn   func() (any, error)
		}{
			{"merge-filings", func() (any, error) {
				period := str("period")
				if period == "" {
					period = time.Now().UTC().Format("2006-01")
				}
				var bundle []StateFiling
				for _, code := range s.adapters.ReferenceAdapters() {
					f, err := s.adapters.For(code).PullFilings(period)
					if err != nil {
						return nil, err
					}
					bundle = append(bundle, f...)
				}
				return map[string]any{"period": period, "single_filing_bundle": len(bundle)}, nil
			}},
		}), nil
	case "wf-jrb-attribution-publish":
		return s.runner.Execute(name, []struct {
			Name string
			Fn   func() (any, error)
		}{
			{"build-sign-store", func() (any, error) {
				period := str("period")
				if period == "" {
					period = time.Now().UTC().Format("2006-01")
				}
				inputs := defaultAttributionInputs()
				feed, err := s.formula.BuildAttributionFeed(period, 100_000_000_00, inputs)
				if err != nil {
					return nil, err
				}
				doc, err := s.signer.Sign(feed)
				if err != nil {
					return nil, err
				}
				if err := s.saveFeed(period, doc); err != nil {
					return nil, err
				}
				return map[string]any{"feed_id": feed.FeedID, "states": len(feed.States),
					"signature": doc.Signature[:16] + "...", "verified": Verify(doc)}, nil
			}},
		}), nil
	}
	msg := "expected one of " + strings.Join(WorkflowNames, ", ")
	return nil, &msg
}

// defaultAttributionInputs provides a dev consumption/derivation matrix across
// all 36 states + FCT (SIMULATED shares; production sources from the geo
// attribution pipeline).
func defaultAttributionInputs() []StateConsumptionInput {
	var out []StateConsumptionInput
	n := len(nigerianStates)
	base := 10000 / n
	rem := 10000 - base*n
	for i, st := range nigerianStates {
		share := base
		if i == 0 {
			share += rem
		}
		out = append(out, StateConsumptionInput{
			StateCode: st.Code, ConsumptionBps: share, DerivationBps: share,
		})
	}
	return out
}
