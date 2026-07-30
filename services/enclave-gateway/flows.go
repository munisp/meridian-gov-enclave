package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Flow describes one audited cross-zone flow (F1-F8 accepted; F6 internal;
// F9/F10 forbidden by construction — no routes registered).
type Flow struct {
	ID             string   // e.g. "F1"
	Name           string   // human name
	Topic          string   // nrs.* family
	RequiredFields []string // schema validation vs relevant rp-* (embedded dev schemas)
	Scope          string   // required caller scope/role (Permify-style dev check)
	ConsumerURL    string   // enclave consumer API (empty -> local dispatch fallback)
	InternalOnly   bool     // F6: enclave-internal
}

// embedded dev schemas — derived from rp-ubl-bis / rp-carf-schema / rp-gir-schema /
// rp-presumptive-* / rp-mbs-business-rules required-field subsets. In production the
// gateway fetches the pinned pack from rp-registry; the fallback keeps dev standalone.
func (s *Server) flows() map[string]*Flow {
	return map[string]*Flow{
		"F1": {ID: "F1", Name: "ubl-preclearance-invoices", Topic: "nrs.invoice.einvoice.v1",
			RequiredFields: []string{"invoice_id", "supplier_tin", "issue_date", "lines", "total_kobo"},
			Scope:          "flow:f1:write", ConsumerURL: s.cfg.F1ConsumerURL},
		"F2": {ID: "F2", Name: "cbcreports", Topic: "nrs.cbc.report.v1",
			RequiredFields: []string{"report_id", "mpe_group", "jurisdictions", "period"},
			Scope:          "flow:f2:write", ConsumerURL: s.cfg.F2ConsumerURL},
		"F3": {ID: "F3", Name: "carf-exchanges", Topic: "nrs.carf.exchange.v1",
			RequiredFields: []string{"exchange_id", "reporting_platform", "sellers", "period"},
			Scope:          "flow:f3:write", ConsumerURL: s.cfg.F3ConsumerURL},
		"F4": {ID: "F4", Name: "gir-filings", Topic: "nrs.gir.filing.v1",
			RequiredFields: []string{"filing_id", "mpe_group", "top_up_tax", "jurisdictions"},
			Scope:          "flow:f4:write", ConsumerURL: s.cfg.F4ConsumerURL},
		"F5": {ID: "F5", Name: "mbs-remittance-declarations", Topic: "nrs.mbs.declaration.v1",
			RequiredFields: []string{"declaration_id", "merchant_id", "period", "turnover_kobo"},
			Scope:          "flow:f5:write", ConsumerURL: s.cfg.F5ConsumerURL},
		"F6": {ID: "F6", Name: "eoi-requests", Topic: "nrs.jrb.eoi.v1",
			RequiredFields: []string{"eoi_id", "requester_state", "responder_state", "subject_pseudo_tin"},
			Scope:          "flow:f6:internal", InternalOnly: true},
	}
}

// scopeCheck is the dev Permify-style check: caller roles admin/operator carry
// all flow scopes; auditor carries read scopes only. In production Permify
// evaluates the same scope strings.
func scopeCheck(p *Principal, scope string) bool {
	if p.HasRole("admin") || p.HasRole("operator") {
		return true
	}
	return strings.HasSuffix(scope, ":read")
}

// pipeline is the audited F1-F6 path: auth -> schema validate -> scope check
// -> WORM receipt (BEFORE the consumer sees the message) -> dispatch.
func (s *Server) pipeline(w http.ResponseWriter, r *http.Request, f *Flow) {
	p := r.Context().Value(ctxPrincipal).(*Principal)

	if f.InternalOnly {
		// F6 is enclave-internal: shared token + never exposed cross-zone.
		if r.Header.Get("X-Internal-Flow-Token") != s.cfg.InternalFlowToken {
			writeProblem(w, http.StatusForbidden, "Forbidden",
				"F6 is enclave-internal: X-Internal-Flow-Token required")
			return
		}
	} else if !scopeCheck(p, f.Scope) {
		writeProblem(w, http.StatusForbidden, "Forbidden", "scope "+f.Scope+" required")
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil || len(raw) == 0 {
		writeProblem(w, http.StatusBadRequest, "Bad request", "empty body")
		return
	}
	var msg map[string]any
	if err := json.Unmarshal(raw, &msg); err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", "invalid JSON: "+err.Error())
		return
	}
	// Schema validation against the embedded rp-* required-field subset.
	var missing []string
	for _, rf := range f.RequiredFields {
		if _, ok := msg[rf]; !ok {
			missing = append(missing, rf)
		}
	}
	if len(missing) > 0 {
		writeProblem(w, http.StatusUnprocessableEntity, "Schema validation failed",
			"missing required fields (rp-* embedded schema): "+strings.Join(missing, ", "))
		return
	}

	// WORM evidence receipt BEFORE dispatch — if WORM fails, nothing proceeds.
	rc, err := s.worm.Store(f.ID, f.Topic, raw)
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "WORM store failed", err.Error())
		return
	}
	s.logReceipt(rc)

	// Dispatch to enclave consumer, forwarding the stamped caller identity.
	caller, _ := r.Context().Value(ctxCaller).(string)
	dispatch, err := s.dispatch(f, raw, caller)
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "Dispatch failed", err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"flow": f.ID, "topic": f.Topic, "receipt": rc, "dispatch": dispatch,
	})
}

// dispatch forwards to the enclave consumer API, or to the local spool when no
// consumer is wired (dev fallback).
func (s *Server) dispatch(f *Flow, raw []byte, caller string) (map[string]any, error) {
	if f.ConsumerURL != "" {
		req, err := http.NewRequest(http.MethodPost, f.ConsumerURL, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if caller != "" {
			// Verified caller identity (mTLS CN / JWT sub) stamped before forwarding.
			req.Header.Set("X-Meridian-Caller", caller)
		}
		resp, err := s.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("consumer %s: %w", f.ConsumerURL, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return nil, fmt.Errorf("consumer %s: %s", f.ConsumerURL, resp.Status)
		}
		return map[string]any{"mode": "consumer-api", "status": resp.Status}, nil
	}
	// Local spool: durable handoff to the enclave consumer.
	dir := filepath.Join(s.cfg.DataRoot, "spool", f.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	name := fmt.Sprintf("%d.json", time.Now().UnixNano())
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o644); err != nil {
		return nil, err
	}
	return map[string]any{"mode": "local-spool", "spool": filepath.Join("spool", f.ID, name)}, nil
}
