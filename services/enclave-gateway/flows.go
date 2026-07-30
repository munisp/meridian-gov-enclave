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
		"F1": {ID: "F1", Name: "ubl-preclearance-invoices", Topic: "nrs.mbs.preclearance.v1",
			RequiredFields: []string{"invoice_id", "supplier_tin", "issue_date", "lines", "total_kobo"},
			Scope:          "flow:f1:send", ConsumerURL: s.cfg.F1ConsumerURL},
		"F2": {ID: "F2", Name: "b2c-reports", Topic: "nrs.mbs.b2c.v1",
			RequiredFields: []string{"report_id", "supplier_tin", "period", "total_sales_kobo", "total_vat_kobo"},
			Scope:          "flow:f2:send", ConsumerURL: s.cfg.F2ConsumerURL},
		"F3": {ID: "F3", Name: "carf-messages", Topic: "nrs.vasp.carf.v1",
			RequiredFields: []string{"message_id", "reporting_vasp", "tax_year", "reportable_users"},
			Scope:          "flow:f3:send", ConsumerURL: s.cfg.F3ConsumerURL},
		"F4": {ID: "F4", Name: "etr-gir-filings", Topic: "nrs.globe.gir.v1",
			RequiredFields: []string{"filing_id", "mne_group", "fiscal_year", "gir_document"},
			Scope:          "flow:f4:send", ConsumerURL: s.cfg.F4ConsumerURL},
		"F5": {ID: "F5", Name: "presumptive-remittances", Topic: "nrs.psm.remittance.v1",
			RequiredFields: []string{"remittance_id", "operator_tin", "period", "amount_kobo", "certificate_serial"},
			Scope:          "flow:f5:send", ConsumerURL: s.cfg.F5ConsumerURL},
		"F6": {ID: "F6", Name: "eoi-exchange", Topic: "nrs.jrb.eoi.v1",
			RequiredFields: []string{"eoi_id", "requester_state", "responder_state", "subject_pseudo_tin"},
			Scope:          "flow:f6:internal", InternalOnly: true},
	}
}

var devRoleScopes = map[string][]string{
	"admin":    {"flow:f1:send", "flow:f2:send", "flow:f3:send", "flow:f4:send", "flow:f5:send", "flow:f7:read", "flow:f8:read", "receipts:read"},
	"operator": {"flow:f1:send", "flow:f2:send", "flow:f3:send", "flow:f4:send", "flow:f5:send", "flow:f7:read", "flow:f8:read"},
	"auditor":  {"flow:f7:read", "flow:f8:read", "receipts:read"},
}

// scopeCheck is the Permify-style scope check (dev file-backed equivalent:
// role -> scope map; production swaps in Permify via core permify-models).
func scopeCheck(p *Principal, scope string) bool {
	for _, r := range p.Roles {
		for _, s := range devRoleScopes[r] {
			if s == scope {
				return true
			}
		}
	}
	return false
}

// validateSchema checks required fields and envelope sanity against the flow's
// embedded schema (stand-in for rp-* JSON Schema validation).
func validateSchema(f *Flow, payload map[string]any) []string {
	var errs []string
	for _, field := range f.RequiredFields {
		v, ok := payload[field]
		if !ok || v == nil || v == "" {
			errs = append(errs, "missing required field: "+field)
		}
	}
	return errs
}

// pipeline is THE audited path for accepted cross-zone messages:
// schema validate -> scope check -> SYNCHRONOUS WORM evidence receipt (before
// the enclave consumer sees anything) -> dispatch to enclave consumer.
func (s *Server) pipeline(w http.ResponseWriter, r *http.Request, f *Flow) {
	p := r.Context().Value(ctxPrincipal).(*Principal)

	if f.InternalOnly {
		// F6 EOI: enclave-internal; never accepted from north-south callers.
		// The shared internal token IS the authorisation (mTLS in prod profile);
		// north-south scope checks do not apply.
		if r.Header.Get("X-Internal-Flow-Token") != s.cfg.InternalFlowToken {
			writeProblem(w, http.StatusForbidden, "Forbidden",
				"F6 (EOI exchange) is enclave-internal and not a north-south flow")
			return
		}
	} else if !scopeCheck(p, f.Scope) {
		writeProblem(w, http.StatusForbidden, "Forbidden",
			"principal lacks required scope "+f.Scope)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", "unreadable body")
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad request", "body must be a JSON object")
		return
	}
	if verrs := validateSchema(f, payload); len(verrs) > 0 {
		writeProblem(w, http.StatusUnprocessableEntity, "Schema validation failed",
			strings.Join(verrs, "; ")+" (schema: embedded dev subset of rp-*)")
		return
	}
	msgID, _ := payload[f.RequiredFields[0]].(string)
	if msgID == "" {
		msgID = fmt.Sprintf("msg-%d", time.Now().UnixNano())
	}

	// Synchronous WORM evidence receipt BEFORE dispatch.
	receipt, err := s.worm.Store(f.ID, msgID, raw)
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "Evidence store unavailable",
			"message NOT dispatched: "+err.Error())
		return
	}
	s.logReceipt(receipt)

	// Dispatch to enclave consumer, forwarding the stamped caller identity.
	caller, _ := r.Context().Value(ctxCaller).(string)
	dispatch, err := s.dispatch(f, raw, caller)
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "Consumer dispatch failed", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"flow": f.ID, "message_id": msgID, "accepted": true,
		"evidence_receipt": receipt, "dispatch": dispatch,
	})
}

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
			return nil, fmt.Errorf("consumer POST %s: %w", f.ConsumerURL, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return nil, fmt.Errorf("consumer returned %d: %s", resp.StatusCode, string(b))
		}
		return map[string]any{"mode": "consumer-api", "url": f.ConsumerURL, "status": resp.StatusCode}, nil
	}
	// Local dev fallback: durable spool inside the enclave data root.
	dir := filepath.Join(s.cfg.DataRoot, "dispatched", strings.ToLower(f.ID))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	name := fmt.Sprintf("%s-%d.json", strings.ToLower(f.ID), time.Now().UnixNano())
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o644); err != nil {
		return nil, err
	}
	return map[string]any{"mode": "local-spool", "path": filepath.Join(dir, name)}, nil
}
