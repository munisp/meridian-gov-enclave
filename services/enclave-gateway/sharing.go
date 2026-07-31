package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// sharing.go — NDPA consent-receipt data-sharing gateway (I20). Inter-agency
// disclosure leaves the enclave ONLY with a valid consent receipt or a
// recognised statutory basis; every response is minimised to the requesting
// agency's field allowlist; cohorts smaller than k are refused (k-anonymity);
// and every disclosure is logged to a full disclosure log (WORM-adjacent
// append-only file). REAL enforcement with a local consent-receipt store
// (CONSENT_STORE_URL integration point documented in README).

// statutoryBases are the NDPA lawful bases accepted in lieu of a consent
// receipt (NDPA 2023 §25: legal obligation, public task, vital interest).
var statutoryBases = map[string]bool{
	"legal_obligation": true,
	"public_task":      true,
	"vital_interest":   true,
	"court_order":      true,
}

// agencyAllowlist is the data-minimisation policy: which pseudonymised
// fields each agency may receive.
var agencyAllowlist = map[string][]string{
	"firs":   {"tin_hash", "state", "band", "amount_kobo", "period"},
	"jtb":    {"tin_hash", "state", "period"},
	"cbn":    {"amount_kobo", "period", "band"},
	"stats":  {"state", "band"}, // aggregate-only agency
	"npc":    {"state"},
}

const sharingK = 5 // k-anonymity floor (matches analytics disclosure pack)

// ConsentReceipt is a registered NDPA consent receipt.
type ConsentReceipt struct {
	ReceiptID string `json:"receipt_id"`
	Subject   string `json:"subject"` // tin_hash
	Purpose   string `json:"purpose"`
	Agency    string `json:"agency"`
	Granted   bool   `json:"granted"`
	Revoked   bool   `json:"revoked"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// DiscloseRequest asks the gateway to share subject records with an agency.
type DiscloseRequest struct {
	Agency         string   `json:"agency"`
	Purpose        string   `json:"purpose"`
	ConsentReceipt string   `json:"consent_receipt,omitempty"`
	StatutoryBasis string   `json:"statutory_basis,omitempty"`
	Subjects       []map[string]any `json:"subjects"` // candidate records
}

// DisclosureLogEntry is one line of the full disclosure log.
type DisclosureLogEntry struct {
	ID        string   `json:"id"`
	Agency    string   `json:"agency"`
	Purpose   string   `json:"purpose"`
	Basis     string   `json:"basis"` // consent:<receipt>|statutory:<basis>
	Subjects  int      `json:"subjects"`
	Fields    []string `json:"fields"`
	Caller    string   `json:"caller"`
	CreatedAt string   `json:"created_at"`
}

func (s *Server) disclosureLogPath() string {
	return filepath.Join(s.cfg.DataRoot, "disclosure.log")
}

// loadConsentReceipt resolves a receipt from the local consent store
// (consents.json in DataRoot; SIMULATED store — prod wires CONSENT_STORE_URL).
func (s *Server) loadConsentReceipt(id string) (ConsentReceipt, error) {
	data, err := os.ReadFile(filepath.Join(s.cfg.DataRoot, "consents.json"))
	if err != nil {
		return ConsentReceipt{}, fmt.Errorf("consent store unavailable: %w", err)
	}
	var all []ConsentReceipt
	if err := json.Unmarshal(data, &all); err != nil {
		return ConsentReceipt{}, err
	}
	for _, c := range all {
		if c.ReceiptID == id {
			return c, nil
		}
	}
	return ConsentReceipt{}, fmt.Errorf("consent receipt %s not found", id)
}

// Disclose enforces the sharing policy and returns minimised records.
func (s *Server) Disclose(req DiscloseRequest, caller string) ([]map[string]any, DisclosureLogEntry, error) {
	entry := DisclosureLogEntry{
		ID: fmt.Sprintf("disc-%d", time.Now().UnixNano()), Agency: req.Agency,
		Purpose: req.Purpose, Caller: caller, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	allow, known := agencyAllowlist[strings.ToLower(req.Agency)]
	if !known {
		return nil, entry, fmt.Errorf("unknown agency %q (no minimisation policy registered)", req.Agency)
	}
	// 1. lawful basis: valid consent receipt OR statutory basis
	switch {
	case req.ConsentReceipt != "":
		cr, err := s.loadConsentReceipt(req.ConsentReceipt)
		if err != nil {
			return nil, entry, fmt.Errorf("consent check failed: %w", err)
		}
		if !cr.Granted || cr.Revoked {
			return nil, entry, fmt.Errorf("consent receipt %s is not granted (revoked=%v)", cr.ReceiptID, cr.Revoked)
		}
		if cr.ExpiresAt != "" {
			if exp, err := time.Parse(time.RFC3339, cr.ExpiresAt); err == nil && time.Now().UTC().After(exp) {
				return nil, entry, fmt.Errorf("consent receipt %s expired", cr.ReceiptID)
			}
		}
		if !strings.EqualFold(cr.Agency, req.Agency) {
			return nil, entry, fmt.Errorf("consent receipt is for agency %q, not %q", cr.Agency, req.Agency)
		}
		entry.Basis = "consent:" + cr.ReceiptID
	case statutoryBases[req.StatutoryBasis]:
		entry.Basis = "statutory:" + req.StatutoryBasis
	default:
		return nil, entry, fmt.Errorf("no lawful basis: provide a valid consent_receipt or statutory basis (NDPA §25)")
	}
	// 2. k-anonymity: refuse cohorts below k
	if len(req.Subjects) < sharingK {
		return nil, entry, fmt.Errorf("k-anonymity: cohort of %d below k=%d; aggregation required", len(req.Subjects), sharingK)
	}
	// 3. minimisation: project each record onto the agency allowlist
	out := make([]map[string]any, 0, len(req.Subjects))
	for _, subj := range req.Subjects {
		row := map[string]any{}
		for _, f := range allow {
			if v, ok := subj[f]; ok {
				row[f] = v
			}
		}
		out = append(out, row)
	}
	entry.Subjects = len(out)
	entry.Fields = allow
	// 4. full disclosure log (append-only)
	f, err := os.OpenFile(s.disclosureLogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, entry, fmt.Errorf("disclosure log unavailable (fail closed): %w", err)
	}
	defer f.Close()
	line, _ := json.Marshal(entry)
	if _, err := f.Write(append(line, '\n')); err != nil {
		return nil, entry, err
	}
	return out, entry, nil
}

func (s *Server) handleDisclose(w http.ResponseWriter, r *http.Request) {
	var req DiscloseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	caller := r.Header.Get("X-Meridian-Caller")
	out, entry, err := s.Disclose(req, caller)
	if err != nil {
		writeProblem(w, http.StatusForbidden, "sharing_denied", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": out, "disclosure": entry})
}

func (s *Server) handleDisclosureLog(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.disclosureLogPath())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"entries": []string{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": strings.Split(strings.TrimSpace(string(data)), "\n")})
}
