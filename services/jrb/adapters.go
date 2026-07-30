package main

import (
	"fmt"
	"time"
)

// StateAdapter is the per-state IRS adapter framework. Real adapters integrate
// with state IRS APIs; the reference adapters below are simulators behind the
// same interface (honesty tag: SIMULATED).
type StateAdapter interface {
	StateCode() string
	Name() string
	// PullFilings returns filings-under-MoU available for JRB single-filing
	// reconciliation for a period.
	PullFilings(period string) ([]StateFiling, error)
	// PushAssessment delivers a JRB assessment notice to the state IRS.
	PushAssessment(notice AssessmentNotice) (string, error)
	Health() string
}

type StateFiling struct {
	FilingID      string `json:"filing_id"`
	PseudoTIN     string `json:"pseudo_tin"`
	TaxType       string `json:"tax_type"`
	Period        string `json:"period"`
	AmountKobo    int64  `json:"amount_kobo"`
	PlaceOfSupply string `json:"place_of_supply"` // LGA / market for consumption attribution
	FiledAt       string `json:"filed_at"`
}

type AssessmentNotice struct {
	NoticeID      string `json:"notice_id"`
	PseudoTIN     string `json:"pseudo_tin"`
	TaxType       string `json:"tax_type"`
	AmountKobo    int64  `json:"amount_kobo"`
	Basis         string `json:"basis"`
	IssuedAt      string `json:"issued_at"`
}

// AdapterRegistry resolves state codes to adapters. Unregistered states fall
// back to the generic adapter so all 36 states + FCT are reachable in dev.
type AdapterRegistry struct {
	adapters map[string]StateAdapter
}

func NewAdapterRegistry() *AdapterRegistry {
	r := &AdapterRegistry{adapters: map[string]StateAdapter{}}
	r.Register(&LagosLIRSAdapter{})
	r.Register(&FCTIRSAdapter{})
	return r
}

func (r *AdapterRegistry) Register(a StateAdapter) { r.adapters[a.StateCode()] = a }

func (r *AdapterRegistry) For(stateCode string) StateAdapter {
	if a, ok := r.adapters[stateCode]; ok {
		return a
	}
	return &GenericStateAdapter{code: stateCode}
}

func (r *AdapterRegistry) ReferenceAdapters() []string {
	out := []string{}
	for code := range r.adapters {
		out = append(out, code)
	}
	return out
}

// --- reference adapter: Lagos LIRS (SIMULATED) -----------------------------

type LagosLIRSAdapter struct{}

func (a *LagosLIRSAdapter) StateCode() string { return "NG-LA" }
func (a *LagosLIRSAdapter) Name() string      { return "Lagos Internal Revenue Service (LIRS)" }
func (a *LagosLIRSAdapter) Health() string    { return "ok (simulated adapter)" }

func (a *LagosLIRSAdapter) PullFilings(period string) ([]StateFiling, error) {
	return []StateFiling{
		{FilingID: "LA-" + period + "-001", PseudoTIN: "ptin_lagos_001", TaxType: "PAYE",
			Period: period, AmountKobo: 18_500_000_00, PlaceOfSupply: "ikeja", FiledAt: time.Now().UTC().Format(time.RFC3339)},
		{FilingID: "LA-" + period + "-002", PseudoTIN: "ptin_lagos_002", TaxType: "VAT",
			Period: period, AmountKobo: 6_250_000_00, PlaceOfSupply: "lekki", FiledAt: time.Now().UTC().Format(time.RFC3339)},
	}, nil
}

func (a *LagosLIRSAdapter) PushAssessment(n AssessmentNotice) (string, error) {
	if n.PseudoTIN == "" {
		return "", fmt.Errorf("pseudo_tin required")
	}
	return fmt.Sprintf("LIRS-ACK-%s", n.NoticeID), nil
}

// --- reference adapter: FCT-IRS (SIMULATED) --------------------------------

type FCTIRSAdapter struct{}

func (a *FCTIRSAdapter) StateCode() string { return "NG-FC" }
func (a *FCTIRSAdapter) Name() string      { return "FCT Internal Revenue Service" }
func (a *FCTIRSAdapter) Health() string    { return "ok (simulated adapter)" }

func (a *FCTIRSAdapter) PullFilings(period string) ([]StateFiling, error) {
	return []StateFiling{
		{FilingID: "FC-" + period + "-001", PseudoTIN: "ptin_fct_001", TaxType: "PAYE",
			Period: period, AmountKobo: 9_750_000_00, PlaceOfSupply: "abuja-municipal", FiledAt: time.Now().UTC().Format(time.RFC3339)},
	}, nil
}

func (a *FCTIRSAdapter) PushAssessment(n AssessmentNotice) (string, error) {
	if n.PseudoTIN == "" {
		return "", fmt.Errorf("pseudo_tin required")
	}
	return fmt.Sprintf("FCTIRS-ACK-%s", n.NoticeID), nil
}

// --- generic fallback adapter (SIMULATED) ----------------------------------

type GenericStateAdapter struct{ code string }

func (a *GenericStateAdapter) StateCode() string { return a.code }
func (a *GenericStateAdapter) Name() string      { return "State IRS (generic simulated adapter)" }
func (a *GenericStateAdapter) Health() string    { return "ok (generic simulated adapter)" }

func (a *GenericStateAdapter) PullFilings(period string) ([]StateFiling, error) {
	return []StateFiling{}, nil // no simulated filings for non-reference states
}

func (a *GenericStateAdapter) PushAssessment(n AssessmentNotice) (string, error) {
	if n.PseudoTIN == "" {
		return "", fmt.Errorf("pseudo_tin required")
	}
	return fmt.Sprintf("%s-ACK-%s", a.code, n.NoticeID), nil
}
