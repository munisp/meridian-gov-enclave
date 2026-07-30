package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// StateAdapter is the per-state IRS integration framework (T11). Reference
// adapters (lagos_lirs, fct_irs) are SIMULATED in dev; production adapters
// implement the same interface against real state APIs.
type StateAdapter interface {
	StateCode() string
	PullFilings(period string) ([]StateFiling, error)
	PushAssessment(notice AssessmentNotice) (string, error) // returns ack id
}

// StateFiling is a filing row pulled from a state IRS system (pseudonymised).
type StateFiling struct {
	FilingID      string `json:"filing_id"`
	PseudoTIN     string `json:"pseudo_tin"`
	TaxType       string `json:"tax_type"`
	Period        string `json:"period"`
	AmountKobo    int64  `json:"amount_kobo"`
	PlaceOfSupply string `json:"place_of_supply"`
	FiledAt       string `json:"filed_at"`
}

// AssessmentNotice is pushed to a state IRS (wf-jrb-route).
type AssessmentNotice struct {
	NoticeID  string `json:"notice_id"`
	PseudoTIN string `json:"pseudo_tin"`
	TaxType   string `json:"tax_type"`
	IssuedAt  string `json:"issued_at"`
}

// --- reference adapter: lagos_lirs (SIMULATED dev data) ----------------------

type lagosLIRSAdapter struct{}

func (a lagosLIRSAdapter) StateCode() string { return "NG-LA" }

func (a lagosLIRSAdapter) PullFilings(period string) ([]StateFiling, error) {
	return []StateFiling{
		{FilingID: "LIRS-2026-0001", PseudoTIN: "ptin_lag_demo1", TaxType: "PIT", Period: period,
			AmountKobo: 2_500_000_00, PlaceOfSupply: "NG-LA", FiledAt: time.Now().UTC().Format(time.RFC3339)},
		{FilingID: "LIRS-2026-0002", PseudoTIN: "ptin_lag_demo2", TaxType: "CIT", Period: period,
			AmountKobo: 14_000_000_00, PlaceOfSupply: "NG-LA", FiledAt: time.Now().UTC().Format(time.RFC3339)},
	}, nil
}

func (a lagosLIRSAdapter) PushAssessment(n AssessmentNotice) (string, error) {
	ack, _ := json.Marshal(map[string]any{"adapter": "lagos_lirs", "notice_id": n.NoticeID,
		"ack": "LIRS-ACK-" + n.NoticeID, "simulated": true})
	return "LIRS-ACK-" + n.NoticeID + " (sha:" + shortHash(ack) + ")", nil
}

// --- reference adapter: fct_irs (SIMULATED dev data) -------------------------

type fctIRSAdapter struct{}

func (a fctIRSAdapter) StateCode() string { return "NG-FC" }

func (a fctIRSAdapter) PullFilings(period string) ([]StateFiling, error) {
	return []StateFiling{
		{FilingID: "FCTIRS-2026-0001", PseudoTIN: "ptin_fct_demo1", TaxType: "PIT", Period: period,
			AmountKobo: 1_100_000_00, PlaceOfSupply: "NG-FC", FiledAt: time.Now().UTC().Format(time.RFC3339)},
	}, nil
}

func (a fctIRSAdapter) PushAssessment(n AssessmentNotice) (string, error) {
	return "FCTIRS-ACK-" + n.NoticeID, nil
}

// --- generic fallback adapter (covers every state code) -----------------------

type genericAdapter struct{ code string }

func (a genericAdapter) StateCode() string { return a.code }

func (a genericAdapter) PullFilings(period string) ([]StateFiling, error) {
	return []StateFiling{
		{FilingID: fmt.Sprintf("%s-GEN-%s-1", a.code, period), PseudoTIN: "ptin_" + a.code + "_demo",
			TaxType: "PIT", Period: period, AmountKobo: 100_000_00,
			PlaceOfSupply: a.code, FiledAt: time.Now().UTC().Format(time.RFC3339)},
	}, nil
}

func (a genericAdapter) PushAssessment(n AssessmentNotice) (string, error) {
	return a.code + "-ACK-" + n.NoticeID, nil
}

// AdapterRegistry resolves state codes to adapters.
type AdapterRegistry struct {
	reference map[string]StateAdapter
}

func NewAdapterRegistry() *AdapterRegistry {
	return &AdapterRegistry{reference: map[string]StateAdapter{
		"NG-LA": lagosLIRSAdapter{},
		"NG-FC": fctIRSAdapter{},
	}}
}

func (r *AdapterRegistry) For(stateCode string) StateAdapter {
	if a, ok := r.reference[stateCode]; ok {
		return a
	}
	return genericAdapter{code: stateCode}
}

func (r *AdapterRegistry) ReferenceAdapters() []string {
	out := []string{}
	for code := range r.reference {
		out = append(out, code)
	}
	return out
}

func shortHash(b []byte) string {
	sum := [32]byte{}
	for i, x := range b {
		sum[i%32] ^= x
	}
	return fmt.Sprintf("%x", sum[:4])
}
