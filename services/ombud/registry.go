package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Lifecycle states from rp-procedure-ombud (ombud.lifecycle.states).
var lifecycleStates = []string{"received", "acknowledged", "under_review", "hearing", "decided", "closed"}

var errNotFound = fmt.Errorf("not found")

// Case is an ombud appeal case.
type Case struct {
	ID                 string   `json:"id"`
	AppellantPseudoTIN string   `json:"appellant_pseudo_tin"`
	Authority          string   `json:"authority"` // e.g. NRS, NG-LA
	TaxType            string   `json:"tax_type"`
	DisputedAmountKobo int64    `json:"disputed_amount_kobo"`
	Grounds            string   `json:"grounds"`
	State              string   `json:"state"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
	AckDeadline        string   `json:"ack_deadline"`
	DecideDeadline     string   `json:"decide_deadline"`
	Deposit            *DepositHold `json:"deposit,omitempty"`
	Decision           string   `json:"decision,omitempty"`
	Outcome            string   `json:"outcome,omitempty"` // appellant_win | revenue_win | settled
	Documents          []CaseDoc `json:"documents,omitempty"`
	History            []HistoryEntry `json:"history"`
}

// CaseDoc: documents may be privileged; privileged docs are filtered from
// search results unless the caller holds a privileged-capable role.
type CaseDoc struct {
	DocID      string `json:"doc_id"`
	Title      string `json:"title"`
	Privileged bool   `json:"privileged"`
	EvidenceID string `json:"evidence_id,omitempty"` // WORM evidence-pack id
	AddedAt    string `json:"added_at"`
}

type HistoryEntry struct {
	At     string `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Detail string `json:"detail,omitempty"`
}

type CaseStore struct {
	mu   sync.Mutex
	path string
	byID map[string]*Case
	seq  int

	ackDays    int // rp-procedure-ombud: ombud.deadline.acknowledge
	decideDays int // rp-procedure-ombud: ombud.deadline.decide
}

func NewCaseStore(root string, ackDays, decideDays int) (*CaseStore, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	s := &CaseStore{path: filepath.Join(root, "cases.json"), byID: map[string]*Case{},
		ackDays: ackDays, decideDays: decideDays}
	if data, err := os.ReadFile(s.path); err == nil {
		var rows []*Case
		if json.Unmarshal(data, &rows) == nil {
			for _, c := range rows {
				s.byID[c.ID] = c
			}
			s.seq = len(rows)
		}
	}
	return s, nil
}

func (s *CaseStore) saveLocked() {
	rows := make([]*Case, 0, len(s.byID))
	for _, c := range s.byID {
		rows = append(rows, c)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	data, _ := json.MarshalIndent(rows, "", "  ")
	_ = os.WriteFile(s.path, data, 0o644)
}

func (s *CaseStore) Intake(actor string, c *Case) (*Case, error) {
	if c.AppellantPseudoTIN == "" || !strings.HasPrefix(c.AppellantPseudoTIN, "ptin_") {
		return nil, fmt.Errorf("appellant_pseudo_tin (ptin_...) required; raw TINs are never stored")
	}
	if c.DisputedAmountKobo <= 0 {
		return nil, fmt.Errorf("disputed_amount_kobo must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	now := time.Now().UTC()
	c.ID = fmt.Sprintf("OMB-%06d", s.seq)
	c.State = lifecycleStates[0]
	c.CreatedAt = now.Format(time.RFC3339)
	c.UpdatedAt = c.CreatedAt
	c.AckDeadline = now.AddDate(0, 0, s.ackDays).Format(time.RFC3339)
	c.DecideDeadline = now.AddDate(0, 0, s.decideDays).Format(time.RFC3339)
	c.History = []HistoryEntry{{At: c.CreatedAt, Actor: actor, Action: "intake",
		Detail: "case received; deadlines set per rp-procedure-ombud"}}
	s.byID[c.ID] = c
	s.saveLocked()
	return c, nil
}

func stateIndex(state string) int {
	for i, st := range lifecycleStates {
		if st == state {
			return i
		}
	}
	return -1
}

// Transition moves a case forward through the lifecycle (sequential, no skipping;
// closing allowed from decided).
func (s *CaseStore) Transition(actor, id, action, detail string) (*Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return nil, errNotFound
	}
	var next string
	switch action {
	case "acknowledge":
		next = "acknowledged"
	case "review":
		next = "under_review"
	case "schedule_hearing":
		next = "hearing"
	case "decide":
		next = "decided"
		c.Decision = detail
	case "close":
		if c.State != "decided" {
			return nil, fmt.Errorf("case must be decided before closing")
		}
		next = "closed"
	default:
		return nil, fmt.Errorf("unknown action %s", action)
	}
	if next != "closed" && stateIndex(next) != stateIndex(c.State)+1 {
		return nil, fmt.Errorf("lifecycle is sequential: cannot move from %s to %s", c.State, next)
	}
	c.State = next
	c.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	c.History = append(c.History, HistoryEntry{At: c.UpdatedAt, Actor: actor, Action: action, Detail: detail})
	s.saveLocked()
	return c, nil
}

func (s *CaseStore) Get(id string) (*Case, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	return c, ok
}

func (s *CaseStore) List() []*Case {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Case, 0, len(s.byID))
	for _, c := range s.byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

func (s *CaseStore) AttachDeposit(id string, h *DepositHold) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return errNotFound
	}
	c.Deposit = h
	c.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	c.History = append(c.History, HistoryEntry{At: c.UpdatedAt, Actor: "system",
		Action: "deposit_hold", Detail: fmt.Sprintf("hold %s for %d kobo on ledger 500", h.HoldID, h.AmountKobo)})
	s.saveLocked()
	return nil
}

func (s *CaseStore) AddDocument(id string, doc CaseDoc) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return errNotFound
	}
	doc.AddedAt = time.Now().UTC().Format(time.RFC3339)
	c.Documents = append(c.Documents, doc)
	c.UpdatedAt = doc.AddedAt
	s.saveLocked()
	return nil
}

// Search is the dev privilege-filtered index: full-text over id/grounds/
// tax_type/authority; privileged documents are dropped from results unless the
// caller role may see privilege (registry | member).
func (s *CaseStore) Search(q string, canSeePrivileged bool) []*Case {
	q = strings.ToLower(q)
	var out []*Case
	for _, c := range s.List() {
		hay := strings.ToLower(c.ID + " " + c.Grounds + " " + c.TaxType + " " + c.Authority)
		if q != "" && !strings.Contains(hay, q) {
			continue
		}
		cp := *c
		if !canSeePrivileged {
			var docs []CaseDoc
			for _, d := range cp.Documents {
				if !d.Privileged {
					docs = append(docs, d)
				}
			}
			cp.Documents = docs
		}
		out = append(out, &cp)
	}
	return out
}
