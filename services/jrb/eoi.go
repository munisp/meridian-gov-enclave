package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/munisp/meridian-gov-enclave/packages/storex"
)

// EOI (Exchange of Information) record. Visibility is enforced as a FOUR-PARTY
// rule: requester authority + responder authority + JRB secretariat (+ NRS
// oversight role) may see the exchange; ANY fourth party is hard-denied.
type EOI struct {
	ID               string `json:"id"`
	RequesterID      string `json:"requester_id"`      // authority ID, e.g. NG-LA
	ResponderID      string `json:"responder_id"`      // authority ID, e.g. NG-KN
	SubjectPseudoTIN string `json:"subject_pseudo_tin"` // pseudonymised subject only
	Purpose          string `json:"purpose"`
	Status           string `json:"status"` // requested | in_transit | answered | closed
	Request          string `json:"request"`
	Response         string `json:"response,omitempty"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
	GatewayReceipt   string `json:"gateway_receipt,omitempty"` // WORM receipt id from enclave-gateway send
}

// canView enforces the four-party visibility rule.
func (e *EOI) canView(authorityID string, isSecretariat bool) bool {
	if isSecretariat {
		return true
	}
	return authorityID == e.RequesterID || authorityID == e.ResponderID
}

// EOITable is the Postgres table (H3 DDL, idempotent auto-migrate).
const EOITable = "jrb_eoi"

type EOIStore struct {
	mu   sync.Mutex
	path string
	byID map[string]*EOI
	seq  int
	pg   *storex.DB // nil -> JSON-file dev fallback
}

func NewEOIStore(root string, pg *storex.DB) (*EOIStore, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	s := &EOIStore{path: filepath.Join(root, "eoi.json"), byID: map[string]*EOI{}, pg: pg}
	load := func(rows []*EOI) {
		for _, r := range rows {
			s.byID[r.ID] = r
		}
		s.seq = len(s.byID)
	}
	if pg != nil {
		docs, err := pg.LoadDocs(context.Background(), EOITable)
		if err != nil {
			return nil, fmt.Errorf("load eoi from postgres: %w", err)
		}
		var rows []*EOI
		for _, doc := range docs {
			var e EOI
			if json.Unmarshal(doc, &e) == nil {
				rows = append(rows, &e)
			}
		}
		load(rows)
	} else if data, err := os.ReadFile(s.path); err == nil {
		var rows []*EOI
		if json.Unmarshal(data, &rows) == nil {
			load(rows)
		}
	}
	return s, nil
}

func (s *EOIStore) saveLocked() {
	rows := make([]*EOI, 0, len(s.byID))
	for _, e := range s.byID {
		rows = append(rows, e)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if s.pg != nil {
		ctx := context.Background()
		for _, e := range rows {
			if doc, err := json.Marshal(e); err == nil {
				_ = s.pg.UpsertDoc(ctx, EOITable, e.ID, doc)
			}
		}
		return
	}
	data, _ := json.MarshalIndent(rows, "", "  ")
	_ = os.WriteFile(s.path, data, 0o644)
}

func (s *EOIStore) Create(req *EOI) (*EOI, error) {
	if req.RequesterID == "" || req.ResponderID == "" || req.SubjectPseudoTIN == "" {
		return nil, fmt.Errorf("requester_id, responder_id and subject_pseudo_tin are required")
	}
	if req.RequesterID == req.ResponderID {
		return nil, fmt.Errorf("requester and responder must differ")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	now := time.Now().UTC().Format(time.RFC3339)
	e := &EOI{
		ID: fmt.Sprintf("EOI-%06d", s.seq), RequesterID: req.RequesterID,
		ResponderID: req.ResponderID, SubjectPseudoTIN: req.SubjectPseudoTIN,
		Purpose: req.Purpose, Status: "requested", Request: req.Request,
		CreatedAt: now, UpdatedAt: now,
	}
	s.byID[e.ID] = e
	s.saveLocked()
	return e, nil
}

// GetFor enforces four-party visibility: hard deny for any fourth party.
func (s *EOIStore) GetFor(id, authorityID string, isSecretariat bool) (*EOI, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok {
		return nil, errNotFound
	}
	if !e.canView(authorityID, isSecretariat) {
		return nil, errForbidden
	}
	return e, nil
}

// ListFor returns only records visible to the caller.
func (s *EOIStore) ListFor(authorityID string, isSecretariat bool) []*EOI {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*EOI
	for _, e := range s.byID {
		if e.canView(authorityID, isSecretariat) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

func (s *EOIStore) Answer(id, responderID, response string) (*EOI, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok {
		return nil, errNotFound
	}
	if e.ResponderID != responderID {
		return nil, errForbidden
	}
	e.Response = response
	e.Status = "answered"
	e.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	s.saveLocked()
	return e, nil
}

func (s *EOIStore) MarkSent(id, receiptID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.byID[id]; ok {
		e.Status = "in_transit"
		e.GatewayReceipt = receiptID
		e.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		s.saveLocked()
	}
}

var (
	errNotFound  = fmt.Errorf("not found")
	errForbidden = fmt.Errorf("forbidden: four-party visibility rule denies access")
)
