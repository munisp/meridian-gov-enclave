package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// EOI is an exchange-of-information between two authorities. Four-party
// visibility is enforced in THIS store (requester + responder + secretariat;
// any fourth party is hard-denied — test-proven).
type EOI struct {
	ID               string `json:"id"`
	RequesterID      string `json:"requester_id"`
	ResponderID      string `json:"responder_id"`
	SubjectPseudoTIN string `json:"subject_pseudo_tin"`
	Purpose          string `json:"purpose"`
	Status           string `json:"status"` // draft | sent | answered | closed
	Request          string `json:"request"`
	Response         string `json:"response,omitempty"`
	GatewayReceiptID string `json:"gateway_receipt,omitempty"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

var (
	errNotFound  = errors.New("eoi not found")
	errForbidden = errors.New("four-party visibility: access denied")
)

// EOIStore persists EOIs (JSON doc store; DATABASE_URL Postgres path via
// storex in prod — same document schema).
type EOIStore struct {
	mu   sync.Mutex
	dir  string
	pg   pgDocStore
	byID map[string]*EOI
	seq  int
}

const EOITable = "jrb_eoi"

func NewEOIStore(dataRoot string, pg pgDocStore) (*EOIStore, error) {
	s := &EOIStore{dir: filepath.Join(dataRoot, "eoi"), pg: pg, byID: map[string]*EOI{}}
	if pg == nil {
		if err := os.MkdirAll(s.dir, 0o755); err != nil {
			return nil, err
		}
		if err := s.load(); err != nil {
			return nil, err
		}
	} else if err := s.loadPG(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *EOIStore) load() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			return err
		}
		var rec EOI
		if err := json.Unmarshal(data, &rec); err != nil {
			return err
		}
		s.byID[rec.ID] = &rec
	}
	return nil
}

func (s *EOIStore) persist(e *EOI) error {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	if s.pg != nil {
		return s.pg.UpsertDoc(EOITable, e.ID, data)
	}
	return os.WriteFile(filepath.Join(s.dir, e.ID+".json"), data, 0o644)
}

// visible reports whether authorityID may see e (four-party rule).
func visible(e *EOI, authorityID string, isSecretariat bool) bool {
	return isSecretariat || e.RequesterID == authorityID || e.ResponderID == authorityID
}

func (s *EOIStore) Create(req *EOI) (*EOI, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.RequesterID == "" || req.ResponderID == "" || req.SubjectPseudoTIN == "" {
		return nil, errors.New("requester_id, responder_id, subject_pseudo_tin required")
	}
	if req.RequesterID == req.ResponderID {
		return nil, errors.New("requester and responder must differ")
	}
	s.seq++
	now := time.Now().UTC().Format(time.RFC3339)
	e := &EOI{
		ID:               fmt.Sprintf("EOI-%s-%04d", time.Now().UTC().Format("20060102"), s.seq),
		RequesterID:      req.RequesterID,
		ResponderID:      req.ResponderID,
		SubjectPseudoTIN: req.SubjectPseudoTIN,
		Purpose:          req.Purpose,
		Status:           "draft",
		Request:          req.Request,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	s.byID[e.ID] = e
	return e, s.persist(e)
}

func (s *EOIStore) MarkSent(id, receiptID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok {
		return errNotFound
	}
	e.Status = "sent"
	e.GatewayReceiptID = receiptID
	e.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return s.persist(e)
}

// GetFor enforces the four-party visibility rule on reads.
func (s *EOIStore) GetFor(id, authorityID string, isSecretariat bool) (*EOI, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok {
		return nil, errNotFound
	}
	if !visible(e, authorityID, isSecretariat) {
		return nil, errForbidden
	}
	return e, nil
}

// ListFor returns only exchanges visible to the caller (inbox filtering).
func (s *EOIStore) ListFor(authorityID string, isSecretariat bool) []*EOI {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*EOI
	for _, e := range s.byID {
		if visible(e, authorityID, isSecretariat) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// Answer lets ONLY the responder authority answer.
func (s *EOIStore) Answer(id, authorityID, response string) (*EOI, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok {
		return nil, errNotFound
	}
	if e.ResponderID != authorityID {
		return nil, errForbidden
	}
	e.Response = response
	e.Status = "answered"
	e.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return e, s.persist(e)
}
