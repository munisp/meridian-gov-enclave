package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/munisp/meridian-gov-enclave/packages/storex"
)

// Authority is one row of the JRB authority registry (NRS, secretariat,
// 36 states + FCT, plus onboarded bodies).
type Authority struct {
	ID              string    `json:"id"`
	Kind            string    `json:"kind"` // nrs | jrb_secretariat | state_irs | other
	Name            string    `json:"name"`
	Status          string    `json:"status"` // seeded | active | suspended
	CertFingerprint string    `json:"cert_fingerprint,omitempty"`
	OnboardedAt     string    `json:"onboarded_at,omitempty"`
	OnboardingNotes string    `json:"onboarding_notes,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// pgDocStore is the storex-backed Postgres document path (H3); nil in dev.
type pgDocStore interface {
	UpsertDoc(ctx context.Context, table, id string, doc []byte) error
	DeleteDoc(ctx context.Context, table, id string) error
	LoadDocs(ctx context.Context, table string) (map[string][]byte, error)
}

// AuthorityStore persists the registry. Dev: JSON files (zero config).
// Prod: DATABASE_URL Postgres via storex (jrb_authorities, JSONB docs).
type AuthorityStore struct {
	mu   sync.Mutex
	dir  string
	pg   pgDocStore
	byID map[string]*Authority
}

const AuthoritiesTable = "jrb_authorities"

func NewAuthorityStore(dataRoot string, pg pgDocStore) (*AuthorityStore, error) {
	s := &AuthorityStore{dir: filepath.Join(dataRoot, "authorities"), pg: pg,
		byID: map[string]*Authority{}}
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
	s.seed()
	return s, nil
}

func (s *AuthorityStore) load() error {
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
		var a Authority
		if err := json.Unmarshal(data, &a); err != nil {
			return err
		}
		s.byID[a.ID] = &a
	}
	return nil
}

func (s *AuthorityStore) loadPG() error {
	docs, err := s.pg.LoadDocs(context.Background(), AuthoritiesTable)
	if err != nil {
		return err
	}
	for id, raw := range docs {
		var a Authority
		if err := json.Unmarshal(raw, &a); err != nil {
			return fmt.Errorf("decode authority %s: %w", id, err)
		}
		s.byID[id] = &a
	}
	return nil
}

// seed inserts NRS, the secretariat, and all 36 states + FCT when missing.
func (s *AuthorityStore) seed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	seeds := []Authority{
		{ID: "NRS", Kind: "nrs", Name: "Nigerian Revenue Service", Status: "active"},
		{ID: "JRB-SEC", Kind: "jrb_secretariat", Name: "Joint Revenue Board Secretariat", Status: "active"},
	}
	for _, st := range nigerianStates {
		seeds = append(seeds, Authority{ID: st.Code, Kind: "state_irs", Name: st.Name, Status: "seeded"})
	}
	for _, a := range seeds {
		if _, ok := s.byID[a.ID]; ok {
			continue
		}
		a.CreatedAt, a.UpdatedAt = now, now
		s.byID[a.ID] = &a
		_ = s.persistLocked(&a)
	}
}

func (s *AuthorityStore) persistLocked(a *Authority) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	if s.pg != nil {
		return s.pg.UpsertDoc(context.Background(), AuthoritiesTable, a.ID, data)
	}
	return os.WriteFile(filepath.Join(s.dir, a.ID+".json"), data, 0o644)
}

func (s *AuthorityStore) List() []Authority {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Authority, 0, len(s.byID))
	for _, a := range s.byID {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *AuthorityStore) Get(id string) (*Authority, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	return a, ok
}

func (s *AuthorityStore) Upsert(a *Authority) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.byID[a.ID]; ok {
		a.CreatedAt = cur.CreatedAt
	} else {
		a.CreatedAt = time.Now().UTC()
	}
	a.UpdatedAt = time.Now().UTC()
	s.byID[a.ID] = a
	return s.persistLocked(a)
}

func (s *AuthorityStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
	if s.pg != nil {
		return s.pg.DeleteDoc(context.Background(), AuthoritiesTable, id)
	}
	return os.Remove(filepath.Join(s.dir, id+".json"))
}

// certFingerprint computes SHA-256 over the DER bytes of a PEM certificate.
func certFingerprint(pemStr string) (string, error) {
	var der []byte
	rest := []byte(pemStr)
	for {
		var block *struct {
			Type  string
			Bytes []byte
		}
		_ = block
		b, r := pemDecode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			der = b.Bytes
			break
		}
		rest = r
	}
	if der == nil {
		return "", errors.New("no CERTIFICATE PEM block found")
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// pemBlock mirrors encoding/pem.Block without importing twice.
type pemBlock struct {
	Type  string
	Bytes []byte
}

// Onboard registers an authority with a dev cert upload + fingerprint.
// Prod onboarding (mTLS + OIDC) is recorded via OnboardingNotes.
func (s *AuthorityStore) Onboard(id, certPEM string) (*Authority, error) {
	fp, err := certFingerprint(certPEM)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok {
		return nil, fmt.Errorf("unknown authority %q", id)
	}
	a.CertFingerprint = fp
	a.Status = "active"
	a.OnboardedAt = time.Now().UTC().Format(time.RFC3339)
	a.OnboardingNotes = "dev: cert upload + sha256 fingerprint; prod: mTLS + OIDC"
	a.UpdatedAt = time.Now().UTC()
	return a, s.persistLocked(a)
}

// RotateCert replaces an authority certificate, revoking the old fingerprint.
func (s *AuthorityStore) RotateCert(id, certPEM string) (*Authority, string, error) {
	fp, err := certFingerprint(certPEM)
	if err != nil {
		return nil, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok {
		return nil, "", fmt.Errorf("unknown authority %q", id)
	}
	old := a.CertFingerprint
	a.CertFingerprint = fp
	a.OnboardedAt = time.Now().UTC().Format(time.RFC3339)
	a.UpdatedAt = time.Now().UTC()
	return a, old, s.persistLocked(a)
}

// compile-time assertion that storex.DB satisfies pgDocStore when wired.
var _ pgDocStore = (*storex.DB)(nil)
