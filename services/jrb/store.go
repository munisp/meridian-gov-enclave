package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/munisp/meridian-gov-enclave/packages/storex"
)

// Authority is a member of the Joint Revenue Board registry: NRS, the JRB
// secretariat itself, or a state IRS / FCT-IRS.
type Authority struct {
	ID             string `json:"id"` // e.g. "NG-LA", "NRS", "JRB-SEC"
	Kind           string `json:"kind"` // nrs | secretariat | state_irs
	Name           string `json:"name"`
	StateCode      string `json:"state_code,omitempty"`
	Status         string `json:"status"` // seeded | onboarding | active | suspended
	CertFingerprint string `json:"cert_fingerprint,omitempty"`
	OnboardedAt    string `json:"onboarded_at,omitempty"`
	MTLSNotes      string `json:"mtls_notes,omitempty"`
}

const prodMTLSNotes = "PROD: authority presents an X.509 client certificate issued by the " +
	"JRB PKI; mTLS both directions plus OIDC client-credentials. Dev profile accepts a PEM " +
	"cert upload and records its SHA-256 fingerprint instead."

// AuthoritiesTable is the Postgres table (H3 DDL, idempotent auto-migrate).
const AuthoritiesTable = "jrb_authorities"

type AuthorityStore struct {
	mu   sync.Mutex
	path string
	byID map[string]*Authority
	pg   *storex.DB // nil -> JSON-file dev fallback
}

// NewAuthorityStore opens the store. When pg is non-nil (DATABASE_URL set) the
// canonical rows live in Postgres (jrb_authorities, JSONB docs matching the
// JSON file schema); otherwise the embedded JSON file is used.
func NewAuthorityStore(root string, pg *storex.DB) (*AuthorityStore, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	s := &AuthorityStore{path: filepath.Join(root, "authorities.json"), byID: map[string]*Authority{}, pg: pg}
	if pg != nil {
		docs, err := pg.LoadDocs(context.Background(), AuthoritiesTable)
		if err != nil {
			return nil, fmt.Errorf("load authorities from postgres: %w", err)
		}
		for id, doc := range docs {
			var a Authority
			if json.Unmarshal(doc, &a) == nil {
				s.byID[id] = &a
			}
		}
	} else if data, err := os.ReadFile(s.path); err == nil {
		var rows []*Authority
		if json.Unmarshal(data, &rows) == nil {
			for _, r := range rows {
				s.byID[r.ID] = r
			}
		}
	}
	s.seed()
	return s, s.saveLocked()
}

func (s *AuthorityStore) seed() {
	if s.byID["NRS"] == nil {
		s.byID["NRS"] = &Authority{ID: "NRS", Kind: "nrs", Name: "Nigeria Revenue Service",
			Status: "active", OnboardedAt: time.Now().UTC().Format(time.RFC3339)}
	}
	if s.byID["JRB-SEC"] == nil {
		s.byID["JRB-SEC"] = &Authority{ID: "JRB-SEC", Kind: "secretariat",
			Name: "Joint Revenue Board Secretariat", Status: "active",
			OnboardedAt: time.Now().UTC().Format(time.RFC3339)}
	}
	for _, st := range nigerianStates {
		if s.byID[st.Code] == nil {
			s.byID[st.Code] = &Authority{ID: st.Code, Kind: "state_irs", Name: st.IRS,
				StateCode: st.Code, Status: "seeded"}
		}
	}
}

func (s *AuthorityStore) saveLocked() error {
	rows := make([]*Authority, 0, len(s.byID))
	for _, a := range s.byID {
		rows = append(rows, a)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if s.pg != nil {
		ctx := context.Background()
		for _, a := range rows {
			doc, err := json.Marshal(a)
			if err != nil {
				return err
			}
			if err := s.pg.UpsertDoc(ctx, AuthoritiesTable, a.ID, doc); err != nil {
				return fmt.Errorf("postgres upsert authority %s: %w", a.ID, err)
			}
		}
		return nil
	}
	data, _ := json.MarshalIndent(rows, "", "  ")
	return os.WriteFile(s.path, data, 0o644)
}

func (s *AuthorityStore) List() []*Authority {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]*Authority, 0, len(s.byID))
	for _, a := range s.byID {
		rows = append(rows, a)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows
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
	s.byID[a.ID] = a
	return s.saveLocked()
}

func (s *AuthorityStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
	if s.pg != nil {
		if err := s.pg.DeleteDoc(context.Background(), AuthoritiesTable, id); err != nil {
			return err
		}
	}
	return s.saveLocked()
}

// Onboard processes an authority onboarding: dev profile accepts a PEM client
// certificate and records its SHA-256 fingerprint; production uses mTLS (notes
// recorded on the authority record).
func (s *AuthorityStore) Onboard(id, certPEM string) (*Authority, error) {
	a, ok := s.Get(id)
	if !ok {
		return nil, fmt.Errorf("unknown authority %s", id)
	}
	fp, subject, err := certFingerprint(certPEM)
	if err != nil {
		return nil, err
	}
	a.Status = "active"
	a.CertFingerprint = fp
	a.OnboardedAt = time.Now().UTC().Format(time.RFC3339)
	a.MTLSNotes = prodMTLSNotes + " Dev cert subject: " + subject
	return a, s.Upsert(a)
}

// certFingerprint validates the PEM and returns the SHA-256 fingerprint of the
// DER bytes plus the certificate subject.
func certFingerprint(certPEM string) (string, string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", "", fmt.Errorf("invalid PEM: expected CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("cannot parse certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), cert.Subject.String(), nil
}

// RotateCert replaces an authority certificate (wf-jrb-cert-rotate activity):
// old fingerprint is invalidated, new one recorded.
func (s *AuthorityStore) RotateCert(id, newCertPEM string) (*Authority, string, error) {
	a, ok := s.Get(id)
	if !ok {
		return nil, "", fmt.Errorf("unknown authority %s", id)
	}
	old := a.CertFingerprint
	fp, subject, err := certFingerprint(newCertPEM)
	if err != nil {
		return nil, "", err
	}
	a.CertFingerprint = fp
	a.MTLSNotes = prodMTLSNotes + " Dev cert subject: " + subject
	return a, old, s.Upsert(a)
}
