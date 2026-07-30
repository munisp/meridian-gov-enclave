package main

import (
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

type AuthorityStore struct {
	mu   sync.Mutex
	path string
	byID map[string]*Authority
}

func NewAuthorityStore(root string) (*AuthorityStore, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	s := &AuthorityStore{path: filepath.Join(root, "authorities.json"), byID: map[string]*Authority{}}
	if data, err := os.ReadFile(s.path); err == nil {
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
