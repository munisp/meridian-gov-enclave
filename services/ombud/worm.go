package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// EvidenceReceipt is the synchronous WORM proof issued BEFORE any enclave
// consumer sees an accepted cross-zone message (SPEC 5).
type EvidenceReceipt struct {
	EvidenceID string `json:"evidence_id"`
	SHA256     string `json:"sha256"`
	WormURI    string `json:"worm_uri"`
	Immutable  bool   `json:"immutable"`
	StoredAt   string `json:"stored_at"`
	Mode       string `json:"mode"` // audit-evidence-api | local-worm
	Flow       string `json:"flow"`
	MessageID  string `json:"message_id"`
}

// WORMStore is the write-once evidence interface (core audit-evidence API or
// local dev fallback). Real client wired via AUDIT_EVIDENCE_URL.
type WORMStore interface {
	Store(flow, messageID string, payload []byte) (*EvidenceReceipt, error)
	Mode() string
}

// --- core audit-evidence API client ---------------------------------------

type APIWORMStore struct {
	base   string
	client *http.Client
}

func NewAPIWORMStore(base string) *APIWORMStore {
	return &APIWORMStore{base: base, client: &http.Client{Timeout: 8 * time.Second}}
}

func (s *APIWORMStore) Mode() string { return "audit-evidence-api" }

func (s *APIWORMStore) Store(flow, messageID string, payload []byte) (*EvidenceReceipt, error) {
	sum := sha256.Sum256(payload)
	body, _ := json.Marshal(map[string]any{
		"kind": "cross-zone-message", "flow": flow, "message_id": messageID,
		"sha256": hex.EncodeToString(sum[:]), "payload_b64": base64Encode(payload),
	})
	resp, err := s.client.Post(s.base+"/v1/evidence", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("audit-evidence API returned %d", resp.StatusCode)
	}
	var out struct {
		EvidenceID string `json:"evidence_id"`
		WormURI    string `json:"worm_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &EvidenceReceipt{
		EvidenceID: out.EvidenceID, SHA256: hex.EncodeToString(sum[:]),
		WormURI: out.WormURI, Immutable: true, StoredAt: time.Now().UTC().Format(time.RFC3339),
		Mode: s.Mode(), Flow: flow, MessageID: messageID,
	}, nil
}

func base64Encode(b []byte) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	for i := 0; i < len(b); i += 3 {
		var n uint32
		remain := len(b) - i
		n = uint32(b[i]) << 16
		if remain > 1 {
			n |= uint32(b[i+1]) << 8
		}
		if remain > 2 {
			n |= uint32(b[i+2])
		}
		out = append(out, chars[(n>>18)&63], chars[(n>>12)&63])
		if remain > 1 {
			out = append(out, chars[(n>>6)&63])
		} else {
			out = append(out, '=')
		}
		if remain > 2 {
			out = append(out, chars[n&63])
		} else {
			out = append(out, '=')
		}
	}
	return string(out)
}

// --- local dev WORM fallback ----------------------------------------------
// Append-only directory: each evidence object written once, manifest logs
// sha256 chained to the previous entry (tamper-evident). Simulated WORM for
// dev; production uses the core audit-evidence service backed by object-lock
// storage.

type LocalWORMStore struct {
	dir string
	mu  sync.Mutex
}

func NewLocalWORMStore(root string) (*LocalWORMStore, error) {
	dir := filepath.Join(root, "worm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &LocalWORMStore{dir: dir}, nil
}

func (s *LocalWORMStore) Mode() string { return "local-worm" }

func (s *LocalWORMStore) Store(flow, messageID string, payload []byte) (*EvidenceReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sum := sha256.Sum256(payload)
	id := fmt.Sprintf("ev-%d-%s", time.Now().UnixNano(), hex.EncodeToString(sum[:8]))
	objPath := filepath.Join(s.dir, id+".json")
	if _, err := os.Stat(objPath); err == nil {
		return nil, fmt.Errorf("WORM violation: object %s already exists", id)
	}
	receipt := &EvidenceReceipt{
		EvidenceID: id, SHA256: hex.EncodeToString(sum[:]),
		WormURI: "worm://local/" + id, Immutable: true,
		StoredAt: time.Now().UTC().Format(time.RFC3339),
		Mode:     s.Mode(), Flow: flow, MessageID: messageID,
	}
	obj := map[string]any{
		"receipt": receipt,
		"payload": json.RawMessage(payload),
	}
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(objPath, data, 0o444); err != nil { // read-only: write-once
		return nil, err
	}
	// Tamper-evident chained manifest.
	prev := s.lastManifestHash()
	mline := fmt.Sprintf("%s %s %s prev=%s\n", receipt.StoredAt, id, receipt.SHA256, prev)
	mh := sha256.Sum256(append([]byte(prev), []byte(mline)...))
	f, err := os.OpenFile(filepath.Join(s.dir, "manifest.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.WriteString(mline + "manifest_hash=" + hex.EncodeToString(mh[:]) + "\n"); err != nil {
		return nil, err
	}
	return receipt, nil
}

func (s *LocalWORMStore) lastManifestHash() string {
	data, err := os.ReadFile(filepath.Join(s.dir, "manifest.log"))
	if err != nil || len(data) == 0 {
		return "genesis"
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	last := lines[len(lines)-1]
	if i := bytes.Index(last, []byte("manifest_hash=")); i >= 0 {
		return string(last[i+len("manifest_hash="):])
	}
	return "genesis"
}

// ListReceipts reads the local manifest for the admin receipt log endpoint.
func (s *LocalWORMStore) ListReceipts(limit int) []map[string]string {
	data, err := os.ReadFile(filepath.Join(s.dir, "manifest.log"))
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var out []map[string]string
	for i := len(lines) - 1; i >= 0 && len(out) < limit; i-- {
		if lines[i] == "" || strings.HasPrefix(lines[i], "manifest_hash") {
			continue
		}
		out = append(out, map[string]string{"entry": lines[i]})
	}
	return out
}

func newWORMStore(cfg Config) (WORMStore, *LocalWORMStore, error) {
	if cfg.AuditEvidenceURL != "" {
		return NewAPIWORMStore(cfg.AuditEvidenceURL), nil, nil
	}
	l, err := NewLocalWORMStore(cfg.DataRoot)
	if err != nil {
		return nil, nil, err
	}
	return l, l, nil
}
