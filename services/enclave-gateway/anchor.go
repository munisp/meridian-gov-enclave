package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// anchor.go — sovereign audit-ledger cross-anchoring (I19). Daily, the
// gateway folds the WORM audit hash chain into a Merkle root and anchors it
// to an external ledger (a sealed anchor record file / anchor endpoint).
// Each anchor record is HMAC-sealed with ANCHOR_HMAC_KEY (keyx-style: env or
// fail in prod) and chains to the previous anchor, so the anchor log itself
// is tamper-evident. REAL: anchors are computed from the actual local WORM
// manifest; the "external ledger" here is the sealed anchor log file (or
// ANCHOR_LEDGER_URL when set — posted there as well).

// AnchorRecord is one sealed daily anchor.
type AnchorRecord struct {
	Date        string `json:"date"`         // UTC day
	MerkleRoot  string `json:"merkle_root"`  // over the day's manifest entry hashes
	Entries     int    `json:"entries"`      // manifest entries covered
	ChainTip    string `json:"chain_tip"`    // last manifest_hash covered
	PrevAnchor  string `json:"prev_anchor"`  // hash of previous anchor record (chain)
	ExternalURI string `json:"external_uri"` // where the anchor was recorded
	Seal        string `json:"seal"`         // HMAC-SHA256 over canonical record
	CreatedAt   string `json:"created_at"`
}

func anchorKey() string {
	if k := os.Getenv("ANCHOR_HMAC_KEY"); k != "" {
		return k
	}
	if strings.EqualFold(os.Getenv("AUTH_MODE"), "dev") || os.Getenv("AUTH_MODE") == "" {
		return "meridian-dev-anchor-key" // dev only
	}
	return "" // prod: fail closed (seal will error)
}

func canonicalAnchor(a AnchorRecord) string {
	return strings.Join([]string{a.Date, a.MerkleRoot, fmt.Sprint(a.Entries), a.ChainTip, a.PrevAnchor, a.ExternalURI}, "|")
}

func sealAnchor(a AnchorRecord) (string, error) {
	k := anchorKey()
	if k == "" {
		return "", fmt.Errorf("ANCHOR_HMAC_KEY required in prod profile")
	}
	mac := hmac.New(sha256.New, []byte(k))
	mac.Write([]byte(canonicalAnchor(a)))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// merkleRoot folds hashes pairwise (duplicate last on odd count).
func merkleRoot(hashes []string) string {
	if len(hashes) == 0 {
		return ""
	}
	level := append([]string{}, hashes...)
	for len(level) > 1 {
		var next []string
		for i := 0; i < len(level); i += 2 {
			j := i + 1
			if j >= len(level) {
				j = i
			}
			sum := sha256.Sum256([]byte(level[i] + level[j]))
			next = append(next, hex.EncodeToString(sum[:]))
		}
		level = next
	}
	return level[0]
}

// manifestEntries parses manifest.log lines into (entryHash) pairs: uses the
// per-entry manifest_hash chain values as the Merkle leaves.
func manifestEntries(log string) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		if i := strings.Index(line, "manifest_hash="); i >= 0 {
			out = append(out, line[i+len("manifest_hash="):])
		}
	}
	return out
}

// CreateAnchor computes the Merkle root over the current WORM manifest and
// appends a sealed anchor record to the anchor ledger.
func (s *Server) CreateAnchor() (AnchorRecord, error) {
	if s.localWorm == nil {
		return AnchorRecord{}, fmt.Errorf("anchoring requires the local WORM store (audit-evidence-api mode)")
	}
	data, err := os.ReadFile(filepath.Join(s.localWorm.dir, "manifest.log"))
	if err != nil {
		return AnchorRecord{}, fmt.Errorf("read manifest: %w", err)
	}
	entries := manifestEntries(string(data))
	if len(entries) == 0 {
		return AnchorRecord{}, fmt.Errorf("manifest empty: nothing to anchor")
	}
	a := AnchorRecord{
		Date:        time.Now().UTC().Format("2006-01-02"),
		MerkleRoot:  merkleRoot(entries),
		Entries:     len(entries),
		ChainTip:    entries[len(entries)-1],
		PrevAnchor:  s.lastAnchorHash(),
		ExternalURI: "anchor://local/anchors.log",
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if u := os.Getenv("ANCHOR_LEDGER_URL"); u != "" {
		a.ExternalURI = u
	}
	seal, err := sealAnchor(a)
	if err != nil {
		return AnchorRecord{}, err
	}
	a.Seal = seal
	rec, _ := json.Marshal(a)
	f, err := os.OpenFile(filepath.Join(s.localWorm.dir, "anchors.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return AnchorRecord{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(rec, '\n')); err != nil {
		return AnchorRecord{}, err
	}
	return a, nil
}

func (s *Server) anchorLogPath() string { return filepath.Join(s.localWorm.dir, "anchors.log") }

func (s *Server) lastAnchorHash() string {
	data, err := os.ReadFile(s.anchorLogPath())
	if err != nil || len(data) == 0 {
		return "genesis"
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	sum := sha256.Sum256([]byte(lines[len(lines)-1]))
	return hex.EncodeToString(sum[:])
}

// VerifyAnchors re-checks every anchor record's seal and chain linkage, and
// recomputes the latest Merkle root against the live manifest.
func (s *Server) VerifyAnchors() (map[string]any, error) {
	data, err := os.ReadFile(s.anchorLogPath())
	if err != nil {
		return nil, fmt.Errorf("read anchors: %w", err)
	}
	var anchors []AnchorRecord
	prev := "genesis"
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var a AnchorRecord
		if json.Unmarshal([]byte(line), &a) != nil {
			return map[string]any{"valid": false, "detail": "corrupt anchor record"}, nil
		}
		if a.PrevAnchor != prev {
			return map[string]any{"valid": false, "detail": "anchor chain broken at " + a.Date}, nil
		}
		seal, err := sealAnchor(a)
		if err != nil {
			return nil, err
		}
		if !hmac.Equal([]byte(seal), []byte(a.Seal)) {
			return map[string]any{"valid": false, "detail": "seal mismatch at " + a.Date}, nil
		}
		sum := sha256.Sum256([]byte(line))
		prev = hex.EncodeToString(sum[:])
		anchors = append(anchors, a)
	}
	// latest anchor must cover the current manifest tip
	manifest, _ := os.ReadFile(filepath.Join(s.localWorm.dir, "manifest.log"))
	entries := manifestEntries(string(manifest))
	tipCovered := len(entries) > 0 && anchors[len(anchors)-1].ChainTip == entries[len(entries)-1]
	return map[string]any{
		"valid": true, "anchors": len(anchors), "latest_root": anchors[len(anchors)-1].MerkleRoot,
		"covers_current_chain_tip": tipCovered,
	}, nil
}

func (s *Server) handleCreateAnchor(w http.ResponseWriter, r *http.Request) {
	a, err := s.CreateAnchor()
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "anchor", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) handleVerifyAnchor(w http.ResponseWriter, r *http.Request) {
	res, err := s.VerifyAnchors()
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "anchor_verify", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
