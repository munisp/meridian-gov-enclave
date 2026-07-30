package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// AttributionFormula holds the NTAA VAT attribution parameters loaded from
// rp-attribution-formula (embedded fallback pack under packs/).
type AttributionFormula struct {
	PlaceOfConsumptionWeightBps int // NTAA: 30% follows place of consumption
	ResidualBps                 int // remaining 70%
	EqualityShareOfResidualBps  int // 50% of residual on equality
	DerivationShareOfResidualBps int
	PackRef                     string
}

// LoadAttributionFormula parses the embedded fallback pack. The production path
// fetches the pinned signed pack from rp-registry; the parser below extracts the
// formula parameters from the embedded YAML so dev runs standalone.
func LoadAttributionFormula(packsDir string) *AttributionFormula {
	f := &AttributionFormula{
		PlaceOfConsumptionWeightBps:  3000,
		ResidualBps:                  7000,
		EqualityShareOfResidualBps:   5000,
		DerivationShareOfResidualBps: 5000,
		PackRef:                      "rp-attribution-formula@1.0.0",
	}
	data, err := os.ReadFile(filepath.Join(packsDir, "rp-attribution-formula", "1.0.0.yaml"))
	if err != nil {
		return f // constants above are the embedded fallback
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "place_of_consumption_weight_bps:"); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				f.PlaceOfConsumptionWeightBps = n
			}
		}
		if v, ok := strings.CutPrefix(line, "residual_bps:"); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				f.ResidualBps = n
			}
		}
	}
	return f
}

// StateConsumptionInput: consumption and derivation shares per state for a period.
type StateConsumptionInput struct {
	StateCode      string `json:"state_code"`
	ConsumptionBps int    `json:"consumption_bps"` // share of national consumption (basis points)
	DerivationBps  int    `json:"derivation_bps"`  // share of national derivation (basis points)
}

// StateAttribution is one row of the signed feed.
type StateAttribution struct {
	StateCode                string `json:"state_code"`
	ConsumptionPortionKobo   int64  `json:"consumption_portion_kobo"`
	EqualityPortionKobo      int64  `json:"equality_portion_kobo"`
	DerivationPortionKobo    int64  `json:"derivation_portion_kobo"`
	TotalKobo                int64  `json:"total_kobo"`
}

// AttributionFeed is the feed payload that gets ed25519-signed.
type AttributionFeed struct {
	FeedID    string             `json:"feed_id"`
	Period    string             `json:"period"`
	PoolKobo  int64              `json:"pool_kobo"`
	Formula   *AttributionFormula `json:"formula"`
	States    []StateAttribution `json:"states"`
	BuiltAt   string             `json:"built_at"`
}

// BuildAttributionFeed implements the NTAA 30% place-of-consumption formula:
//   - 30% of pool distributed by consumption share
//   - 70% residual: 50% equality (equal split), 50% derivation share
func (f *AttributionFormula) BuildAttributionFeed(period string, poolKobo int64,
	inputs []StateConsumptionInput) (*AttributionFeed, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("at least one state input required")
	}
	var consSum, derSum int
	for _, in := range inputs {
		consSum += in.ConsumptionBps
		derSum += in.DerivationBps
	}
	if consSum == 0 {
		return nil, fmt.Errorf("consumption shares must sum to > 0")
	}
	consumptionPool := poolKobo * int64(f.PlaceOfConsumptionWeightBps) / 10000
	residualPool := poolKobo - consumptionPool
	equalityPool := residualPool * int64(f.EqualityShareOfResidualBps) / 10000
	derivationPool := residualPool - equalityPool

	n := int64(len(inputs))
	feed := &AttributionFeed{
		FeedID: fmt.Sprintf("attr-%s-%d", period, time.Now().UnixNano()),
		Period: period, PoolKobo: poolKobo, Formula: f,
		BuiltAt: time.Now().UTC().Format(time.RFC3339),
	}
	var allocated int64
	for i, in := range inputs {
		row := StateAttribution{StateCode: in.StateCode}
		row.ConsumptionPortionKobo = consumptionPool * int64(in.ConsumptionBps) / int64(consSum)
		row.EqualityPortionKobo = equalityPool / n
		if derSum > 0 {
			row.DerivationPortionKobo = derivationPool * int64(in.DerivationBps) / int64(derSum)
		}
		if i == len(inputs)-1 { // remainder to last row keeps total exact
			row.TotalKobo = poolKobo - allocated
		} else {
			row.TotalKobo = row.ConsumptionPortionKobo + row.EqualityPortionKobo + row.DerivationPortionKobo
		}
		allocated += row.TotalKobo
		feed.States = append(feed.States, row)
	}
	return feed, nil
}

// FeedSigner signs attribution feeds with ed25519 (dev keypair persisted in the
// data root; production uses the JRB HSM-backed key ceremony).
type FeedSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func NewFeedSigner(root string) (*FeedSigner, error) {
	keyPath := filepath.Join(root, "feed_signing_key.hex")
	if data, err := os.ReadFile(keyPath); err == nil {
		raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
		if err == nil && len(raw) == ed25519.PrivateKeySize {
			priv := ed25519.PrivateKey(raw)
			return &FeedSigner{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		return nil, err
	}
	return &FeedSigner{priv: priv, pub: pub}, nil
}

// SignedFeedDoc is the served document: feed bytes + signature + public key,
// matching the enclave-gateway F7 verification contract.
type SignedFeedDoc struct {
	Feed      json.RawMessage `json:"feed"`
	Signature string          `json:"signature"`
	PublicKey string          `json:"public_key"`
	KeyID     string          `json:"key_id"`
}

func (s *FeedSigner) Sign(feed *AttributionFeed) (*SignedFeedDoc, error) {
	raw, err := json.Marshal(feed)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(s.priv, raw)
	return &SignedFeedDoc{
		Feed: raw, Signature: hex.EncodeToString(sig),
		PublicKey: hex.EncodeToString(s.pub), KeyID: "jrb-feed-dev-key",
	}, nil
}

// Verify checks a signed feed doc (used in tests and by wf-jrb-attribution-publish).
func Verify(doc *SignedFeedDoc) bool {
	pub, err := hex.DecodeString(doc.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(doc.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), doc.Feed, sig)
}
