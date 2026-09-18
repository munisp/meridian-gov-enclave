package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/munisp/meridian-gov-enclave/packages/keyx/provider"
)

// AttributionFormula is the NTAA 2025 (gazetted) VAT horizontal attribution
// formula for the states'/LGAs' share of the VAT pool:
//
//	50% equality + 20% population + 30% place of consumption.
//
// There is NO derivation limb in the gazetted NTAA formula (the earlier
// 35/35 equality/derivation residual hardcode was wrong and has been
// removed). Weights are loaded from the rp-attribution-formula pack when
// available; the embedded fallback carries the same statutory constants so
// dev stays standalone. A pack whose weights do not sum to 10000 bps is
// rejected (fail closed to the statutory constants). The formula is
// effective-dated: it applies only to periods on/after the pack's
// effective_from; earlier periods are refused rather than computed with an
// unverifiable formula.
type AttributionFormula struct {
	PackRef                     string
	EqualityWeightBps           int
	PopulationWeightBps         int
	PlaceOfConsumptionWeightBps int
	// EffectiveFrom is the first month (YYYY-MM) the formula governs,
	// from the pack's effective_from date.
	EffectiveFrom string
}

// statutoryWeights are the NTAA 2025 gazetted VAT attribution weights.
const (
	statutoryEqualityBps    = 5000
	statutoryPopulationBps  = 2000
	statutoryConsumptionBps = 3000
)

func LoadAttributionFormula(packsDir string) *AttributionFormula {
	f := &AttributionFormula{
		PackRef:                     "rp-attribution-formula@1.0.0",
		EqualityWeightBps:           statutoryEqualityBps,
		PopulationWeightBps:         statutoryPopulationBps,
		PlaceOfConsumptionWeightBps: statutoryConsumptionBps,
		EffectiveFrom:               "2026-01",
	}
	path := filepath.Join(packsDir, "rp-attribution-formula", "1.0.0.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return f // embedded fallback (statutory constants)
	}
	var pack struct {
		ID            string `yaml:"id"`
		Version       string `yaml:"version"`
		EffectiveFrom string `yaml:"effective_from"`
		Rules         []struct {
			ID   string         `yaml:"id"`
			Then map[string]any `yaml:"then"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return f
	}
	f.PackRef = fmt.Sprintf("%s@%s", pack.ID, pack.Version)
	if len(pack.EffectiveFrom) >= 7 {
		f.EffectiveFrom = pack.EffectiveFrom[:7]
	}
	eq, pop, cons := f.EqualityWeightBps, f.PopulationWeightBps, f.PlaceOfConsumptionWeightBps
	for _, rule := range pack.Rules {
		if rule.ID != "attr.vat.state_share" {
			continue
		}
		if v, ok := rule.Then["equality_weight_bps"].(int); ok {
			eq = v
		}
		if v, ok := rule.Then["population_weight_bps"].(int); ok {
			pop = v
		}
		if v, ok := rule.Then["place_of_consumption_weight_bps"].(int); ok {
			cons = v
		}
	}
	// Fail closed: a pack whose weights do not partition 100% exactly is
	// rejected in favour of the statutory constants — a mis-summing pack
	// must never silently scale state allocations.
	if eq+pop+cons != 10000 {
		return f
	}
	f.EqualityWeightBps, f.PopulationWeightBps, f.PlaceOfConsumptionWeightBps = eq, pop, cons
	return f
}

// StateConsumptionInput is a state's population and consumption shares (bps
// of the national totals) for a period.
type StateConsumptionInput struct {
	StateCode      string `json:"state_code"`
	ConsumptionBps int    `json:"consumption_bps"`
	PopulationBps  int    `json:"population_bps"`
}

// FeedState is one state's attributed VAT revenue row.
type FeedState struct {
	StateCode              string `json:"state_code"`
	ConsumptionPortionKobo int64  `json:"consumption_portion_kobo"`
	EqualityPortionKobo    int64  `json:"equality_portion_kobo"`
	PopulationPortionKobo  int64  `json:"population_portion_kobo"`
	TotalKobo              int64  `json:"total_kobo"`
}

// AttributionFeed is the NTAA attribution feed for a period (signed output).
type AttributionFeed struct {
	FeedID   string         `json:"feed_id"`
	Period   string         `json:"period"`
	PoolKobo int64          `json:"pool_kobo"`
	Formula  map[string]any `json:"formula"`
	States   []FeedState    `json:"states"`
	BuiltAt  string         `json:"built_at"`
	PackRef  string         `json:"pack_ref"`
}

// BuildAttributionFeed computes the feed per the gazetted NTAA formula:
// consumption portion = 30% of pool distributed by consumption shares;
// population portion = 20% distributed by population shares; equality
// portion = 50% shared equally per state. There is no derivation limb.
// The formula is effective-dated: periods before the pack's effective_from
// are refused (no gazetted formula in force to compute them with). Integer
// kobo; rounding remainders go to the largest consumption share state and
// the pool is conserved exactly (test-proven).
func (f *AttributionFormula) BuildAttributionFeed(period string, poolKobo int64,
	inputs []StateConsumptionInput) (*AttributionFeed, error) {
	if poolKobo < 0 || len(inputs) == 0 {
		return nil, errors.New("pool_kobo >= 0 and at least one state input required")
	}
	if f.EffectiveFrom != "" && period < f.EffectiveFrom {
		return nil, fmt.Errorf("no gazetted NTAA attribution formula in force for "+
			"period %q (formula effective from %s); refusing to compute",
			period, f.EffectiveFrom)
	}
	var cTot, pTot int
	seen := map[string]bool{}
	for _, in := range inputs {
		if in.StateCode == "" || seen[in.StateCode] {
			return nil, fmt.Errorf("duplicate or empty state_code %q", in.StateCode)
		}
		seen[in.StateCode] = true
		if in.ConsumptionBps < 0 || in.PopulationBps < 0 {
			return nil, errors.New("shares must be non-negative bps")
		}
		cTot += in.ConsumptionBps
		pTot += in.PopulationBps
	}
	if cTot <= 0 {
		return nil, errors.New("consumption shares must sum to > 0 bps")
	}
	if pTot <= 0 {
		return nil, errors.New("population shares must sum to > 0 bps")
	}
	consPool := poolKobo * int64(f.PlaceOfConsumptionWeightBps) / 10000
	popPool := poolKobo * int64(f.PopulationWeightBps) / 10000
	eqPool := poolKobo - consPool - popPool // 50%, remainder-safe
	n := int64(len(inputs))

	states := make([]FeedState, 0, len(inputs))
	var distributed int64
	largestIdx, largestShare := 0, -1
	for i, in := range inputs {
		cons := consPool * int64(in.ConsumptionBps) / int64(cTot)
		pop := popPool * int64(in.PopulationBps) / int64(pTot)
		eq := eqPool / n
		st := FeedState{
			StateCode:              in.StateCode,
			ConsumptionPortionKobo: cons,
			EqualityPortionKobo:    eq,
			PopulationPortionKobo:  pop,
			TotalKobo:              cons + eq + pop,
		}
		distributed += st.TotalKobo
		if in.ConsumptionBps > largestShare {
			largestShare, largestIdx = in.ConsumptionBps, i
		}
		states = append(states, st)
	}
	// Conserve the pool exactly: remainder to the largest consumption state.
	if rem := poolKobo - distributed; rem != 0 {
		states[largestIdx].ConsumptionPortionKobo += rem
		states[largestIdx].TotalKobo += rem
	}
	return &AttributionFeed{
		FeedID:   "feed-" + period + "-" + time.Now().UTC().Format("150405"),
		Period:   period,
		PoolKobo: poolKobo,
		Formula: map[string]any{
			"equality_weight_bps":             f.EqualityWeightBps,
			"population_weight_bps":           f.PopulationWeightBps,
			"place_of_consumption_weight_bps": f.PlaceOfConsumptionWeightBps,
			"effective_from":                  f.EffectiveFrom,
			"pack_ref":                        f.PackRef,
		},
		States:  states,
		BuiltAt: time.Now().UTC().Format(time.RFC3339),
		PackRef: f.PackRef,
	}, nil
}

// --- ed25519 feed signing (gateway F7 verifies before serving) ----------------

// FeedSigner signs attribution feeds with an ed25519 keypair persisted under
// <dataRoot>/signing/ (dev ceremony; prod uses HSM-backed keys).
type FeedSigner struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	// prov, when non-nil and non-software, routes feed signing to the HSM/KMS
	// key provider (KEY_PROVIDER=hsm|pkcs11|cloud-kms); priv stays nil.
	prov provider.SignerProvider
}

// NewFeedSignerWithProvider loads the feed signer through the key-provider
// abstraction. A nil or software-mode prov keeps the legacy dev keypair
// behaviour (NewFeedSigner). A non-software prov signs via the HSM/KMS
// "feed" key; construction fails closed if the provider cannot serve the
// public key.
func NewFeedSignerWithProvider(dataRoot string, prov provider.SignerProvider) (*FeedSigner, error) {
	if prov == nil || prov.Mode() == "software" {
		return NewFeedSigner(dataRoot)
	}
	pub, err := prov.PublicKey(context.Background(), "feed")
	if err != nil {
		return nil, fmt.Errorf("feed signer: provider public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("feed signer: provider returned %d-byte public key, want ed25519", len(pub))
	}
	return &FeedSigner{prov: prov, pub: ed25519.PublicKey(append([]byte(nil), pub...))}, nil
}

func NewFeedSigner(dataRoot string) (*FeedSigner, error) {
	dir := filepath.Join(dataRoot, "signing")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "feed-signing.key")
	if raw, err := os.ReadFile(keyPath); err == nil && len(raw) == ed25519.PrivateKeySize {
		priv := ed25519.PrivateKey(raw)
		return &FeedSigner{pub: priv.Public().(ed25519.PublicKey), priv: priv}, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "feed-signing.pub"),
		[]byte(hex.EncodeToString(pub)), 0o644); err != nil {
		return nil, err
	}
	return &FeedSigner{pub: pub, priv: priv}, nil
}

// SignedFeedDoc is the signed feed envelope served via gateway F7.
type SignedFeedDoc struct {
	Feed      json.RawMessage `json:"feed"`
	Signature string          `json:"signature"`  // hex ed25519 over feed bytes
	PublicKey string          `json:"public_key"` // hex ed25519 public key
}

func (s *FeedSigner) Sign(feed *AttributionFeed) (*SignedFeedDoc, error) {
	raw, err := json.Marshal(feed)
	if err != nil {
		return nil, err
	}
	var sig []byte
	if s.prov != nil {
		sig, err = s.prov.Sign(context.Background(), "feed", raw)
		if err != nil {
			return nil, fmt.Errorf("feed sign: %w", err)
		}
	} else {
		sig = ed25519.Sign(s.priv, raw)
	}
	return &SignedFeedDoc{
		Feed:      raw,
		Signature: hex.EncodeToString(sig),
		PublicKey: hex.EncodeToString(s.pub),
	}, nil
}

// Verify checks a signed feed document (used by tests and the gateway).
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

var _ = strings.TrimSpace // keep strings import used across build tags
