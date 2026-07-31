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

// AttributionFormula is the NTAA VAT attribution formula: 30% place of
// consumption, residual 70% on equality + derivation. Loaded from the
// rp-attribution-formula pack (embedded fallback keeps dev standalone).
type AttributionFormula struct {
	PackRef                       string
	PlaceOfConsumptionWeightBps   int
	ResidualBps                   int
}

func LoadAttributionFormula(packsDir string) *AttributionFormula {
	f := &AttributionFormula{
		PackRef:                     "rp-attribution-formula@1.0.0",
		PlaceOfConsumptionWeightBps: 3000,
		ResidualBps:                 7000,
	}
	path := filepath.Join(packsDir, "rp-attribution-formula", "1.0.0.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return f // embedded fallback
	}
	var pack struct {
		ID      string `yaml:"id"`
		Version string `yaml:"version"`
		Rules   []struct {
			ID   string         `yaml:"id"`
			Then map[string]any `yaml:"then"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return f
	}
	f.PackRef = fmt.Sprintf("%s@%s", pack.ID, pack.Version)
	for _, rule := range pack.Rules {
		switch rule.ID {
		case "attr.vat.state_share":
			if v, ok := rule.Then["place_of_consumption_weight_bps"].(int); ok {
				f.PlaceOfConsumptionWeightBps = v
			}
		case "attr.vat.residual":
			if v, ok := rule.Then["residual_bps"].(int); ok {
				f.ResidualBps = v
			}
		}
	}
	return f
}

// StateConsumptionInput is a state's consumption and derivation shares (bps of
// the national totals) for a period.
type StateConsumptionInput struct {
	StateCode      string `json:"state_code"`
	ConsumptionBps int    `json:"consumption_bps"`
	DerivationBps  int    `json:"derivation_bps"`
}

// FeedState is one state's attributed VAT revenue row.
type FeedState struct {
	StateCode               string `json:"state_code"`
	ConsumptionPortionKobo  int64  `json:"consumption_portion_kobo"`
	EqualityPortionKobo     int64  `json:"equality_portion_kobo"`
	DerivationPortionKobo   int64  `json:"derivation_portion_kobo"`
	TotalKobo               int64  `json:"total_kobo"`
}

// AttributionFeed is the NTAA attribution feed for a period (signed output).
type AttributionFeed struct {
	FeedID    string               `json:"feed_id"`
	Period    string               `json:"period"`
	PoolKobo  int64                `json:"pool_kobo"`
	Formula   map[string]any       `json:"formula"`
	States    []FeedState          `json:"states"`
	BuiltAt   string               `json:"built_at"`
	PackRef   string               `json:"pack_ref"`
}

// BuildAttributionFeed computes the feed. Consumption portion = 30% of pool
// distributed by consumption shares; residual 70% split half equality (equal
// per state) half derivation (by derivation shares). Integer kobo; rounding
// remainders go to the largest consumption share state and the pool is
// conserved exactly (test-proven).
func (f *AttributionFormula) BuildAttributionFeed(period string, poolKobo int64,
	inputs []StateConsumptionInput) (*AttributionFeed, error) {
	if poolKobo < 0 || len(inputs) == 0 {
		return nil, errors.New("pool_kobo >= 0 and at least one state input required")
	}
	var cTot, dTot int
	seen := map[string]bool{}
	for _, in := range inputs {
		if in.StateCode == "" || seen[in.StateCode] {
			return nil, fmt.Errorf("duplicate or empty state_code %q", in.StateCode)
		}
		seen[in.StateCode] = true
		if in.ConsumptionBps < 0 || in.DerivationBps < 0 {
			return nil, errors.New("shares must be non-negative bps")
		}
		cTot += in.ConsumptionBps
		dTot += in.DerivationBps
	}
	if cTot <= 0 {
		return nil, errors.New("consumption shares must sum to > 0 bps")
	}
	consPool := poolKobo * int64(f.PlaceOfConsumptionWeightBps) / 10000
	residPool := poolKobo - consPool
	eqPool := residPool / 2
	derPool := residPool - eqPool
	n := int64(len(inputs))

	states := make([]FeedState, 0, len(inputs))
	var distributed int64
	largestIdx, largestShare := 0, -1
	for i, in := range inputs {
		cons := consPool * int64(in.ConsumptionBps) / int64(cTot)
		eq := eqPool / n
		var der int64
		if dTot > 0 {
			der = derPool * int64(in.DerivationBps) / int64(dTot)
		}
		st := FeedState{
			StateCode:              in.StateCode,
			ConsumptionPortionKobo: cons,
			EqualityPortionKobo:    eq,
			DerivationPortionKobo:  der,
			TotalKobo:              cons + eq + der,
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
			"place_of_consumption_weight_bps": f.PlaceOfConsumptionWeightBps,
			"residual_bps":                    f.ResidualBps,
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
	Signature string          `json:"signature"` // hex ed25519 over feed bytes
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
