package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// GateClient checks the activation gate for Ombud rules (reg-watch API;
// fallback local gate file <data>/gates.json). Decisions and admissions are
// refused while the gate is not active.
type GateClient interface {
	Active(gate string) (bool, string, error) // (active, mode, err)
	Mode() string
}

type RegWatchGateClient struct {
	base string
	http *http.Client
}

func NewRegWatchGateClient(base string) *RegWatchGateClient {
	return &RegWatchGateClient{base: base, http: &http.Client{Timeout: 5 * time.Second}}
}

func (g *RegWatchGateClient) Mode() string { return "reg-watch-api" }

func (g *RegWatchGateClient) Active(gate string) (bool, string, error) {
	resp, err := g.http.Get(g.base + "/v1/gates")
	if err != nil {
		return false, g.Mode(), err
	}
	defer resp.Body.Close()
	var out struct {
		Gates map[string]bool `json:"gates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, g.Mode(), err
	}
	return out.Gates[gate], g.Mode(), nil
}

// LocalGateClient: dev fallback backed by <data>/gates.json. Default state is
// ACTIVE in dev so the service is usable standalone; flip with the admin
// endpoint or by editing the file (honesty tag: simulated reg-watch).
type LocalGateClient struct {
	path string
}

func NewLocalGateClient(root string) *LocalGateClient {
	return &LocalGateClient{path: filepath.Join(root, "gates.json")}
}

func (g *LocalGateClient) Mode() string { return "local-gate-file" }

func (g *LocalGateClient) read() map[string]bool {
	gates := map[string]bool{"ombud.rules_active": true} // dev default: active
	if data, err := os.ReadFile(g.path); err == nil {
		_ = json.Unmarshal(data, &gates)
	}
	return gates
}

func (g *LocalGateClient) Active(gate string) (bool, string, error) {
	return g.read()[gate], g.Mode(), nil
}

func (g *LocalGateClient) Flip(gate string, active bool) error {
	gates := g.read()
	gates[gate] = active
	data, _ := json.MarshalIndent(gates, "", "  ")
	return os.WriteFile(g.path, data, 0o644)
}

func newGateClient(cfg Config) (GateClient, *LocalGateClient) {
	if cfg.RegWatchURL != "" {
		return NewRegWatchGateClient(cfg.RegWatchURL), nil
	}
	l := NewLocalGateClient(cfg.DataRoot)
	return l, l
}
