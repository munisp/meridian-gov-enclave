package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// WorkflowRun records an in-proc workflow execution (Temporal dev fallback).
type WorkflowRun struct {
	RunID      string         `json:"run_id"`
	Workflow   string         `json:"workflow"`
	Status     string         `json:"status"` // running | completed | failed
	StartedAt  string         `json:"started_at"`
	FinishedAt string         `json:"finished_at,omitempty"`
	Steps      []WorkflowStep `json:"steps"`
}

// WorkflowStep is one step of a run.
type WorkflowStep struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"`
}

// WorkflowRunner is the in-proc dev runner.
type WorkflowRunner struct {
	mu   sync.Mutex
	seq  int
	runs []*WorkflowRun
}

func NewWorkflowRunner() *WorkflowRunner { return &WorkflowRunner{} }

func (r *WorkflowRunner) Execute(name string, steps []struct {
	Name string
	Fn   func() (any, error)
}) *WorkflowRun {
	r.mu.Lock()
	r.seq++
	run := &WorkflowRun{
		RunID:     fmt.Sprintf("run-%s-%04d", time.Now().UTC().Format("20060102"), r.seq),
		Workflow:  name, Status: "running",
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
	r.runs = append([]*WorkflowRun{run}, r.runs...)
	if len(r.runs) > 200 {
		r.runs = r.runs[:200]
	}
	r.mu.Unlock()

	ok := true
	for _, st := range steps {
		step := WorkflowStep{Name: st.Name, Status: "running",
			StartedAt: time.Now().UTC().Format(time.RFC3339)}
		res, err := st.Fn()
		if err != nil {
			step.Status, step.Error, ok = "failed", err.Error(), false
		} else {
			step.Status, step.Result = "completed", res
		}
		step.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		run.Steps = append(run.Steps, step)
		if !ok {
			break
		}
	}
	r.mu.Lock()
	if ok {
		run.Status = "completed"
	} else {
		run.Status = "failed"
	}
	run.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	r.mu.Unlock()
	return run
}

func (r *WorkflowRunner) List() []*WorkflowRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*WorkflowRun, len(r.runs))
	copy(out, r.runs)
	return out
}

// WorkflowNames is the wf-jrb-* catalogue.
var WorkflowNames = []string{
	"wf-jrb-onboard", "wf-jrb-route", "wf-jrb-reconcile", "wf-jrb-eoi",
	"wf-jrb-joint-audit", "wf-jrb-cert-rotate", "wf-jrb-single-filing",
	"wf-jrb-attribution-publish",
}

// GatewayClient is the ONLY cross-zone send path: enclave-gateway F6 with WORM
// receipt capture. When the gateway URL is unset, a local simulated receipt is
// returned (honesty tag: mode=simulated-local).
type GatewayClient struct {
	base  string
	token string
	http  *http.Client
}

// GatewaySendResult is the WORM receipt captured from the gateway.
type GatewaySendResult struct {
	ReceiptID string `json:"receipt_id"`
	SHA256    string `json:"sha256"`
	Mode      string `json:"mode"` // enclave-gateway | simulated-local
}

// SendF6EOI posts an EOI payload via gateway F6 (enclave-internal flow).
func (g *GatewayClient) SendF6EOI(payload []byte) (*GatewaySendResult, error) {
	if g.base == "" {
		return &GatewaySendResult{
			ReceiptID: fmt.Sprintf("sim-ev-%d", time.Now().UnixNano()),
			SHA256:    "simulated", Mode: "simulated-local",
		}, nil
	}
	req, err := http.NewRequest(http.MethodPost, g.base+"/flows/f6/eoi-exchange",
		bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Flow-Token", g.token)
	resp, err := g.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gateway rejected F6 send: %d %s", resp.StatusCode, string(body))
	}
	var out struct {
		Receipt struct {
			EvidenceID string `json:"evidence_id"`
			SHA256     string `json:"sha256"`
		} `json:"evidence_receipt"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &GatewaySendResult{ReceiptID: out.Receipt.EvidenceID,
		SHA256: out.Receipt.SHA256, Mode: "enclave-gateway"}, nil
}
