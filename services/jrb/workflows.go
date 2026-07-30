package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

// --- in-process workflow runner (dev fallback for Temporal, SPEC 1.1) ------

type WorkflowRun struct {
	RunID      string         `json:"run_id"`
	Workflow   string         `json:"workflow"`
	Status     string         `json:"status"` // running | completed | failed
	StartedAt  string         `json:"started_at"`
	FinishedAt string         `json:"finished_at,omitempty"`
	Steps      []WorkflowStep `json:"steps"`
}

type WorkflowStep struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
	FinishedAt string `json:"finished_at"`
}

type WorkflowRunner struct {
	mu   sync.Mutex
	runs map[string]*WorkflowRun
	seq  int
}

func NewWorkflowRunner() *WorkflowRunner {
	return &WorkflowRunner{runs: map[string]*WorkflowRun{}}
}

func (r *WorkflowRunner) Execute(name string, steps []struct {
	Name string
	Fn   func() (any, error)
}) *WorkflowRun {
	r.mu.Lock()
	r.seq++
	run := &WorkflowRun{RunID: fmt.Sprintf("run-%06d", r.seq), Workflow: name,
		Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339)}
	r.runs[run.RunID] = run
	r.mu.Unlock()

	for _, st := range steps {
		step := WorkflowStep{Name: st.Name, Status: "running"}
		res, err := st.Fn()
		step.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		if err != nil {
			step.Status = "failed"
			step.Error = err.Error()
			run.Steps = append(run.Steps, step)
			run.Status = "failed"
			break
		}
		step.Status = "completed"
		step.Result = res
		run.Steps = append(run.Steps, step)
	}
	if run.Status == "running" {
		run.Status = "completed"
	}
	run.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	return run
}

func (r *WorkflowRunner) List() []*WorkflowRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*WorkflowRun, 0, len(r.runs))
	for _, run := range r.runs {
		out = append(out, run)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RunID > out[j].RunID })
	return out
}

func (r *WorkflowRunner) Get(id string) (*WorkflowRun, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	run, ok := r.runs[id]
	return run, ok
}

var WorkflowNames = []string{
	"wf-jrb-onboard", "wf-jrb-route", "wf-jrb-reconcile", "wf-jrb-eoi",
	"wf-jrb-joint-audit", "wf-jrb-cert-rotate", "wf-jrb-single-filing",
	"wf-jrb-attribution-publish",
}

// --- cross-zone client: sends ONLY via enclave-gateway (WORM receipts) -----

type GatewayClient struct {
	base  string // empty -> local simulated receipt (honesty tag: SIMULATED)
	token string
	http  *http.Client
}

type GatewaySendResult struct {
	ReceiptID string `json:"receipt_id"`
	SHA256    string `json:"sha256"`
	Mode      string `json:"mode"` // enclave-gateway | simulated-local
}

func (c *GatewayClient) SendF6EOI(payload []byte) (*GatewaySendResult, error) {
	if c.base == "" {
		// Dev fallback when the gateway is not running: simulated receipt.
		return &GatewaySendResult{
			ReceiptID: fmt.Sprintf("sim-rcpt-%d", time.Now().UnixNano()),
			SHA256:    "simulated", Mode: "simulated-local",
		}, nil
	}
	req, err := http.NewRequest("POST", c.base+"/flows/f6/eoi-exchange", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Dev-Role", "admin")
	req.Header.Set("X-Internal-Flow-Token", c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusAccepted {
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
