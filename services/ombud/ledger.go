package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Ledger scheme (SPEC 1.5): ledger 500 = dispute_deposits. Account id is
// 128-bit: high 64 bits = namespace code, low 64 bits = entity serial.
// Transfer codes: 5=settle(post), 6=hold(pending), 7=release(void).
const (
	LedgerDisputeDeposits = 500
	CodeSettle            = 5
	CodeHold              = 6
	CodeRelease           = 7

	nsDepositPool = 9001 // namespace: ombud deposit pool (revenue-side)
	nsAppellant   = 9002 // namespace: appellant deposit accounts
)

// AccountID builds a 128-bit account id as (hi:lo) hex pair strings.
func AccountID(namespace, serial uint64) string {
	return fmt.Sprintf("%016x%016x", namespace, serial)
}

// DepositHold records a 20% appeal deposit hold.
type DepositHold struct {
	HoldID     string `json:"hold_id"`
	CaseID     string `json:"case_id"`
	AmountKobo int64  `json:"amount_kobo"`
	Status     string `json:"status"` // held | released | settled
	CreatedAt  string `json:"created_at"`
	Mode       string `json:"mode"` // core-ledger-api | dev-inmemory
}

// LedgerClient mirrors the core ledger interface subset ombud needs
// (SPEC 1.5). Real client used when LEDGER_URL is set; dev fallback below
// implements TigerBeetle semantics in memory.
type LedgerClient interface {
	Hold(caseID string, serial uint64, amountKobo int64) (*DepositHold, error)
	Release(holdID string) error
	Settle(holdID string) error
	Balance(accountID string) (int64, error)
	Mode() string
}

// --- core ledger API client -------------------------------------------------

type CoreLedgerClient struct {
	base string
	http *http.Client
}

func NewCoreLedgerClient(base string) *CoreLedgerClient {
	return &CoreLedgerClient{base: base, http: &http.Client{Timeout: 8 * time.Second}}
}

func (c *CoreLedgerClient) Mode() string { return "core-ledger-api" }

func (c *CoreLedgerClient) post(path string, body any, out any) error {
	raw, _ := json.Marshal(body)
	resp, err := c.http.Post(c.base+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ledger API %s -> %d", path, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *CoreLedgerClient) Hold(caseID string, serial uint64, amountKobo int64) (*DepositHold, error) {
	var out struct {
		TransferID string `json:"transfer_id"`
	}
	err := c.post("/v1/transfers/pending", map[string]any{
		"ledger": LedgerDisputeDeposits, "code": CodeHold,
		"debit_account_id":  AccountID(nsAppellant, serial),
		"credit_account_id": AccountID(nsDepositPool, serial),
		"amount":            amountKobo, "user_data": caseID,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &DepositHold{HoldID: out.TransferID, CaseID: caseID, AmountKobo: amountKobo,
		Status: "held", CreatedAt: time.Now().UTC().Format(time.RFC3339), Mode: c.Mode()}, nil
}

func (c *CoreLedgerClient) Release(holdID string) error {
	return c.post("/v1/transfers/"+holdID+"/void", map[string]any{"code": CodeRelease}, nil)
}

func (c *CoreLedgerClient) Settle(holdID string) error {
	return c.post("/v1/transfers/"+holdID+"/post", map[string]any{"code": CodeSettle}, nil)
}

func (c *CoreLedgerClient) Balance(accountID string) (int64, error) {
	resp, err := c.http.Get(c.base + "/v1/accounts/" + accountID + "/balance")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var out struct {
		Balance int64 `json:"balance"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	return out.Balance, nil
}

// --- dev in-memory fallback (TigerBeetle semantics) -------------------------

type memTransfer struct {
	id      string
	amount  int64
	pending bool
	caseID  string
}

type InMemLedgerClient struct {
	mu        sync.Mutex
	seq       int
	transfers map[string]*memTransfer
	holds     map[string]*DepositHold
	poolBal   int64
}

func NewInMemLedgerClient() *InMemLedgerClient {
	return &InMemLedgerClient{transfers: map[string]*memTransfer{}, holds: map[string]*DepositHold{}}
}

func (c *InMemLedgerClient) Mode() string { return "dev-inmemory" }

func (c *InMemLedgerClient) Hold(caseID string, serial uint64, amountKobo int64) (*DepositHold, error) {
	if amountKobo <= 0 {
		return nil, fmt.Errorf("deposit amount must be positive")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	id := fmt.Sprintf("tb-hold-%06d", c.seq)
	c.transfers[id] = &memTransfer{id: id, amount: amountKobo, pending: true, caseID: caseID}
	h := &DepositHold{HoldID: id, CaseID: caseID, AmountKobo: amountKobo, Status: "held",
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Mode: c.Mode()}
	c.holds[id] = h
	return h, nil
}

func (c *InMemLedgerClient) Release(holdID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.transfers[holdID]
	if !ok || !t.pending {
		return fmt.Errorf("no pending hold %s", holdID)
	}
	t.pending = false // void: funds never moved
	c.holds[holdID].Status = "released"
	return nil
}

func (c *InMemLedgerClient) Settle(holdID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.transfers[holdID]
	if !ok || !t.pending {
		return fmt.Errorf("no pending hold %s", holdID)
	}
	t.pending = false
	c.poolBal += t.amount // post: pool account credited
	c.holds[holdID].Status = "settled"
	return nil
}

func (c *InMemLedgerClient) Balance(accountID string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.poolBal, nil
}

func newLedgerClient(cfg Config) LedgerClient {
	if cfg.LedgerURL != "" {
		return NewCoreLedgerClient(cfg.LedgerURL)
	}
	return NewInMemLedgerClient()
}
