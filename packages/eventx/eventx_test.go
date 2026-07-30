package eventx

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOutboxEmitterDevFallback(t *testing.T) {
	t.Setenv("KAFKA_BROKERS", "")
	dir := t.TempDir()
	e := New("svc-test", dir)
	defer e.Close()
	err := e.Emit(context.Background(), "nrs.jrb.attribution.v1", Envelope{
		Type: "nrs.jrb.attribution.v1", Data: map[string]any{"state": "NG-LA"},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "outbox.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var line struct {
		Topic    string   `json:"topic"`
		Envelope Envelope `json:"envelope"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &line); err != nil {
		t.Fatal(err)
	}
	if line.Topic != "nrs.jrb.attribution.v1" || line.Envelope.Source != "svc-test" ||
		line.Envelope.ID == "" || line.Envelope.Time == "" {
		t.Fatalf("bad outbox line: %+v", line)
	}
	if len(line.Envelope.ID) != 26 {
		t.Fatalf("id not ulid-shaped: %q", line.Envelope.ID)
	}
}

func TestSplitCSV(t *testing.T) {
	got := splitCSV("a:9092,b:9092,,c:9092")
	if len(got) != 3 || got[0] != "a:9092" || got[2] != "c:9092" {
		t.Fatalf("splitCSV: %v", got)
	}
}
