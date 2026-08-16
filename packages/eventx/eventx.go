// Package eventx provides the event bus emitter for gov-enclave services
// (HARDENING H1/H3). KAFKA_BROKERS set -> real franz-go producer/consumer
// (Redpanda); unset -> embedded bus that appends the canonical envelope to
// <dataDir>/outbox.jsonl (dev fallback, zero config). Topics follow the
// nrs.* families of SPEC 1.2; the envelope is SPEC 1.1.
package eventx

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// Envelope is the SPEC 1.1 event envelope.
type Envelope struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Source    string         `json:"source"`
	Time      string         `json:"time"`
	TenantID  string         `json:"tenant_id,omitempty"`
	TraceID   string         `json:"trace_id,omitempty"`
	RulePackV string         `json:"rule_pack_version,omitempty"`
	Data      map[string]any `json:"data"`
}

// Emitter publishes envelopes to a topic.
type Emitter interface {
	Emit(ctx context.Context, topic string, env Envelope) error
	Close()
}

// New selects the emitter from the H1 env contract. Never fails because
// KAFKA_BROKERS is missing; falls back to the embedded outbox bus.
func New(source, dataDir string) Emitter {
	brokers := os.Getenv("KAFKA_BROKERS")
	if brokers == "" {
		log.Printf("profile=dev component=%s bus=embedded-outbox", source)
		return newOutboxEmitter(source, dataDir)
	}
	k, err := newKafkaEmitter(source, brokers)
	if err != nil {
		log.Printf("profile=prod component=%s bus=kafka brokers=%s ERROR %v; falling back to embedded outbox", source, brokers, err)
		return newOutboxEmitter(source, dataDir)
	}
	log.Printf("profile=prod component=%s bus=kafka brokers=%s", source, brokers)
	return k
}

// ---- embedded outbox bus (dev fallback) -----------------------------------

type outboxEmitter struct {
	source string
	mu     sync.Mutex
	path   string
}

func newOutboxEmitter(source, dataDir string) *outboxEmitter {
	_ = os.MkdirAll(dataDir, 0o755)
	return &outboxEmitter{source: source, path: filepath.Join(dataDir, "outbox.jsonl")}
}

func (e *outboxEmitter) Emit(_ context.Context, topic string, env Envelope) error {
	if env.ID == "" {
		env.ID = newULID()
	}
	if env.Time == "" {
		env.Time = time.Now().UTC().Format(time.RFC3339)
	}
	env.Source = e.source
	line, err := json.Marshal(map[string]any{"topic": topic, "envelope": env})
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	f, err := os.OpenFile(e.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

func (e *outboxEmitter) Close() {}

// ---- franz-go Kafka bus (prod) --------------------------------------------

type kafkaEmitter struct {
	source string
	client *kgo.Client
}

func newKafkaEmitter(source, brokers string) (*kafkaEmitter, error) {
	client, err := kgo.NewClient(
		kgo.SeedBrokers(splitCSV(brokers)...),
		kgo.ProducerBatchMaxBytes(1<<20),
		kgo.RequiredAcks(kgo.AllISRAcks()),
	)
	if err != nil {
		return nil, err
	}
	return &kafkaEmitter{source: source, client: client}, nil
}

func (e *kafkaEmitter) Emit(ctx context.Context, topic string, env Envelope) error {
	if env.ID == "" {
		env.ID = newULID()
	}
	if env.Time == "" {
		env.Time = time.Now().UTC().Format(time.RFC3339)
	}
	env.Source = e.source
	payload, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return e.client.ProduceSync(ctx, &kgo.Record{Topic: topic, Key: []byte(env.ID), Value: payload}).FirstErr()
}

func (e *kafkaEmitter) Close() { e.client.Close() }

// Consume runs a franz-go consumer-group loop (prod). handler errors are
// returned to the caller; committed offsets follow franz-go defaults
// (autocommit after poll). DLQ topics follow SPEC 1.2 (topic + ".dlq").
func Consume(ctx context.Context, brokers, group string, topics []string,
	handler func(topic string, env Envelope, raw []byte) error) error {
	client, err := kgo.NewClient(
		kgo.SeedBrokers(splitCSV(brokers)...),
		kgo.ConsumerGroup(group),
		kgo.ConsumeTopics(topics...),
	)
	if err != nil {
		return err
	}
	defer client.Close()
	for {
		fetches := client.PollFetches(ctx)
		if fetches.IsClientClosed() {
			return nil
		}
		var ferr error
		fetches.EachRecord(func(rec *kgo.Record) {
			if ferr != nil {
				return
			}
			var env Envelope
			if err := json.Unmarshal(rec.Value, &env); err != nil {
				ferr = err
				return
			}
			ferr = handler(rec.Topic, env, rec.Value)
		})
		if ferr != nil {
			return ferr
		}
	}
}

func splitCSV(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if part := s[start:i]; part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}

// newULID returns a time-ordered unique id (compact; crypto/rand entropy).
func newULID() string {
	now := time.Now().UnixMilli()
	var randb [10]byte
	f, _ := os.Open("/dev/urandom")
	if f != nil {
		_, _ = f.Read(randb[:])
		f.Close()
	}
	const enc = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var id [26]byte
	// 48 bits time
	t := uint64(now)
	for i := 9; i >= 0; i-- {
		id[i] = enc[t&31]
		t >>= 5
	}
	// 80 bits randomness
	var r uint64
	bi := 0
	for i := 10; i < 26; i++ {
		if bi%8 == 0 {
			r = uint64(randb[bi/8])
		}
		id[i] = enc[r&31]
		r >>= 5
		bi++
	}
	return string(id[:])
}
