// Package storex provides the DATABASE_URL Postgres path (HARDENING H1/H3)
// for gov-enclave Go services. When DATABASE_URL is unset the services keep
// their embedded JSON-file stores (dev fallback, zero config); when set, the
// same document rows persist to Postgres via pgx/v5 with idempotent
// auto-migration (CREATE TABLE IF NOT EXISTS) matching the JSON document
// schemas one-to-one (id TEXT PRIMARY KEY, doc JSONB).
package storex

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgx pool for document stores.
type DB struct {
	Pool *pgxpool.Pool
}

// Open connects when databaseURL is non-empty and applies the idempotent DDL
// statements. Returns (nil, nil) when databaseURL is empty (dev fallback).
// Startup never fails because the var is missing.
func Open(ctx context.Context, databaseURL, component string, ddl ...string) (*DB, error) {
	if databaseURL == "" {
		log.Printf("profile=dev component=%s store=json-file", component)
		return nil, nil
	}
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	cfg.MaxConns = 8
	cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres connect: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	for _, stmt := range ddl {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			pool.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}
	log.Printf("profile=prod component=%s store=postgres", component)
	return &DB{Pool: pool}, nil
}

// Close releases the pool (nil-safe).
func (d *DB) Close() {
	if d != nil {
		d.Pool.Close()
	}
}

// DocTableDDL returns the idempotent DDL for a JSONB document table.
func DocTableDDL(table string) string {
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
  id TEXT PRIMARY KEY,
  doc JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`, table)
}

// UpsertDoc inserts or replaces a document row.
func (d *DB) UpsertDoc(ctx context.Context, table, id string, doc []byte) error {
	_, err := d.Pool.Exec(ctx,
		fmt.Sprintf(`INSERT INTO %s (id, doc, updated_at) VALUES ($1, $2, now())
  ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()`, table),
		id, doc)
	return err
}

// DeleteDoc removes a document row.
func (d *DB) DeleteDoc(ctx context.Context, table, id string) error {
	_, err := d.Pool.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, table), id)
	return err
}

// LoadDocs loads all document rows keyed by id.
func (d *DB) LoadDocs(ctx context.Context, table string) (map[string][]byte, error) {
	rows, err := d.Pool.Query(ctx, fmt.Sprintf(`SELECT id, doc FROM %s`, table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]byte{}
	for rows.Next() {
		var id string
		var doc []byte
		if err := rows.Scan(&id, &doc); err != nil {
			return nil, err
		}
		out[id] = doc
	}
	return out, rows.Err()
}
