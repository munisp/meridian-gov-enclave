package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	ServiceName      string
	Version          string
	Port             string
	AuthMode         string
	JWTSecret        string
	DataRoot         string
	LedgerURL        string // core ledger API; empty -> dev TigerBeetle-semantics fallback
	AuditEvidenceURL string // core audit-evidence API; empty -> local WORM fallback
	RegWatchURL      string // core reg-watch API; empty -> local gate file fallback
	PacksDir         string
	DatabaseURL      string // H1: postgres://... ; empty -> embedded JSON stores
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadConfig() Config {
	cwd, _ := os.Getwd()
	return Config{
		ServiceName:      "ombud",
		Version:          "0.1.0",
		Port:             getenv("PORT", "8403"),
		AuthMode:         getenv("AUTH_MODE", "dev"),
		JWTSecret:        getenv("MERIDIAN_DEV_JWT_SECRET", "meridian-dev-secret"),
		DataRoot:         getenv("OMBUD_DATA_ROOT", filepath.Join(cwd, "data")),
		LedgerURL:        os.Getenv("LEDGER_URL"),
		AuditEvidenceURL: os.Getenv("AUDIT_EVIDENCE_URL"),
		RegWatchURL:      os.Getenv("REG_WATCH_URL"),
		PacksDir:         getenv("PACKS_DIR", "packs"),
		DatabaseURL:      os.Getenv("DATABASE_URL"),
	}
}

// --- minimal YAML scalar extraction for embedded fallback packs ------------
// (Production loads pinned packs from rp-registry; dev parses the embedded
// fallback files for the scalar parameters the service needs.)

func packScalar(packsDir, packID, key string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(packsDir, packID, "1.0.0.yaml"))
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		// block style: "days: 7"
		if v, ok := strings.CutPrefix(line, key+":"); ok {
			return strings.TrimSpace(strings.Trim(v, "{},")), true
		}
		// inline flow style: "then: { days: 7, narrate: ... }"
		if idx := strings.Index(line, "{ "+key+":"); idx >= 0 {
			rest := line[idx+len("{ "+key+":"):]
			rest = strings.TrimSpace(rest)
			if cut := strings.IndexAny(rest, ",}"); cut >= 0 {
				rest = rest[:cut]
			}
			return strings.TrimSpace(rest), true
		}
	}
	return "", false
}

func packInt(packsDir, packID, key string, def int) int {
	if v, ok := packScalar(packsDir, packID, key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
