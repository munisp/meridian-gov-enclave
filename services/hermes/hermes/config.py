"""Hermes configuration: env-driven settings + platform endpoint constants.

Endpoint paths are the canonical APISIX /v1 surfaces from SPEC D (Hermes
tool-use over platform APIs). Sibling repos' live surfaces are not available
inside this enclave clone, so every base URL is env-overridable; only the
canonical paths from the spec are pinned here.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


# Canonical platform endpoint paths (SPEC D). Base URLs are env-overridable.
ENDPOINTS: dict[str, str] = {
    # taxpayer copilot
    "get_obligations": "/v1/taxpayers/{tin}/obligations",
    "get_filing_calendar": "/v1/filings/calendar",
    "estimate_tax": "/v1/rules-engine/estimate",
    "file_nil_return": "/v1/filings",
    # auditor copilot
    "get_taxpayer_360": "/v1/taxpayer-360/{tin}",
    "search_filings": "/v1/filings",
    "search_payments": "/v1/payments",
    "get_kyc_evidence": "/v1/kyc/cases/{case_id}/evidence",
    "get_rule_pack": "/v1/rules-engine/packs/{version}",
    "assemble_evidence": "/v1/audit-cases/{case_id}/evidence",
    "draft_finding": "/v1/audit-cases/{case_id}/drafts",
    # ops copilot
    "hubble_flows": "/v1/obs/hubble/flows",
    "kafka_lag": "/v1/obs/kafka/lag",
    "drift_report": "/v1/obs/drift/{svc}",
    "pod_health": "/v1/obs/k8s/health",
    "run_runbook": "/v1/ops/runbooks",
    # policy copilot
    "list_rule_packs": "/v1/rules-engine/packs",
    "simulate": "/v1/rules-engine/sandbox/simulate",
    "aggregate_taxpayers": "/v1/analytics/aggregate",
    "save_scenario": "/v1/rules-engine/scenarios",
    # onboarding assistant
    "create_kyc_case": "/v1/kyc/cases",
    "get_case_status": "/v1/kyc/cases/{case_id}",
    "get_field_gaps": "/v1/kyc/cases/{case_id}/field-gaps",
    # static/local tools (explain_term, upload_doc_hint) have no endpoint.
}


@dataclass(frozen=True)
class Settings:
    service_name: str = "hermes"
    version: str = "0.1.0"
    port: int = int(os.environ.get("PORT", "8405"))
    # Auth: dev (HS256 + X-Dev-Role, sibling pattern) | keycloak (RS256, fail-closed)
    auth_mode: str = os.environ.get("AUTH_MODE", "dev")
    jwt_secret: str = os.environ.get("MERIDIAN_DEV_JWT_SECRET", "meridian-dev-secret")
    profile: str = os.environ.get("PROFILE", "dev")  # prod => fail-closed
    # LLM adapter: "ollama" | "rule"
    llm_adapter: str = os.environ.get("HERMES_LLM_ADAPTER", "rule")
    ollama_url: str = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    ollama_model: str = os.environ.get("OLLAMA_MODEL", "qwen2.5:32b-instruct")
    ollama_model_ussd: str = os.environ.get("OLLAMA_MODEL_USSD", "qwen2.5:14b")
    # Platform API base (APISIX gateway). Tool HTTP calls are user-token scoped.
    platform_base_url: str = os.environ.get("HERMES_PLATFORM_BASE_URL", "http://localhost:9080")
    # Loop hard limits (SPEC D section 0)
    max_tool_calls: int = int(os.environ.get("HERMES_MAX_TOOL_CALLS", "8"))
    tool_timeout_s: float = float(os.environ.get("HERMES_TOOL_TIMEOUT_S", "30"))
    max_answer_tokens: int = int(os.environ.get("HERMES_MAX_ANSWER_TOKENS", "4096"))
    # Audit: Kafka topic hermes.toolcalls.v1 (7y retention, hash-chained);
    # JSONL fallback when Kafka unreachable.
    kafka_bootstrap: str = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "")
    audit_topic: str = os.environ.get("HERMES_AUDIT_TOPIC", "hermes.toolcalls.v1")
    audit_jsonl_path: str = os.environ.get("HERMES_AUDIT_JSONL", "")
    # Memory: Redis TTL 24h; embedded fallback when redis lib/URL absent.
    redis_url: str = os.environ.get("REDIS_URL", "")
    memory_ttl_s: int = int(os.environ.get("HERMES_MEMORY_TTL_S", str(24 * 3600)))
    # USSD
    ussd_max_chars: int = int(os.environ.get("HERMES_USSD_MAX_CHARS", "160"))
    # WhatsApp Business Cloud channel (docs/WHATSAPP.md)
    whatsapp_verify_token: str = os.environ.get("WHATSAPP_VERIFY_TOKEN", "")
    whatsapp_app_secret: str = os.environ.get("WHATSAPP_APP_SECRET", "")
    whatsapp_access_token: str = os.environ.get("WHATSAPP_ACCESS_TOKEN", "")
    whatsapp_phone_number_id: str = os.environ.get("WHATSAPP_PHONE_NUMBER_ID", "")
    whatsapp_graph_url: str = os.environ.get("WHATSAPP_GRAPH_URL", "https://graph.facebook.com")
    whatsapp_max_chars: int = int(os.environ.get("WHATSAPP_MAX_CHARS", "4096"))
    # WhatsApp onboarding + stores (REDIS_URL above is reused; in-memory
    # fallback when unset/unreachable). Session TTL matches memory.py (24h);
    # dedup TTL 48h; OTP 6-digit, 10-min TTL, 3 attempts.
    whatsapp_session_ttl_s: int = int(os.environ.get("WHATSAPP_SESSION_TTL_S", str(24 * 3600)))
    whatsapp_dedup_ttl_s: int = int(os.environ.get("WHATSAPP_DEDUP_TTL_S", str(48 * 3600)))
    whatsapp_otp_ttl_s: int = int(os.environ.get("WHATSAPP_OTP_TTL_S", "600"))
    whatsapp_otp_max_attempts: int = int(os.environ.get("WHATSAPP_OTP_MAX_ATTEMPTS", "3"))
    endpoints: dict = field(default_factory=lambda: dict(ENDPOINTS))


def get_settings() -> Settings:
    return Settings()
