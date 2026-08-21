"""Hermes configuration: env-driven settings + platform endpoint constants.

Endpoint paths are the REAL routes registered by the owning services in the
sibling repos (wiring audit §3.3); tools whose SPEC D endpoint exists nowhere
are gated as `planned` in hermes.agent.tools and do not appear here. Every
base URL is env-overridable; defaults point at each service's real listener
(see SERVICE_URLS) with the APISIX edge as the platform fallback.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


# Real platform endpoint paths per live tool (see hermes.agent.tools).
ENDPOINTS: dict[str, str] = {
    # taxpayer copilot
    "estimate_tax": "/v1/evaluate",                    # core rules-engine
    "file_nil_return": "/v1/filings/vat",              # compliance filings (nil VAT return)
    # auditor copilot
    "get_taxpayer_360": "/v1/taxpayer360/{tin_hash}",  # core tin-graph
    "search_payments": "/v1/payments",                 # inclusion presumptive
    "get_kyc_evidence": "/v1/cases/{case_id}/evidence",  # inclusion kyc-engine
    "get_rule_pack": "/v1/packs/{id}/{version}",       # core rp-registry
    # policy copilot
    "list_rule_packs": "/v1/packs",                    # core rules-engine
    # onboarding assistant
    "create_kyc_case": "/v1/cases",                    # inclusion kyc-engine
    "get_case_status": "/v1/cases/{case_id}",          # inclusion kyc-engine
    # static/local tools (explain_term, upload_doc_hint) have no endpoint.
    # Planned tools (get_obligations, get_filing_calendar, search_filings,
    # assemble_evidence, draft_finding, hubble_flows, kafka_lag, drift_report,
    # pod_health, run_runbook, simulate, aggregate_taxpayers, save_scenario,
    # get_field_gaps) intentionally have no entry: no real route exists.
}


def _service_urls() -> dict[str, str]:
    """Per-service base URLs for tool dispatch. Defaults are each service's
    real dev listener (from its main.go/envOr or compose file); an empty
    value falls back to the APISIX platform base (platform_base_url)."""
    return {
        "rules-engine": os.environ.get("HERMES_RULES_ENGINE_URL", "http://localhost:8001"),
        "rp-registry": os.environ.get("HERMES_RP_REGISTRY_URL", "http://localhost:8002"),
        "tin-graph": os.environ.get("HERMES_TIN_GRAPH_URL", "http://localhost:8003"),
        "kyc-engine": os.environ.get("HERMES_KYC_URL", "http://localhost:8105"),
        "presumptive": os.environ.get("HERMES_PRESUMPTIVE_URL", "http://localhost:8102"),
        # filings has no documented standalone port: route via the gateway.
        "filings": os.environ.get("HERMES_FILINGS_URL", ""),
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
    # Platform API base: the APISIX edge gateway (core-platform
    # infra/apisix/config.yaml node_listen 9080). Tool HTTP calls are
    # user-token scoped; per-service overrides in service_urls win when set.
    platform_base_url: str = os.environ.get("HERMES_PLATFORM_BASE_URL", "http://localhost:9080")
    # Per-service tool-dispatch base URLs (env-overridable; "" => platform base).
    service_urls: dict = field(default_factory=_service_urls)
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
    # REAL onboarding clients (docs/WHATSAPP.md). Both required when
    # PROFILE=prod with the WhatsApp channel active (fail-closed at startup);
    # unset in dev => honest SIM fallback (SimOtpSender / SimTokenIssuer).
    notification_url: str = os.environ.get("NOTIFICATION_URL", "")
    otp_send_timeout_s: float = float(os.environ.get("OTP_SEND_TIMEOUT_S", "5"))
    identity_url: str = os.environ.get("IDENTITY_URL", "")
    identity_exchange_timeout_s: float = float(os.environ.get("IDENTITY_EXCHANGE_TIMEOUT_S", "10"))
    endpoints: dict = field(default_factory=lambda: dict(ENDPOINTS))


_DEV_SECRET_DEFAULT = "meridian-dev-secret"


def _refuse_insecure_prod(s: Settings) -> None:
    """A1-10: prod refuses to boot on the default/missing dev JWT secret or
    AUTH_MODE=dev — both leave HS256/X-Dev-Role auth fully forgeable."""
    # NOTE: dataclass field defaults are frozen at import time; read env
    # directly so the gate honours the live process environment.
    profile = os.environ.get("PROFILE", "dev")
    if profile != "prod":
        return
    if os.environ.get("AUTH_MODE", "dev") == "dev":
        raise RuntimeError(
            "hermes: PROFILE=prod refuses AUTH_MODE=dev (HS256 dev secret + "
            "X-Dev-Role are forgeable); configure AUTH_MODE=keycloak")
    jwt_secret = os.environ.get("MERIDIAN_DEV_JWT_SECRET", _DEV_SECRET_DEFAULT)
    if not jwt_secret or jwt_secret == _DEV_SECRET_DEFAULT:
        raise RuntimeError(
            "hermes: PROFILE=prod refuses the default/missing MERIDIAN_DEV_JWT_SECRET; "
            "set a strong secret explicitly (fail-closed)")


def get_settings() -> Settings:
    s = Settings()
    _refuse_insecure_prod(s)
    return s
