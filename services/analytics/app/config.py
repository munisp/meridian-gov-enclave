"""Configuration via env vars with sane localhost defaults (SPEC 1.3)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    service_name: str = "analytics"
    version: str = "0.1.0"
    port: int = int(os.environ.get("PORT", "8401"))
    auth_mode: str = os.environ.get("AUTH_MODE", "dev")  # dev | prod
    jwt_secret: str = os.environ.get("MERIDIAN_DEV_JWT_SECRET", "meridian-dev-secret")
    # Sovereign enclave data root: lakehouse parquet zones live here.
    data_root: str = os.environ.get("ANALYTICS_DATA_ROOT", os.path.join(os.getcwd(), "data"))
    tin_hmac_key: str = os.environ.get("TIN_HMAC_KEY", "dev-tin-hmac-key-change-me")
    # Core platform dependencies (behind interfaces; local fallbacks when unset).
    tin_graph_url: str = os.environ.get("TIN_GRAPH_URL", "")  # e.g. http://localhost:8002
    audit_evidence_url: str = os.environ.get("AUDIT_EVIDENCE_URL", "")
    # Scoring / disclosure defaults (overridable via rp-disclosure-control pack).
    case_score_threshold: int = int(os.environ.get("CASE_SCORE_THRESHOLD", "650"))
    packs_dir: str = field(default_factory=lambda: os.environ.get(
        "PACKS_DIR", os.path.join(os.path.dirname(__file__), "packs")))


_DEV_SECRET_DEFAULT = "meridian-dev-secret"


def _refuse_insecure_prod(s: Settings) -> None:
    """A1-10: prod refuses to boot on the default/missing dev JWT secret or
    AUTH_MODE=dev — both leave HS256/X-Dev-Role auth fully forgeable."""
    # NOTE: dataclass field defaults are frozen at import time; read env
    # directly so the gate honours the live process environment.
    auth_mode = os.environ.get("AUTH_MODE", "dev")
    profile = os.environ.get("PROFILE", "prod" if auth_mode == "keycloak" else "dev")
    if profile != "prod":
        return
    if auth_mode == "dev":
        raise RuntimeError(
            "analytics: PROFILE=prod refuses AUTH_MODE=dev (HS256 dev secret + "
            "X-Dev-Role are forgeable); configure AUTH_MODE=keycloak")
    jwt_secret = os.environ.get("MERIDIAN_DEV_JWT_SECRET", _DEV_SECRET_DEFAULT)
    if not jwt_secret or jwt_secret == _DEV_SECRET_DEFAULT:
        raise RuntimeError(
            "analytics: PROFILE=prod refuses the default/missing MERIDIAN_DEV_JWT_SECRET; "
            "set a strong secret explicitly (fail-closed)")


def get_settings() -> Settings:
    s = Settings()
    _refuse_insecure_prod(s)
    return s
