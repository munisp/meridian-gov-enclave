"""Configuration via env vars (SPEC 1.3). Fail-closed in prod: the
liability ledger adapter and the ed25519 signing key MUST be configured
when AUTH_MODE=keycloak, else the service refuses to decide applications."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    service_name: str = "tcc"
    version: str = "0.1.0"
    port: int = int(os.environ.get("PORT", "8405"))
    auth_mode: str = os.environ.get("AUTH_MODE", "dev")  # dev | keycloak
    jwt_secret: str = os.environ.get("MERIDIAN_DEV_JWT_SECRET", "meridian-dev-secret")
    data_root: str = os.environ.get("TCC_DATA_ROOT", os.path.join(os.getcwd(), "data"))
    # Rev360/ledger interface for outstanding-liability checks.
    ledger_url: str = os.environ.get("TCC_LEDGER_URL", "")  # e.g. http://ledger:8010
    # ed25519 private key PEM (PKCS8). Dev: ephemeral key generated at boot.
    signing_key_pem: str = os.environ.get("TCC_SIGNING_KEY_PEM", "")
    # NTAA s.72 statutory decision SLA in days.
    sla_days: int = 14
    disclosure_years: int = 3

    @property
    def prod(self) -> bool:
        return self.auth_mode == "keycloak"


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
            "tcc: PROFILE=prod refuses AUTH_MODE=dev (HS256 dev secret + "
            "X-Dev-Role are forgeable); configure AUTH_MODE=keycloak")
    jwt_secret = os.environ.get("MERIDIAN_DEV_JWT_SECRET", _DEV_SECRET_DEFAULT)
    if not jwt_secret or jwt_secret == _DEV_SECRET_DEFAULT:
        raise RuntimeError(
            "tcc: PROFILE=prod refuses the default/missing MERIDIAN_DEV_JWT_SECRET; "
            "set a strong secret explicitly (fail-closed)")


def get_settings() -> Settings:
    s = Settings()
    _refuse_insecure_prod(s)
    return s
