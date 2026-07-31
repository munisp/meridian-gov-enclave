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


def get_settings() -> Settings:
    return Settings()
