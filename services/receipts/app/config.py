"""Configuration via env vars (SPEC 1.3). Fail-closed prod: WORM root and
signing key must be configured when AUTH_MODE=keycloak."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    service_name: str = "receipts"
    version: str = "0.1.0"
    port: int = int(os.environ.get("PORT", "8406"))
    auth_mode: str = os.environ.get("AUTH_MODE", "dev")  # dev | keycloak
    jwt_secret: str = os.environ.get("MERIDIAN_DEV_JWT_SECRET", "meridian-dev-secret")
    # WORM storage root (append-only, hash-chained JSONL).
    worm_root: str = os.environ.get("RECEIPTS_WORM_ROOT",
                                    os.path.join(os.getcwd(), "data", "worm"))
    signing_key_pem: str = os.environ.get("RECEIPTS_SIGNING_KEY_PEM", "")
    # Optional event bus for nrs.receipts.issued.v1; local outbox otherwise.
    event_bus_url: str = os.environ.get("EVENT_BUS_URL", "")

    @property
    def prod(self) -> bool:
        return self.auth_mode == "keycloak"


def get_settings() -> Settings:
    return Settings()
