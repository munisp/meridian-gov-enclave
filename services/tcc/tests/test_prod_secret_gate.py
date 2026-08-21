"""A1-10 regression: tcc prod refuses default/missing dev JWT secret and
AUTH_MODE=dev at boot."""
from __future__ import annotations

import pytest


def _get_settings():
    # Imported lazily inside tests: the Settings dataclass freezes env vars
    # into field defaults at IMPORT time, so importing app.config at module
    # level here would poison sibling test modules that set env first.
    from app.config import get_settings

    return get_settings


def test_prod_refuses_default_dev_secret(monkeypatch):
    monkeypatch.setenv("PROFILE", "prod")
    monkeypatch.setenv("AUTH_MODE", "keycloak")
    monkeypatch.setenv("MERIDIAN_DEV_JWT_SECRET", "meridian-dev-secret")
    with pytest.raises(RuntimeError):
        _get_settings()()
    monkeypatch.setenv("MERIDIAN_DEV_JWT_SECRET", "strong-prod-secret-0123456789abcdef")
    # boot no longer refuses (NOTE: dataclass field values are frozen at
    # import time, so only the no-raise behavior is asserted here)
    _get_settings()()


def test_prod_refuses_dev_auth_mode(monkeypatch):
    monkeypatch.setenv("PROFILE", "prod")
    monkeypatch.setenv("AUTH_MODE", "dev")
    with pytest.raises(RuntimeError):
        _get_settings()()


def test_dev_default_secret_still_allowed(monkeypatch):
    monkeypatch.delenv("PROFILE", raising=False)
    monkeypatch.setenv("AUTH_MODE", "dev")
    monkeypatch.delenv("MERIDIAN_DEV_JWT_SECRET", raising=False)
    assert _get_settings()().jwt_secret == "meridian-dev-secret"
