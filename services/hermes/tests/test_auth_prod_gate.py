"""A1-08/A1-10 regression: hermes prod fail-closed gates.

A1-08: PROFILE=prod + AUTH_MODE=keycloak without KEYCLOAK_AUDIENCE refuses
to boot (validate_auth_config) and decode_rs256 denies bearers even if the
boot gate were bypassed.
A1-10: prod refuses the default/missing dev JWT secret and AUTH_MODE=dev.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hermes.gateway import auth as auth_mod  # noqa: E402
from hermes.config import get_settings  # noqa: E402


def test_validate_auth_config_prod_requires_audience(monkeypatch):
    monkeypatch.delenv("KEYCLOAK_AUDIENCE", raising=False)
    with pytest.raises(RuntimeError):
        auth_mod.validate_auth_config("keycloak", "prod")
    monkeypatch.setenv("KEYCLOAK_AUDIENCE", "hermes")
    auth_mod.validate_auth_config("keycloak", "prod")
    monkeypatch.delenv("KEYCLOAK_AUDIENCE", raising=False)
    auth_mod.validate_auth_config("keycloak", "dev")


def test_decode_rs256_denies_in_prod_without_audience(monkeypatch):
    monkeypatch.setenv("PROFILE", "prod")
    monkeypatch.setenv("KEYCLOAK_ISSUER", "https://idp.example/realms/m")
    monkeypatch.delenv("KEYCLOAK_AUDIENCE", raising=False)
    monkeypatch.setattr(auth_mod, "_jwks_client", object())  # bypass JWKS build
    assert auth_mod.decode_rs256("a.b.c") is None


def test_prod_refuses_default_dev_secret(monkeypatch):
    monkeypatch.setenv("PROFILE", "prod")
    monkeypatch.setenv("AUTH_MODE", "keycloak")
    monkeypatch.setenv("MERIDIAN_DEV_JWT_SECRET", "meridian-dev-secret")
    with pytest.raises(RuntimeError):
        get_settings()
    monkeypatch.setenv("MERIDIAN_DEV_JWT_SECRET", "strong-prod-secret-0123456789abcdef")
    # boot no longer refuses (NOTE: dataclass field values are frozen at
    # import time, so only the no-raise behavior is asserted here)
    get_settings()


def test_prod_refuses_dev_auth_mode(monkeypatch):
    monkeypatch.setenv("PROFILE", "prod")
    monkeypatch.setenv("AUTH_MODE", "dev")
    with pytest.raises(RuntimeError):
        get_settings()


def test_dev_default_secret_still_allowed(monkeypatch):
    monkeypatch.setenv("PROFILE", "dev")
    monkeypatch.setenv("AUTH_MODE", "dev")
    monkeypatch.delenv("MERIDIAN_DEV_JWT_SECRET", raising=False)
    assert get_settings().jwt_secret == "meridian-dev-secret"
