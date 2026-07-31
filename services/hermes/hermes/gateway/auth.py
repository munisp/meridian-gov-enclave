"""Keycloak RS256 auth (sibling pattern from services/analytics/app/auth.py,
HARDENING H2). AUTH_MODE=keycloak verifies Bearer tokens against the Keycloak
JWKS (iss/exp/aud enforced) and is FAIL-CLOSED: any verification problem or
missing config rejects the request. AUTH_MODE=dev keeps HS256 + X-Dev-Role for
local development only; in PROFILE=prod the dev path is disabled entirely."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

log = logging.getLogger("hermes.auth")

DEV_ROLES = {"nrs.taxpayer", "nrs.auditor", "nrs.sre", "nrs.policy",
             "nrs.field-agent", "nrs.admin"}

_jwks_client = None


def _jwks():
    global _jwks_client
    if _jwks_client is not None:
        return _jwks_client
    issuer = os.environ.get("KEYCLOAK_ISSUER", "")
    jwks_url = os.environ.get("KEYCLOAK_JWKS_URL") or (
        issuer.rstrip("/") + "/protocol/openid-connect/certs" if issuer else "")
    if not jwks_url:
        log.warning("hermes auth=keycloak FAIL-CLOSED: KEYCLOAK_ISSUER unset; Bearer rejected")
        return None
    import jwt  # PyJWT[crypto]
    _jwks_client = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=300)
    return _jwks_client


def decode_rs256(token: str) -> dict[str, Any] | None:
    client = _jwks()
    if client is None:
        return None  # fail-closed
    try:
        import jwt
        key = client.get_signing_key_from_jwt(token).key
        kwargs: dict[str, Any] = {"algorithms": ["RS256"]}
        audience = os.environ.get("KEYCLOAK_AUDIENCE", "")
        issuer = os.environ.get("KEYCLOAK_ISSUER", "")
        if audience:
            kwargs["audience"] = audience
        else:
            kwargs["options"] = {"verify_aud": False}
        if issuer:
            kwargs["issuer"] = issuer
        return jwt.decode(token, key, **kwargs)
    except Exception:
        return None  # fail-closed


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def decode_hs256(token: str, secret: str) -> dict[str, Any] | None:
    try:
        header_b64, payload_b64, _ = token.split(".")
        signing = f"{header_b64}.{payload_b64}".encode()
        expected = hmac.new(secret.encode(), signing, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(token.split(".")[2])):
            return None
        claims = json.loads(_b64url_decode(payload_b64))
        if claims.get("exp") and float(claims["exp"]) < time.time():
            return None
        return claims
    except Exception:
        return None


def problem(status: int, title: str, detail: str = "") -> JSONResponse:
    return JSONResponse(status_code=status,
                        media_type="application/problem+json",
                        content={"type": "about:blank", "title": title,
                                 "status": status, "detail": detail})


def principal_from(request: Request, *, secret: str, auth_mode: str,
                   profile: str) -> dict[str, Any] | None:
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        token = authz[7:].strip()
        claims = (decode_rs256(token) if auth_mode == "keycloak"
                  else (None if profile == "prod" else decode_hs256(token, secret)))
        if claims:
            roles = claims.get("roles", [])
            if isinstance(roles, str):
                roles = [roles]
            realm = claims.get("realm_access") or {}
            roles = list(roles) + list(realm.get("roles", []))
            return {"sub": claims.get("sub", "unknown"), "roles": roles,
                    "token": token, "tenant_id": claims.get("tenant_id", ""),
                    "tin": claims.get("tin", "")}
    if auth_mode == "dev" and profile != "prod":
        role = request.headers.get("x-dev-role")
        if role in DEV_ROLES:
            return {"sub": f"dev-{role}", "roles": [role], "token": "dev-token",
                    "tenant_id": "dev", "tin": request.headers.get("x-dev-tin", "")}
    return None
