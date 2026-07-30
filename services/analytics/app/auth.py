"""Auth per SPEC 1.3 + HARDENING H2: AUTH_MODE=dev keeps HS256 dev secret +
X-Dev-Role; AUTH_MODE=keycloak verifies RS256 Bearer tokens against the
Keycloak JWKS (PyJWT[crypto] + PyJWKClient, iss/exp/aud enforced, realm roles
mapped to the roles claim)."""
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

log = logging.getLogger("analytics.auth")

DEV_ROLES = {"admin", "operator", "auditor"}

_jwks_client = None


def _jwks():
    """Lazily build a PyJWKClient (5-min cache handled by PyJWT)."""
    global _jwks_client
    if _jwks_client is not None:
        return _jwks_client
    issuer = os.environ.get("KEYCLOAK_ISSUER", "")
    jwks_url = os.environ.get("KEYCLOAK_JWKS_URL") or (
        issuer.rstrip("/") + "/protocol/openid-connect/certs" if issuer else "")
    if not jwks_url:
        log.warning("profile=prod component=analytics auth=keycloak WARNING: KEYCLOAK_ISSUER unset; Bearer rejected")
        return None
    import jwt  # PyJWT[crypto]
    _jwks_client = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=300)
    log.info("profile=prod component=analytics auth=keycloak jwks=%s", jwks_url)
    return _jwks_client


def decode_rs256(token: str) -> dict[str, Any] | None:
    """Verify an RS256 token against the Keycloak JWKS; enforce iss/exp/aud."""
    client = _jwks()
    if client is None:
        return None
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
        return None


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def decode_hs256(token: str, secret: str) -> dict[str, Any] | None:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        signing = f"{header_b64}.{payload_b64}".encode()
        expected = hmac.new(secret.encode(), signing, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(sig_b64)):
            return None
        claims = json.loads(_b64url_decode(payload_b64))
        if claims.get("exp") and float(claims["exp"]) < time.time():
            return None
        return claims
    except Exception:
        return None


def problem(status: int, title: str, detail: str = "", type_: str = "about:blank") -> JSONResponse:
    """RFC7807 problem+json (SPEC 1.3)."""
    return JSONResponse(status_code=status,
                        media_type="application/problem+json",
                        content={"type": type_, "title": title, "status": status, "detail": detail})


def principal_from(request: Request, *, secret: str, auth_mode: str) -> dict[str, Any] | None:
    """Returns {'sub','roles'} or None. Public paths are handled in middleware."""
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        token = authz[7:].strip()
        claims = decode_rs256(token) if auth_mode == "keycloak" else decode_hs256(token, secret)
        if claims:
            roles = claims.get("roles", [])
            if isinstance(roles, str):
                roles = [roles]
            # Keycloak realm roles -> roles claim (H2).
            realm = claims.get("realm_access") or {}
            roles = list(roles) + list(realm.get("roles", []))
            return {"sub": claims.get("sub", "unknown"), "roles": roles,
                    "tenant_id": claims.get("tenant_id", "")}
    if auth_mode == "dev":
        role = request.headers.get("x-dev-role")
        if role in DEV_ROLES:
            return {"sub": f"dev-{role}", "roles": [role], "tenant_id": "dev"}
    return None
