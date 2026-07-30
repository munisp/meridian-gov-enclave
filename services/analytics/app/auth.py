"""Auth per SPEC 1.3: Bearer JWT (HS256 dev secret) or X-Dev-Role when AUTH_MODE=dev."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

DEV_ROLES = {"admin", "operator", "auditor"}


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
        claims = decode_hs256(authz[7:].strip(), secret)
        if claims:
            roles = claims.get("roles", [])
            if isinstance(roles, str):
                roles = [roles]
            return {"sub": claims.get("sub", "unknown"), "roles": roles,
                    "tenant_id": claims.get("tenant_id", "")}
    if auth_mode == "dev":
        role = request.headers.get("x-dev-role")
        if role in DEV_ROLES:
            return {"sub": f"dev-{role}", "roles": [role], "tenant_id": "dev"}
    return None
