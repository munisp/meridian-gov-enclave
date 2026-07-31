"""Small shared utilities: ULID generation, RFC3339 timestamps, RFC7807
problems, dev auth (mirrors services/analytics conventions, SPEC 1.3)."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import time
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _encode(value: int, length: int) -> str:
    out = []
    for _ in range(length):
        out.append(_CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(out))


def new_ulid() -> str:
    ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand = int.from_bytes(os.urandom(10), "big")
    return _encode(ms, 10) + _encode(rand, 16)


def now_rfc3339() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def problem(status: int, title: str, detail: str = "",
            type_: str = "about:blank") -> JSONResponse:
    """RFC7807 problem+json (SPEC 1.3)."""
    return JSONResponse(status_code=status,
                        media_type="application/problem+json",
                        content={"type": type_, "title": title,
                                 "status": status, "detail": detail})


DEV_ROLES = {"admin", "operator", "auditor", "taxpayer"}


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _decode_hs256(token: str, secret: str) -> dict[str, Any] | None:
    try:
        head, payload, sig = token.split(".")
        expect = hmac.new(secret.encode(), f"{head}.{payload}".encode(),
                          hashlib.sha256).digest()
        if not hmac.compare_digest(expect, _b64url_decode(sig)):
            return None
        claims = json.loads(_b64url_decode(payload))
        if claims.get("exp") and time.time() > claims["exp"]:
            return None
        return {"sub": claims.get("sub", "dev"),
                "roles": claims.get("roles", ["operator"])}
    except Exception:
        return None


def principal_from(request: Request, *, secret: str,
                   auth_mode: str) -> dict[str, Any] | None:
    """Dev: HS256 Bearer or X-Dev-Role. Prod (keycloak): HS256 dev path is
    disabled — RS256 verification is wired via JWKS in the gateway tier;
    here we fail closed (SPEC 1.3 fail-closed prod)."""
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        token = authz[7:].strip()
        if auth_mode == "keycloak":
            return None  # RS256 only at gateway; fail closed here
        return _decode_hs256(token, secret)
    if auth_mode != "keycloak":
        role = request.headers.get("x-dev-role", "")
        if role in DEV_ROLES:
            return {"sub": f"dev-{role}", "roles": [role]}
    return None
