"""TIN pseudonymisation per SPEC 1.3: pseudo_tin = HMAC-SHA256(tin, TIN_HMAC_KEY).

Gold-zone datasets MUST carry pseudo_tin only — never raw TIN.
"""
from __future__ import annotations

import hashlib
import hmac


def pseudo_tin(tin: str, key: str) -> str:
    """Deterministic keyed pseudonym for a taxpayer identification number."""
    normalised = (tin or "").strip().upper()
    digest = hmac.new(key.encode("utf-8"), normalised.encode("utf-8"), hashlib.sha256)
    return "ptin_" + digest.hexdigest()[:32]


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
