"""Verifiable certificate signing (ed25519) for TCCs.

REAL: ed25519 sign/verify over a canonical payload; certificate ID is a
ULID embedded in a QR-verifiable verification string
`NRSTCC1|<cert_id>|<issued_at>|<signature_b64url>` (same shape discipline
as the e-invoice QR payload `NRS1|...`). Verification is self-contained:
GET /v1/tcc/verify/{id} recomputes and compares.

Key management: TCC_SIGNING_KEY_PEM (PKCS8 PEM) in prod — fail-closed if
absent. Dev: ephemeral key generated at boot, tagged "key_mode": "dev-
ephemeral" (SIM) on issued certificates.
"""
from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)


class SigningUnavailable(RuntimeError):
    pass


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class CertificateSigner:
    def __init__(self, pem: str, prod: bool) -> None:
        self.key_mode = "kms-pem"
        if pem:
            self._priv = serialization.load_pem_private_key(
                pem.encode(), password=None)
        elif prod:
            raise SigningUnavailable(
                "TCC_SIGNING_KEY_PEM unset in prod; signing is fail-closed")
        else:
            self._priv = Ed25519PrivateKey.generate()
            self.key_mode = "dev-ephemeral"
        self._pub: Ed25519PublicKey = self._priv.public_key()

    def public_key_b64(self) -> str:
        raw = self._pub.public_bytes(serialization.Encoding.Raw,
                                     serialization.PublicFormat.Raw)
        return _b64e(raw)

    @staticmethod
    def canonical_payload(cert: dict) -> bytes:
        """Canonical JSON over the disclosure fields that are certified."""
        body = {k: cert[k] for k in (
            "certificate_id", "tin", "as_of", "years", "issued_at")}
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def sign_payload(self, payload: bytes) -> str:
        return _b64e(self._priv.sign(payload))

    def verification_string(self, cert: dict, signature: str) -> str:
        return f"NRSTCC1|{cert['certificate_id']}|{cert['issued_at']}|{signature}"

    def verify(self, cert: dict, signature: str) -> bool:
        try:
            self._pub.verify(_b64d(signature), self.canonical_payload(cert))
            return True
        except Exception:
            return False
