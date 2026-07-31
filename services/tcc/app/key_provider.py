"""KEY_PROVIDER-driven signing for the TCC service (Python mirror of
packages/keyx/provider; same env contract + fail-closed semantics).

Modes (KEY_PROVIDER env):
  software   [REAL] default — the service's existing CertificateSigner
             (TCC_SIGNING_KEY_PEM, or dev-ephemeral). Keys never leave host.
  cloud-kms  [REAL] Meridian KMS REST shim (same wire contract as the Go
             provider): KMS_BASE_URL, KMS_KEY_ID (default "signing"),
             KMS_BEARER_TOKEN (optional). Signing runs remotely over HTTPS;
             every returned signature is verified locally against the
             KMS-published public key before acceptance — a KMS returning an
             invalid signature is treated as unavailable (fail-closed).
  hsm|pkcs11 fail-closed here: the CGO-free PKCS#11 exec-plugin bridge
             ships with the Go services only.

FAIL-CLOSED: naming a non-software provider that cannot be initialised
raises KeyProviderUnavailable at startup — never a silent software
fallback.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .certs import CertificateSigner


class KeyProviderUnavailable(RuntimeError):
    pass


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: bytes | str) -> bytes:
    if isinstance(s, bytes):
        s = s.decode()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def provider_mode(env: dict | None = None) -> str:
    env = os.environ if env is None else env
    return (env.get("KEY_PROVIDER") or "software").strip().lower()


class KMSSigner:
    """[REAL] cloud-KMS REST shim signer (ed25519)."""

    def __init__(self, env: dict | None = None) -> None:
        env = os.environ if env is None else env
        self.base = (env.get("KMS_BASE_URL") or "").rstrip("/")
        self.key_id = env.get("KMS_KEY_ID") or "signing"
        self.token = env.get("KMS_BEARER_TOKEN") or ""
        if not self.base:
            raise KeyProviderUnavailable(
                "KEY_PROVIDER=cloud-kms requires KMS_BASE_URL (fail-closed)")
        self.key_mode = "cloud-kms"
        self.available = True
        self._pub = self._fetch_public_key()

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(self.base + path, method=method)
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, data=data, timeout=5) as resp:
                return json.loads(resp.read().decode())
        except Exception as exc:
            raise KeyProviderUnavailable(f"kms {method} {path}: {exc}") from exc

    def _fetch_public_key(self) -> Ed25519PublicKey:
        out = self._request("GET", f"/v1/keys/{self.key_id}/public")
        if out.get("algorithm") != "ed25519":
            raise KeyProviderUnavailable(
                f"kms key {self.key_id}: algorithm {out.get('algorithm')!r}, want ed25519")
        return Ed25519PublicKey.from_public_bytes(_b64d(out["public_key_b64"]))

    def public_key_b64(self) -> str:
        return _b64e(self._pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def sign_bytes(self, payload: bytes) -> bytes:
        out = self._request("POST", f"/v1/keys/{self.key_id}/sign",
                            {"payload_b64": _b64e(payload), "algorithm": "ed25519"})
        sig = _b64d(out["signature_b64"])
        # verify-before-accept: a KMS returning an invalid signature is down
        try:
            self._pub.verify(sig, payload)
        except Exception as exc:
            raise KeyProviderUnavailable(
                "kms returned an invalid signature (fail-closed)") from exc
        return sig

    def sign(self, payload: bytes) -> str:
        return _b64e(self.sign_bytes(payload))

    def verify(self, payload: bytes, signature: str) -> bool:
        try:
            self._pub.verify(_b64d(signature), payload)
            return True
        except Exception:
            return False


class TCCKMSSigner(KMSSigner):
    """Adapter giving KMSSigner the CertificateSigner surface used by main.py."""

    canonical_payload = staticmethod(CertificateSigner.canonical_payload)

    def sign_payload(self, payload: bytes) -> str:
        return self.sign(payload)

    def verification_string(self, cert: dict, signature: str) -> str:
        return (f"NRSTCC1|{cert['certificate_id']}|{cert['issued_at']}"
                f"|{signature}")

    def verify(self, cert: dict, signature: str) -> bool:  # type: ignore[override]
        return super().verify(CertificateSigner.canonical_payload(cert), signature)


def build_signer(software_factory, env: dict | None = None):
    """software mode -> software_factory(); cloud-kms -> TCCKMSSigner;
    anything else fail-closed."""
    mode = provider_mode(env)
    if mode in ("", "software"):
        return software_factory()
    if mode == "cloud-kms":
        return TCCKMSSigner(env)
    raise KeyProviderUnavailable(
        f"KEY_PROVIDER={mode}: Python services support software|cloud-kms; "
        "the PKCS#11 exec-plugin bridge ships with the Go services (fail-closed)")
