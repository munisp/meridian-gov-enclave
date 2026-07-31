"""KEY_PROVIDER wiring tests (TCC): software default unchanged, cloud-kms
signs+verifies through the REST shim with verify-before-accept, unknown
providers fail closed."""
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.key_provider import (KeyProviderUnavailable, KMSSigner, build_signer,
                              provider_mode)
from app.certs import CertificateSigner


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class _Shim(BaseHTTPRequestHandler):
    priv = Ed25519PrivateKey.generate()
    bad_sig = False

    def _send(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        pub = self.priv.public_key().public_bytes_raw() if hasattr(
            self.priv.public_key(), "public_bytes_raw") else None
        if pub is None:
            from cryptography.hazmat.primitives import serialization
            pub = self.priv.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self._send({"public_key_b64": _b64e(pub), "algorithm": "ed25519"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        payload = base64.urlsafe_b64decode(body["payload_b64"] + "=" * (-len(body["payload_b64"]) % 4))
        sig = b"0" * 64 if self.bad_sig else self.priv.sign(payload)
        self._send({"signature_b64": _b64e(sig), "key_version": "1"})

    def log_message(self, *a):
        pass


@pytest.fixture()
def shim():
    srv = HTTPServer(("127.0.0.1", 0), _Shim)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_software_default_unchanged():
    s = build_signer(lambda: CertificateSigner("", False), env={})
    assert isinstance(s, CertificateSigner)
    assert s.key_mode == "dev-ephemeral"


def test_cloud_kms_sign_verify(shim):
    env = {"KEY_PROVIDER": "cloud-kms", "KMS_BASE_URL": shim, "KMS_KEY_ID": "tcc"}
    s = build_signer(None, env)
    cert = {"certificate_id": "c1", "tin": "t", "as_of": "2026", "years": 3,
            "issued_at": "2026-01-01T00:00:00Z"}
    sig = s.sign_payload(s.canonical_payload(cert))
    assert s.verify(cert, sig)
    assert not s.verify({**cert, "tin": "other"}, sig)
    assert s.key_mode == "cloud-kms"


def test_cloud_kms_requires_base_url():
    with pytest.raises(KeyProviderUnavailable):
        build_signer(None, env={"KEY_PROVIDER": "cloud-kms"})


def test_kms_bad_signature_fails_closed(shim):
    _Shim.bad_sig = True
    try:
        with pytest.raises(KeyProviderUnavailable):
            build_signer(None, env={"KEY_PROVIDER": "cloud-kms", "KMS_BASE_URL": shim}).sign(b"x")
    finally:
        _Shim.bad_sig = False


def test_hsm_mode_fails_closed():
    with pytest.raises(KeyProviderUnavailable):
        build_signer(None, env={"KEY_PROVIDER": "hsm"})


def test_provider_mode_default():
    assert provider_mode({}) == "software"
