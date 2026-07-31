"""TCC service — Tax Clearance Certificate issuance (NTAA 2025 s.72).

Eligibility = no outstanding liabilities (rev360/ledger adapter,
fail-closed prod, sim tagged) + 3-year disclosure coverage. Two-week
statutory SLA with breach alerts. Certificates are ed25519-signed with a
QR-verifiable ID; GET /v1/tcc/verify/{id} is public.

REAL/SIM tags: see app/ledger.py (ledger) and app/certs.py (key mode).
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from pydantic import BaseModel

from . import core, ledger
from .certs import CertificateSigner, SigningUnavailable
from .config import get_settings
from .key_provider import KeyProviderUnavailable, build_signer
from .util import new_ulid, now_rfc3339, principal_from, problem

settings = get_settings()
app = FastAPI(title="Meridian Gov-Enclave TCC", version=settings.version)

store = core.TccStore()
sim_ledger = ledger.SimLedger()
try:
    # KEY_PROVIDER: software default (unchanged); cloud-kms routes signing to
    # the KMS REST shim; any other non-software mode fails closed at startup.
    signer = build_signer(
        lambda: CertificateSigner(settings.signing_key_pem, settings.prod))
except (SigningUnavailable, KeyProviderUnavailable):
    # prod without key / uninitialisable provider: fail closed at decide time
    signer = None

PUBLIC_PATHS = {"/healthz", "/readyz", "/openapi.json", "/docs",
                "/docs/oauth2-redirect"}
PUBLIC_PREFIXES = ("/docs", "/v1/tcc/verify/")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES):
        return await call_next(request)
    principal = principal_from(request, secret=settings.jwt_secret,
                               auth_mode=settings.auth_mode)
    if principal is None:
        return problem(401, "Unauthorized",
                       "Bearer JWT or X-Dev-Role (dev) required")
    request.state.principal = principal
    return await call_next(request)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    return problem(500, "Internal error", str(exc))


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": settings.service_name,
            "version": settings.version}


@app.get("/readyz")
def readyz():
    return {"status": "ready",
            "ledger": "real" if settings.ledger_url else "sim",
            "signer": "ready" if signer else "unavailable"}


class ApplyIn(BaseModel):
    tin: str
    idempotency_key: str


@app.post("/v1/tcc/applications", status_code=201)
def apply(body: ApplyIn):
    if not body.tin or not body.idempotency_key:
        return problem(422, "Invalid application", "tin and idempotency_key required")
    rec, created = store.apply(body.tin, now_rfc3339(),
                               body.idempotency_key, f"TCC-{new_ulid()}")
    return rec


@app.post("/v1/tcc/applications/{application_id}/decide")
def decide(application_id: str):
    """Evaluate eligibility (no outstanding liabilities via the ledger
    adapter + 3-year disclosure coverage) and issue or deny with reasons.
    NTAA s.72: within two weeks of demand; late decisions are flagged."""
    rec = store.get(application_id)
    if rec is None:
        return problem(404, "Not found", "unknown application")
    if rec["status"] != "pending":
        return problem(409, "Already decided", f"application is {rec['status']}")
    try:
        years, mode = ledger.get_positions(
            rec["tin"], settings.disclosure_years,
            ledger_url=settings.ledger_url, sim=sim_ledger, prod=settings.prod)
    except ledger.LedgerUnavailable as exc:
        return problem(503, "Liability ledger unavailable", str(exc))
    eligible, reasons = core.evaluate_eligibility(years, settings.disclosure_years)
    cert_id = None
    if eligible:
        if signer is None:
            return problem(503, "Signing unavailable",
                           "TCC_SIGNING_KEY_PEM unset (fail-closed prod)")
        cert_id = f"CERT-{new_ulid()}"
        cert = {
            "certificate_id": cert_id,
            "application_id": rec["application_id"],
            "tin": rec["tin"],
            "as_of": now_rfc3339()[:10],
            "issued_at": now_rfc3339(),
            "years": years[: settings.disclosure_years],
            "statute": "NTAA 2025 s.72",
            "key_mode": signer.key_mode,
            "ledger_mode": mode,
            "public_key_b64": signer.public_key_b64(),
        }
        sig = signer.sign_payload(signer.canonical_payload(cert))
        cert["signature_b64"] = sig
        cert["qr_verification"] = signer.verification_string(cert, sig)
        store.register_cert(cert)
    return store.decide(application_id, now=now_rfc3339(),
                        sla_days=settings.sla_days, eligible=eligible,
                        reasons=reasons, certificate_id=cert_id,
                        ledger_mode=mode)


@app.get("/v1/tcc/applications/{application_id}")
def get_application(application_id: str):
    rec = store.get(application_id)
    if rec is None:
        return problem(404, "Not found", "unknown application")
    return rec


@app.get("/v1/tcc/{certificate_id}")
def get_certificate(certificate_id: str):
    cert = store.cert(certificate_id)
    if cert is None:
        return problem(404, "Not found", "unknown certificate")
    return cert


@app.get("/v1/tcc/verify/{certificate_id}")
def verify_certificate(certificate_id: str):
    """Public verification: recompute signature over the certified
    disclosure and compare. No auth (SPEC: verifiable by MDAs/banks)."""
    cert = store.cert(certificate_id)
    if cert is None:
        return problem(404, "Not found", "unknown certificate")
    ok = signer.verify(cert, cert["signature_b64"]) if signer else False
    return {"certificate_id": certificate_id, "valid": ok,
            "tin": cert["tin"], "as_of": cert["as_of"],
            "qr_verification": cert["qr_verification"]}


@app.get("/v1/tcc/sla/breaches")
def sla_breaches():
    return {"breaches": store.sla_breaches(now_rfc3339(), settings.sla_days),
            "sla_days": settings.sla_days}
