"""TCC issuance workflow — NTAA 2025 s.72.

Application -> eligibility evaluation (no outstanding liabilities, per the
rev360/ledger adapter) -> issue verifiable certificate OR deny with
reasons, within a 2-week statutory SLA. The certificate discloses the 3
preceding years: total chargeable income, tax payable, tax paid, tax
outstanding / "no tax due" (s.72 gazette text).

Clocks are injectable for deterministic tests. SLA breach detection is via
`sla_breaches(now)` (alert payload per breach); decisions stamp
`decided_at` and late-but-decided applications are flagged `sla_breached`.

REAL: eligibility logic, SLA clock, denial-with-reasons, disclosure model.
SIM: ledger/notification backends per adapters (tagged on responses).
"""
from __future__ import annotations

import datetime as dt

from . import store


class TccError(ValueError):
    pass


def _parse(ts: str) -> dt.datetime:
    return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))


def evaluate_eligibility(years: list[dict], disclosure_years: int) -> tuple[bool, list[str]]:
    """Eligible iff no outstanding liabilities across the disclosure window
    and filings are complete for each disclosed year. Reasons are returned
    for the denial path (NTAA s.72: reasons must be given)."""
    reasons: list[str] = []
    if len(years) < disclosure_years:
        reasons.append(
            f"filing history covers {len(years)} of required "
            f"{disclosure_years} preceding years (NTAA s.72 disclosure)")
    for y in years:
        if int(y.get("tax_outstanding_kobo", 0)) > 0:
            reasons.append(
                f"outstanding liability of {y['tax_outstanding_kobo']} kobo "
                f"for year {y.get('year')}")
        if not y.get("filings_complete", False):
            reasons.append(f"filings incomplete for year {y.get('year')}")
    return (not reasons), reasons


class TccStore:
    """Durable via app.store.DocStore (Postgres in prod, in-memory dev
    fallback) — certificates + SLA state survive restarts (audit P0)."""

    def __init__(self, docs: "store.DocStore | None" = None) -> None:
        self._docs = docs if docs is not None else store.DocStore()

    def _add(self, rec: dict) -> dict:
        self._docs.put("tcc_apps", rec["application_id"], rec)
        return rec

    def apply(self, tin: str, now: str, idempotency_key: str,
              application_id: str) -> tuple[dict, bool]:
        prior = self._docs.get("tcc_idem", idempotency_key)
        if prior is not None:
            return self._docs.get("tcc_apps", prior["application_id"]), False
        rec = {"application_id": application_id, "tin": tin,
               "applied_at": now, "status": "pending",
               "decided_at": None, "sla_breached": False,
               "denial_reasons": [], "certificate_id": None}
        self._docs.put("tcc_idem", idempotency_key,
                       {"application_id": application_id})
        return self._add(rec), True

    def get(self, application_id: str) -> dict | None:
        return self._docs.get("tcc_apps", application_id)

    def decide(self, application_id: str, *, now: str, sla_days: int,
               eligible: bool, reasons: list[str], certificate_id: str | None,
               ledger_mode: str) -> dict:
        rec = self._docs.get("tcc_apps", application_id)
        if rec is None:
            raise TccError("unknown application")
        if rec["status"] != "pending":
            raise TccError(f"application already {rec['status']}")
        rec["decided_at"] = now
        rec["sla_breached"] = (_parse(now) - _parse(rec["applied_at"])
                               > dt.timedelta(days=sla_days))
        rec["ledger_mode"] = ledger_mode
        if eligible and certificate_id:
            rec["status"] = "issued"
            rec["certificate_id"] = certificate_id
        else:
            rec["status"] = "denied"
            rec["denial_reasons"] = reasons
        self._docs.put("tcc_apps", application_id, rec)
        return rec

    def register_cert(self, cert: dict) -> None:
        self._docs.put("tcc_certs", cert["certificate_id"], cert)

    def cert(self, certificate_id: str) -> dict | None:
        return self._docs.get("tcc_certs", certificate_id)

    def sla_breaches(self, now: str, sla_days: int) -> list[dict]:
        out = []
        for rec in self._docs.scan("tcc_apps"):
            if rec["status"] != "pending":
                continue
            age = _parse(now) - _parse(rec["applied_at"])
            if age > dt.timedelta(days=sla_days):
                out.append({
                    "alert": "tcc.sla.breach",
                    "application_id": rec["application_id"],
                    "tin": rec["tin"],
                    "applied_at": rec["applied_at"],
                    "age_days": age.days,
                    "statute": "NTAA 2025 s.72: TCC to be issued or refused "
                               "with reasons within two weeks of demand",
                })
        return out
