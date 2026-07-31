"""Liability ledger adapter — eligibility evidence for TCC issuance.

REAL: HTTP client against the Rev360/ledger interface when TCC_LEDGER_URL
is set (`GET /v1/ledger/positions/{tin}?years=N` returning per-year
{total_income_kobo, tax_payable_kobo, tax_paid_kobo, tax_outstanding_kobo,
filings_complete}). Fail-closed in prod: no URL + AUTH_MODE=keycloak =>
eligibility check raises LedgerUnavailable and applications cannot be
decided (no silent sim fallback).

SIM: when TCC_LEDGER_URL is unset in dev, a caller-seeded in-memory ledger
is used (`SimLedger.seed`); every response carries "ledger_mode": "sim".
"""
from __future__ import annotations

import httpx


class LedgerUnavailable(RuntimeError):
    pass


class LedgerResult(dict):
    """{years: [{year, total_income_kobo, tax_payable_kobo, tax_paid_kobo,
    tax_outstanding_kobo, filings_complete}], mode}"""


class SimLedger:
    def __init__(self) -> None:
        self._positions: dict[str, list[dict]] = {}

    def seed(self, tin: str, years: list[dict]) -> None:
        self._positions[tin] = years

    def positions(self, tin: str, years: int) -> list[dict]:
        return self._positions.get(tin, [])


class LedgerClient:
    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def positions(self, tin: str, years: int) -> list[dict]:
        try:
            r = httpx.get(f"{self._base}/v1/ledger/positions/{tin}",
                          params={"years": years}, timeout=self._timeout)
            r.raise_for_status()
            return list(r.json().get("years", []))
        except Exception as exc:  # fail closed upstream -> unavailable
            raise LedgerUnavailable(str(exc)) from exc


def get_positions(tin: str, years: int, *, ledger_url: str, sim: SimLedger,
                  prod: bool) -> tuple[list[dict], str]:
    """Returns (year rows, mode). Fail-closed in prod without a ledger."""
    if ledger_url:
        return LedgerClient(ledger_url).positions(tin, years), "real"
    if prod:
        raise LedgerUnavailable(
            "TCC_LEDGER_URL unset in prod; eligibility check is fail-closed")
    return sim.positions(tin, years), "sim"
