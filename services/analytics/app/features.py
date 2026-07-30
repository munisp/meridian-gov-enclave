"""Feature materialisation (T4): fv_filing_divergence_30d, fv_import_mismatch_ytd,
fv_graph_risk_90d.

Features are computed from silver/bronze and written to the GOLD zone with
pseudo_tin only (SPEC 1.3: derived planes store tin_hash/pseudo_tin only).
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from .lakehouse import Lakehouse
from .pseudo import pseudo_tin
from .util import now_rfc3339

FEATURES = ("fv_filing_divergence_30d", "fv_import_mismatch_ytd", "fv_graph_risk_90d")


def _days_ago(n: int) -> str:
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=n)).strftime("%Y-%m-%d")


def _year_start() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-01-01")


def materialise_filing_divergence(lh: Lakehouse, hmac_key: str) -> list[dict[str, Any]]:
    """|MBS taxview turnover - MoU filed turnover| over trailing 30d, per TIN."""
    since = _days_ago(30)
    mbs = lh.read("bronze", "mbs_taxview", where=f"dt >= '{since}'", limit=100000)
    filings = lh.read("bronze", "filings_mou", where=f"dt >= '{since}'", limit=100000)
    mbs_by_tin: dict[str, int] = {}
    for r in mbs:
        mbs_by_tin[r["tin"]] = mbs_by_tin.get(r["tin"], 0) + int(r.get("turnover_kobo") or 0)
    filed_by_tin: dict[str, int] = {}
    for r in filings:
        filed_by_tin[r["tin"]] = filed_by_tin.get(r["tin"], 0) + int(r.get("declared_turnover_kobo") or 0)
    rows = []
    for tin in sorted(set(mbs_by_tin) | set(filed_by_tin)):
        m, f = mbs_by_tin.get(tin, 0), filed_by_tin.get(tin, 0)
        denom = max(f, 1)
        div_bps = min(100000, abs(m - f) * 10000 // denom)
        rows.append({
            "pseudo_tin": pseudo_tin(tin, hmac_key),
            "feature": "fv_filing_divergence_30d",
            "window_days": 30,
            "mbs_turnover_kobo": m,
            "filed_turnover_kobo": f,
            "divergence_bps": div_bps,
            "computed_at": now_rfc3339(),
        })
    if rows:
        lh.write("gold", "fv_filing_divergence_30d", rows)
    return rows


def materialise_import_mismatch(lh: Lakehouse, hmac_key: str) -> list[dict[str, Any]]:
    """Customs-declared import value YTD vs import-VAT base declared YTD, per importer."""
    y0 = _year_start()
    customs = lh.read("silver", "customs_declarations", where=f"dt >= '{y0}'", limit=200000)
    vat = lh.read("bronze", "import_vat_declarations", where=f"dt >= '{y0}'", limit=200000)
    cust_by_tin: dict[str, int] = {}
    for r in customs:
        cust_by_tin[r["importer_tin"]] = cust_by_tin.get(r["importer_tin"], 0) + int(r.get("customs_value_kobo") or 0)
    vat_by_tin: dict[str, int] = {}
    for r in vat:
        vat_by_tin[r["tin"]] = vat_by_tin.get(r["tin"], 0) + int(r.get("import_vat_base_kobo") or 0)
    rows = []
    for tin in sorted(set(cust_by_tin) | set(vat_by_tin)):
        c, v = cust_by_tin.get(tin, 0), vat_by_tin.get(tin, 0)
        denom = max(c, 1)
        mis_bps = min(100000, abs(c - v) * 10000 // denom)
        rows.append({
            "pseudo_tin": pseudo_tin(tin, hmac_key),
            "feature": "fv_import_mismatch_ytd",
            "window": "ytd",
            "customs_value_ytd_kobo": c,
            "import_vat_base_ytd_kobo": v,
            "mismatch_bps": mis_bps,
            "computed_at": now_rfc3339(),
        })
    if rows:
        lh.write("gold", "fv_import_mismatch_ytd", rows)
    return rows


def materialise_graph_risk(lh: Lakehouse, hmac_key: str) -> list[dict[str, Any]]:
    """Graph-risk roll-up over 90d from entity-graph snapshots captured at ingest.

    Bronze dataset `entity_graph_snapshots` rows: {tin, entity_id, relation,
    target_entity_id, weight, risk_flag, captured_at}.
    """
    since = _days_ago(90)
    snaps = lh.read("bronze", "entity_graph_snapshots", where=f"dt >= '{since}'", limit=200000)
    by_tin: dict[str, list[dict[str, Any]]] = {}
    for r in snaps:
        by_tin.setdefault(r["tin"], []).append(r)
    rows = []
    for tin, edges in sorted(by_tin.items()):
        risky = [e for e in edges if str(e.get("risk_flag", "")).lower() in ("1", "true", "high")]
        weight_sum = sum(float(e.get("weight") or 0) for e in risky)
        rows.append({
            "pseudo_tin": pseudo_tin(tin, hmac_key),
            "feature": "fv_graph_risk_90d",
            "window_days": 90,
            "edge_count": len(edges),
            "risky_edge_count": len(risky),
            "risk_weight": round(weight_sum, 4),
            "computed_at": now_rfc3339(),
        })
    if rows:
        lh.write("gold", "fv_graph_risk_90d", rows)
    return rows


MATERIALISERS = {
    "fv_filing_divergence_30d": materialise_filing_divergence,
    "fv_import_mismatch_ytd": materialise_import_mismatch,
    "fv_graph_risk_90d": materialise_graph_risk,
}


def materialise_all(lh: Lakehouse, hmac_key: str) -> dict[str, int]:
    return {name: len(fn(lh, hmac_key)) for name, fn in MATERIALISERS.items()}
