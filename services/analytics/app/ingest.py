"""Ingest pipelines (T4 + T15).

- MBS taxview ingest (bronze mbs_taxview)
- Filings-under-MoU ingest (bronze filings_mou)
- CAC registry extract ingest (bronze cac_registry + entity resolution queue)
- NSW declarations ingest (T15): bronze nsw_declarations -> validated SILVER
  customs_declarations store with importer-TIN reconciliation vs tin-graph
  (core API, local fallback) -> GOLD import-VAT landing-cost data product.

Money is integer kobo only (SPEC 1.3).
"""
from __future__ import annotations

from typing import Any

from .lakehouse import Lakehouse
from .pseudo import pseudo_tin
from .tingraph import TinGraph
from .util import new_ulid, now_rfc3339

# NSW declaration validation requirements (Nigeria Single Window payload subset).
REQUIRED_DECL_FIELDS = ("declaration_id", "importer_tin", "hs_code",
                        "customs_value_kobo", "duty_kobo", "port_code", "declared_at")
VAT_RATE_BPS = 750  # 7.5% VAT on landing cost (rp-vat-rates baseline)


def ingest_mbs_taxview(lh: Lakehouse, records: list[dict[str, Any]]) -> dict[str, Any]:
    """MBS taxview: {tin, period, turnover_kobo, invoice_count, source_app}."""
    errors = _require(records, ("tin", "period", "turnover_kobo"))
    if errors:
        return {"accepted": 0, "rejected": len(errors), "errors": errors}
    for r in records:
        r.setdefault("ingest_id", new_ulid())
        r.setdefault("ingested_at", now_rfc3339())
    receipt = lh.write("bronze", "mbs_taxview", records)
    return {"accepted": len(records), "rejected": 0, "receipt": receipt}


def ingest_filings_mou(lh: Lakehouse, records: list[dict[str, Any]]) -> dict[str, Any]:
    """Filings under MoU: {tin, period, tax_type, declared_turnover_kobo, filed_at}."""
    errors = _require(records, ("tin", "period", "tax_type", "declared_turnover_kobo"))
    if errors:
        return {"accepted": 0, "rejected": len(errors), "errors": errors}
    for r in records:
        r.setdefault("ingest_id", new_ulid())
        r.setdefault("ingested_at", now_rfc3339())
    receipt = lh.write("bronze", "filings_mou", records)
    return {"accepted": len(records), "rejected": 0, "receipt": receipt}


def ingest_cac_registry(lh: Lakehouse, records: list[dict[str, Any]]) -> dict[str, Any]:
    """CAC registry extract: {rc_number, legal_name, tin, status, incorporated_at}.
    Queues unresolved TINs for wf-entity-resolution."""
    errors = _require(records, ("rc_number", "legal_name"))
    if errors:
        return {"accepted": 0, "rejected": len(errors), "errors": errors}
    queue = []
    for r in records:
        r.setdefault("ingest_id", new_ulid())
        r.setdefault("ingested_at", now_rfc3339())
        if not r.get("tin"):
            queue.append({"tin": "", "rc_number": r["rc_number"],
                          "name": r["legal_name"], "queued_at": now_rfc3339()})
    receipt = lh.write("bronze", "cac_registry", records)
    if queue:
        lh.write("bronze", "entity_resolution_queue", queue)
    return {"accepted": len(records), "rejected": 0, "receipt": receipt,
            "queued_for_resolution": len(queue)}


def ingest_import_vat_declarations(lh: Lakehouse, records: list[dict[str, Any]]) -> dict[str, Any]:
    """Import-VAT declarations: {tin, period, import_vat_base_kobo, import_vat_kobo}."""
    errors = _require(records, ("tin", "period", "import_vat_base_kobo"))
    if errors:
        return {"accepted": 0, "rejected": len(errors), "errors": errors}
    for r in records:
        r.setdefault("ingest_id", new_ulid())
        r.setdefault("ingested_at", now_rfc3339())
    receipt = lh.write("bronze", "import_vat_declarations", records)
    return {"accepted": len(records), "rejected": 0, "receipt": receipt}


def ingest_nsw_declarations(lh: Lakehouse, tg: TinGraph, hmac_key: str,
                            records: list[dict[str, Any]]) -> dict[str, Any]:
    """T15: NSW customs declarations.

    1. Validate + land raw in bronze nsw_declarations.
    2. Reconcile importer TIN vs tin-graph -> silver customs_declarations store.
    3. Build import-VAT landing-cost data product in gold (pseudonymised).
    """
    bronze_rows, silver_rows, recon = [], [], {"verified": 0, "unverified": 0, "invalid": 0}
    rejected: list[dict[str, Any]] = []
    for i, rec in enumerate(records):
        missing = [f for f in REQUIRED_DECL_FIELDS if rec.get(f) in (None, "")]
        if missing:
            rejected.append({"index": i, "declaration_id": rec.get("declaration_id"),
                             "errors": [f"missing required field: {f}" for f in missing]})
            continue
        row = dict(rec)
        row.setdefault("ingest_id", new_ulid())
        row.setdefault("ingested_at", now_rfc3339())
        bronze_rows.append(row)

        ver = tg.verify_tin(str(rec["importer_tin"]))
        status = "verified" if ver.get("valid") else (
            "invalid" if ver.get("status") == "suspended" else "unverified")
        recon[status] = recon.get(status, 0) + 1
        silver_rows.append({
            "declaration_id": rec["declaration_id"],
            "importer_tin": str(rec["importer_tin"]),
            "importer_entity_id": ver.get("entity_id"),
            "tin_status": status,
            "hs_code": str(rec["hs_code"]),
            "port_code": str(rec["port_code"]),
            "customs_value_kobo": int(rec["customs_value_kobo"]),
            "duty_kobo": int(rec["duty_kobo"]),
            "declared_at": str(rec["declared_at"]),
            "reconciled_at": now_rfc3339(),
            "tin_graph_mode": tg.mode(),
        })

    if bronze_rows:
        lh.write("bronze", "nsw_declarations", bronze_rows)
    if silver_rows:
        lh.write("silver", "customs_declarations", silver_rows)

    # Import-VAT landing-cost data product (gold, pseudonymised).
    gold_rows = []
    for s in silver_rows:
        landing = s["customs_value_kobo"] + s["duty_kobo"]
        vat_due = landing * VAT_RATE_BPS // 10000
        gold_rows.append({
            "declaration_id": s["declaration_id"],
            "pseudo_tin": pseudo_tin(s["importer_tin"], hmac_key),
            "hs_code": s["hs_code"],
            "port_code": s["port_code"],
            "customs_value_kobo": s["customs_value_kobo"],
            "duty_kobo": s["duty_kobo"],
            "landing_cost_kobo": landing,
            "import_vat_due_kobo": vat_due,
            "vat_rate_bps": VAT_RATE_BPS,
            "tin_status": s["tin_status"],
            "computed_at": now_rfc3339(),
        })
    if gold_rows:
        lh.write("gold", "import_vat_landing_cost", gold_rows)

    return {"accepted": len(bronze_rows), "rejected": len(rejected),
            "errors": rejected, "reconciliation": recon,
            "products": {"silver.customs_declarations": len(silver_rows),
                         "gold.import_vat_landing_cost": len(gold_rows)}}


def _require(records: list[dict[str, Any]], fields: tuple[str, ...]) -> list[dict[str, Any]]:
    errors = []
    for i, rec in enumerate(records):
        missing = [f for f in fields if rec.get(f) in (None, "")]
        if missing:
            errors.append({"index": i, "errors": [f"missing required field: {f}" for f in missing]})
    return errors
