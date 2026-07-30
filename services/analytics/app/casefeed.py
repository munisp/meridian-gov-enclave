"""Case feed API (T4): emits nrs.cases.feed.v1 envelopes (SPEC 1.1 shape) for
scores at/above the case threshold. Feed items are pseudonymised and carry the
mandatory explanation payload reference.
"""
from __future__ import annotations

from typing import Any

from .lakehouse import Lakehouse
from .util import new_ulid, now_rfc3339

CASE_FEED_TYPE = "nrs.cases.feed.v1"
SOURCE = "analytics"


def _envelope(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": case["case_id"],
        "type": CASE_FEED_TYPE,
        "source": SOURCE,
        "time": case["created_at"],
        "tenant_id": "",
        "trace_id": case.get("trace_id", ""),
        "rule_pack_version": case.get("rule_pack_version", ""),
        "data": case["data"],
    }


def emit_cases(lh: Lakehouse, threshold: int) -> int:
    """Open cases for the latest high scores; idempotent per pseudo_tin+band day."""
    existing = {(r.get("pseudo_tin"), str(r.get("dt")))
                for r in lh.read("bronze", "case_feed", limit=500000)}
    emitted = 0
    rows = lh.read("gold", "risk_scores", limit=500000)
    latest: dict[str, dict[str, Any]] = {}
    for r in rows:
        cur = latest.get(r["pseudo_tin"])
        if cur is None or str(r.get("scored_at", "")) > str(cur.get("scored_at", "")):
            latest[r["pseudo_tin"]] = r
    for ptin, score_row in latest.items():
        if int(score_row.get("score") or 0) < threshold:
            continue
        from .util import today
        if (ptin, today()) in existing:
            continue
        case = {
            "case_id": new_ulid(),
            "pseudo_tin": ptin,
            "created_at": now_rfc3339(),
            "rule_pack_version": score_row.get("rule_pack_version", ""),
            "trace_id": score_row.get("score_id", ""),
            "data": {
                "case_type": "risk_score_threshold",
                "score": score_row["score"],
                "band": score_row["band"],
                "score_id": score_row["score_id"],
                "model": {"id": score_row["model_id"], "version": score_row["model_version"]},
                "explanation_ref": f"/v1/scores/{ptin}/explanation",
                "status": "open",
            },
        }
        env = _envelope(case)
        lh.write("bronze", "case_feed", [{**env, "data": env["data"], "pseudo_tin": ptin}])
        emitted += 1
    return emitted


def feed(lh: Lakehouse, *, since: str | None = None, band: str | None = None,
         limit: int = 200) -> list[dict[str, Any]]:
    where_parts = []
    if since:
        where_parts.append(f"dt >= '{since}'")
    where = " AND ".join(where_parts) if where_parts else None
    rows = lh.read("bronze", "case_feed", where=where, limit=50000)
    out = []
    for r in rows:
        import json
        data = r.get("data")
        if isinstance(data, str):
            data = json.loads(data)
        if band and data.get("band") != band:
            continue
        out.append({
            "id": r["id"], "type": CASE_FEED_TYPE, "source": SOURCE,
            "time": r.get("time") or r.get("created_at", ""),
            "tenant_id": r.get("tenant_id", "") or "",
            "trace_id": r.get("trace_id", "") or "",
            "rule_pack_version": r.get("rule_pack_version", "") or "",
            "data": data,
        })
    out.sort(key=lambda e: e["time"], reverse=True)
    return out[:limit]
