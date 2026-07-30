"""Daily scoring engine (T4): transparent rule+score model.

Audit defensibility: every score carries a MANDATORY explanation payload —
per-rule contributions, evidence references, model and rule-pack versions —
so a reviewer can reconstruct exactly why a taxpayer scored as they did.
Gold output is pseudonymised (pseudo_tin only).
"""
from __future__ import annotations

from typing import Any

from .lakehouse import Lakehouse
from .util import new_ulid, now_rfc3339

MODEL_ID = "nrs-risk-rules"
MODEL_VERSION = "1.0.0"
PACK_REF = "rp-disclosure-control@1.0.0"

# Transparent additive rule set. Each rule maps a feature to a weighted score
# contribution with a human-readable narrative. Score = clamp(sum, 0, 1000).
RULES: list[dict[str, Any]] = [
    {
        "id": "score.filing_divergence.high",
        "feature": "fv_filing_divergence_30d",
        "when": "divergence_bps >= 5000",
        "points": 350,
        "narrate": "Filed turnover diverges from MBS e-invoice turnover by >=50% in 30d",
    },
    {
        "id": "score.filing_divergence.medium",
        "feature": "fv_filing_divergence_30d",
        "when": "2000 <= divergence_bps < 5000",
        "points": 175,
        "narrate": "Filed turnover diverges from MBS e-invoice turnover by 20-50% in 30d",
    },
    {
        "id": "score.import_mismatch.high",
        "feature": "fv_import_mismatch_ytd",
        "when": "mismatch_bps >= 3000",
        "points": 300,
        "narrate": "Customs import value exceeds import-VAT base by >=30% YTD",
    },
    {
        "id": "score.import_mismatch.medium",
        "feature": "fv_import_mismatch_ytd",
        "when": "1000 <= mismatch_bps < 3000",
        "points": 150,
        "narrate": "Customs import value exceeds import-VAT base by 10-30% YTD",
    },
    {
        "id": "score.graph_risk.high",
        "feature": "fv_graph_risk_90d",
        "when": "risky_edge_count >= 3",
        "points": 250,
        "narrate": "Entity graph shows >=3 risky relationships in 90d",
    },
    {
        "id": "score.graph_risk.medium",
        "feature": "fv_graph_risk_90d",
        "when": "1 <= risky_edge_count < 3",
        "points": 100,
        "narrate": "Entity graph shows 1-2 risky relationships in 90d",
    },
]


def _rule_fires(rule: dict[str, Any], feature_row: dict[str, Any]) -> bool:
    fid = rule["id"]
    if "filing_divergence" in fid:
        v = int(feature_row.get("divergence_bps") or 0)
        return v >= 5000 if "high" in fid else 2000 <= v < 5000
    if "import_mismatch" in fid:
        v = int(feature_row.get("mismatch_bps") or 0)
        return v >= 3000 if "high" in fid else 1000 <= v < 3000
    if "graph_risk" in fid:
        v = int(feature_row.get("risky_edge_count") or 0)
        return v >= 3 if "high" in fid else 1 <= v < 3
    return False


def score_all(lh: Lakehouse) -> list[dict[str, Any]]:
    """Score every pseudonymised subject with fresh features. Returns gold rows."""
    # Latest feature row per pseudo_tin per feature (by computed_at).
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for feat in ("fv_filing_divergence_30d", "fv_import_mismatch_ytd", "fv_graph_risk_90d"):
        for row in lh.read("gold", feat, limit=500000):
            key = (row["pseudo_tin"], feat)
            cur = latest.get(key)
            if cur is None or str(row.get("computed_at", "")) > str(cur.get("computed_at", "")):
                latest[key] = row
    subjects: dict[str, dict[str, dict[str, Any]]] = {}
    for (ptin, feat), row in latest.items():
        subjects.setdefault(ptin, {})[feat] = row

    out: list[dict[str, Any]] = []
    for ptin, feats in sorted(subjects.items()):
        contributions = []
        total = 0
        for rule in RULES:
            frow = feats.get(rule["feature"])
            if frow and _rule_fires(rule, frow):
                total += rule["points"]
                contributions.append({
                    "rule_id": rule["id"],
                    "narrate": rule["narrate"],
                    "points": rule["points"],
                    "evidence": {
                        "feature": rule["feature"],
                        "feature_row": {k: v for k, v in frow.items()
                                        if k not in ("computed_at",)},
                    },
                })
        total = max(0, min(1000, total))
        band = "high" if total >= 650 else ("medium" if total >= 300 else "low")
        explanation = {
            "model": {"id": MODEL_ID, "version": MODEL_VERSION},
            "rule_pack_version": PACK_REF,
            "score": total,
            "band": band,
            "contributions": contributions,
            "generated_at": now_rfc3339(),
        }
        out.append({
            "score_id": new_ulid(),
            "pseudo_tin": ptin,
            "score": total,
            "band": band,
            "model_id": MODEL_ID,
            "model_version": MODEL_VERSION,
            "rule_pack_version": PACK_REF,
            "explanation": explanation,
            "scored_at": now_rfc3339(),
        })
    if out:
        lh.write("gold", "risk_scores", out)
    return out


def explanation_for(lh: Lakehouse, pseudo: str) -> dict[str, Any] | None:
    rows = lh.read("gold", "risk_scores", where=f"pseudo_tin = '{pseudo}'",
                   limit=5000)
    if not rows:
        return None
    rows.sort(key=lambda r: str(r.get("scored_at", "")), reverse=True)
    return rows[0]
