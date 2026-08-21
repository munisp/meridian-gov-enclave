"""Analytics service (T4 + T15) — FastAPI entrypoint.

Sovereign-zone analytics: lakehouse-lite, ingest (MBS taxview, filings-under-MoU,
CAC registry, NSW declarations), feature materialisation, transparent daily
scoring with explanation payloads, k-anonymity disclosure control, case feed.
"""
from __future__ import annotations

import json
import os
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import casefeed, disclosure, features, ingest, scoring, workflows
from .auth import principal_from, problem, validate_auth_config
from .config import get_settings
from .lakehouse import Lakehouse, get_lakehouse
from .tingraph import TinGraph, get_tin_graph

settings = get_settings()
# A1-08: prod keycloak mode without KEYCLOAK_AUDIENCE refuses to boot.
validate_auth_config(settings.auth_mode, os.environ.get("PROFILE", "prod" if settings.auth_mode == "keycloak" else "dev"))
lh: Lakehouse = get_lakehouse(os.path.join(settings.data_root, "lakehouse"))
tg: TinGraph = get_tin_graph(settings.tin_graph_url, settings.data_root)
_pack = disclosure.load_pack(settings)

app = FastAPI(title="Meridian Gov-Enclave Analytics", version=settings.version)

PUBLIC_PATHS = {"/healthz", "/readyz", "/openapi.json", "/docs", "/docs/oauth2-redirect"}


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path in PUBLIC_PATHS or request.url.path.startswith("/docs"):
        return await call_next(request)
    principal = principal_from(request, secret=settings.jwt_secret, auth_mode=settings.auth_mode)
    if principal is None:
        return problem(401, "Unauthorized", "Bearer JWT or X-Dev-Role (dev) required")
    request.state.principal = principal
    return await call_next(request)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    return problem(500, "Internal error", str(exc))


# ---------------------------------------------------------------- health
@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": settings.service_name, "version": settings.version}


@app.get("/readyz")
def readyz():
    return {"status": "ready", "lakehouse": "duckdb", "tin_graph_mode": tg.mode()}


# ---------------------------------------------------------------- ingest
class IngestBatch(BaseModel):
    records: list[dict[str, Any]] = Field(min_length=1, max_length=50000)


@app.post("/ingest/mbs/taxview", status_code=201)
def ingest_mbs(batch: IngestBatch):
    return ingest.ingest_mbs_taxview(lh, batch.records)


@app.post("/ingest/filings-mou", status_code=201)
def ingest_filings(batch: IngestBatch):
    return ingest.ingest_filings_mou(lh, batch.records)


@app.post("/ingest/cac/registry", status_code=201)
def ingest_cac(batch: IngestBatch):
    return ingest.ingest_cac_registry(lh, batch.records)


@app.post("/ingest/import-vat/declarations", status_code=201)
def ingest_import_vat(batch: IngestBatch):
    return ingest.ingest_import_vat_declarations(lh, batch.records)


@app.post("/ingest/nsw/declarations", status_code=201)
def ingest_nsw(batch: IngestBatch):
    """T15: NSW customs declarations -> customs_declarations store + importer-TIN
    reconciliation + import-VAT landing-cost data product."""
    return ingest.ingest_nsw_declarations(lh, tg, settings.tin_hmac_key, batch.records)


# ---------------------------------------------------------------- lakehouse
@app.get("/v1/lakehouse/datasets")
def lakehouse_datasets(zone: str | None = Query(default=None)):
    return {"datasets": lh.datasets(zone)}


@app.get("/v1/lakehouse/{zone}/{dataset}")
def lakehouse_read(zone: str, dataset: str, limit: int = Query(default=500, le=10000)):
    if zone == "gold":
        # defence in depth: never expose raw identifiers from gold
        rows = lh.read(zone, dataset, limit=limit)
        for r in rows:
            for forbidden in ("tin", "nin", "rc_number", "importer_tin"):
                r.pop(forbidden, None)
        return {"zone": zone, "dataset": dataset, "rows": rows,
                "disclosure": "pseudonymised export; raw identifiers stripped"}
    return {"zone": zone, "dataset": dataset, "rows": lh.read(zone, dataset, limit=limit)}


# ---------------------------------------------------------------- features
@app.post("/v1/features/materialise", status_code=202)
def materialise(feature: str | None = Query(default=None)):
    if feature:
        if feature not in features.MATERIALISERS:
            return problem(404, "Unknown feature", f"expected one of {features.FEATURES}")
        rows = features.MATERIALISERS[feature](lh, settings.tin_hmac_key)
        return {"feature": feature, "rows": len(rows)}
    return {"materialised": features.materialise_all(lh, settings.tin_hmac_key)}


@app.get("/v1/features")
def list_features():
    return {"features": list(features.FEATURES)}


# ---------------------------------------------------------------- scoring
@app.post("/v1/scoring/run", status_code=202)
def run_scoring():
    rows = scoring.score_all(lh)
    return {"scored": len(rows),
            "bands": {b: sum(1 for r in rows if r["band"] == b) for b in ("high", "medium", "low")}}


@app.get("/v1/scores")
def list_scores(band: str | None = Query(default=None), limit: int = Query(default=200, le=5000)):
    rows = lh.read("gold", "risk_scores", limit=100000)
    latest: dict[str, dict[str, Any]] = {}
    for r in rows:
        cur = latest.get(r["pseudo_tin"])
        if cur is None or str(r.get("scored_at", "")) > str(cur.get("scored_at", "")):
            latest[r["pseudo_tin"]] = r
    out = [r for r in latest.values() if not band or r["band"] == band]
    for r in out:
        r.pop("explanation", None)  # list view: drill-down via explanation endpoint
    out.sort(key=lambda r: r["score"], reverse=True)
    return {"scores": out[:limit], "model": {"id": scoring.MODEL_ID, "version": scoring.MODEL_VERSION}}


@app.get("/v1/scores/{pseudo}/explanation")
def score_explanation(pseudo: str):
    row = scoring.explanation_for(lh, pseudo)
    if row is None:
        return problem(404, "Score not found", f"no score for {pseudo}")
    expl = row.get("explanation")
    if isinstance(expl, str):
        expl = json.loads(expl)
    return {"pseudo_tin": pseudo, "score": row["score"], "band": row["band"],
            "explanation": expl}


# ---------------------------------------------------------------- disclosure control
@app.get("/v1/aggregates/risk-by-band")
def aggregate_risk_by_band():
    """Example governed aggregate: subject counts per risk band, k-anonymity enforced."""
    rows = lh.read("gold", "risk_scores", limit=500000)
    by_band: dict[str, set] = {}
    for r in rows:
        by_band.setdefault(r["band"], set()).add(r["pseudo_tin"])
    cells = [{"band": b, "n_subjects": len(s), "max_share_bps": 10000 // max(len(s), 1)}
             for b, s in sorted(by_band.items())]
    governed = disclosure.enforce_aggregation(cells, subject_col="band",
                                              value_col="n_subjects", pack=_pack)
    return governed


@app.get("/v1/disclosure/pack")
def disclosure_pack():
    return {"pack": {"id": _pack.get("id"), "version": _pack.get("version"),
                     "status": _pack.get("status")},
            "params": disclosure.pack_params(_pack)}


# ---------------------------------------------------------------- workflows
@app.get("/v1/workflows")
def workflow_catalog():
    return {"workflows": workflows.WORKFLOW_NAMES, "runner": "inproc (Temporal fallback)"}


@app.post("/v1/workflows/{name}/run", status_code=202)
def run_workflow(name: str):
    try:
        if name == "wf-daily-scoring":
            return workflows.wf_daily_scoring(lh, settings.tin_hmac_key, settings.case_score_threshold)
        if name == "wf-entity-resolution":
            return workflows.wf_entity_resolution(lh, tg)
        if name.startswith("wf-feature-"):
            feat = "fv_" + name.removeprefix("wf-feature-").replace("-", "_")
            mapping = {"fv_filing_divergence": "fv_filing_divergence_30d",
                       "fv_import_mismatch": "fv_import_mismatch_ytd",
                       "fv_graph_risk": "fv_graph_risk_90d"}
            return workflows.wf_feature(lh, settings.tin_hmac_key,
                                        mapping.get(feat, feat))
    except KeyError as exc:
        return problem(404, "Unknown workflow", str(exc))
    return problem(404, "Unknown workflow", f"expected one of {workflows.WORKFLOW_NAMES}")


@app.get("/v1/workflows/runs")
def workflow_runs(limit: int = Query(default=50, le=200)):
    return {"runs": workflows.list_runs(limit)}


@app.get("/v1/workflows/runs/{run_id}")
def workflow_run(run_id: str):
    run = workflows.get_run(run_id)
    if run is None:
        return problem(404, "Run not found", run_id)
    return run


# ---------------------------------------------------------------- case feed
@app.get("/v1/cases/feed")
def case_feed(since: str | None = Query(default=None),
              band: str | None = Query(default=None),
              limit: int = Query(default=200, le=1000)):
    """nrs.cases.feed.v1 envelope-shaped feed (SPEC 1.1)."""
    return {"type": casefeed.CASE_FEED_TYPE,
            "items": casefeed.feed(lh, since=since, band=band, limit=limit)}


@app.post("/v1/cases/emit", status_code=202)
def case_emit():
    return {"emitted": casefeed.emit_cases(lh, settings.case_score_threshold)}


def main() -> None:
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.port, reload=False)


if __name__ == "__main__":
    main()
