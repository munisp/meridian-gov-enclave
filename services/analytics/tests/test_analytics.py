"""End-to-end tests: ingest -> silver/gold products -> features -> scoring ->
explanations -> k-anonymity -> case feed (nrs.cases.feed.v1 envelope shape)."""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

os.environ["ANALYTICS_DATA_ROOT"] = "/tmp/analytics-test-data"
os.environ["TIN_HMAC_KEY"] = "test-hmac-key"
os.environ["AUTH_MODE"] = "dev"

import shutil

shutil.rmtree("/tmp/analytics-test-data", ignore_errors=True)

from app.main import app  # noqa: E402
from app.pseudo import pseudo_tin  # noqa: E402

client = TestClient(app)
H = {"X-Dev-Role": "admin"}

TIN_A = "12345678-0001"
TIN_B = "87654321-0001"


def test_health():
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["service"] == "analytics"


def test_auth_required():
    r = client.get("/v1/lakehouse/datasets")
    assert r.status_code == 401
    assert r.headers["content-type"].startswith("application/problem+json")


def test_nsw_ingest_reconciles_and_builds_landing_cost():
    batch = {"records": [
        {"declaration_id": "NSW-001", "importer_tin": TIN_A, "hs_code": "8703.22",
         "customs_value_kobo": 5_000_000_00, "duty_kobo": 1_000_000_00,
         "port_code": "NGAPP", "declared_at": "2026-07-20T10:00:00Z"},
        {"declaration_id": "NSW-002", "importer_tin": TIN_B, "hs_code": "0402.21",
         "customs_value_kobo": 2_000_000_00, "duty_kobo": 400_000_00,
         "port_code": "NGLOS", "declared_at": "2026-07-21T10:00:00Z"},
        {"declaration_id": "NSW-BAD", "importer_tin": ""},  # rejected
    ]}
    r = client.post("/ingest/nsw/declarations", json=batch, headers=H)
    assert r.status_code == 201
    body = r.json()
    assert body["accepted"] == 2 and body["rejected"] == 1
    assert body["products"]["silver.customs_declarations"] == 2
    assert body["products"]["gold.import_vat_landing_cost"] == 2
    # landing cost = value + duty; VAT 7.5%
    gold = client.get("/v1/lakehouse/gold/import_vat_landing_cost", headers=H).json()["rows"]
    row = next(g for g in gold if g["declaration_id"] == "NSW-001")
    assert row["landing_cost_kobo"] == 6_000_000_00
    assert row["import_vat_due_kobo"] == 45_000_000  # 7.5% of 6,000,000.00
    assert row["pseudo_tin"] == pseudo_tin(TIN_A, "test-hmac-key")
    assert "tin" not in row and "importer_tin" not in row  # gold pseudonym-only


def test_features_scoring_explanation_and_cases():
    # MBS says 10m turnover; MoU filing says 6m -> divergence 66% (high)
    client.post("/ingest/mbs/taxview", headers=H, json={"records": [
        {"tin": TIN_A, "period": "2026-07", "turnover_kobo": 10_000_000_00,
         "invoice_count": 42, "source_app": "test-erp"}]})
    client.post("/ingest/filings-mou", headers=H, json={"records": [
        {"tin": TIN_A, "period": "2026-07", "tax_type": "VAT",
         "declared_turnover_kobo": 4_000_000_00, "filed_at": "2026-07-25T00:00:00Z"}]})
    # customs 5m vs import-VAT base 2m -> mismatch 60% (high)
    client.post("/ingest/import-vat/declarations", headers=H, json={"records": [
        {"tin": TIN_A, "period": "2026-07", "import_vat_base_kobo": 2_000_000_00,
         "import_vat_kobo": 150_000_00}]})

    r = client.post("/v1/workflows/wf-daily-scoring/run", headers=H)
    assert r.status_code == 202
    run = r.json()
    assert run["status"] == "completed", run
    steps = {s["name"]: s for s in run["steps"]}
    assert steps["materialise-features"]["result"]["fv_filing_divergence_30d"] >= 1

    scores = client.get("/v1/scores", headers=H).json()["scores"]
    s = next(x for x in scores if x["pseudo_tin"] == pseudo_tin(TIN_A, "test-hmac-key"))
    assert s["score"] >= 650 and s["band"] == "high"

    expl = client.get(f"/v1/scores/{pseudo_tin(TIN_A, 'test-hmac-key')}/explanation",
                      headers=H).json()["explanation"]
    assert expl["model"]["id"] == "nrs-risk-rules"
    rule_ids = {c["rule_id"] for c in expl["contributions"]}
    assert "score.filing_divergence.high" in rule_ids
    assert "score.import_mismatch.high" in rule_ids
    total = sum(c["points"] for c in expl["contributions"])
    assert min(1000, total) == expl["score"]

    # case feed envelope shape (SPEC 1.1)
    feed = client.get("/v1/cases/feed", headers=H).json()
    assert feed["type"] == "nrs.cases.feed.v1"
    item = next(i for i in feed["items"] if i["data"]["score_id"] == s["score_id"])
    for key in ("id", "type", "source", "time", "tenant_id", "trace_id",
                "rule_pack_version", "data"):
        assert key in item
    assert item["data"]["status"] == "open"


def test_k_anonymity_suppression():
    # only 2 subjects -> every band cell with < 5 subjects suppressed
    agg = client.get("/v1/aggregates/risk-by-band", headers=H).json()
    assert agg["k"] == 5
    for row in agg["rows"]:
        if row["n_subjects"] is not None and row["n_subjects"] < 5:
            pytest.fail("unsuppressed small cell leaked")
        assert row["suppressed"] is True


def test_mbs_cac_ingest_validation():
    r = client.post("/ingest/mbs/taxview", headers=H, json={"records": [{"period": "x"}]})
    assert r.status_code == 201 and r.json()["rejected"] == 1
    r = client.post("/ingest/cac/registry", headers=H, json={"records": [
        {"rc_number": "RC123", "legal_name": "Test Ventures Ltd"}]})
    assert r.json()["queued_for_resolution"] == 1
    r = client.post("/v1/workflows/wf-entity-resolution/run", headers=H)
    assert r.json()["status"] == "completed"


def test_gold_export_strips_identifiers():
    r = client.get("/v1/lakehouse/gold/import_vat_landing_cost", headers=H)
    for row in r.json()["rows"]:
        assert "importer_tin" not in row and "tin" not in row
