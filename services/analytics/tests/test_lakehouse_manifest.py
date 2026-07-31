"""Lakehouse unification (audit I4): catalog.json manifest on the dev
fallback and the ICEBERG_REST_URI backend-selection guard."""
from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("ANALYTICS_DATA_ROOT", "/tmp/analytics-test-manifest")
os.environ.setdefault("TIN_HMAC_KEY", "test-hmac-key")

from app.lakehouse import DuckDBLakehouse, get_lakehouse  # noqa: E402


def test_write_records_catalog_manifest(tmp_path):
    lh = DuckDBLakehouse(str(tmp_path))
    lh.write("bronze", "mbs_taxview", [{"id": "1", "amount_kobo": 10}], partition="2025-01-01")
    lh.write("bronze", "mbs_taxview", [{"id": "2", "amount_kobo": 5, "new_col": "x"}],
             partition="2025-01-02")
    cat = json.loads((tmp_path / "catalog.json").read_text())
    tbl = cat["tables"]["bronze.mbs_taxview"]
    assert len(tbl["snapshots"]) == 2
    assert tbl["schema_version"] == 1  # column set changed once
    assert "new_col" in tbl["columns"]
    assert [s["partition"] for s in tbl["snapshots"]] == ["2025-01-01", "2025-01-02"]


def test_get_lakehouse_dev_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv("ICEBERG_REST_URI", raising=False)
    assert isinstance(get_lakehouse(str(tmp_path)), DuckDBLakehouse)


def test_iceberg_guard_without_pyiceberg(tmp_path, monkeypatch):
    monkeypatch.setenv("ICEBERG_REST_URI", "http://localhost:8181")
    try:
        import pyiceberg  # noqa: F401
    except ImportError:
        with pytest.raises(RuntimeError, match="pyiceberg"):
            get_lakehouse(str(tmp_path))
    else:
        pytest.skip("pyiceberg installed; needs a live REST catalog")
