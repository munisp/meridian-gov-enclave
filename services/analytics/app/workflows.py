"""In-process workflow runner (dev fallback for Temporal, SPEC 1.1 note).

wf-daily-scoring     : materialise all features -> score -> emit case feed
wf-entity-resolution : resolve unresolved ingest TINs against tin-graph
wf-feature-<name>    : materialise one feature vector

Each run records step-level results for audit defensibility.
"""
from __future__ import annotations

import threading
import traceback
from typing import Any, Callable

from . import features, scoring
from .casefeed import emit_cases
from .lakehouse import Lakehouse
from .tingraph import TinGraph
from .util import new_ulid, now_rfc3339

_runs: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


def _record(run: dict[str, Any]) -> None:
    with _lock:
        _runs[run["run_id"]] = run


def list_runs(limit: int = 50) -> list[dict[str, Any]]:
    with _lock:
        runs = sorted(_runs.values(), key=lambda r: r["started_at"], reverse=True)
    return runs[:limit]


def get_run(run_id: str) -> dict[str, Any] | None:
    with _lock:
        return _runs.get(run_id)


def _execute(name: str, steps: list[tuple[str, Callable[[], Any]]]) -> dict[str, Any]:
    run = {"run_id": new_ulid(), "workflow": name, "status": "running",
           "started_at": now_rfc3339(), "finished_at": None, "steps": []}
    _record(run)
    ok = True
    for step_name, fn in steps:
        step = {"name": step_name, "started_at": now_rfc3339(), "status": "running"}
        try:
            step["result"] = fn()
            step["status"] = "completed"
        except Exception as exc:  # noqa: BLE001 - record and stop the workflow
            step["status"] = "failed"
            step["error"] = str(exc)
            step["trace"] = traceback.format_exc(limit=5)
            ok = False
        step["finished_at"] = now_rfc3339()
        run["steps"].append(step)
        if not ok:
            break
    run["status"] = "completed" if ok else "failed"
    run["finished_at"] = now_rfc3339()
    _record(run)
    return run


def wf_daily_scoring(lh: Lakehouse, hmac_key: str, threshold: int) -> dict[str, Any]:
    return _execute("wf-daily-scoring", [
        ("materialise-features", lambda: features.materialise_all(lh, hmac_key)),
        ("score", lambda: {"scored": len(scoring.score_all(lh))}),
        ("emit-cases", lambda: {"emitted": emit_cases(lh, threshold)}),
    ])


def wf_entity_resolution(lh: Lakehouse, tg: TinGraph) -> dict[str, Any]:
    def _resolve() -> dict[str, Any]:
        pending = lh.read("bronze", "entity_resolution_queue", limit=100000)
        resolved, unresolved = 0, 0
        for row in pending:
            res = tg.resolve_entity(name=row.get("name", ""), tin=row.get("tin", ""),
                                    rc_number=row.get("rc_number", ""))
            if res.get("matched"):
                resolved += 1
            else:
                unresolved += 1
        return {"pending": len(pending), "resolved": resolved, "unresolved": unresolved,
                "tin_graph_mode": tg.mode()}

    return _execute("wf-entity-resolution", [("resolve-queue", _resolve)])


def wf_feature(lh: Lakehouse, hmac_key: str, feature_name: str) -> dict[str, Any]:
    if feature_name not in features.MATERIALISERS:
        raise KeyError(f"unknown feature {feature_name!r}; expected one of {features.FEATURES}")
    fn = features.MATERIALISERS[feature_name]
    return _execute(f"wf-feature-{feature_name.replace('fv_', '')}",
                    [(f"materialise-{feature_name}", lambda: {"rows": len(fn(lh, hmac_key))})])


WORKFLOW_NAMES = ["wf-daily-scoring", "wf-entity-resolution",
                  "wf-feature-filing-divergence", "wf-feature-import-mismatch",
                  "wf-feature-graph-risk"]
