"""Importer/TIN reconciliation against the core tin-graph API (SPEC 2).

Real path: HTTP calls to TIN_GRAPH_URL (`POST /v1/verify/tin`,
`POST /v1/entities/resolve`, `GET /v1/entities/{id}/graph`).
Dev fallback: local registry seeded from a JSON file (or empty), matching the
same interface so analytics runs dev-standalone.
"""
from __future__ import annotations

import abc
import json
import os
from typing import Any

import httpx


class TinGraph(abc.ABC):
    @abc.abstractmethod
    def verify_tin(self, tin: str) -> dict[str, Any]:
        """-> {tin, valid, entity_id, legal_name, status, source}"""

    @abc.abstractmethod
    def resolve_entity(self, *, name: str = "", tin: str = "",
                       rc_number: str = "") -> dict[str, Any]:
        """-> {entity_id, matched, score, candidates[]}"""

    @abc.abstractmethod
    def entity_graph(self, entity_id: str) -> dict[str, Any]:
        """-> {entity_id, edges: [{relation, target_entity_id, weight, since}]}"""

    @abc.abstractmethod
    def mode(self) -> str:  # "core-api" | "local-fallback"
        ...


class CoreTinGraph(TinGraph):
    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base = base_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout)

    def mode(self) -> str:
        return "core-api"

    def verify_tin(self, tin: str) -> dict[str, Any]:
        r = self._client.post(f"{self.base}/v1/verify/tin", json={"tin": tin})
        r.raise_for_status()
        return r.json()

    def resolve_entity(self, *, name: str = "", tin: str = "", rc_number: str = "") -> dict[str, Any]:
        r = self._client.post(f"{self.base}/v1/entities/resolve",
                              json={"name": name, "tin": tin, "rc_number": rc_number})
        r.raise_for_status()
        return r.json()

    def entity_graph(self, entity_id: str) -> dict[str, Any]:
        r = self._client.get(f"{self.base}/v1/entities/{entity_id}/graph")
        r.raise_for_status()
        return r.json()


class LocalTinGraph(TinGraph):
    """File-backed dev registry. Seed file: <data_root>/tin_registry.json with
    [{"tin","entity_id","legal_name","status","edges":[...]}]. Unknown TINs are
    reported as unverified rather than crashing the pipeline."""

    def __init__(self, data_root: str):
        self.path = os.path.join(data_root, "tin_registry.json")
        self._by_tin: dict[str, dict[str, Any]] = {}
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                for row in json.load(fh):
                    self._by_tin[row["tin"].upper()] = row

    def mode(self) -> str:
        return "local-fallback"

    def register(self, row: dict[str, Any]) -> None:
        self._by_tin[row["tin"].upper()] = row
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(list(self._by_tin.values()), fh, indent=2)

    def verify_tin(self, tin: str) -> dict[str, Any]:
        row = self._by_tin.get((tin or "").upper())
        if not row:
            return {"tin": tin, "valid": False, "entity_id": None,
                    "legal_name": None, "status": "unverified", "source": "local-fallback"}
        return {"tin": tin, "valid": row.get("status", "active") == "active",
                "entity_id": row.get("entity_id"), "legal_name": row.get("legal_name"),
                "status": row.get("status", "active"), "source": "local-fallback"}

    def resolve_entity(self, *, name: str = "", tin: str = "", rc_number: str = "") -> dict[str, Any]:
        if tin and tin.upper() in self._by_tin:
            row = self._by_tin[tin.upper()]
            return {"entity_id": row.get("entity_id"), "matched": True, "score": 1.0,
                    "candidates": [{"entity_id": row.get("entity_id"),
                                    "legal_name": row.get("legal_name"), "score": 1.0}]}
        # naive name containment match for dev
        cands = [{"entity_id": r.get("entity_id"), "legal_name": r.get("legal_name"),
                  "score": 0.6}
                 for r in self._by_tin.values()
                 if name and name.lower() in (r.get("legal_name") or "").lower()]
        return {"entity_id": cands[0]["entity_id"] if cands else None,
                "matched": bool(cands), "score": cands[0]["score"] if cands else 0.0,
                "candidates": cands}

    def entity_graph(self, entity_id: str) -> dict[str, Any]:
        for row in self._by_tin.values():
            if row.get("entity_id") == entity_id:
                return {"entity_id": entity_id, "edges": row.get("edges", [])}
        return {"entity_id": entity_id, "edges": []}


def get_tin_graph(base_url: str, data_root: str) -> TinGraph:
    if base_url:
        return CoreTinGraph(base_url)
    return LocalTinGraph(data_root)
