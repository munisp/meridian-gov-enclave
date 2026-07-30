"""rp-disclosure-control enforcement: k-anonymity (+ dominance) on aggregate outputs.

Loads the pack from the rp-registry (AUDIT of packs) when configured, else the
embedded fallback YAML under app/packs/. Every aggregate query exported from the
gold zone must pass through `enforce_aggregation`.
"""
from __future__ import annotations

import os
from typing import Any

import yaml

from .config import Settings

DEFAULTS = {"k": 5, "max_contributor_share_bps": 8500,
            "quasi_identifiers": ["state", "lga", "sector", "tax_type", "band"]}


def load_pack(settings: Settings) -> dict[str, Any]:
    """Load rp-disclosure-control. Embedded fallback per SPEC (packs dir ships
    inside the service so it runs dev-standalone)."""
    path = os.path.join(settings.packs_dir, "rp-disclosure-control", "1.0.0.yaml")
    with open(path, "r", encoding="utf-8") as fh:
        pack = yaml.safe_load(fh)
    return pack


def pack_params(pack: dict[str, Any]) -> dict[str, Any]:
    params = dict(DEFAULTS)
    for rule in pack.get("rules", []):
        then = rule.get("then", {})
        if "k" in then:
            params["k"] = int(then["k"])
        if "max_contributor_share_bps" in then:
            params["max_contributor_share_bps"] = int(then["max_contributor_share_bps"])
        if "quasi_identifiers" in then:
            params["quasi_identifiers"] = list(then["quasi_identifiers"])
    return params


def enforce_aggregation(rows: list[dict[str, Any]], *, subject_col: str,
                        value_col: str | None, pack: dict[str, Any]) -> dict[str, Any]:
    """Apply k-anonymity + dominance to aggregate rows.

    Each input row must carry `n_subjects` (distinct pseudo subjects in cell)
    and optionally `max_share_bps` (largest single contributor share).
    Suppressed cells have their value replaced with None and suppressed=true.
    Returns {rows, suppressed_cells, k, pack_version}.
    """
    params = pack_params(pack)
    k = params["k"]
    out, suppressed = [], 0
    for row in rows:
        r = dict(row)
        n = int(r.get("n_subjects", 0))
        share = int(r.get("max_share_bps", 0))
        reason = None
        if n < k:
            reason = f"k-anonymity: cell has {n} subjects (< k={k})"
        elif value_col and share > params["max_contributor_share_bps"]:
            reason = (f"dominance: largest contributor {share}bps exceeds "
                      f"{params['max_contributor_share_bps']}bps")
        if reason:
            suppressed += 1
            r["suppressed"] = True
            r["suppress_reason"] = reason
            if value_col:
                r[value_col] = None
        else:
            r["suppressed"] = False
        out.append(r)
    return {"rows": out, "suppressed_cells": suppressed, "k": k,
            "pack_version": f"{pack.get('id')}@{pack.get('version')}"}
