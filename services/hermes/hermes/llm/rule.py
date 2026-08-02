"""RuleAdapter: deterministic, offline LLM stand-in for dev/tests.
Pattern-matches intent -> emits the SAME tool-call protocol as Ollama
(tool_calls[{name, args}]). Responses are tagged sim=true so callers and
auditors can distinguish simulated turns from real model output.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .base import LLMResponse, ToolCall
from ..agent.tools import PLANNED_TOOL_NAMES

_TIN_RE = re.compile(r"TIN[:#\s]*([A-Za-z0-9-]{6,})", re.IGNORECASE)
_CASE_RE = re.compile(r"(CASE-[A-Za-z0-9-]+)", re.IGNORECASE)
_PERIOD_RE = re.compile(r"\b(\d{4}(?:-Q[1-4]|-\d{2})?)\b")
_VERSION_RE = re.compile(r"\b(\d{4}\.\d+(?:\.\d+)?)\b")


def _tin(text: str, ctx: Any) -> str:
    m = _TIN_RE.search(text)
    if m:
        return m.group(1)
    return getattr(ctx, "tin", "") or "UNKNOWN"


def _case(text: str) -> str:
    m = _CASE_RE.search(text)
    return m.group(1).upper() if m else "CASE-0001"


def _period(text: str) -> str:
    m = _PERIOD_RE.search(text)
    return m.group(1) if m else "2024-Q3"


def _lang(ctx: Any) -> str:
    return getattr(ctx, "lang", "en") or "en"


# (patterns, tool_name, arg builder). First match wins, per agent.
def _rules(agent: str):
    R: dict[str, list] = {
        "taxpayer-copilot": [
            (r"obligation|what do i owe|owe\b", "get_obligations",
             lambda t, c: {"tin": _tin(t, c)}),
            (r"calendar|due date|deadline|when (do|should) i file", "get_filing_calendar",
             lambda t, c: {"tin": _tin(t, c)}),
            (r"estimate|how much tax|liability|compute", "estimate_tax",
             lambda t, c: {"tin": _tin(t, c), "period": _period(t)}),
            (r"file (a )?nil|nil return", "file_nil_return",
             lambda t, c: {"tin": _tin(t, c), "period": _period(t)}),
            (r"what is|explain|meaning of|define", "explain_term",
             lambda t, c: {"term": _term(t), "lang": _lang(c)}),
        ],
        "auditor-copilot": [
            (r"360|overview|summary of taxpayer", "get_taxpayer_360",
             lambda t, c: {"tin": _tin(t, c)}),
            (r"filing", "search_filings",
             lambda t, c: {"tin": _tin(t, c), "from": "2024-01-01", "to": "2024-12-31"}),
            (r"payment", "search_payments",
             lambda t, c: {"tin": _tin(t, c), "from": "2024-01-01", "to": "2024-12-31"}),
            (r"kyc evidence|evidence for", "get_kyc_evidence",
             lambda t, c: {"case_id": _case(t)}),
            (r"rule pack|rules version", "get_rule_pack",
             lambda t, c: {"id": "rp-vat-rates",
                           "version": (_VERSION_RE.search(t) or [None, "2024.1"])[1]
                           if _VERSION_RE.search(t) else "2024.1"}),
            (r"assemble|attach evidence", "assemble_evidence",
             lambda t, c: {"case_id": _case(t), "refs": ["EV-1"]}),
            (r"draft (a )?finding", "draft_finding",
             lambda t, c: {"case_id": _case(t), "markdown": "Draft finding."}),
        ],
        "ops-copilot": [
            (r"hubble|network flow|flows", "hubble_flows",
             lambda t, c: {"ns": _ns(t), "since": "15m"}),
            (r"lag", "kafka_lag", lambda t, c: {"group": _group(t)}),
            (r"drift", "drift_report", lambda t, c: {"svc": _svc(t)}),
            (r"pod|health", "pod_health", lambda t, c: {"ns": _ns(t)}),
            (r"runbook|restart|scale|pause consumer|rebalance", "run_runbook",
             lambda t, c: {"name": _runbook(t), "params": {}, "dry_run": True}),
        ],
        "policy-copilot": [
            (r"list (rule )?packs|available packs", "list_rule_packs", lambda t, c: {}),
            (r"simulate|what if|threshold", "simulate",
             lambda t, c: {"pack_version": (_VERSION_RE.search(t).group(1)
                                            if _VERSION_RE.search(t) else "2024.1"),
                           "patch": _patch(t), "sample_size": 500}),
            (r"aggregate|how many taxpayers", "aggregate_taxpayers",
             lambda t, c: {"filter": {}}),
            (r"save (the )?scenario", "save_scenario",
             lambda t, c: {"name": "scenario-1", "patch": _patch(t)}),
        ],
        "onboarding-assistant": [
            (r"create (a )?(kyc )?case|new case|start onboarding|onboard", "create_kyc_case",
             lambda t, c: {"subject_type": ("business" if re.search(r"business|kyb|company", t, re.I)
                                            else "individual")}),
            (r"status", "get_case_status", lambda t, c: {"case_id": _case(t)}),
            (r"gap|missing|illegible", "get_field_gaps", lambda t, c: {"case_id": _case(t)}),
            (r"hint|checklist|capture|photo", "upload_doc_hint",
             lambda t, c: {"case_id": _case(t), "doc_type": _doctype(t)}),
        ],
    }
    return R.get(agent, [])


def _term(t: str) -> str:
    for term in ("nil return", "vat", "wht", "tin"):
        if term in t.lower():
            return term
    return "vat"


def _ns(t: str) -> str:
    m = re.search(r"\bns[ =:]?(\w[\w-]*)", t, re.I)
    return m.group(1) if m else "enclave"


def _group(t: str) -> str:
    m = re.search(r"group[ =:]?(\w[\w-]*)", t, re.I)
    return m.group(1) if m else "hermes-consumers"


def _svc(t: str) -> str:
    m = re.search(r"(?:svc|service)[ =:]?(\w[\w-]*)", t, re.I)
    return m.group(1) if m else "ledger"


def _runbook(t: str) -> str:
    tl = t.lower()
    if "scale" in tl:
        return "scale_hpa"
    if "pause" in tl:
        return "pause_consumer"
    if "rebalance" in tl:
        return "rebalance_os_shards"
    return "restart_deploy"


def _patch(t: str) -> dict:
    m = re.search(r"(\d[\d,]{5,})\s*(m|million)?", t, re.I)
    if m:
        val = int(m.group(1).replace(",", ""))
        if m.group(2):
            val *= 1_000_000
        return {"vat_threshold": val}
    return {"vat_threshold": 25_000_000}


def _doctype(t: str) -> str:
    tl = t.lower()
    if "nin" in tl:
        return "nin_slip"
    if "cac" in tl:
        return "cac_cert"
    if "utility" in tl or "bill" in tl:
        return "utility_bill"
    return "nin_slip"


def _collect_numbers(obj: Any, out: set[str]) -> None:
    if isinstance(obj, bool):
        return
    if isinstance(obj, (int, float)):
        out.add(str(obj))
        out.add(f"{obj:,}" if isinstance(obj, int) else str(obj))
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_numbers(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _collect_numbers(v, out)


def _collect_ids(obj: Any, out: list[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("id", "case_id", "filing_id", "payment_id", "obligation_id",
                     "record_id", "evidence_id") and isinstance(v, (str, int)):
                out.append(str(v))
            else:
                _collect_ids(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _collect_ids(v, out)


class RuleAdapter:
    """Deterministic intent->tool-call adapter (sim=true)."""

    def __init__(self, agent: str):
        self.agent = agent
        self.rules = _rules(agent)

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
             ctx: Any = None) -> LLMResponse:
        last = messages[-1] if messages else {}
        if last.get("role") == "tool":
            return LLMResponse(content=self._final_answer(messages), sim=True)
        text = str(last.get("content", ""))
        tool_names = {t["function"]["name"] for t in tools} if tools else set()
        for pattern, name, argf in self.rules:
            if not re.search(pattern, text, re.IGNORECASE):
                continue
            if name in tool_names:
                return LLMResponse(tool_calls=[ToolCall(name=name, args=argf(text, ctx))],
                                   sim=True)
            if name in PLANNED_TOOL_NAMES:
                # Honest unavailability: the capability is planned but has no
                # backing platform endpoint yet — never fake a tool call.
                return LLMResponse(
                    content=(f"That capability ('{name.replace('_', ' ')}') is planned "
                             "but not available yet: no backing platform endpoint "
                             "exists. I have not performed any action."), sim=True)
        return LLMResponse(content=("I can help with "
                                    f"{self.agent.replace('-', ' ')} tasks. "
                                    "Please rephrase your request."), sim=True)

    def _final_answer(self, messages: list[dict[str, Any]]) -> str:
        ids: list[str] = []
        nums: set[str] = set()
        summaries: list[str] = []
        for m in messages:
            if m.get("role") != "tool":
                continue
            try:
                data = json.loads(m.get("content", "{}"))
            except json.JSONDecodeError:
                continue
            _collect_ids(data, ids)
            _collect_numbers(data, nums)
            for k in ("definition", "status", "summary", "message"):
                if isinstance(data, dict) and isinstance(data.get(k), str):
                    summaries.append(data[k])
                    break
        parts = summaries[:1] if summaries else ["Here are the results from the platform."]
        if nums:
            shown = sorted(n for n in nums if len(n) < 15)[:6]
            parts.append("Key figures: " + ", ".join(shown) + ".")
        if ids:
            parts.append("Citations: " + ", ".join(dict.fromkeys(ids)) + ".")
        return " ".join(parts)
