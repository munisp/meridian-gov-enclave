"""Typed pydantic tool schemas + wrappers for all 5 Hermes agents (SPEC D).

Each tool is a typed wrapper over a platform REST surface (canonical paths in
hermes.config.ENDPOINTS). HTTP tools execute with the END USER's Keycloak
token (never a service super-token) so authorization stays user-scoped.
Static tools (explain_term, upload_doc_hint) resolve locally for fidelity.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from typing import Any, Literal, Optional

import httpx
from pydantic import BaseModel, Field

JsonSchema = dict[str, Any]


class Tool(BaseModel):
    name: str
    description: str
    params: dict[str, JsonSchema] = Field(default_factory=dict)
    scope: Literal["read", "action"] = "read"
    endpoint: str = ""       # real route template on the owning service; "" => static/local tool
    method: str = "GET"
    requires_confirmation: bool = False
    agent: str = ""
    service: str = ""        # owning service key (config.SERVICE_URLS); "" => platform base
    planned: bool = False    # no real backend route exists yet: schema kept, gated out
                             # of the live tool list; executor refuses honestly

    def ollama_schema(self) -> dict[str, Any]:
        props = {k: v for k, v in self.params.items()}
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": props,
                    "required": [k for k, v in self.params.items()
                                 if not k.endswith("_") and v.get("required", True)],
                },
            },
        }


def _s(type_: str, desc: str, **kw: Any) -> JsonSchema:
    d: JsonSchema = {"type": type_, "description": desc}
    d.update(kw)
    return d


# ---------------------------------------------------------------------------
# Tool registry (all 5 agents, per SPEC D sections 1-5)
# ---------------------------------------------------------------------------
def _t(name: str, desc: str, params: dict, agent: str, scope: str = "read",
       endpoint: str = "", method: str = "GET", confirm: bool = False,
       service: str = "", planned: bool = False) -> Tool:
    return Tool(name=name, description=desc, params=params, scope=scope,  # type: ignore[arg-type]
                endpoint=endpoint, method=method, requires_confirmation=confirm, agent=agent,
                service=service, planned=planned)


# Endpoint templates below are the REAL routes registered by the owning
# services (wiring audit §3.3); each tool names its owning `service` so the
# executor can resolve the per-service base URL (config.SERVICE_URLS, env
# overridable, falling back to the APISIX platform base). Tools whose SPEC D
# endpoint exists in NO service are marked planned=True: the schema is kept
# for documentation, but they are gated out of the live tool lists and the
# executor refuses them with an honest "planned, not available" error.
TAXPAYER_TOOLS = [
    _t("get_obligations", "List a taxpayer's filing/payment obligations. "
       "PLANNED: no obligations endpoint exists on any service yet.",
       {"tin": _s("string", "Taxpayer Identification Number")},
       "taxpayer-copilot", endpoint="/v1/taxpayers/{tin}/obligations", planned=True),
    _t("get_filing_calendar", "Get the filing calendar (due dates per tax type). "
       "PLANNED: no filing-calendar endpoint exists on any service yet.",
       {"tin": _s("string", "Taxpayer Identification Number")},
       "taxpayer-copilot", endpoint="/v1/filings/calendar", planned=True),
    _t("estimate_tax", "Estimate tax liability for a period via the rules engine.",
       {"tin": _s("string", "TIN"), "period": _s("string", "Period, e.g. 2024-Q3 or 2024-09")},
       "taxpayer-copilot", endpoint="/v1/evaluate", method="POST", service="rules-engine"),
    _t("file_nil_return", "File a NIL VAT return for a period. ACTION: requires explicit "
       "user confirmation (web confirm dialog / USSD PIN re-entry); idempotency-key per period.",
       {"tin": _s("string", "TIN"), "period": _s("string", "Period")},
       "taxpayer-copilot", scope="action", endpoint="/v1/filings/vat", method="POST",
       confirm=True, service="filings"),
    _t("explain_term", "Explain a tax term in the user's language (static glossary).",
       {"term": _s("string", "Term to explain"), "lang": _s("string", "en|ha|yo|ig|pcm")},
       "taxpayer-copilot"),  # static
]

AUDITOR_TOOLS = [
    _t("get_taxpayer_360", "Full 360 view of a taxpayer (registrations, filings, payments). "
       "The executor pseudonymises the TIN to tin_hash (HMAC-SHA256, same derivation as "
       "tin-graph) before calling.",
       {"tin": _s("string", "TIN")}, "auditor-copilot",
       endpoint="/v1/taxpayer360/{tin_hash}", service="tin-graph"),
    _t("search_filings", "Search filings for a TIN in a date range. PLANNED: the filings "
       "service has no list/search route (only per-period GET /v1/filings/vat/{tin}/{period}).",
       {"tin": _s("string", "TIN"), "from": _s("string", "ISO date"), "to": _s("string", "ISO date")},
       "auditor-copilot", endpoint="/v1/filings", planned=True),
    _t("search_payments", "Search payments for a TIN in a date range.",
       {"tin": _s("string", "TIN"), "from": _s("string", "ISO date"), "to": _s("string", "ISO date")},
       "auditor-copilot", endpoint="/v1/payments", service="presumptive"),
    _t("get_kyc_evidence", "Get KYC evidence bundle for a case.",
       {"case_id": _s("string", "KYC case id")},
       "auditor-copilot", endpoint="/v1/cases/{case_id}/evidence", service="kyc-engine"),
    _t("get_rule_pack", "Fetch a signed rule pack by id and version from the rp-registry.",
       {"id": _s("string", "Pack id, e.g. rp-vat-rates"),
        "version": _s("string", "Pack version, e.g. 2024.1")},
       "auditor-copilot", endpoint="/v1/packs/{id}/{version}", service="rp-registry"),
    _t("assemble_evidence", "Attach evidence refs to the auditor's OWN case. ACTION. "
       "PLANNED: no audit-case evidence endpoint exists (case-mgmt /v1/matters is a "
       "different workflow).",
       {"case_id": _s("string", "Audit case id"), "refs": _s("array", "Evidence record ids",
                                                             items={"type": "string"})},
       "auditor-copilot", scope="action", endpoint="/v1/audit-cases/{case_id}/evidence",
       method="POST", confirm=True, planned=True),
    _t("draft_finding", "Draft a finding (markdown) on a case; human publishes. ACTION. "
       "PLANNED: no audit-case drafts endpoint exists on any service yet.",
       {"case_id": _s("string", "Audit case id"), "markdown": _s("string", "Finding text")},
       "auditor-copilot", scope="action", endpoint="/v1/audit-cases/{case_id}/drafts",
       method="POST", confirm=True, planned=True),
]

OPS_TOOLS = [
    _t("hubble_flows", "Recent Hubble network flows for a namespace. PLANNED: no "
       "observability API service exists yet.",
       {"ns": _s("string", "Kubernetes namespace"), "since": _s("string", "e.g. 15m")},
       "ops-copilot", endpoint="/v1/obs/hubble/flows", planned=True),
    _t("kafka_lag", "Consumer-group lag for a Kafka group. PLANNED: no observability "
       "API service exists yet.",
       {"group": _s("string", "Consumer group")},
       "ops-copilot", endpoint="/v1/obs/kafka/lag", planned=True),
    _t("drift_report", "Config drift report for a service. PLANNED: no observability "
       "API service exists yet.",
       {"svc": _s("string", "Service name")},
       "ops-copilot", endpoint="/v1/obs/drift/{svc}", planned=True),
    _t("pod_health", "Pod health summary for a namespace. PLANNED: no observability "
       "API service exists yet.",
       {"ns": _s("string", "Kubernetes namespace")},
       "ops-copilot", endpoint="/v1/obs/k8s/health", planned=True),
    _t("run_runbook", "Run an allowlisted runbook (restart_deploy, scale_hpa, "
       "pause_consumer, rebalance_os_shards). ACTION: dry_run=true first; two-person "
       "rule for prod (approver identity required). PLANNED: no ops/runbooks API "
       "service exists yet.",
       {"name": _s("string", "Runbook name", enum=["restart_deploy", "scale_hpa",
                                                   "pause_consumer", "rebalance_os_shards"]),
        "params": _s("object", "Runbook params (incl. approver for prod)"),
        "dry_run": _s("boolean", "Dry run first, show diff", required=False)},
       "ops-copilot", scope="action", endpoint="/v1/ops/runbooks", method="POST",
       confirm=True, planned=True),
]

POLICY_TOOLS = [
    _t("list_rule_packs", "List available rules-engine packs.",
       {}, "policy-copilot", endpoint="/v1/packs", service="rules-engine"),
    _t("simulate", "What-if simulation of a patched rule pack on an anonymized sample "
       "(aggregates only, k-anonymity floor n>=50). PLANNED: no sandbox/simulate "
       "endpoint exists on any service yet.",
       {"pack_version": _s("string", "Base pack version"),
        "patch": _s("object", "Rule patch, e.g. {\"vat_threshold\": 25000000}"),
        "sample_size": _s("integer", "Sample size (>=50)")},
       "policy-copilot", endpoint="/v1/rules-engine/sandbox/simulate", method="POST",
       planned=True),
    _t("aggregate_taxpayers", "Aggregate-only taxpayer analytics (never row-level). "
       "PLANNED: no aggregate POST endpoint exists (gov analytics exposes only "
       "GET /v1/aggregates/risk-by-band).",
       {"filter": _s("object", "Aggregate filter")},
       "policy-copilot", endpoint="/v1/analytics/aggregate", method="POST", planned=True),
    _t("save_scenario", "Save a what-if scenario as a DRAFT (promotion is a separate "
       "human workflow). ACTION. PLANNED: no scenarios endpoint exists on any service yet.",
       {"name": _s("string", "Scenario name"), "patch": _s("object", "Rule patch")},
       "policy-copilot", scope="action", endpoint="/v1/rules-engine/scenarios",
       method="POST", confirm=True, planned=True),
]

ONBOARDING_TOOLS = [
    _t("create_kyc_case", "Create a KYC/KYB case for the customer being onboarded "
       "(agent-scoped). ACTION.",
       {"subject_type": _s("string", "individual|business", enum=["individual", "business"])},
       "onboarding-assistant", scope="action", endpoint="/v1/cases",
       method="POST", confirm=True, service="kyc-engine"),
    _t("get_case_status", "Status of a KYC case.",
       {"case_id": _s("string", "Case id")},
       "onboarding-assistant", endpoint="/v1/cases/{case_id}", service="kyc-engine"),
    _t("get_field_gaps", "Missing/illegible field flags computed from extraction "
       "reason_codes (gap flags only, never raw forensics). PLANNED: kyc-engine has "
       "no field-gaps route.",
       {"case_id": _s("string", "Case id")},
       "onboarding-assistant", endpoint="/v1/kyc/cases/{case_id}/field-gaps", planned=True),
    _t("upload_doc_hint", "Capture checklist per document type (static content).",
       {"case_id": _s("string", "Case id"), "doc_type": _s("string", "e.g. nin_slip|cac_cert|utility_bill")},
       "onboarding-assistant"),  # static
]

_ALL_TOOLS_BY_AGENT: dict[str, list[Tool]] = {
    "taxpayer-copilot": TAXPAYER_TOOLS,
    "auditor-copilot": AUDITOR_TOOLS,
    "ops-copilot": OPS_TOOLS,
    "policy-copilot": POLICY_TOOLS,
    "onboarding-assistant": ONBOARDING_TOOLS,
}

# Live tool lists exclude planned tools (no real backend route yet).
TOOLS_BY_AGENT: dict[str, list[Tool]] = {
    agent: [t for t in tools if not t.planned]
    for agent, tools in _ALL_TOOLS_BY_AGENT.items()
}

PLANNED_TOOLS_BY_AGENT: dict[str, list[Tool]] = {
    agent: [t for t in tools if t.planned]
    for agent, tools in _ALL_TOOLS_BY_AGENT.items()
}

# Schemas for ALL tools (incl. planned) remain addressable for docs/eval.
TOOL_INDEX: dict[str, Tool] = {t.name: t for tools in _ALL_TOOLS_BY_AGENT.values() for t in tools}

PLANNED_TOOL_NAMES: set[str] = {t.name for tools in PLANNED_TOOLS_BY_AGENT.values() for t in tools}

ALLOWED_RUNBOOKS = {"restart_deploy", "scale_hpa", "pause_consumer", "rebalance_os_shards"}


def tools_for(agent: str) -> list[Tool]:
    return TOOLS_BY_AGENT.get(agent, [])


def planned_tools_for(agent: str) -> list[Tool]:
    return PLANNED_TOOLS_BY_AGENT.get(agent, [])


# ---------------------------------------------------------------------------
# Static content (fidelity-critical; no LLM needed)
# ---------------------------------------------------------------------------
GLOSSARY: dict[str, dict[str, str]] = {
    "vat": {"en": "VAT (Value Added Tax) is a 7.5% consumption tax on goods and services.",
            "ha": "VAT haraji ne kashi 7.5% akan kayayyaki da ayyuka.",
            "yo": "VAT je owo-ori 7.5% lori oja ati isehandehande.",
            "ig": "VAT bu 7.5% ute on ahia na oru.",
            "pcm": "VAT na 7.5% tax wey dem dey put for goods and services."},
    "tin": {"en": "TIN is your Taxpayer Identification Number, unique to you or your business.",
            "ha": "TIN lambar bayanai ce ta mai biya haraji.",
            "yo": "TIN ni idanimo onibaje owo-ori.",
            "ig": "TIN bu nomba njirimara onye na akwu ute.",
            "pcm": "TIN na your own special tax number."},
    "nil return": {"en": "A nil return declares you had no taxable activity in the period.",
                   "ha": "Nil return na nufin babu wani haraji a wannan lokaci.",
                   "yo": "Nil return tumo si pe ko si owo-ori fun asiko na.",
                   "ig": "Nil return putara na enweghi ute obula n'oge ahu.",
                   "pcm": "Nil return mean say you no get any tax for that period."},
    "wht": {"en": "WHT (Withholding Tax) is tax deducted at source from payments.",
            "ha": "WHT haraji ne da ake karba daga tushen biya.",
            "yo": "WHT ni owo-ori ti a yoo ge lati orisun sisanwo.",
            "ig": "WHT bu ute e wesara na isi kwuo.",
            "pcm": "WHT na tax wey dem don comot from source before dem pay you."},
}

DOC_HINTS: dict[str, list[str]] = {
    "nin_slip": ["Use good lighting; avoid glare on the laminated slip",
                 "Capture all 11 NIN digits fully in frame",
                 "Ensure name and date of birth are legible"],
    "cac_cert": ["Place certificate flat; capture all four corners",
                 "RC number must be sharp and readable",
                 "Include the official seal in frame"],
    "utility_bill": ["Bill must be dated within the last 3 months",
                     "Address line must be fully visible",
                     "Avoid folded edges obscuring the account number"],
}


def static_tool_result(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Resolve static/local tools without any network call."""
    if name == "explain_term":
        term = str(args.get("term", "")).strip().lower()
        lang = str(args.get("lang", "en")).lower() or "en"
        entry = GLOSSARY.get(term) or GLOSSARY.get(term.rstrip("s"))
        if not entry:
            return {"term": term, "found": False,
                    "definition": "Term not in glossary; ask an officer or rephrase."}
        return {"term": term, "found": True,
                "definition": entry.get(lang) or entry["en"], "lang": lang}
    if name == "upload_doc_hint":
        dt = str(args.get("doc_type", "")).strip().lower()
        return {"doc_type": dt, "checklist": DOC_HINTS.get(
            dt, ["Capture the full document flat, in good light, all text legible."])}
    raise KeyError(f"not a static tool: {name}")


# ---------------------------------------------------------------------------
# Executor: typed wrappers over platform REST, user-token passthrough
# ---------------------------------------------------------------------------
_PATH_PARAM_RE = re.compile(r"\{([a-z_]+)\}")


class ToolExecutionError(Exception):
    pass


def hash_tin(tin: str, key: bytes) -> str:
    """Pseudonymise a raw TIN exactly as tin-graph does
    (core-platform services/tin-graph internal/graph.HashTIN):
    hex(HMAC-SHA256(TIN_HMAC_KEY, tin))."""
    return hmac.new(key, tin.encode("utf-8"), hashlib.sha256).hexdigest()


def _tin_hmac_key() -> bytes:
    """Mirror tin-graph's TINHMACKey(): env TIN_HMAC_KEY; prod fails closed
    (no dev-secret default); dev uses the same documented dev key."""
    k = os.environ.get("TIN_HMAC_KEY", "")
    if not k:
        if os.environ.get("PROFILE") == "prod":
            raise ToolExecutionError(
                "PROFILE=prod: TIN_HMAC_KEY is required (no dev-secret default)")
        k = "meridian-dev-tin-hmac-key"
    return k.encode("utf-8")


class ToolExecutor:
    """Executes tools against the platform. The Authorization header is ALWAYS
    the end user's token (ctx.user_token) - never a service super-token."""

    def __init__(self, base_url: str, timeout_s: float = 30.0,
                 client: Optional[httpx.Client] = None,
                 transport: Optional[httpx.BaseTransport] = None,
                 service_urls: Optional[dict[str, str]] = None):
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self._client = client
        self._transport = transport
        # Per-service base URLs (keyed by Tool.service); empty/absent entries
        # fall back to the platform base (APISIX edge).
        self.service_urls = {k: v.rstrip("/") for k, v in (service_urls or {}).items() if v}
        self.seen_auth_headers: list[str] = []  # test observability

    def _http(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        return httpx.Client(timeout=self.timeout_s, transport=self._transport)

    def _base_for(self, tool: Tool) -> str:
        return self.service_urls.get(tool.service, self.base_url)

    def execute(self, tool: Tool, args: dict[str, Any], user_token: str) -> dict[str, Any]:
        if not tool.endpoint:
            return static_tool_result(tool.name, args)
        if tool.planned:
            raise ToolExecutionError(
                f"{tool.name} is planned and not available against the live "
                "platform (no backing endpoint exists yet)")
        args = dict(args)
        if tool.name == "run_runbook":
            if args.get("name") not in ALLOWED_RUNBOOKS:
                raise ToolExecutionError(f"runbook not allowlisted: {args.get('name')}")
            args.setdefault("dry_run", True)  # dry-run mandatory first (SPEC D §3)
        if tool.name == "file_nil_return":
            args.setdefault("type", "nil")
            args.setdefault("idempotency_key",
                            f"nil-{args.get('tin')}-{args.get('period')}")
        if tool.name == "get_taxpayer_360":
            # tin-graph serves /v1/taxpayer360/{tin_hash}; derive the hash
            # exactly like the service does instead of sending the raw TIN.
            tin = str(args.pop("tin", ""))
            if not tin:
                raise ToolExecutionError("missing path param: tin")
            args["tin_hash"] = hash_tin(tin, _tin_hmac_key())
        path = tool.endpoint
        for m in _PATH_PARAM_RE.finditer(tool.endpoint):
            key = m.group(1)
            if key not in args:
                raise ToolExecutionError(f"missing path param: {key}")
            path = path.replace("{" + key + "}", str(args.pop(key)))
        url = self._base_for(tool) + path
        headers = {"Authorization": f"Bearer {user_token}",
                   "X-Request-Id": str(uuid.uuid4())}
        self.seen_auth_headers.append(headers["Authorization"])
        try:
            if tool.method == "GET":
                r = self._http().get(url, params={k: v for k, v in args.items()
                                                  if not isinstance(v, (dict, list))},
                                     headers=headers)
            else:
                r = self._http().post(url, json=args, headers=headers)
            r.raise_for_status()
            try:
                return r.json()
            except json.JSONDecodeError:
                return {"status": r.status_code, "body": r.text[:2000]}
        except httpx.HTTPError as e:
            raise ToolExecutionError(f"{tool.name} call failed: {e}") from e
