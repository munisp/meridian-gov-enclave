"""Guardrails (SPEC D section 0 + per-agent sections):
- RBAC scopes per agent
- PII redactor (NIN / phone / MSISDN masking in model-visible output)
- Prompt-injection input filter + adversarial refusals
- Cross-tenant block (TIN must match the user's scope unless case-linked)
- Action-approval gate helpers (enforced in agent.loop)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


class GuardrailViolation(Exception):
    """Raised when a guardrail blocks an action. Message is user-safe."""

    def __init__(self, reason: str, code: str = "blocked"):
        super().__init__(reason)
        self.code = code


# ---------------------------------------------------------------------------
# RBAC scopes per agent
# ---------------------------------------------------------------------------
AGENT_SCOPES: dict[str, str] = {
    "taxpayer-copilot": "nrs.taxpayer",
    "auditor-copilot": "nrs.auditor",
    "ops-copilot": "nrs.sre",
    "policy-copilot": "nrs.policy",
    "onboarding-assistant": "nrs.field-agent",
}
ADMIN_SCOPE = "nrs.admin"


def check_rbac(agent: str, roles: list[str]) -> None:
    required = AGENT_SCOPES.get(agent)
    if required is None:
        raise GuardrailViolation(f"unknown agent: {agent}", "unknown_agent")
    if required not in roles and ADMIN_SCOPE not in roles:
        raise GuardrailViolation(
            f"role '{required}' required for {agent}", "forbidden")


# ---------------------------------------------------------------------------
# PII redactor: NIN (11 digits), Nigerian phone/MSISDN masking.
# Model-visible output must never carry raw NIN/phone; full values only in audit.
# ---------------------------------------------------------------------------
_NIN_RE = re.compile(r"\b\d{11}\b")
# +234 / 234 / 0 prefixed Nigerian MSISDN (70/80/81/90/91 etc.)
_PHONE_RE = re.compile(r"\b(?:\+?234|0)(7|8|9)\d{9}\b")


def _mask(s: str, keep: int = 2) -> str:
    return s[:keep] + "*" * (len(s) - keep * 2) + s[-keep:] if len(s) > keep * 2 else "*" * len(s)


def redact_text(text: str) -> str:
    text = _NIN_RE.sub(lambda m: _mask(m.group(0)), text)
    text = _PHONE_RE.sub(lambda m: _mask(m.group(0), 3), text)
    return text


def redact_value(v: Any) -> Any:
    if isinstance(v, str):
        return redact_text(v)
    if isinstance(v, list):
        return [redact_value(x) for x in v]
    if isinstance(v, dict):
        return {k: redact_value(x) for k, x in v.items()}
    return v


# ---------------------------------------------------------------------------
# Prompt-injection filter
# ---------------------------------------------------------------------------
INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"ignore (all |any |the )?(previous|prior|above) (instructions|prompts|rules)",
        r"disregard (your |all |the )?(instructions|rules|guidelines|system prompt)",
        r"you are now (a |an )?(DAN|jailbroken|unrestricted|new)",
        r"reveal (your |the )?(system prompt|instructions|tools|api key|secret)",
        r"print (your |the )?system prompt",
        r"developer mode",
        r"override (your |the )?(safety|guardrails|restrictions)",
        r"exfiltrat(e|ion)",
        r"\bbypass (the )?(filter|guardrail|approval|confirmation)",
        r"act as (a |an )?(admin|superuser|root) (and|to)",
    ]
]

REFUSAL_MESSAGE = ("I can't help with that request. I'm a tax-services assistant and "
                   "must follow my operating rules.")


def detect_injection(text: str) -> bool:
    return any(p.search(text or "") for p in INJECTION_PATTERNS)


# ---------------------------------------------------------------------------
# Cross-tenant block: a TIN argument must match the caller's scoped TIN unless
# the TIN is case-linked to the caller (auditor case links / agent assignments).
# ---------------------------------------------------------------------------
@dataclass
class TenancyContext:
    tin: str = ""                          # caller's own TIN scope ("" = staff w/o TIN scope)
    linked_tins: set[str] = field(default_factory=set)  # case-linked TINs
    unrestricted: bool = False             # e.g. ops/policy tools carry no TIN


def check_cross_tenant(args: dict[str, Any], tenancy: TenancyContext) -> None:
    tin = args.get("tin")
    if not tin or tenancy.unrestricted:
        return
    if tenancy.tin and str(tin) == tenancy.tin:
        return
    if str(tin) in tenancy.linked_tins:
        return
    raise GuardrailViolation(
        "Cross-tenant access denied: TIN is outside your authorized scope.", "cross_tenant")


# ---------------------------------------------------------------------------
# Action-approval gate (checked in the loop; helper kept here for clarity)
# ---------------------------------------------------------------------------
def requires_approval(tool_scope: str, requires_confirmation: bool) -> bool:
    return tool_scope == "action" and requires_confirmation
