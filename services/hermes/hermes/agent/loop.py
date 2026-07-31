"""Tool-call loop (SPEC D section 0):
system prompt -> user msg -> LLM with tools= -> tool_calls[] -> execute
(allowlisted, user-scoped token) -> observe -> repeat. Hard limits:
8 tool calls/turn, 30s tool timeout, 4096-token answers. Final answers cite
record IDs. Action tools with requires_confirmation short-circuit into a
confirmation_request until the user confirms.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..llm.base import LLMAdapter
from .audit import AuditChain
from .guardrails import (GuardrailViolation, TenancyContext, check_cross_tenant,
                         detect_injection, redact_value, requires_approval,
                         REFUSAL_MESSAGE)
from .memory import MemoryStore
from .tools import Tool, ToolExecutionError, ToolExecutor, tools_for


@dataclass
class UserContext:
    sub: str
    roles: list[str]
    token: str                       # end-user Keycloak token - passed through
    agent: str
    session_id: str = ""
    channel: str = "web"             # web | ussd
    lang: str = "en"
    tin: str = ""                    # caller's TIN scope (taxpayer channel)
    linked_tins: set[str] = field(default_factory=set)
    user_confirmed: bool = False     # set by confirmation flow (web dialog / USSD PIN)
    case_id: str = ""


@dataclass
class ToolCallLog:
    tool: str
    args: dict[str, Any]
    status: str
    result_ref: str = ""
    record_ids: list[str] = field(default_factory=list)


@dataclass
class TurnResult:
    answer: str = ""
    citations: list[str] = field(default_factory=list)
    tool_calls: list[ToolCallLog] = field(default_factory=list)
    sim: bool = False
    blocked: bool = False
    refusal: bool = False
    confirmation_request: dict[str, Any] | None = None


_ID_KEYS = ("id", "case_id", "filing_id", "payment_id", "obligation_id",
            "record_id", "evidence_id", "scenario_id")


def _collect_ids(obj: Any, out: list[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _ID_KEYS and isinstance(v, (str, int)):
                out.append(str(v))
            else:
                _collect_ids(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _collect_ids(v, out)


class AgentLoop:
    def __init__(self, adapter: LLMAdapter, executor: ToolExecutor,
                 audit: AuditChain, memory: MemoryStore,
                 max_tool_calls: int = 8, max_answer_tokens: int = 4096):
        self.adapter = adapter
        self.executor = executor
        self.audit = audit
        self.memory = memory
        self.max_tool_calls = max_tool_calls
        self.max_answer_tokens = max_answer_tokens

    def run_turn(self, ctx: UserContext, user_message: str,
                 system_prompt: str = "") -> TurnResult:
        result = TurnResult()
        # 1) Prompt-injection input filter (adversarial refusal)
        if detect_injection(user_message):
            result.answer = REFUSAL_MESSAGE
            result.refusal = True
            result.blocked = True
            return result

        tools = tools_for(ctx.agent)
        tool_index = {t.name: t for t in tools}
        schemas = [t.ollama_schema() for t in tools]
        messages: list[dict[str, Any]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_message})

        tenancy = TenancyContext(tin=ctx.tin, linked_tins=set(ctx.linked_tins),
                                 unrestricted=(ctx.agent in ("ops-copilot", "policy-copilot")))
        calls_made = 0
        while True:
            resp = self.adapter.chat(messages, schemas, ctx=ctx)
            result.sim = result.sim or resp.sim
            if not resp.tool_calls:
                result.answer = self._truncate(resp.content)
                break
            for call in resp.tool_calls:
                if calls_made >= self.max_tool_calls:
                    result.answer = ("Tool-call limit reached for this turn; "
                                     "please narrow the request.")
                    return result
                tool = tool_index.get(call.name)
                if tool is None:
                    continue  # non-allowlisted tool: ignored
                calls_made += 1
                log = ToolCallLog(tool=tool.name, args=dict(call.args), status="ok")
                # 2) Action-approval gate
                if requires_approval(tool.scope, tool.requires_confirmation) \
                        and not ctx.user_confirmed:
                    log.status = "confirmation_required"
                    result.tool_calls.append(log)
                    result.confirmation_request = {
                        "tool": tool.name, "args": call.args,
                        "prompt": (f"Confirm action '{tool.name}' "
                                   f"with arguments {json.dumps(call.args)}? "
                                   + ("Re-enter your USSD PIN to confirm."
                                      if ctx.channel == "ussd"
                                      else "Confirm in the dialog to proceed.")),
                    }
                    result.answer = result.confirmation_request["prompt"]
                    return result
                # 3) Cross-tenant guard
                try:
                    check_cross_tenant(call.args, tenancy)
                except GuardrailViolation as e:
                    log.status = "blocked_cross_tenant"
                    result.tool_calls.append(log)
                    result.answer = str(e)
                    result.blocked = True
                    result.refusal = True
                    return result
                # 4) Execute (user-scoped token passthrough)
                record_ids: list[str] = []
                try:
                    raw = self.executor.execute(tool, call.args, user_token=ctx.token)
                    status = "ok"
                    result_ref = self._result_ref(raw)
                    _collect_ids(raw, record_ids)
                    # 5) PII minimization: redact model-visible output
                    visible = redact_value(raw)
                except (ToolExecutionError, GuardrailViolation) as e:
                    raw, visible, status, result_ref = {}, {"error": str(e)}, "error", ""
                log.status = status
                log.result_ref = result_ref
                log.record_ids = record_ids
                result.tool_calls.append(log)
                result.citations.extend(i for i in record_ids if i not in result.citations)
                # 6) Audit: EVERY tool call, hash-chained
                self.audit.record_toolcall(
                    actor=ctx.sub, agent=ctx.agent, tool=tool.name, args=call.args,
                    result_ref=result_ref, case_id=ctx.case_id,
                    session_id=ctx.session_id, status=status)
                # 7) Memory: refs only, never PII values
                if ctx.session_id:
                    self.memory.append(ctx.session_id, {
                        "tool": tool.name, "result_ref": result_ref,
                        "record_ids": record_ids, "status": status})
                messages.append({"role": "assistant", "content": None,
                                 "tool_calls": [{"function": {"name": call.name,
                                                              "arguments": call.args}}]})
                messages.append({"role": "tool", "name": tool.name,
                                 "content": json.dumps(visible, default=str)})
                if status == "error":
                    result.answer = f"Tool {tool.name} failed: {visible.get('error')}"
                    return result
            # loop back to the model with tool observations

        return result

    def _truncate(self, text: str) -> str:
        # ~4 chars/token rough bound for the 4096-token answer cap
        return text[: self.max_answer_tokens * 4]

    @staticmethod
    def _result_ref(raw: Any) -> str:
        if isinstance(raw, dict):
            for k in _ID_KEYS:
                if k in raw and isinstance(raw[k], (str, int)):
                    return str(raw[k])
        return ""
