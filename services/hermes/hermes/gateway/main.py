"""Hermes gateway: FastAPI /v1/chat (web + USSD session bridge), Keycloak JWT,
per-agent authz, /healthz /readyz (SPEC D section 0)."""
from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from fastapi import Depends, FastAPI, Request
from pydantic import BaseModel, Field

from ..agent.audit import AuditChain, build_sink
from ..agent.guardrails import GuardrailViolation, check_rbac, redact_text
from ..agent.loop import AgentLoop, UserContext
from ..agent.memory import build_memory
from ..agent.tools import ToolExecutor
from ..config import Settings, get_settings
from ..llm.ollama import OllamaAdapter
from ..llm.rule import RuleAdapter
from .auth import principal_from, problem
from .prompts import system_prompt

log = logging.getLogger("hermes.gateway")


class ChatRequest(BaseModel):
    agent: str
    message: str = Field(min_length=1, max_length=4000)
    channel: str = "web"               # web | ussd
    lang: str = "en"                   # en|ha|yo|ig|pcm
    session_id: str = ""
    confirmed: bool = False            # confirmation flow callback
    linked_tins: list[str] = Field(default_factory=list)
    case_id: str = ""


class ChatResponse(BaseModel):
    answer: str
    citations: list[str] = []
    sim: bool = False
    channel: str = "web"
    session_id: str = ""
    confirmation_request: Optional[dict[str, Any]] = None
    tool_calls: int = 0


def truncate_ussd(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1].rstrip() + "\u2026"


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    s = settings or get_settings()
    app = FastAPI(title="hermes", version=s.version)
    audit = AuditChain(build_sink(s.kafka_bootstrap, s.audit_topic, s.audit_jsonl_path))
    memory = build_memory(s.redis_url, s.memory_ttl_s)

    def build_loop(agent: str, channel: str) -> AgentLoop:
        if s.llm_adapter == "ollama":
            model = s.ollama_model_ussd if channel == "ussd" else s.ollama_model
            adapter = OllamaAdapter(s.ollama_url, model)
        else:
            adapter = RuleAdapter(agent)
        executor = ToolExecutor(s.platform_base_url, s.tool_timeout_s)
        return AgentLoop(adapter, executor, audit, memory,
                         max_tool_calls=s.max_tool_calls,
                         max_answer_tokens=s.max_answer_tokens)

    def require_principal(request: Request):
        p = principal_from(request, secret=s.jwt_secret, auth_mode=s.auth_mode,
                           profile=s.profile)
        if p is None:
            return None
        return p

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": s.service_name, "version": s.version}

    @app.get("/readyz")
    def readyz():
        deps = {"llm_adapter": s.llm_adapter, "audit": "jsonl" if not s.kafka_bootstrap
                else "kafka", "memory": "embedded" if not s.redis_url else "redis"}
        return {"status": "ready", "deps": deps}

    @app.post("/v1/chat", response_model=ChatResponse)
    def chat(req: ChatRequest, request: Request):
        principal = require_principal(request)
        if principal is None:
            return problem(401, "Unauthorized", "valid Bearer token required")
        try:
            check_rbac(req.agent, principal["roles"])
        except GuardrailViolation as e:
            return problem(403, "Forbidden", str(e))

        session_id = req.session_id or str(uuid.uuid4())
        ctx = UserContext(
            sub=principal["sub"], roles=principal["roles"], token=principal["token"],
            agent=req.agent, session_id=session_id, channel=req.channel,
            lang=req.lang, tin=principal.get("tin", ""),
            linked_tins=set(req.linked_tins), user_confirmed=req.confirmed,
            case_id=req.case_id)
        loop = build_loop(req.agent, req.channel)
        result = loop.run_turn(ctx, req.message,
                               system_prompt=system_prompt(req.agent, req.lang))
        answer = result.answer
        if req.channel == "ussd":
            answer = truncate_ussd(redact_text(answer), s.ussd_max_chars)
        return ChatResponse(
            answer=answer, citations=result.citations, sim=result.sim,
            channel=req.channel, session_id=session_id,
            confirmation_request=result.confirmation_request,
            tool_calls=len(result.tool_calls))

    return app


app = create_app()
