"""Action-approval gate: requires_confirmation -> confirmation_request flow."""
import httpx

from hermes.agent.audit import AuditChain
from hermes.agent.loop import AgentLoop, UserContext
from hermes.agent.memory import EmbeddedMemory
from hermes.agent.tools import ToolExecutor
from hermes.config import ENDPOINTS
from hermes.llm.rule import RuleAdapter


def make_loop(agent, fixtures):
    def handler(request):
        for name, body in fixtures.items():
            ep = ENDPOINTS.get(name, "")
            prefix = "/" + ep.strip("/").split("/{")[0].strip("/")
            if ep and request.url.path.startswith(prefix):
                return httpx.Response(200, json=body)
        return httpx.Response(404, json={"error": "nf"})
    ex = ToolExecutor("http://t.local", transport=httpx.MockTransport(handler))
    return AgentLoop(RuleAdapter(agent), ex, AuditChain(), EmbeddedMemory()), ex


def test_nil_return_requires_confirmation_first():
    loop, ex = make_loop("taxpayer-copilot",
                         {"file_nil_return": {"filing_id": "FIL-1"}})
    c = UserContext(sub="u", roles=["nrs.taxpayer"], token="tok",
                    agent="taxpayer-copilot", tin="12345678")
    r = loop.run_turn(c, "File a nil return for 2024-Q2, TIN 12345678")
    assert r.confirmation_request is not None
    assert r.confirmation_request["tool"] == "file_nil_return"
    assert not ex.seen_auth_headers  # nothing executed pre-confirmation


def test_nil_return_executes_after_confirmation():
    loop, ex = make_loop("taxpayer-copilot",
                         {"file_nil_return": {"filing_id": "FIL-1"}})
    c = UserContext(sub="u", roles=["nrs.taxpayer"], token="tok",
                    agent="taxpayer-copilot", tin="12345678", user_confirmed=True)
    r = loop.run_turn(c, "File a nil return for 2024-Q2, TIN 12345678")
    assert r.confirmation_request is None
    assert r.tool_calls[0].status == "ok"
    assert ex.seen_auth_headers  # executed with user token


def test_ussd_confirmation_prompt_mentions_pin():
    loop, _ = make_loop("taxpayer-copilot", {"file_nil_return": {"filing_id": "F"}})
    c = UserContext(sub="u", roles=["nrs.taxpayer"], token="tok",
                    agent="taxpayer-copilot", tin="12345678", channel="ussd")
    r = loop.run_turn(c, "File a nil return for 2024-Q2, TIN 12345678")
    assert "PIN" in r.confirmation_request["prompt"]


def test_runbook_planned_not_executed_even_after_confirm():
    # run_runbook is planned (no ops API exists): even a confirmed user must
    # get an honest unavailability answer, never an execution.
    loop, ex = make_loop("ops-copilot", {"run_runbook": {"ok": True}})
    c = UserContext(sub="sre", roles=["nrs.sre"], token="tok", agent="ops-copilot")
    r = loop.run_turn(c, "restart deploy via runbook")
    assert r.confirmation_request is None
    assert not [t for t in r.tool_calls if t.status == "ok"]
    assert "planned" in r.answer.lower() or "not available" in r.answer.lower()
    c.user_confirmed = True
    r2 = loop.run_turn(c, "restart deploy via runbook")
    assert not [t for t in r2.tool_calls if t.status == "ok"]
    assert not ex.seen_auth_headers  # nothing ever executed


def test_executor_runbook_allowlist():
    import pytest
    from hermes.agent.tools import TOOL_INDEX, ToolExecutionError
    ex = ToolExecutor("http://t.local",
                      transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    with pytest.raises(ToolExecutionError):
        ex.execute(TOOL_INDEX["run_runbook"], {"name": "rm_rf", "params": {}}, "tok")
