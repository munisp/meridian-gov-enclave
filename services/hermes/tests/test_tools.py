"""Tool schema registry: all 5 agents' tools per SPEC D."""
from hermes.agent.tools import (ALLOWED_RUNBOOKS, TOOL_INDEX, TOOLS_BY_AGENT,
                                static_tool_result, tools_for)


def test_all_five_agents_present():
    assert set(TOOLS_BY_AGENT) == {"taxpayer-copilot", "auditor-copilot",
                                   "ops-copilot", "policy-copilot",
                                   "onboarding-assistant"}


def test_tool_counts_per_spec():
    assert len(tools_for("taxpayer-copilot")) == 5
    assert len(tools_for("auditor-copilot")) == 7
    assert len(tools_for("ops-copilot")) == 5
    assert len(tools_for("policy-copilot")) == 4
    assert len(tools_for("onboarding-assistant")) == 4


def test_action_tools_require_confirmation():
    for name in ("file_nil_return", "assemble_evidence", "draft_finding",
                 "run_runbook", "save_scenario", "create_kyc_case"):
        t = TOOL_INDEX[name]
        assert t.scope == "action" and t.requires_confirmation


def test_read_tools_have_no_confirmation():
    for name, t in TOOL_INDEX.items():
        if t.scope == "read":
            assert not t.requires_confirmation, name


def test_endpoints_canonical():
    assert TOOL_INDEX["get_obligations"].endpoint == "/v1/taxpayers/{tin}/obligations"
    assert TOOL_INDEX["estimate_tax"].endpoint == "/v1/rules-engine/estimate"
    assert TOOL_INDEX["get_taxpayer_360"].endpoint == "/v1/taxpayer-360/{tin}"
    assert TOOL_INDEX["run_runbook"].endpoint == "/v1/ops/runbooks"
    assert TOOL_INDEX["simulate"].endpoint == "/v1/rules-engine/sandbox/simulate"
    assert TOOL_INDEX["create_kyc_case"].endpoint == "/v1/kyc/cases"


def test_runbook_allowlist():
    assert ALLOWED_RUNBOOKS == {"restart_deploy", "scale_hpa", "pause_consumer",
                                "rebalance_os_shards"}


def test_ollama_schema_shape():
    schema = TOOL_INDEX["estimate_tax"].ollama_schema()
    assert schema["type"] == "function"
    assert schema["function"]["name"] == "estimate_tax"
    assert "tin" in schema["function"]["parameters"]["properties"]


def test_static_glossary_multilingual():
    r = static_tool_result("explain_term", {"term": "vat", "lang": "ha"})
    assert r["found"] and "7.5" in r["definition"]
    r = static_tool_result("explain_term", {"term": "vat", "lang": "pcm"})
    assert "7.5%" in r["definition"]


def test_static_doc_hints():
    r = static_tool_result("upload_doc_hint", {"case_id": "C1", "doc_type": "nin_slip"})
    assert any("NIN" in h for h in r["checklist"])
