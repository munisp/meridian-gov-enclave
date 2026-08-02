"""Tool schema registry: all 5 agents' tools per SPEC D."""
from hermes.agent.tools import (ALLOWED_RUNBOOKS, PLANNED_TOOLS_BY_AGENT,
                                PLANNED_TOOL_NAMES, TOOL_INDEX, TOOLS_BY_AGENT,
                                static_tool_result, tools_for)


def test_all_five_agents_present():
    assert set(TOOLS_BY_AGENT) == {"taxpayer-copilot", "auditor-copilot",
                                   "ops-copilot", "policy-copilot",
                                   "onboarding-assistant"}


def test_live_tool_counts():
    # Only tools with a REAL backing route stay in the live lists.
    assert len(tools_for("taxpayer-copilot")) == 3
    assert len(tools_for("auditor-copilot")) == 4
    assert len(tools_for("ops-copilot")) == 0
    assert len(tools_for("policy-copilot")) == 1
    assert len(tools_for("onboarding-assistant")) == 3


def test_planned_tools_gated():
    # Schemas are kept (TOOL_INDEX) but planned tools are out of the live
    # lists and flagged planned.
    expected = {"get_obligations", "get_filing_calendar", "search_filings",
                "assemble_evidence", "draft_finding", "hubble_flows",
                "kafka_lag", "drift_report", "pod_health", "run_runbook",
                "simulate", "aggregate_taxpayers", "save_scenario",
                "get_field_gaps"}
    assert PLANNED_TOOL_NAMES == expected
    for name in expected:
        assert TOOL_INDEX[name].planned
    live = {t.name for tools in TOOLS_BY_AGENT.values() for t in tools}
    assert not (expected & live)
    planned_total = sum(len(v) for v in PLANNED_TOOLS_BY_AGENT.values())
    assert planned_total == len(expected)


def test_action_tools_require_confirmation():
    for name in ("file_nil_return", "assemble_evidence", "draft_finding",
                 "run_runbook", "save_scenario", "create_kyc_case"):
        t = TOOL_INDEX[name]
        assert t.scope == "action" and t.requires_confirmation


def test_read_tools_have_no_confirmation():
    for name, t in TOOL_INDEX.items():
        if t.scope == "read":
            assert not t.requires_confirmation, name


def test_endpoints_real_routes():
    # Live endpoints match the routes actually registered by the services.
    assert TOOL_INDEX["estimate_tax"].endpoint == "/v1/evaluate"
    assert TOOL_INDEX["estimate_tax"].service == "rules-engine"
    assert TOOL_INDEX["file_nil_return"].endpoint == "/v1/filings/vat"
    assert TOOL_INDEX["get_taxpayer_360"].endpoint == "/v1/taxpayer360/{tin_hash}"
    assert TOOL_INDEX["get_taxpayer_360"].service == "tin-graph"
    assert TOOL_INDEX["get_rule_pack"].endpoint == "/v1/packs/{id}/{version}"
    assert TOOL_INDEX["get_rule_pack"].service == "rp-registry"
    assert TOOL_INDEX["list_rule_packs"].endpoint == "/v1/packs"
    assert TOOL_INDEX["create_kyc_case"].endpoint == "/v1/cases"
    assert TOOL_INDEX["get_case_status"].endpoint == "/v1/cases/{case_id}"
    assert TOOL_INDEX["get_kyc_evidence"].endpoint == "/v1/cases/{case_id}/evidence"
    assert TOOL_INDEX["search_payments"].endpoint == "/v1/payments"
    assert TOOL_INDEX["search_payments"].service == "presumptive"


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


def test_executor_refuses_planned_tool():
    import httpx
    from hermes.agent.tools import ToolExecutionError, ToolExecutor

    def handler(request):  # must never be called
        raise AssertionError("planned tool must not hit the network")
    ex = ToolExecutor("http://t.local", transport=httpx.MockTransport(handler))
    try:
        ex.execute(TOOL_INDEX["kafka_lag"], {"group": "g"}, user_token="tok")
    except ToolExecutionError as e:
        assert "planned" in str(e) and "not available" in str(e)
    else:
        raise AssertionError("expected ToolExecutionError")


def test_executor_taxpayer360_hashes_tin_and_uses_service_url():
    import hashlib
    import hmac as hmac_mod
    import httpx
    from hermes.agent.tools import ToolExecutor, hash_tin
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"record_id": "T360-1"})
    ex = ToolExecutor("http://platform.local",
                      transport=httpx.MockTransport(handler),
                      service_urls={"tin-graph": "http://tin-graph.local"})
    out = ex.execute(TOOL_INDEX["get_taxpayer_360"], {"tin": "12345678"},
                     user_token="tok")
    assert out["record_id"] == "T360-1"
    expected = hmac_mod.new(b"meridian-dev-tin-hmac-key", b"12345678",
                            hashlib.sha256).hexdigest()
    assert expected == hash_tin("12345678", b"meridian-dev-tin-hmac-key")
    assert seen["url"] == f"http://tin-graph.local/v1/taxpayer360/{expected}"
    assert "12345678" not in seen["url"]  # raw TIN never sent


def test_executor_service_url_fallback_to_platform_base():
    import httpx
    from hermes.agent.tools import ToolExecutor
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"ok": True})
    ex = ToolExecutor("http://platform.local",
                      transport=httpx.MockTransport(handler))
    ex.execute(TOOL_INDEX["list_rule_packs"], {}, user_token="tok")
    assert seen["url"].startswith("http://platform.local/v1/packs")
