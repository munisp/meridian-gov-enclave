"""Hash-chained audit records + JSONL sink."""
import json
import os

from hermes.agent.audit import GENESIS_HASH, AuditChain, JsonlSink


def test_chain_links_and_verifies():
    chain = AuditChain()
    chain.record_toolcall(actor="u1", agent="taxpayer-copilot", tool="get_obligations",
                          args={"tin": "1"}, result_ref="OB-1", session_id="s1")
    chain.record_toolcall(actor="u1", agent="taxpayer-copilot", tool="estimate_tax",
                          args={"tin": "1"}, result_ref="EST-1", session_id="s1")
    assert chain.records[0]["prev_hash"] == GENESIS_HASH
    assert chain.records[1]["prev_hash"] == chain.records[0]["hash"]
    assert AuditChain.verify(chain.records)


def test_tamper_detected():
    chain = AuditChain()
    chain.record_toolcall(actor="u1", agent="a", tool="t", args={}, result_ref="")
    rec = dict(chain.records[0])
    rec["actor"] = "mallory"
    assert not AuditChain.verify([rec])


def test_args_hashed_not_raw():
    chain = AuditChain()
    chain.record_toolcall(actor="u1", agent="a", tool="t",
                          args={"nin": "12345678901"}, result_ref="")
    assert "12345678901" not in json.dumps(chain.records[0])
    assert len(chain.records[0]["args_hash"]) == 64


def test_jsonl_sink(tmp_path):
    path = os.path.join(tmp_path, "audit.jsonl")
    chain = AuditChain(JsonlSink(path))
    chain.record_toolcall(actor="u1", agent="a", tool="t", args={"x": 1}, result_ref="")
    lines = open(path).read().strip().split("\n")
    assert len(lines) == 1
    assert AuditChain.verify([json.loads(lines[0])])
