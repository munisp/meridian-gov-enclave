"""Audit (SPEC D section 0 + Tool schema + eval):
EVERY tool call -> hash-chained record -> Kafka topic hermes.toolcalls.v1.
Retention: 7 years (regulator can replay any agent decision end-to-end).
JSONL fallback when Kafka is unreachable (dev / tests / enclave outage).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any, Protocol

GENESIS_HASH = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def hash_args(args: dict[str, Any]) -> str:
    """SHA-256 of canonical args (values never stored raw in the chain record)."""
    return hashlib.sha256(canonical(args).encode()).hexdigest()


class AuditSink(Protocol):
    def emit(self, record: dict[str, Any]) -> None: ...
    def close(self) -> None: ...


class JsonlSink:
    """Append-only JSONL fallback sink (WORM-style local file)."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def emit(self, record: dict[str, Any]) -> None:
        if not self.path:
            return
        with self._lock, open(self.path, "a", encoding="utf-8") as f:
            f.write(canonical(record) + "\n")

    def close(self) -> None:
        pass


class KafkaSink:
    """Kafka producer sink for hermes.toolcalls.v1 (lazy import; optional dep).
    Topic retention is configured cluster-side at 7 years (SPEC D)."""

    def __init__(self, bootstrap: str, topic: str):
        from kafka import KafkaProducer  # type: ignore  # optional dependency
        self.topic = topic
        self._producer = KafkaProducer(
            bootstrap_servers=bootstrap.split(","),
            value_serializer=lambda v: canonical(v).encode(),
            acks="all",
        )

    def emit(self, record: dict[str, Any]) -> None:
        self._producer.send(self.topic, record)

    def close(self) -> None:
        self._producer.flush()
        self._producer.close()


class AuditChain:
    """Hash-chained audit log: each record embeds prev_hash; tamper-evident."""

    def __init__(self, sink: AuditSink | None = None):
        self.sink: AuditSink = sink or JsonlSink("")
        self._prev = GENESIS_HASH
        self._seq = 0
        self._lock = threading.Lock()
        self.records: list[dict[str, Any]] = []  # in-memory mirror (tests/replay)

    def record_toolcall(self, *, actor: str, agent: str, tool: str,
                        args: dict[str, Any], result_ref: str,
                        case_id: str = "", session_id: str = "",
                        status: str = "ok") -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            rec: dict[str, Any] = {
                "seq": self._seq,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "actor": actor, "agent": agent, "tool": tool,
                "args_hash": hash_args(args),
                "result_ref": result_ref,
                "case_id": case_id, "session_id": session_id,
                "status": status,
                "prev_hash": self._prev,
            }
            rec["hash"] = hashlib.sha256(canonical(rec).encode()).hexdigest()
            self._prev = rec["hash"]
            self.records.append(rec)
        self.sink.emit(rec)
        return rec

    @staticmethod
    def verify(records: list[dict[str, Any]]) -> bool:
        prev = GENESIS_HASH
        for rec in records:
            if rec.get("prev_hash") != prev:
                return False
            body = {k: v for k, v in rec.items() if k != "hash"}
            if hashlib.sha256(canonical(body).encode()).hexdigest() != rec.get("hash"):
                return False
            prev = rec["hash"]
        return True


def build_sink(kafka_bootstrap: str = "", topic: str = "hermes.toolcalls.v1",
               jsonl_path: str = "") -> AuditSink:
    """Kafka when configured & reachable; JSONL fallback otherwise."""
    if kafka_bootstrap:
        try:
            return KafkaSink(kafka_bootstrap, topic)
        except Exception:
            pass  # fall through to JSONL
    return JsonlSink(jsonl_path)
