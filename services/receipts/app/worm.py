"""WORM storage for issued e-receipts.

REAL: append-only JSONL with a SHA-256 hash chain (each record binds the
previous record's hash, like the enclave-gateway evidence WORM). Writes go
through `Store.append` only; there is no update/delete path. `verify_chain`
re-reads the file and detects tampering/truncation. In prod the root must
be on immutable/object-locked storage (deployment concern; flagged in
README).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading

GENESIS = "0" * 64


class WormStore:
    def __init__(self, root: str) -> None:
        self._root = root
        self._path = os.path.join(root, "receipts.jsonl")
        self._lock = threading.Lock()
        os.makedirs(root, exist_ok=True)

    def _tail_hash(self) -> str:
        if not os.path.exists(self._path):
            return GENESIS
        last = GENESIS
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)["record_hash"]
        return last

    @staticmethod
    def _hash(prev: str, payload: dict) -> str:
        body = json.dumps({"prev": prev, "payload": payload},
                          sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(body).hexdigest()

    def append(self, payload: dict) -> dict:
        with self._lock:
            prev = self._tail_hash()
            rec = {"prev_hash": prev, "payload": payload,
                   "record_hash": self._hash(prev, payload)}
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return rec

    def get(self, receipt_id: str) -> dict | None:
        if not os.path.exists(self._path):
            return None
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec["payload"].get("receipt_id") == receipt_id:
                    return rec
        return None

    def rrrs(self) -> set[str]:
        """All RRR references ever minted (B3 #11: RRR minting is
        collision-checked against the authoritative WORM store, not an
        empty set)."""
        out: set[str] = set()
        if not os.path.exists(self._path):
            return out
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                rrr = json.loads(line)["payload"].get("rrr")
                if rrr:
                    out.add(rrr)
        return out

    def verify_chain(self) -> bool:
        if not os.path.exists(self._path):
            return True
        prev = GENESIS
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec["prev_hash"] != prev:
                    return False
                if self._hash(prev, rec["payload"]) != rec["record_hash"]:
                    return False
                prev = rec["record_hash"]
        return True


class IdempotencyStore:
    """Durable idempotency bindings for receipt issuance (B3 #11).

    Append-only JSONL mapping idempotency key -> {payload_hash,
    receipt_id}. Survives restarts (the previous in-memory dict lost
    every binding on restart, allowing duplicate receipts per event).
    The binding is payload-bound: replaying a key with a different
    request payload is a 409 conflict, not a silent replay.
    """

    def __init__(self, root: str) -> None:
        self._path = os.path.join(root, "idempotency.jsonl")
        self._lock = threading.Lock()
        os.makedirs(root, exist_ok=True)
        self._by_key: dict[str, dict] = {}
        if os.path.exists(self._path):
            with open(self._path, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        rec = json.loads(line)
                        self._by_key[rec["key"]] = rec

    def get(self, key: str) -> dict | None:
        return self._by_key.get(key)

    def record(self, key: str, payload_hash: str, receipt_id: str) -> None:
        rec = {"key": key, "payload_hash": payload_hash,
               "receipt_id": receipt_id}
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._by_key[key] = rec
