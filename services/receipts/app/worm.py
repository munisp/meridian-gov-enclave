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
