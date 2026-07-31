"""Session memory (SPEC D section 0): Redis TTL 24h, NO PII at rest -
store references (record IDs, case IDs, tool-call refs), never raw values.
Embedded in-process fallback when redis lib/URL is unavailable (dev/tests).
"""
from __future__ import annotations

import time
from typing import Any, Protocol


class MemoryStore(Protocol):
    def append(self, session_id: str, ref: dict[str, Any]) -> None: ...
    def get(self, session_id: str) -> list[dict[str, Any]]: ...
    def clear(self, session_id: str) -> None: ...


class EmbeddedMemory:
    """In-process TTL store (fallback). Values are reference dicts only."""

    def __init__(self, ttl_s: int = 24 * 3600):
        self.ttl_s = ttl_s
        self._data: dict[str, tuple[float, list[dict[str, Any]]]] = {}

    def _prune(self, session_id: str) -> None:
        item = self._data.get(session_id)
        if item and time.time() - item[0] > self.ttl_s:
            self._data.pop(session_id, None)

    def append(self, session_id: str, ref: dict[str, Any]) -> None:
        self._prune(session_id)
        _, refs = self._data.get(session_id, (time.time(), []))
        refs.append(dict(ref))
        self._data[session_id] = (time.time(), refs)

    def get(self, session_id: str) -> list[dict[str, Any]]:
        self._prune(session_id)
        return list(self._data.get(session_id, (0.0, []))[1])

    def clear(self, session_id: str) -> None:
        self._data.pop(session_id, None)


class RedisMemory:
    def __init__(self, url: str, ttl_s: int = 24 * 3600):
        import redis  # type: ignore  # optional dependency
        import json
        self._json = json
        self.ttl_s = ttl_s
        self._r = redis.Redis.from_url(url, decode_responses=True)

    def _key(self, session_id: str) -> str:
        return f"hermes:mem:{session_id}"

    def append(self, session_id: str, ref: dict[str, Any]) -> None:
        k = self._key(session_id)
        self._r.rpush(k, self._json.dumps(ref))
        self._r.expire(k, self.ttl_s)

    def get(self, session_id: str) -> list[dict[str, Any]]:
        return [self._json.loads(x) for x in self._r.lrange(self._key(session_id), 0, -1)]

    def clear(self, session_id: str) -> None:
        self._r.delete(self._key(session_id))


def build_memory(redis_url: str = "", ttl_s: int = 24 * 3600) -> MemoryStore:
    if redis_url:
        try:
            m = RedisMemory(redis_url, ttl_s)
            return m
        except Exception:
            pass
    return EmbeddedMemory(ttl_s)
