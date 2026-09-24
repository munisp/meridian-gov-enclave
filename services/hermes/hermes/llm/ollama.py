"""Ollama adapter for local dev — /api/chat with tools."""
from __future__ import annotations

import threading
from typing import Any

import httpx

from .base import LLMResponse, ToolCall

# One pooled client for the whole process: the gateway builds a NEW
# OllamaAdapter per agent turn, and per-call `httpx.Client(...)` construction
# paid a full TCP+TLS setup on every LLM round trip (and leaked sockets
# under load). The per-request timeout override preserves each adapter's
# configured timeout_s.
_SHARED: httpx.Client | None = None
_SHARED_LOCK = threading.Lock()


def _shared_client() -> httpx.Client:
    global _SHARED
    with _SHARED_LOCK:
        if _SHARED is None:
            _SHARED = httpx.Client(timeout=httpx.Timeout(60.0, connect=5.0))
    return _SHARED


class OllamaAdapter:
    """Ollama /api/chat. tools_supported=True for qwen3 etc."""

    def __init__(self, base_url: str, model: str, timeout_s: float = 60.0,
                 client: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_s = timeout_s
        self._client = client

    def chat(self, messages: list[dict[str, Any]],
             tools: list[dict[str, Any]]) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
        if self._client is not None:
            r = self._client.post(f"{self.base_url}/api/chat", json=payload)
        else:
            r = _shared_client().post(f"{self.base_url}/api/chat", json=payload,
                                      timeout=self.timeout_s)
        r.raise_for_status()
        data = r.json()
        msg = data.get("message", {})
        tcs = [ToolCall(id=f"tc_{i}", name=t["function"]["name"],
                        arguments=t["function"].get("arguments", {}))
               for i, t in enumerate(msg.get("tool_calls", []))]
        return LLMResponse(content=msg.get("content", ""), tool_calls=tcs,
                           finish_reason=data.get("done_reason", "stop"))
