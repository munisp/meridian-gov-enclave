"""OllamaAdapter: POST {OLLAMA_URL}/api/chat with tools= (SPEC D section 0).
Model default qwen2.5:32b-instruct (USSD path: qwen2.5:14b). All inference
stays in-enclave; no PII leaves the sovereign zone."""
from __future__ import annotations

from typing import Any

import httpx

from .base import LLMResponse, ToolCall


class OllamaAdapter:
    def __init__(self, base_url: str = "http://localhost:11434",
                 model: str = "qwen2.5:32b-instruct", timeout_s: float = 60.0,
                 client: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_s = timeout_s
        self._client = client

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
             ctx: Any = None) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"num_ctx": 32768},
        }
        if tools:
            payload["tools"] = tools
        http = self._client or httpx.Client(timeout=self.timeout_s)
        try:
            r = http.post(f"{self.base_url}/api/chat", json=payload)
            r.raise_for_status()
            data = r.json()
        finally:
            if self._client is None:
                http.close()
        msg = data.get("message", {})
        calls = [
            ToolCall(name=c.get("function", {}).get("name", ""),
                     args=c.get("function", {}).get("arguments", {}) or {})
            for c in (msg.get("tool_calls") or [])
        ]
        return LLMResponse(content=msg.get("content", ""), tool_calls=calls, sim=False)
