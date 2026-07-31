"""LLM adapter protocol: OllamaAdapter (real, in-enclave) and RuleAdapter
(deterministic dev/test fallback; responses tagged sim=true)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    sim: bool = False  # True when produced by the deterministic RuleAdapter


class LLMAdapter(Protocol):
    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
             ctx: Any = None) -> LLMResponse: ...
