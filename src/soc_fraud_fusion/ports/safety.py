"""SafetyPort: prompt-injection / unsafe-content screening (slice 3, the Model Armor edge).

The G5 row's stack names Model Armor and its dependencies omit agent-guardrail-gateway, and the CSV
wins: this service screens directly through a SafetyPort rather than through the
agent-guardrail-gateway. Input is screened BEFORE it reaches the generation port, so a runbook is
never drafted from prompt-injected alert text; output is screened before it leaves. Primary GCP
adapter calls Model Armor with a lazy SDK import; the local adapter is a deterministic heuristic;
the on-prem adapter fails fast.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..domain.models import Direction, SafetyVerdict


@runtime_checkable
class SafetyPort(Protocol):
    def screen(self, text: str, direction: Direction) -> SafetyVerdict:
        """Screen ``text`` (INPUT or OUTPUT) and return an allow/block verdict."""
        ...
