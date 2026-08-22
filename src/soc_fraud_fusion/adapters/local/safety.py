"""Local SafetyPort: a deterministic prompt-injection / unsafe-content heuristic (no SDK).

Stands in for Model Armor offline. It blocks text that carries well-known prompt-injection or
jailbreak markers so the gate, the tests and the demo can prove that screened-out input never
reaches the generation port, without a live safety service. The heuristic is deliberately simple
and case-insensitive; the managed adapter is the real screen.
"""

from __future__ import annotations

from ...config import Settings
from ...domain.models import Direction, SafetyVerdict

#: Substrings that mark an obvious prompt-injection / jailbreak attempt. Not exhaustive: this is
#: the OFFLINE screen, and Model Armor is the real one. Kept lowercase for a case-insensitive scan.
_INJECTION_MARKERS: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous",
    "disregard the above",
    "disregard your instructions",
    "system prompt",
    "you are now",
    "jailbreak",
    "reveal your instructions",
    "override the runbook",
)


class LocalSafety:
    """Deterministic offline safety screen for the ``local`` profile."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def screen(self, text: str, direction: Direction) -> SafetyVerdict:
        lowered = text.lower()
        matched = tuple(marker for marker in _INJECTION_MARKERS if marker in lowered)
        if matched:
            return SafetyVerdict(
                allowed=False,
                direction=direction,
                reason="Local safety screen matched a prompt-injection marker.",
                categories=("prompt_injection",),
            )
        return SafetyVerdict(
            allowed=True,
            direction=direction,
            reason="No prompt-injection marker matched.",
        )
