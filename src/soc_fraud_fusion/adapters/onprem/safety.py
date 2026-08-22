"""On-prem SafetyPort: fail-fast portability placeholder (the sovereign-exit proof, P-12).

The client screens through its own content-safety service, so this binding refuses at call time
rather than passing text through unscreened. Refusing is the correct failure: a screen that
silently allowed everything would let prompt-injected alert text reach the generator.
"""

from __future__ import annotations

from ...config import Settings
from ...domain.models import Direction, SafetyVerdict


class OnPremSafety:
    """Satisfies SafetyPort but refuses: the client binds its own safety screen."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def screen(self, text: str, direction: Direction) -> SafetyVerdict:
        raise NotImplementedError(
            "on-prem safety screening is a portability placeholder: bind the client's own "
            "content-safety service (see docs/onprem-migration.md)."
        )
