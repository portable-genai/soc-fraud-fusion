"""On-prem GenerationPort: fail-fast portability placeholder (the sovereign-exit proof, P-12).

The client points narration at its own hosted model, so this binding refuses at call time rather
than emitting an ungrounded draft.
"""

from __future__ import annotations

from ...config import Settings
from ...domain.models import NarrationDraft, NarrationRequest


class OnPremGeneration:
    """Satisfies GenerationPort but refuses: the client binds its own hosted model."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def narrate(self, request: NarrationRequest) -> NarrationDraft:
        raise NotImplementedError(
            "on-prem narration is a portability placeholder: bind the client's own hosted model "
            "(see docs/onprem-migration.md)."
        )
