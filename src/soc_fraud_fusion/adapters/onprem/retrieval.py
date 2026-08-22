"""On-prem RetrievalPort: fail-fast portability placeholder (the sovereign-exit proof, P-12).

The client points retrieval at its own governed knowledge base, so this binding refuses at call
time rather than returning silent emptiness that would strip narration of its grounding.
"""

from __future__ import annotations

from ...config import Settings
from ...domain.models import RetrievalQuery, RetrievedPassage


class OnPremRetrieval:
    """Satisfies RetrievalPort but refuses: the client binds its own governed retrieval."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def retrieve(self, query: RetrievalQuery) -> list[RetrievedPassage]:
        raise NotImplementedError(
            "on-prem retrieval is a portability placeholder: bind the client's own governed "
            "runbook / threat-intel index (see docs/onprem-migration.md)."
        )
