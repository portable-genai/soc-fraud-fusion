"""RetrievalPort: governed runbook and threat-intel retrieval (slice 2).

Passages inform NARRATION only, never the score or the verdict, so an incident's band is
identical with retrieval stubbed empty. Primary GCP adapter calls Hrz2 (File Search is Hrz2's
managed backend), pinned to the residency region; the local adapter serves a fixture corpus; the
on-prem adapter fails fast. Every passage carries a runbook/threat-intel citation.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..domain.models import RetrievalQuery, RetrievedPassage


@runtime_checkable
class RetrievalPort(Protocol):
    def retrieve(self, query: RetrievalQuery) -> list[RetrievedPassage]:
        """Return ranked runbook / threat-intel passages with citations for ``query``."""
        ...
