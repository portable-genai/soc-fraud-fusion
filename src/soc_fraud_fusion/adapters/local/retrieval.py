"""Local RetrievalPort: a deterministic fixture corpus of runbook / threat-intel passages.

Ranks the fixture passages by naive term overlap with the query and returns the top ``k``. It is
deterministic and SDK-free, so the offline gate can assert that narration is grounded in retrieved
prose without a live Hrz2 backend. Retrieval informs narration only: an incident's band is
identical with this adapter returning nothing.
"""

from __future__ import annotations

from ...config import Settings
from ...domain.models import RetrievalQuery, RetrievedPassage
from ._fixtures import PASSAGES


class LocalRetrieval:
    """Serve fixture runbook / threat-intel passages for the ``local`` profile."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def retrieve(self, query: RetrievalQuery) -> list[RetrievedPassage]:
        terms = {t for t in query.text.lower().split() if len(t) > 3}

        def overlap(passage: RetrievedPassage) -> int:
            haystack = f"{passage.title} {passage.snippet}".lower()
            return sum(1 for term in terms if term in haystack)

        ranked = sorted(PASSAGES, key=lambda p: (-overlap(p), p.source_id))
        hits = [p for p in ranked if overlap(p) > 0][: max(query.k, 0)]
        return hits
