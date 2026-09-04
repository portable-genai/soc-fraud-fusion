"""GCP RetrievalPort: governed retrieval through enterprise-knowledge-base (File Search is
enterprise-knowledge-base's backend).

The ``google.cloud.discoveryengine`` import lives inside :meth:`retrieve`, so the
``local``/``onprem`` profiles import this module with no GCP SDK installed. The data store is
pinned to the residency region. Passages inform narration only, never the score or the band.
"""

from __future__ import annotations

from ...config import Settings
from ...domain.models import RetrievalQuery, RetrievedPassage


class Hrz2RetrievalAdapter:
    """Query the enterprise-knowledge-base governed knowledge base for runbook / threat-intel
    passages.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def retrieve(self, query: RetrievalQuery) -> list[RetrievedPassage]:  # pragma: no cover
        from google.cloud import discoveryengine_v1 as de  # noqa: PLC0415 - lazy

        client = de.SearchServiceClient()
        request = de.SearchRequest(
            serving_config=self._settings.retrieval_datastore,
            query=query.text,
            page_size=max(query.k, 1),
        )
        out: list[RetrievedPassage] = []
        for result in client.search(request):
            document = result.document
            struct = dict(document.struct_data or {})
            out.append(
                RetrievedPassage(
                    source_id=str(document.id),
                    title=str(struct.get("title", document.id)),
                    snippet=str(struct.get("snippet", "")),
                    locator=str(struct.get("locator", "")),
                )
            )
        return out
