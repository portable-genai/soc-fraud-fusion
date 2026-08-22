"""GCP GenerationPort: Gemini narration (SDK imports stay lazy).

The ``google`` GenAI import lives inside :meth:`narrate`, so the ``local``/``onprem`` profiles
import this module with no GCP SDK installed. The prompt carries ONLY the engine-owned incident
facts plus retrieved passages; the orchestrator then validates the returned draft against a
schema and discards it on failure, so a hallucinated figure never survives.
"""

from __future__ import annotations

from ...config import Settings
from ...domain.models import NarrationDraft, NarrationRequest


class GeminiGeneration:
    """Draft a cited incident summary and runbook through Gemini on Vertex AI."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def narrate(self, request: NarrationRequest) -> NarrationDraft:  # pragma: no cover - live GCP
        from google import genai  # noqa: PLC0415 - lazy

        client = genai.Client(vertexai=True, location=self._settings.region)
        prompt = self._prompt(request)
        response = client.models.generate_content(
            model=self._settings.generation_model,
            contents=prompt,
        )
        text = str(getattr(response, "text", "")).strip()
        narrative, _, runbook_block = text.partition("RUNBOOK:")
        runbook = tuple(
            line.strip("- ").strip() for line in runbook_block.splitlines() if line.strip()
        )
        cited_ids = (
            *(hit.technique_id for hit in request.incident.techniques),
            *(p.source_id for p in request.passages),
            *(g.citation.source_id for g in request.grounding),
        )
        return NarrationDraft(narrative=narrative.strip(), runbook=runbook, cited_ids=cited_ids)

    @staticmethod
    def _prompt(request: NarrationRequest) -> str:
        incident = request.incident
        techniques = "; ".join(f"{h.technique_id} {h.name}" for h in incident.techniques)
        passages = "\n".join(f"[{p.source_id}] {p.snippet}" for p in request.passages)
        return (
            "You are a SOC analyst. Summarise this incident and draft a response runbook using "
            "ONLY the facts below. Do not invent any figure, technique or indicator.\n"
            f"Incident: {incident.incident_id} subject {incident.subject} "
            f"severity {incident.severity.value} score {incident.score}.\n"
            f"Techniques: {techniques}.\n"
            f"Runbook passages:\n{passages}\n"
            "Return the summary, then a line 'RUNBOOK:' then one step per line."
        )
