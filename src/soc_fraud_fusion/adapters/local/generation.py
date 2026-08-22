"""Local GenerationPort: a deterministic, grounded narrator (no SDK, no network).

Builds the incident summary and the response runbook from the engine-owned facts and the
retrieved passages ONLY, restating nothing the engine did not produce. It is deterministic, so
the offline gate can assert groundedness against a known-good draft, and it doubles as the
fallback the orchestrator uses when a managed draft fails schema validation: interdiction never
waits on generation.
"""

from __future__ import annotations

from ...config import Settings
from ...domain.models import NarrationDraft, NarrationRequest


class LocalGeneration:
    """Deterministic grounded narrator for the ``local`` profile (and the managed fallback)."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def narrate(self, request: NarrationRequest) -> NarrationDraft:
        incident = request.incident
        techniques = (
            ", ".join(f"{hit.technique_id} ({hit.name})" for hit in incident.techniques)
            or "no mapped techniques"
        )
        narrative = (
            f"Incident {incident.incident_id} for {incident.subject} correlated "
            f"{len(incident.alert_ids)} alerts into a {incident.severity.value} finding "
            f"(score {incident.score}). Mapped ATT&CK techniques: {techniques}. "
            f"Recommended action: {incident.recommended_action.value} (subject to human review)."
        )
        runbook = self._runbook(request)
        cited_ids = (
            *(hit.technique_id for hit in incident.techniques),
            *(p.source_id for p in request.passages),
            *(g.citation.source_id for g in request.grounding),
        )
        return NarrationDraft(narrative=narrative, runbook=runbook, cited_ids=cited_ids)

    @staticmethod
    def _runbook(request: NarrationRequest) -> tuple[str, ...]:
        steps: list[str] = []
        for passage in request.passages:
            steps.append(f"{passage.title} [{passage.source_id}]: {passage.snippet}")
        for hit in request.grounding:
            steps.append(f"Indicator {hit.indicator} is {hit.verdict} [{hit.citation.source_id}].")
        if not steps:
            steps.append(
                "No runbook passage retrieved; escalate to a human responder for manual triage."
            )
        return tuple(steps)
