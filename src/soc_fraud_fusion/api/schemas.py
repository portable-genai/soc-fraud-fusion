"""API request/response schemas (Pydantic) mapped to/from the pure-domain models."""

from __future__ import annotations

from pydantic import BaseModel

from ..domain.models import IncidentAssessment


class FuseRequest(BaseModel):
    """Fuse the alerts in ``scope`` into one incident for ``subject``."""

    subject: str
    scope: str


class CitationModel(BaseModel):
    source_id: str
    title: str
    snippet: str = ""


class TechniqueModel(BaseModel):
    technique_id: str
    tactic: str
    name: str
    signal_type: str


class IncidentModel(BaseModel):
    incident_id: str
    subject: str
    score: int
    severity: str
    recommended_action: str
    alert_ids: list[str]
    entities: list[str]
    assets: list[str]
    timeline: list[str]
    techniques: list[TechniqueModel]
    uplifts: list[str]
    signal_key: str


class FuseResponse(BaseModel):
    subject: str
    severity: str
    decision: str
    summary: str
    requires_human_review: bool
    #: Where the escalation WENT (rule R8): the human-review-console review id, or the local queue
    #: reference.
    #: Never empty, because every incident escalates. A caller can tell a routed escalation from a
    #: flag that stopped here, which is the whole point of the rule.
    review_ref: str = ""
    grounded: bool = False
    incident: IncidentModel
    narrative: str
    runbook: list[str]
    citations: list[CitationModel] = []

    @classmethod
    def from_domain(cls, result: IncidentAssessment, *, review_ref: str = "") -> FuseResponse:
        incident = result.incident
        return cls(
            subject=result.subject,
            severity=result.severity.value,
            decision=result.decision.value,
            summary=result.summary,
            requires_human_review=result.requires_human_review,
            review_ref=review_ref,
            grounded=result.grounded,
            incident=IncidentModel(
                incident_id=incident.incident_id,
                subject=incident.subject,
                score=incident.score,
                severity=incident.severity.value,
                recommended_action=incident.recommended_action.value,
                alert_ids=list(incident.alert_ids),
                entities=list(incident.entities),
                assets=list(incident.assets),
                timeline=list(incident.timeline),
                techniques=[
                    TechniqueModel(
                        technique_id=t.technique_id,
                        tactic=t.tactic,
                        name=t.name,
                        signal_type=t.signal_type,
                    )
                    for t in incident.techniques
                ],
                uplifts=list(incident.uplifts),
                signal_key=incident.signal_key,
            ),
            narrative=result.narrative,
            runbook=list(result.runbook),
            citations=[
                CitationModel(source_id=c.source_id, title=c.title, snippet=c.snippet)
                for c in result.citations
            ],
        )


class HealthResponse(BaseModel):
    status: str
    profile: str
    region: str
    #: Provenance the UI banner states on every page: where the runtime sits and which model
    #: answers. Both are read off the service because the browser cannot know either.
    runtime: str = "local"  # "gcp" | "local"
    generator_model: str = "deterministic-offline-stub"
