"""The deterministic fusion service: correlate, screen, ground, narrate, audit, escalate.

The order mirrors the reference orchestration: screen the input through the safety port BEFORE it
could reach the generator, correlate the raw alerts with the pure engine (which owns the score,
band, ATT&CK techniques and recommendation), retrieve runbook prose and ground the indicators for
NARRATION only, draft the summary and runbook through the generation port, VALIDATE that draft
against the engine facts and DISCARD it on failure (falling back to a deterministic narrator so an
incident never waits on generation), screen the output, then write an already-redacted audit
record.

Two invariants the plan pins:

* the model narrates and never decides: the score, the band, the techniques and the recommended
  action come from :class:`CorrelationEngine`, and the narrator receives those FACTS, never the
  raw alert text, so no raw identifier reaches the model at all;
* every incident is consequential: ``requires_human_review`` is always True and the surfaces
  route it to human-review-console (rule R8). The system never executes containment.
"""

from __future__ import annotations

import re
from dataclasses import replace

from pii_kit import redact

from ..ports.alerts import AlertFeedPort
from ..ports.audit import AuditSinkPort
from ..ports.generation import GenerationPort
from ..ports.grounding import GroundingPort
from ..ports.observability import ObservabilityTracerPort
from ..ports.retrieval import RetrievalPort
from ..ports.safety import SafetyPort
from .correlation_engine import CorrelationEngine
from .kernel import AuditEvent, Citation, Decision, utcnow
from .models import (
    Alert,
    Direction,
    FusionRequest,
    GroundingHit,
    Incident,
    IncidentAssessment,
    NarrationDraft,
    NarrationRequest,
    RetrievalQuery,
    RetrievedPassage,
)
from .pii import PII_PATTERNS

#: Any ``Txxxx`` / ``Txxxx.yyy`` token in a draft that is NOT a mapped technique is a hallucinated
#: technique id, and the draft is discarded. The pattern is deliberately broad so a fabricated id
#: cannot slip through by using an unusual suffix.
_TECHNIQUE_TOKEN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

#: A ``score N`` figure in a draft must equal the engine's score, or the draft is discarded.
_SCORE_TOKEN = re.compile(r"score\s+(\d+)", re.IGNORECASE)

#: One span per fused incident. Structural attributes only: see :meth:`FusionService.fuse`.
_FUSE_SPAN = "fusion.fuse"


def _redacted_citation(citation: Citation) -> Citation:
    """Mask every field of a citation, locator and title included.

    An alert's citation snippet IS its free-text detail (``adapters/local/_fixtures.py`` builds it
    that way, and a real intake edge does the same), so a citation from this edge is raw source
    text wearing a provenance shape. No sink can tell that apart from an engine-built citation by
    inspection, so the masking is unconditional: it is a no-op on text that carries nothing.
    """
    return Citation(
        source_id=redact(citation.source_id, PII_PATTERNS),
        title=redact(citation.title, PII_PATTERNS),
        snippet=redact(citation.snippet, PII_PATTERNS),
    )


def _redacted_alerts(alerts: tuple[Alert, ...]) -> tuple[Alert, ...]:
    """Mask the free text on every raw alert, where it crosses out of the intake edge.

    The alert rows are what a source system wrote, and they feed FOUR sinks: the correlation
    engine (which copies their citations onto the incident), the narration request the model
    reads, the citations the WORM record stores, and the payload the review console renders.
    Only the audit SUMMARY was masked, so an identifier in an alert detail came back verbatim in
    the citation beside the summary that had just removed it. Masking here covers all four once
    rather than four times, and none of it touches a consequential value: the score reads
    ``signal_type`` and the timestamps, never this text.
    """
    return tuple(
        replace(
            alert,
            entity=redact(alert.entity, PII_PATTERNS),
            asset=redact(alert.asset, PII_PATTERNS),
            indicator=redact(alert.indicator, PII_PATTERNS),
            detail=redact(alert.detail, PII_PATTERNS),
            citation=_redacted_citation(alert.citation),
        )
        for alert in alerts
    )


class FusionService:
    """Fuse alerts into one cited, ATT&CK-mapped, always-human-reviewed incident assessment."""

    def __init__(
        self,
        *,
        alerts: AlertFeedPort,
        safety: SafetyPort,
        retrieval: RetrievalPort,
        grounding: GroundingPort,
        generation: GenerationPort,
        audit: AuditSinkPort,
        tracer: ObservabilityTracerPort,
        engine: CorrelationEngine,
    ) -> None:
        self._alerts = alerts
        self._safety = safety
        self._retrieval = retrieval
        self._grounding = grounding
        self._generation = generation
        self._audit = audit
        self._tracer = tracer
        self._engine = engine

    def fuse(
        self, request: FusionRequest, *, actor: str, tenant: str = "", as_of: str = ""
    ) -> IncidentAssessment:
        """Fuse one scope's alerts end to end, inside one span.

        ``tenant`` is the VERIFIED principal's, never a value from a request body, and it scopes
        the read: a scope name is a label a caller chose, not an entitlement to the rows behind
        it. An empty tenant reads no alerts rather than every alert.

        The span's attributes are a fixed structural set: the action and the actor, and nothing
        else. The caller-supplied subject and scope stay OFF the span deliberately: both are free
        strings a caller chose, and the guard proves they stay off. Never an alert's detail,
        never an indicator, never the drafted narrative. A trace backend is not the WORM audit
        trail: it has no redaction stage, a wider read audience and no retention rule written
        against a regulator's requirement, so anything content-shaped that reaches a span has
        left the boundary the redact-before-write calls exist to hold, and left it silently.
        """
        with self._tracer.span(_FUSE_SPAN, action="fuse", actor=actor):
            return self._fuse(request, actor=actor, tenant=tenant, as_of=as_of)

    def _fuse(
        self, request: FusionRequest, *, actor: str, tenant: str, as_of: str
    ) -> IncidentAssessment:
        """The six steps, unchanged. Split out so the span above wraps the WHOLE body."""
        # Masked at the intake edge, once, so nothing downstream has to remember: the engine,
        # the model, the WORM citations and the console payload all read the same masked rows.
        raw: tuple[Alert, ...] = _redacted_alerts(
            tuple(self._alerts.fetch(request.scope, tenant=tenant))
        )
        as_of = as_of or utcnow().isoformat()

        # 1. Screen the alert text BEFORE it could reach the generator. It is already masked, so
        #    the screen (and any managed screening log) never sees a raw identifier either.
        joined = " ".join(a.detail for a in raw)
        input_verdict = self._safety.screen(joined, Direction.INPUT)

        # 2. Correlate with the pure engine. This is the consequential step and it is untouched by
        #    the safety verdict: the score reflects the structured signals, not the free text.
        incident = self._engine.correlate(raw, subject=request.subject, as_of=as_of)

        # 3. Retrieve runbook prose and ground the indicators, for NARRATION only.
        passages: tuple[RetrievedPassage, ...] = tuple(
            self._retrieval.retrieve(RetrievalQuery(text=self._query(incident)))
        )
        indicators = tuple(a.indicator for a in raw if a.indicator)
        grounding: tuple[GroundingHit, ...] = (
            tuple(self._grounding.lookup(indicators)) if indicators else ()
        )

        # 4. Draft the narration. On blocked input the generator is NEVER called: a deterministic
        #    fallback records the block instead, so injected alert text cannot reach the model.
        narration = self._narrate(incident, passages, grounding, input_ok=input_verdict.allowed)

        # 5. Screen the output; a blocked draft is replaced by the deterministic fallback.
        if not self._safety.screen(narration.narrative, Direction.OUTPUT).allowed:
            narration = _fallback(incident, passages, grounding, blocked="output")

        citations = self._citations(incident, passages, grounding)
        summary = (
            f"{incident.subject}: {incident.severity.value} incident, "
            f"{len(incident.alert_ids)} alerts, {len(incident.techniques)} ATT&CK techniques, "
            f"recommend {incident.recommended_action.value}"
        )

        # 6. Redact BEFORE the audit write: the raw alert details never reach the WORM record.
        audit_text = " :: ".join((summary, " ".join(a.detail for a in raw), narration.narrative))
        # The summary and the narrative are redacted here as well: the alert details already are
        # (see above), and the subject is the caller's own free string.
        self._audit.record(
            AuditEvent(
                action="fuse",
                actor=actor,
                decision=Decision.ESCALATED,
                severity=incident.severity,
                redacted_summary=redact(audit_text, PII_PATTERNS),
                citations=tuple(_redacted_citation(c) for c in citations),
                timestamp=utcnow(),
            )
        )

        return IncidentAssessment(
            subject=incident.subject,
            severity=incident.severity,
            decision=Decision.ESCALATED,
            summary=summary,
            requires_human_review=True,
            incident=incident,
            narrative=narration.narrative,
            runbook=narration.runbook,
            grounded=bool(passages),
            citations=citations,
        )

    # ------------------------------------------------------------------ narration
    def _narrate(
        self,
        incident: Incident,
        passages: tuple[RetrievedPassage, ...],
        grounding: tuple[GroundingHit, ...],
        *,
        input_ok: bool,
    ) -> NarrationDraft:
        if not input_ok:
            return _fallback(incident, passages, grounding, blocked="input")
        draft = self._generation.narrate(
            NarrationRequest(incident=incident, passages=passages, grounding=grounding)
        )
        if not _valid(draft, incident):
            return _fallback(incident, passages, grounding, blocked="")
        return draft

    @staticmethod
    def _query(incident: Incident) -> str:
        names = " ".join(hit.name for hit in incident.techniques)
        return f"response runbook for {incident.subject} {names}".strip()

    @staticmethod
    def _citations(
        incident: Incident,
        passages: tuple[RetrievedPassage, ...],
        grounding: tuple[GroundingHit, ...],
    ) -> tuple[Citation, ...]:
        seen: set[str] = set()
        out: list[Citation] = []
        candidates: list[Citation] = list(incident.citations)
        candidates.extend(
            Citation(source_id=p.source_id, title=p.title, snippet=p.snippet) for p in passages
        )
        candidates.extend(g.citation for g in grounding)
        for citation in candidates:
            if citation.source_id in seen:
                continue
            seen.add(citation.source_id)
            out.append(citation)
        return tuple(out)


def _valid(draft: NarrationDraft, incident: Incident) -> bool:
    """Reject a draft that restates a figure or technique the engine did not produce.

    Groundedness is enforced here, not hoped for: every ATT&CK id the narrative mentions must be
    a mapped technique, and any ``score N`` it states must equal the engine's score. A draft that
    fails is discarded in favour of the deterministic fallback, so a hallucinated number can never
    reach a reviewer.
    """
    allowed = {hit.technique_id for hit in incident.techniques}
    text = f"{draft.narrative} {' '.join(draft.runbook)}"
    if any(token not in allowed for token in _TECHNIQUE_TOKEN.findall(text)):
        return False
    return all(int(figure) == incident.score for figure in _SCORE_TOKEN.findall(text))


def _fallback(
    incident: Incident,
    passages: tuple[RetrievedPassage, ...],
    grounding: tuple[GroundingHit, ...],
    *,
    blocked: str,
) -> NarrationDraft:
    """The deterministic narrator: restates engine facts and retrieved prose, nothing else.

    Used when the input was blocked (the generator is never called), when the output was blocked,
    or when a managed draft failed validation. It builds the narrative and runbook purely from the
    incident, the passages and the grounding, so it can never be ungrounded.
    """
    techniques = ", ".join(f"{h.technique_id} ({h.name})" for h in incident.techniques)
    prefix = ""
    if blocked == "input":
        prefix = "Input safety screen blocked the alert text; narration is engine-only. "
    elif blocked == "output":
        prefix = "Output safety screen blocked the drafted narration; engine-only fallback. "
    narrative = (
        f"{prefix}Incident {incident.incident_id} for {incident.subject} correlated "
        f"{len(incident.alert_ids)} alerts into a {incident.severity.value} finding "
        f"(score {incident.score}). Techniques: {techniques or 'none'}. "
        f"Recommended action: {incident.recommended_action.value} (subject to human review)."
    )
    steps: list[str] = [f"{p.title} [{p.source_id}]: {p.snippet}" for p in passages]
    steps.extend(
        f"Indicator {g.indicator} is {g.verdict} [{g.citation.source_id}]." for g in grounding
    )
    if not steps:
        steps.append("No runbook passage retrieved; route to a human responder for manual triage.")
    return NarrationDraft(narrative=narrative, runbook=tuple(steps))
