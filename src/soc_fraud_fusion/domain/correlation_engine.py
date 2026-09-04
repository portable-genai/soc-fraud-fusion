"""The deterministic alert-correlation and ATT&CK-mapping engine (pure stdlib).

This is the consequential core: it reconciles a set of raw alerts into ONE incident, maps each
alert's signal type onto a MITRE ATT&CK technique by a pure lookup from pack data (never a model
guess), sums an auditable score, and derives the severity band and the containment
RECOMMENDATION. The model narrates the result; it never produces the score, the band, the
technique ids or the recommendation.

Every number is replayable: the score is ``baseline`` plus one ``+weight`` per unique
contributing technique, clamped to 100, and the ``signal_key`` fingerprint is a content hash so
re-running the same alerts diffs to nothing. ``as_of`` is supplied by the caller, so the engine
holds no clock.
"""

from __future__ import annotations

import hashlib

from .kernel import Citation, Severity
from .models import (
    Alert,
    AttackMap,
    Incident,
    RecommendedAction,
    TechniqueHit,
)

#: The score can never exceed this. A summed-uplift model without a clamp lets one noisy source
#: dominate every incident; the clamp keeps the band meaningful.
_SCORE_CEILING = 100

#: Band to recommendation. MONITOR/INVESTIGATE/CONTAIN are recommendations, never actions: every
#: one still sets ``requires_human_review`` and routes to human-review-console.
_ACTION_BY_SEVERITY: dict[Severity, RecommendedAction] = {
    Severity.LOW: RecommendedAction.MONITOR,
    Severity.MEDIUM: RecommendedAction.INVESTIGATE,
    Severity.HIGH: RecommendedAction.INVESTIGATE,
    Severity.CRITICAL: RecommendedAction.CONTAIN,
}


class CorrelationEngine:
    """Fuse raw alerts into one cited, ATT&CK-mapped, deterministically scored incident."""

    def __init__(self, attack_map: AttackMap) -> None:
        self._map = attack_map
        self._by_signal = attack_map.by_signal()

    def correlate(self, alerts: tuple[Alert, ...], *, subject: str, as_of: str) -> Incident:
        """Reconcile ``alerts`` into one incident scored against the loaded policy.

        Alerts arrive already scoped to one subject (the intake port fetched them by scope). The
        engine reconciles their entities, assets and timeline, maps each distinct signal type to
        a technique, and sums the score. An empty alert set yields a LOW, empty incident rather
        than raising: "nothing correlated" is a valid, auditable answer.
        """
        ordered = tuple(sorted(alerts, key=lambda a: (a.observed_at, a.alert_id)))
        entities = _distinct(a.entity for a in ordered if a.entity)
        assets = _distinct(a.asset for a in ordered if a.asset)
        timeline = _distinct(a.observed_at for a in ordered if a.observed_at)

        techniques, uplifts, score = self._score(ordered)
        severity = self._band(score)
        citations = self._citations(ordered, techniques)
        signal_key = self._fingerprint(subject, ordered, techniques)

        return Incident(
            incident_id=f"INC-{signal_key[:12]}",
            subject=subject,
            as_of=as_of,
            alert_ids=tuple(a.alert_id for a in ordered),
            entities=entities,
            assets=assets,
            timeline=timeline,
            techniques=techniques,
            score=score,
            severity=severity,
            recommended_action=_ACTION_BY_SEVERITY[severity],
            signal_key=signal_key,
            uplifts=uplifts,
            citations=citations,
        )

    # ------------------------------------------------------------------ scoring
    def _score(
        self, alerts: tuple[Alert, ...]
    ) -> tuple[tuple[TechniqueHit, ...], tuple[str, ...], int]:
        """Map signals to techniques and sum the score, one auditable line per technique.

        A technique is counted ONCE even if several alerts carry the same signal type: the score
        reflects distinct adversary techniques observed, not alert volume, so a single flapping
        sensor cannot inflate the band. Alerts whose signal type is not in the pack contribute no
        score and no technique (the engine never invents a mapping).
        """
        policy = self._map.policy
        uplifts: list[str] = [f"baseline = {policy.baseline}"]
        score = policy.baseline
        hits: list[TechniqueHit] = []
        seen: set[str] = set()
        for alert in alerts:
            technique = self._by_signal.get(alert.signal_type)
            if technique is None or technique.technique_id in seen:
                continue
            seen.add(technique.technique_id)
            hits.append(
                TechniqueHit(
                    technique_id=technique.technique_id,
                    tactic=technique.tactic,
                    name=technique.name,
                    signal_type=technique.signal_type,
                    citation=technique.citation,
                )
            )
            score += technique.weight
            uplifts.append(
                f"+{technique.weight} {technique.technique_id} ({technique.signal_type})"
            )
        score = min(score, _SCORE_CEILING)
        uplifts.append(f"= {score} (clamped to {_SCORE_CEILING})")
        ordered_hits = tuple(sorted(hits, key=lambda h: h.technique_id))
        return ordered_hits, tuple(uplifts), score

    def _band(self, score: int) -> Severity:
        policy = self._map.policy
        if score >= policy.critical_at:
            return Severity.CRITICAL
        if score >= policy.high_at:
            return Severity.HIGH
        if score >= policy.medium_at:
            return Severity.MEDIUM
        return Severity.LOW

    # ------------------------------------------------------------------ provenance
    @staticmethod
    def _citations(
        alerts: tuple[Alert, ...], techniques: tuple[TechniqueHit, ...]
    ) -> tuple[Citation, ...]:
        seen: set[str] = set()
        out: list[Citation] = []
        for citation in (*(a.citation for a in alerts), *(t.citation for t in techniques)):
            if citation.source_id in seen:
                continue
            seen.add(citation.source_id)
            out.append(citation)
        return tuple(out)

    @staticmethod
    def _fingerprint(
        subject: str, alerts: tuple[Alert, ...], techniques: tuple[TechniqueHit, ...]
    ) -> str:
        """A content hash over the reconciled inputs, so an identical incident diffs to nothing.

        Cribbed from the ``signal_key`` fingerprint convention: hash the sorted, canonicalised
        content rather than any wall-clock or object id, so the same alerts always fingerprint
        the same and any change to the correlated set is visible as a changed key.
        """
        parts = [subject]
        parts.extend(f"{a.alert_id}|{a.signal_type}|{a.observed_at}" for a in alerts)
        parts.extend(sorted(t.technique_id for t in techniques))
        digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
        return digest


def _distinct(values: object) -> tuple[str, ...]:
    """Deduplicate while preserving first-seen order, then return a sorted tuple for stability."""
    seen: list[str] = []
    for value in values:  # type: ignore[attr-defined]
        text = str(value)
        if text not in seen:
            seen.append(text)
    return tuple(sorted(seen))
