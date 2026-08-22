"""Vertical artifact models: the SOC fraud-and-security fusion types.

The artifacts THIS vertical produces, as opposed to the vertical-neutral machinery in
``kernel.py``. The service's own name is deliberately not substituted into this docstring: a
rendered line whose length depends on ``friendly_name`` fails the repo's own format check for
no reason but the length of its name.

Everything here is a frozen, slotted dataclass or a ``StrEnum``: pure stdlib, replayable, with a
``Citation`` on every claim that leaves the engine. A fork building a different vertical rewrites
this module and keeps ``kernel.py`` untouched.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hex_service_kit.enums import LenientStrEnum

from .kernel import Citation, Decision, Severity

# --------------------------------------------------------------------------------------- #
# Enumerations (each member IS its wire value; a mis-cased value is refused at construction)
# --------------------------------------------------------------------------------------- #


class Direction(LenientStrEnum):
    """Which side of the model a safety screen guards."""

    INPUT = "input"
    OUTPUT = "output"


class RecommendedAction(LenientStrEnum):
    """The engine's containment RECOMMENDATION. Never executed: it routes to a human (R8)."""

    MONITOR = "monitor"
    INVESTIGATE = "investigate"
    CONTAIN = "contain"


class GroundingKind(LenientStrEnum):
    """What a grounding lookup resolved: an indicator of compromise or a CVE record."""

    IOC = "ioc"
    CVE = "cve"


# --------------------------------------------------------------------------------------- #
# Intake: raw cited alert rows (a port returns these; it never scores or correlates)
# --------------------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Alert:
    """One raw security-or-fraud alert row, exactly as a source system emitted it.

    ``signal_type`` is the source's own canonical signal label (e.g. ``impossible_travel``);
    it is mapped to an ATT&CK technique by the deterministic engine, never guessed by a model.
    ``observed_at`` is an ISO 8601 string so the row is pure, sortable and byte-identical on
    replay. Every alert carries a ``Citation`` back to the alert store.
    """

    alert_id: str
    source_system: str
    entity: str
    asset: str
    indicator: str
    signal_type: str
    observed_at: str
    detail: str
    citation: Citation
    #: The tenant that OWNS this row: the data tag object-level authorization is derived from.
    #: A scope name is a label, not an entitlement, so the feed matches this against the verified
    #: principal's tenant and returns nothing else. Empty means the row predates tagging and
    #: belongs to nobody, so no principal may read it.
    tenant: str = ""


@dataclass(frozen=True, slots=True)
class FusionRequest:
    """One request to fuse the alerts in a scope into a single correlated incident."""

    subject: str
    scope: str


# --------------------------------------------------------------------------------------- #
# Retrieval and grounding (advisory to narration only; never to the score or the verdict)
# --------------------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class RetrievalQuery:
    """A governed-retrieval request for runbook and threat-intel passages."""

    text: str
    k: int = 4


@dataclass(frozen=True, slots=True)
class RetrievedPassage:
    """One ranked passage with a runbook/threat-intel citation."""

    source_id: str
    title: str
    snippet: str
    locator: str = ""


@dataclass(frozen=True, slots=True)
class GroundingHit:
    """One resolved indicator or CVE, carrying its own MEDIA/INTEL citation."""

    indicator: str
    kind: GroundingKind
    verdict: str
    citation: Citation


# --------------------------------------------------------------------------------------- #
# Safety screening (Model Armor, or a deterministic local screen)
# --------------------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class SafetyVerdict:
    """The outcome of screening one text through the safety port."""

    allowed: bool
    direction: Direction
    reason: str
    categories: tuple[str, ...] = ()


class SafetyBlockedError(RuntimeError):
    """Raised when screened text is blocked, so it can never reach the generation port."""

    def __init__(self, verdict: SafetyVerdict) -> None:
        self.verdict = verdict
        super().__init__(verdict.reason)


# --------------------------------------------------------------------------------------- #
# ATT&CK mapping and scoring policy (pack DATA, loaded outside the pure domain)
# --------------------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class TechniqueDef:
    """One ATT&CK technique the pack maps a signal type onto, with its score weight."""

    signal_type: str
    technique_id: str
    tactic: str
    name: str
    weight: int
    citation: Citation


@dataclass(frozen=True, slots=True)
class FusionPolicy:
    """Adopter-owned scoring numbers (config, not algorithm). No jurisdiction branch here."""

    baseline: int
    medium_at: int
    high_at: int
    critical_at: int


@dataclass(frozen=True, slots=True)
class AttackMap:
    """The immutable signal-to-technique map plus the scoring policy, built from a pack."""

    version: str
    techniques: tuple[TechniqueDef, ...]
    policy: FusionPolicy

    def by_signal(self) -> dict[str, TechniqueDef]:
        """Index the techniques by signal type (last definition wins, as the pack ordered)."""
        return {t.signal_type: t for t in self.techniques}


# --------------------------------------------------------------------------------------- #
# Correlation output: the incident, its ATT&CK techniques, and the assessment routed to R8
# --------------------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class TechniqueHit:
    """An ATT&CK technique the incident matched, with the signal that raised it."""

    technique_id: str
    tactic: str
    name: str
    signal_type: str
    citation: Citation


@dataclass(frozen=True, slots=True)
class Incident:
    """One correlated incident: reconciled entities, assets, timeline and ATT&CK techniques.

    The ``score``, ``severity`` band and ``recommended_action`` are the engine's alone. Each
    ``uplifts`` line is one auditable arithmetic step (``baseline`` then ``+weight`` per
    contributing signal), so a reviewer can re-derive the score by hand. ``signal_key`` is a
    stable content fingerprint, so re-running the same alerts diffs to nothing.
    """

    incident_id: str
    subject: str
    as_of: str
    alert_ids: tuple[str, ...]
    entities: tuple[str, ...]
    assets: tuple[str, ...]
    timeline: tuple[str, ...]
    techniques: tuple[TechniqueHit, ...]
    score: int
    severity: Severity
    recommended_action: RecommendedAction
    signal_key: str
    uplifts: tuple[str, ...]
    citations: tuple[Citation, ...] = ()


@dataclass(frozen=True, slots=True)
class NarrationRequest:
    """The grounded, engine-owned facts a narrator may restate, and nothing else."""

    incident: Incident
    passages: tuple[RetrievedPassage, ...] = ()
    grounding: tuple[GroundingHit, ...] = ()


@dataclass(frozen=True, slots=True)
class NarrationDraft:
    """A drafted incident summary and response runbook, before schema validation."""

    narrative: str
    runbook: tuple[str, ...]
    cited_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class IncidentAssessment:
    """The routed result: a correlated incident, its cited narration, always human-reviewed.

    Field names ``subject`` / ``severity`` / ``decision`` / ``summary`` / ``citations`` mirror
    the vertical-neutral shape the audit record, the review payload and the API schema consume,
    so the R8 plumbing stays generic. The incident and its narration hang off the same result.
    """

    subject: str
    severity: Severity
    decision: Decision
    summary: str
    requires_human_review: bool
    incident: Incident
    narrative: str
    runbook: tuple[str, ...]
    grounded: bool
    citations: tuple[Citation, ...] = field(default_factory=tuple)
