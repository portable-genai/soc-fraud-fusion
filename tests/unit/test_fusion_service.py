"""The fusion orchestrator: model narrates only, blocked input never reaches the generator,
a hallucinated draft is discarded, PII is masked before the write, and every incident is routed.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from soc_fraud_fusion.adapters._review_payload import result_to_review
from soc_fraud_fusion.adapters.local._fixtures import FIXTURE_TENANT
from soc_fraud_fusion.adapters.local.audit import LocalAuditAdapter
from soc_fraud_fusion.adapters.local.generation import LocalGeneration
from soc_fraud_fusion.config import Settings, build_container
from soc_fraud_fusion.domain.correlation_engine import CorrelationEngine
from soc_fraud_fusion.domain.fusion_service import FusionService
from soc_fraud_fusion.domain.kernel import Severity
from soc_fraud_fusion.domain.models import (
    Direction,
    NarrationDraft,
    NarrationRequest,
    SafetyVerdict,
)
from soc_fraud_fusion.factory import build_fusion_service
from soc_fraud_fusion.packs import attack_map_for

from tests.fixtures import sample_cases


def _settings() -> Settings:
    return Settings(profile="local", audit_path=":memory:", tenant="demo-bank")


def _service() -> FusionService:
    return build_fusion_service(build_container(_settings()))


class _SpyGeneration(LocalGeneration):
    """A generation adapter that records whether it was called at all."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.calls = 0

    def narrate(self, request: NarrationRequest) -> NarrationDraft:
        self.calls += 1
        return super().narrate(request)


class _BlockingSafety:
    """A safety adapter that blocks every INPUT, to prove the generator is never reached."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def screen(self, text: str, direction: Direction) -> SafetyVerdict:
        blocked = direction is Direction.INPUT
        return SafetyVerdict(allowed=not blocked, direction=direction, reason="test")


class _HallucinatingGeneration:
    """A generation adapter that fabricates a technique id the engine never produced."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def narrate(self, request: NarrationRequest) -> NarrationDraft:
        return NarrationDraft(
            narrative="Incident involved technique T9999 with score 999.", runbook=()
        )


class _DivergentGeneration:
    """A valid generator whose wording is nothing like the reference narrator's.

    It restates the engine's OWN score (so the groundedness validator keeps the draft) but is
    otherwise unrecognisable, so any consequential number that moved between this and the real
    generator would have to have come FROM the generator, which is the defect the determinism
    invariant forbids.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def narrate(self, request: NarrationRequest) -> NarrationDraft:
        score = request.incident.score
        return NarrationDraft(
            narrative=f"Unrelated phrasing entirely, but the engine score {score} is restated.",
            runbook=("triage", "escalate"),
        )


def _assemble(*, safety: object, generation: object) -> FusionService:
    box = build_container(_settings())
    return FusionService(
        alerts=box.alerts,
        safety=safety,  # type: ignore[arg-type]
        retrieval=box.retrieval,
        grounding=box.grounding,
        generation=generation,  # type: ignore[arg-type]
        audit=box.audit,
        tracer=box.tracer,
        engine=CorrelationEngine(attack_map_for()),
    )


def test_every_incident_requires_human_review_and_never_auto_contains() -> None:
    result = _service().fuse(
        sample_cases.ROUTINE_CASE,
        actor=sample_cases.ACTOR,
        tenant=FIXTURE_TENANT,
        as_of=sample_cases.AS_OF,
    )
    assert result.requires_human_review is True
    assert result.decision.value == "escalated"


def test_blocked_input_never_reaches_the_generation_port() -> None:
    spy = _SpyGeneration(_settings())
    service = _assemble(safety=_BlockingSafety(_settings()), generation=spy)
    result = service.fuse(
        sample_cases.ESCALATING_CASE,
        actor=sample_cases.ACTOR,
        tenant=FIXTURE_TENANT,
        as_of=sample_cases.AS_OF,
    )
    assert spy.calls == 0, "the generator was called on input the safety screen blocked"
    assert "engine-only" in result.narrative
    # The score is untouched by the block: it reads structured signals, not the free text.
    assert result.severity is Severity.CRITICAL


def test_a_hallucinated_draft_is_discarded_for_the_deterministic_fallback() -> None:
    # Use the real permissive local safety so the generator IS called, then rejected on validation.
    box = build_container(_settings())
    service = FusionService(
        alerts=box.alerts,
        safety=box.safety,
        retrieval=box.retrieval,
        grounding=box.grounding,
        generation=_HallucinatingGeneration(_settings()),
        audit=box.audit,
        tracer=box.tracer,
        engine=CorrelationEngine(attack_map_for()),
    )
    result = service.fuse(
        sample_cases.ESCALATING_CASE,
        actor=sample_cases.ACTOR,
        tenant=FIXTURE_TENANT,
        as_of=sample_cases.AS_OF,
    )
    assert "T9999" not in result.narrative, "a hallucinated technique id reached the reviewer"
    assert "999" not in result.narrative
    assert str(result.incident.score) in result.narrative


def test_pii_is_redacted_before_the_audit_write() -> None:
    audit = LocalAuditAdapter(_settings())
    box = build_container(_settings())
    service = FusionService(
        alerts=box.alerts,
        safety=box.safety,
        retrieval=box.retrieval,
        grounding=box.grounding,
        generation=box.generation,
        audit=audit,
        tracer=box.tracer,
        engine=CorrelationEngine(attack_map_for()),
    )
    service.fuse(
        sample_cases.PII_CASE,
        actor=sample_cases.ACTOR,
        tenant=FIXTURE_TENANT,
        as_of=sample_cases.AS_OF,
    )
    summary = str(audit.log.read_all()[-1]["redacted_summary"])
    assert sample_cases.PLANTED_NRIC not in summary
    assert "REDACTED" in summary
    assert audit.log.verify_chain().ok


def test_no_planted_identifier_reaches_the_model_the_worm_record_or_the_console() -> None:
    """The three sinks, one test: what the model reads, what the WORM record keeps, what leaves.

    The alert detail is free text a source system wrote, and the intake edge quotes it verbatim
    into the alert's own citation snippet. `redact` was applied to the joined text handed to the
    safety screen and to the audit SUMMARY, and to nothing else, so the incident the engine built
    out of those raw alerts went into the narration request (the model read it) and its citations
    went into the WORM record beside a summary that had just masked the same string.

    Scanning the summary alone sees none of that, which is the whole reason this test reads the
    fields beside it. `actor` is excluded on purpose: it is the verified principal and an address
    by design, so scanning it would make this unfailable in the wrong direction.
    """
    seen: list[NarrationRequest] = []
    audit = LocalAuditAdapter(_settings())
    box = build_container(_settings())
    inner = box.generation

    class _Tap:
        def narrate(self, request: NarrationRequest) -> NarrationDraft:
            seen.append(request)
            return inner.narrate(request)

    service = FusionService(
        alerts=box.alerts,
        safety=box.safety,
        retrieval=box.retrieval,
        grounding=box.grounding,
        generation=_Tap(),
        audit=audit,
        tracer=box.tracer,
        engine=CorrelationEngine(attack_map_for()),
    )
    result = service.fuse(
        sample_cases.PII_CASE,
        actor=sample_cases.ACTOR,
        tenant=FIXTURE_TENANT,
        as_of=sample_cases.AS_OF,
    )
    planted = (sample_cases.PLANTED_NRIC, sample_cases.PLANTED_EMAIL)

    # 1. The model. The WHOLE request, incident included, not just the narrative it returns.
    assert seen, "the generator must have been called"
    read_by_model = json.dumps(asdict(seen[-1]), default=str)
    for token in planted:
        assert token not in read_by_model, f"{token} reached the model"

    # 2. The WORM record, content fields only.
    rows = [dict(row) for row in audit.log.read_all()]
    assert rows
    for row in rows:
        stored = row["redacted_summary"] + json.dumps(row["citations"], default=str)
        for token in planted:
            assert token not in stored, f"{token} survived into the WORM record: {stored!r}"

    # 3. What LEAVES for the review console (rule R8), locator and source key included.
    outbound = json.dumps(
        asdict(result_to_review(result, maker=sample_cases.ACTOR, tenant=sample_cases.TENANT)),
        default=str,
    )
    for token in planted:
        assert token not in outbound, f"{token} left for Hrz7 in {outbound!r}"


def test_narration_is_grounded_when_retrieval_returns_passages() -> None:
    result = _service().fuse(
        sample_cases.ESCALATING_CASE,
        actor=sample_cases.ACTOR,
        tenant=FIXTURE_TENANT,
        as_of=sample_cases.AS_OF,
    )
    assert result.grounded is True
    assert result.runbook, "a grounded incident should carry runbook steps"


def test_the_band_is_identical_with_retrieval_stubbed_empty() -> None:
    """Retrieval informs narration only, never the score or the band."""

    class _EmptyRetrieval:
        def __init__(self, settings: Settings) -> None:
            self._settings = settings

        def retrieve(self, query: object) -> list[object]:
            return []

    box = build_container(_settings())
    service = FusionService(
        alerts=box.alerts,
        safety=box.safety,
        retrieval=_EmptyRetrieval(_settings()),  # type: ignore[arg-type]
        grounding=box.grounding,
        generation=box.generation,
        audit=box.audit,
        tracer=box.tracer,
        engine=CorrelationEngine(attack_map_for()),
    )
    stubbed = service.fuse(
        sample_cases.ESCALATING_CASE,
        actor=sample_cases.ACTOR,
        tenant=FIXTURE_TENANT,
        as_of=sample_cases.AS_OF,
    )
    full = _service().fuse(
        sample_cases.ESCALATING_CASE,
        actor=sample_cases.ACTOR,
        tenant=FIXTURE_TENANT,
        as_of=sample_cases.AS_OF,
    )
    assert stubbed.severity is full.severity
    assert stubbed.incident.score == full.incident.score
    assert stubbed.grounded is False


def test_numbers_are_identical_with_the_generation_adapter_stubbed_out() -> None:
    """The determinism invariant: swap the narrator, the consequential numbers do not move.

    The score, band, recommended action, ATT&CK ids, per-signal uplift arithmetic and the
    replay fingerprint all come from the pure engine, so a completely different (but valid)
    generator must produce a byte-identical incident. Only the prose changes. This is the
    "generation stubbed gives identical numbers" proof stated as a standing test.
    """
    real = _assemble(
        safety=build_container(_settings()).safety, generation=LocalGeneration(_settings())
    )
    stubbed = _assemble(
        safety=build_container(_settings()).safety, generation=_DivergentGeneration(_settings())
    )
    r = real.fuse(
        sample_cases.ESCALATING_CASE,
        actor=sample_cases.ACTOR,
        tenant=FIXTURE_TENANT,
        as_of=sample_cases.AS_OF,
    )
    s = stubbed.fuse(
        sample_cases.ESCALATING_CASE,
        actor=sample_cases.ACTOR,
        tenant=FIXTURE_TENANT,
        as_of=sample_cases.AS_OF,
    )
    assert s.incident.score == r.incident.score
    assert s.severity is r.severity
    assert s.incident.recommended_action is r.incident.recommended_action
    assert s.incident.techniques == r.incident.techniques
    assert s.incident.uplifts == r.incident.uplifts
    assert s.incident.signal_key == r.incident.signal_key
    assert s.narrative != r.narrative, "the divergent generator must actually change the prose"
