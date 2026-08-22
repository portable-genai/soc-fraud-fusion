"""The fusion path opens ONE span, and that span carries no content.

A trace backend is not the WORM audit trail. It has no redaction stage, no retention policy
written against a regulator's requirement, and a far wider read audience than the audit store.
So the value of tracing the fusion path depends entirely on the span carrying structural
attributes only: which action, whose, how long. An alert's free-text detail, an indicator, the
subject or the caller-chosen scope reaching a span has left the boundary that the
redact-before-write calls exist to hold, and it has left it silently.

The content case drives the scope whose fixture alert carries a planted NRIC, so the check runs
against input that would actually leak if any attribute were content-shaped.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from soc_fraud_fusion.adapters.local._fixtures import FIXTURE_TENANT
from soc_fraud_fusion.config import Settings, build_container
from soc_fraud_fusion.domain.correlation_engine import CorrelationEngine
from soc_fraud_fusion.domain.fusion_service import FusionService
from soc_fraud_fusion.domain.models import FusionRequest, IncidentAssessment
from soc_fraud_fusion.packs import attack_map_for

from tests.fixtures import sample_cases

#: Every attribute key the fusion span is allowed to carry. The caller-supplied subject and scope
#: are deliberately absent: both are free strings a caller chose, so neither is structural. A
#: critical incident that started explaining itself on the span (the severity, a technique, an
#: indicator) would widen this set, which is the point of asserting on the set rather than on the
#: individual keys.
_FUSE_KEYS = {"action", "actor"}


class _RecordingTracer:
    """Captures every span name and attribute so the test can inspect what was emitted."""

    def __init__(self) -> None:
        self.spans: list[tuple[str, dict[str, str]]] = []

    @contextmanager
    def span(self, name: str, **attributes: str) -> Iterator[None]:
        self.spans.append((name, dict(attributes)))
        yield

    def record_token_usage(self, usage: object, model: str) -> None:
        return None


def _fuse(request: FusionRequest) -> tuple[_RecordingTracer, IncidentAssessment]:
    """The REAL local adapters for every port except the tracer under inspection."""
    box = build_container(Settings(profile="local", audit_path=":memory:", tenant="demo-bank"))
    tracer = _RecordingTracer()
    service = FusionService(
        alerts=box.alerts,
        safety=box.safety,
        retrieval=box.retrieval,
        grounding=box.grounding,
        generation=box.generation,
        audit=box.audit,
        tracer=tracer,  # type: ignore[arg-type]
        engine=CorrelationEngine(attack_map_for()),
    )
    result = service.fuse(
        request, actor=sample_cases.ACTOR, tenant=FIXTURE_TENANT, as_of=sample_cases.AS_OF
    )
    return tracer, result


def _emitted(tracer: _RecordingTracer) -> str:
    """Every span name, attribute KEY and attribute VALUE, as one searchable blob."""
    parts: list[str] = []
    for name, attributes in tracer.spans:
        parts.append(name)
        parts.extend(attributes)
        parts.extend(attributes.values())
    return " ".join(parts)


def test_fusing_one_scope_opens_exactly_one_named_span() -> None:
    tracer, _ = _fuse(sample_cases.ROUTINE_CASE)
    assert [name for name, _ in tracer.spans] == ["fusion.fuse"]


def test_the_span_carries_the_structural_attributes_an_operator_needs() -> None:
    """Enough to answer "whose fusion is slow", and nothing more."""
    tracer, _ = _fuse(sample_cases.ROUTINE_CASE)
    _, attributes = tracer.spans[0]
    assert attributes["action"] == "fuse"
    assert attributes["actor"] == sample_cases.ACTOR


@pytest.mark.parametrize(
    "request_case",
    [
        sample_cases.ROUTINE_CASE,
        sample_cases.ESCALATING_CASE,
        sample_cases.MULE_CASE,
        sample_cases.PII_CASE,
    ],
    ids=["routine", "escalating", "mule", "pii"],
)
def test_the_attribute_set_is_a_fixed_allowlist_whatever_the_severity(
    request_case: FusionRequest,
) -> None:
    """A critical incident must not start attaching its techniques to the span to explain itself."""
    tracer, _ = _fuse(request_case)
    for _, attributes in tracer.spans:
        assert set(attributes) == _FUSE_KEYS


def test_no_span_attribute_carries_alert_content_or_the_planted_identifier() -> None:
    """The scope used here has an NRIC planted in a fixture alert detail, so a leak would show."""
    tracer, result = _fuse(sample_cases.PII_CASE)
    emitted = _emitted(tracer)

    forbidden: list[str] = [
        sample_cases.PLANTED_NRIC,
        sample_cases.PII_CASE.subject,
        sample_cases.PII_CASE.scope,
        "ops@delta.example",
        "192.0.2.201",
        # The incident id, the drafted narrative and the summary are the other content-shaped
        # values in reach of this call.
        result.incident.incident_id,
        result.narrative,
        result.summary,
    ]
    for literal in forbidden:
        assert literal, "an empty needle would pass this test for the wrong reason"
        assert literal not in emitted, f"a span attribute carried {literal!r}"
        assert literal.lower() not in emitted.lower(), f"a span attribute carried {literal!r}"

    # Belt and braces: no distinctive token of the drafted narrative appears either, so a
    # truncated or reformatted fragment cannot slip through the whole-string checks above.
    tokens = {
        token.strip("().,:;")
        for token in result.narrative.split()
        if len(token.strip("().,:;")) > 6
    }
    emitted_tokens = set(emitted.lower().split())
    assert tokens, "the fixture must carry distinctive text for this check to mean anything"
    assert not {token.lower() for token in tokens} & emitted_tokens


def test_every_emitted_attribute_value_is_a_string_the_port_declares() -> None:
    """``span(name, **attributes: str)``: a non-string would serialise however the SDK felt."""
    tracer, _ = _fuse(sample_cases.ESCALATING_CASE)
    values: list[Any] = [value for _, attributes in tracer.spans for value in attributes.values()]
    assert values
    assert all(isinstance(value, str) for value in values)
