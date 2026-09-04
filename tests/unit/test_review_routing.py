"""Rule R8: an incident assessment is ROUTED to human-review-console, not left in a per-repo
boolean.

This is the standing gate for the failure the rule exists to prevent. A repo can set
``requires_human_review = True``, pass every other test, and still auto-execute in practice
because nothing ever reads the flag. So the assertions here are about the ROUTING, not the flag:
every incident produces an outbound review, the payload leaves redacted, the managed router
refuses when no console is configured, and the on-prem placeholder refuses rather than swallowing
the escalation. Every incident is consequential, so every one routes.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from soc_fraud_fusion.adapters.gcp.review_router import (
    CloudReviewRouter,
)
from soc_fraud_fusion.adapters.local._fixtures import FIXTURE_TENANT
from soc_fraud_fusion.adapters.local.review_router import (
    LocalReviewRouter,
)
from soc_fraud_fusion.adapters.onprem.review_router import (
    OnPremReviewRouter,
)
from soc_fraud_fusion.api.app import (
    app,
)
from soc_fraud_fusion.config import (
    Settings,
    build_container,
)
from soc_fraud_fusion.domain.kernel import (
    Severity,
)
from soc_fraud_fusion.domain.models import (
    FusionRequest,
    IncidentAssessment,
)
from soc_fraud_fusion.factory import (
    build_fusion_service,
)

from tests.fixtures import sample_cases


def _settings(profile: str = "local") -> Settings:
    return Settings(profile=profile, audit_path=":memory:", tenant="demo-bank")


def _result(case: FusionRequest = sample_cases.ESCALATING_CASE) -> IncidentAssessment:
    service = build_fusion_service(build_container(_settings()))
    return service.fuse(
        case, actor=sample_cases.ACTOR, tenant=FIXTURE_TENANT, as_of=sample_cases.AS_OF
    )


def test_an_incident_produces_an_outbound_review() -> None:
    router = LocalReviewRouter(_settings())
    ref = router.route(_result(), maker=sample_cases.ACTOR)
    assert ref, "routing must return a reference, so the caller can record where it went"
    pending = router.outbox.pending()
    assert len(pending) == 1
    review = pending[0].review
    assert review.maker == sample_cases.ACTOR
    assert review.tenant == "demo-bank"
    assert review.severity == Severity.CRITICAL.value
    assert review.source_key, "a durable outbox needs an idempotency key"


def test_a_critical_incident_demands_dual_control() -> None:
    router = LocalReviewRouter(_settings())
    router.route(_result(), maker=sample_cases.ACTOR)  # the ATO scope bands CRITICAL
    assert router.outbox.pending()[0].review.required_approvals == 2


def test_the_payload_is_redacted_before_it_leaves_the_process() -> None:
    """human-review-console is a shared sink; a raw identifier must never reach the wire."""
    router = LocalReviewRouter(_settings())
    router.route(_result(sample_cases.PII_CASE), maker=sample_cases.ACTOR)
    wire = repr(router.outbox.pending()[0].review.to_payload())
    assert sample_cases.PLANTED_NRIC not in wire
    assert "REDACTED" in wire


def test_the_managed_router_refuses_when_no_console_is_configured() -> None:
    """An escalation with nowhere to go must fail loudly, not return as if it were reviewed."""
    router = CloudReviewRouter(Settings(profile="gcp", audit_path=":memory:", review_url=""))
    with pytest.raises(RuntimeError, match="R8"):
        router.route(_result(), maker=sample_cases.ACTOR)


def test_the_onprem_placeholder_refuses_rather_than_dropping_the_escalation() -> None:
    router = OnPremReviewRouter(_settings("onprem"))
    with pytest.raises(NotImplementedError, match="R8"):
        router.route(_result(), maker=sample_cases.ACTOR)


def test_the_api_routes_the_incident_in_the_same_request() -> None:
    """The serving path, not just the adapter: an escalation must not depend on a later job."""
    client = TestClient(app, client=("127.0.0.1", 50000))
    body = client.post(
        "/v1/fuse",
        json={"subject": sample_cases.ESCALATING_CASE.subject, "scope": "ato-acme"},
        headers={"X-Dev-Persona": "auditor"},
    ).json()
    assert body["requires_human_review"] is True
    assert body["review_ref"], "an incident with no routing reference went nowhere"
    assert body["incident"]["score"] == 100
