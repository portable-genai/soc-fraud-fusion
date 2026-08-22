"""API surface: verified-principal identity, fail-closed S2S, security headers.

The client comes from the shared ``api_client`` fixture, which pins a loopback peer: the
app-object exposure guard refuses the unauthenticated local posture to any other peer, and
TestClient's default peer is the literal host "testclient".
"""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from soc_fraud_fusion.domain.models import (
    FusionRequest,
)

from tests.fixtures import sample_cases

_TOKEN_ENV = "FRAUDFUSION_S2S_TOKEN"


def _fuse_body(case: FusionRequest = sample_cases.ESCALATING_CASE) -> dict[str, str]:
    return {"subject": case.subject, "scope": case.scope}


def test_fuse_uses_the_verified_principal_as_actor(api_client: TestClient) -> None:
    resp = api_client.post(
        "/v1/fuse",
        json=_fuse_body(),
        headers={"X-Dev-Persona": "auditor"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["severity"] == "critical"
    assert body["requires_human_review"] is True
    assert body["incident"]["score"] == 100
    # Rule R8: the escalation was routed, not merely flagged (see test_review_routing.py).
    assert body["review_ref"]


def test_an_alert_scope_of_another_tenant_is_not_fusible(api_client: TestClient) -> None:
    """Object-level authorization: naming a scope is not entitlement to the alerts inside it.

    The verified principal `other-tenant` belongs to `other-bank`. `AlertFeedPort.fetch` took a
    client-supplied scope and no principal at all, so any authenticated caller who named a scope
    received another bank's whole alert set, correlated into an incident with its detail lines
    quoted back.

    A foreign scope now answers exactly as an UNKNOWN scope does, with an empty low incident,
    rather than with a refusal. "No alerts in this scope" was already this port's valid answer,
    so reusing it means the response cannot be read as "that scope exists, but not for you",
    which is what a distinct refusal would say.
    """
    unknown = api_client.post(
        "/v1/fuse",
        json={"subject": "user:acme-treasury", "scope": "no-such-scope"},
        headers={"X-Dev-Persona": "other-tenant"},
    )
    foreign = api_client.post(
        "/v1/fuse",
        json=_fuse_body(),
        headers={"X-Dev-Persona": "other-tenant"},
    )
    assert unknown.status_code == 200 and foreign.status_code == 200
    assert foreign.json()["incident"]["alert_ids"] == [], (
        f"a foreign tenant fused the scope: {foreign.json()['summary']}"
    )
    assert foreign.json()["severity"] == unknown.json()["severity"], (
        "a foreign scope must be indistinguishable from an unknown one"
    )


def test_the_home_tenant_still_fuses_its_own_scope(api_client: TestClient) -> None:
    """The control. Without it, the assertion above is satisfied by fusion being switched off."""
    resp = api_client.post("/v1/fuse", json=_fuse_body(), headers={"X-Dev-Persona": "analyst"})
    assert resp.status_code == 200
    assert len(resp.json()["incident"]["alert_ids"]) == 5


def test_unknown_persona_is_401(api_client: TestClient) -> None:
    resp = api_client.post(
        "/v1/fuse",
        json=_fuse_body(sample_cases.ROUTINE_CASE),
        headers={"X-Dev-Persona": "ghost"},
    )
    assert resp.status_code == 401


def test_healthz_reports_profile_and_region(api_client: TestClient) -> None:
    body = api_client.get("/healthz").json()
    assert body["status"] == "ok"
    assert body["profile"] == "local"
    assert body["region"] == "asia-southeast1"


def test_security_headers_present(api_client: TestClient) -> None:
    headers = api_client.get("/healthz").headers
    assert headers["Content-Security-Policy"] == "frame-ancestors 'self'"
    assert headers["X-Content-Type-Options"] == "nosniff"


@pytest.fixture()
def token_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv(_TOKEN_ENV, "s3cret-service-token")
    yield "s3cret-service-token"


def test_s2s_endpoint_open_when_secret_unset(
    api_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    assert api_client.post("/v1/audit/ping").status_code == 200


def test_s2s_endpoint_rejects_missing_token_when_enforced(
    api_client: TestClient, token_env: str
) -> None:
    assert api_client.post("/v1/audit/ping").status_code == 401


def test_s2s_endpoint_accepts_correct_token(api_client: TestClient, token_env: str) -> None:
    resp = api_client.post("/v1/audit/ping", headers={"Authorization": f"Bearer {token_env}"})
    assert resp.status_code == 200
