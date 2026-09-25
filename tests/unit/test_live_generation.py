"""The laptop ``live`` profile: a local open-weight model narrates, everything else is ``local``.

Offline, like the rest of the gate. The adapter is driven through the shared kit client with a
FAKE transport (``LocalModelClient(settings, transport=fake)``), so what is proved here is this
repository's half of the contract: the messages it builds, the schema it asks for, how a draft
is mapped back, and how an unreachable or unusable model reaches the API. The kit's own suite
owns the parsing and retry mechanics; the retry case below proves this adapter lets them run.
"""

from __future__ import annotations

import json
import urllib.error
from types import ModuleType
from typing import Any

import pytest
from fastapi.testclient import TestClient
from hex_service_kit.localmodel import (
    DEFAULT_LOCAL_MODEL,
    START_RECIPE,
    LocalModelClient,
    LocalModelSettings,
)

from soc_fraud_fusion.adapters.live.generation import DRAFT_SCHEMA, LocalModelGeneration
from soc_fraud_fusion.adapters.local.generation import LocalGeneration
from soc_fraud_fusion.config import (
    DEFAULT_BINDINGS,
    LIVE_PROFILE,
    LOCAL_PROFILE,
    Container,
    Settings,
    build_container,
)
from soc_fraud_fusion.factory import build_fusion_service
from soc_fraud_fusion.ports import PORT_PROTOCOLS
from soc_fraud_fusion.ports.generation import GenerationUnavailableError

from tests.conftest import LOOPBACK_PEER, local_settings, reimport
from tests.fixtures import sample_cases

_MODEL_ID = "mlx-community/gemma-4-31b-it-8bit"


class _FakeServer:
    """Answers each POST with the next scripted reply and records every request body."""

    def __init__(self, *replies: str) -> None:
        self._replies = list(replies)
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, url: str, body: bytes | None, timeout: float) -> bytes:
        assert body is not None, "the adapter only ever POSTs a chat completion"
        self.bodies.append(json.loads(body))
        content = self._replies.pop(0)
        return json.dumps(
            {"model": _MODEL_ID, "choices": [{"message": {"content": content}}], "usage": {}}
        ).encode()


def _unreachable(url: str, body: bytes | None, timeout: float) -> bytes:
    raise urllib.error.URLError("connection refused")


def _live_settings() -> Settings:
    return local_settings(profile=LIVE_PROFILE)


def _live_container(transport: Any) -> Container:
    settings = _live_settings()
    container = build_container(settings)
    client = LocalModelClient(LocalModelSettings(), transport=transport)
    # A cached_property is read from the instance dict first, so this is the bound adapter.
    container.__dict__["generation"] = LocalModelGeneration(settings, client=client)
    return container


def _fuse(container: Container) -> Any:
    return build_fusion_service(container).fuse(
        sample_cases.ESCALATING_CASE, actor=sample_cases.ACTOR, tenant=sample_cases.TENANT
    )


# --------------------------------------------------------------------------------------- #
# The binding: every port binds under live, and only generation differs from local.
# --------------------------------------------------------------------------------------- #
def test_the_container_builds_every_port_under_the_live_profile() -> None:
    container = build_container(_live_settings())
    for port, protocol in PORT_PROTOCOLS.items():
        assert isinstance(getattr(container, port), protocol), port
    assert isinstance(container.generation, LocalModelGeneration)


def test_live_binds_what_local_binds_except_the_model_port() -> None:
    differing = {
        port
        for port, table in DEFAULT_BINDINGS.items()
        if table[LIVE_PROFILE] != table[LOCAL_PROFILE]
    }
    assert differing == {"generation"}


def test_the_banner_names_the_local_model_under_live(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LOCAL_MODEL", raising=False)
    settings = _live_settings()
    assert settings.runtime == "local"
    assert settings.generator_model == DEFAULT_LOCAL_MODEL
    monkeypatch.setenv("LOCAL_MODEL", "some-other/model")
    assert settings.generator_model == "some-other/model"


def test_a_live_profile_rebound_to_the_stub_does_not_name_a_model() -> None:
    rebound = {port: dict(table) for port, table in DEFAULT_BINDINGS.items()}
    rebound["generation"][LIVE_PROFILE] = DEFAULT_BINDINGS["generation"][LOCAL_PROFILE]
    settings = local_settings(profile=LIVE_PROFILE, adapters=rebound)
    assert settings.generator_model == "deterministic-offline-stub"
    assert isinstance(build_container(settings).generation, LocalGeneration)


# --------------------------------------------------------------------------------------- #
# The adapter, through the shared kit client.
# --------------------------------------------------------------------------------------- #
def test_an_invalid_first_answer_is_fed_back_and_the_fenced_retry_is_used() -> None:
    good = {
        "narrative": "Account takeover on user:acme-treasury, escalated for human review.",
        "runbook": ["Revoke active sessions [RB-ATO-01].", "Hold outbound payments."],
    }
    server = _FakeServer(
        "Here is the summary: the account was taken over.",
        "```json\n" + json.dumps(good) + "\n```",
    )
    result = _fuse(_live_container(server))

    assert len(server.bodies) == 2, "the unusable first answer must be retried, once"
    first, retry = server.bodies
    system = first["messages"][0]
    assert system["role"] == "system" and '"narrative"' in system["content"], "schema is stated"
    assert "temperature" not in first, "the request carries none, so none is sent"
    facts = first["messages"][1]["content"]
    assert result.incident.incident_id in facts and f"score {result.incident.score}" in facts
    assert (
        retry["messages"][-1]["role"] == "user" and "not usable" in retry["messages"][-1]["content"]
    )

    assert result.narrative == good["narrative"]
    assert result.runbook == tuple(good["runbook"])


def test_a_draft_that_restates_a_foreign_figure_is_still_discarded_by_the_orchestrator() -> None:
    lying = {"narrative": "Incident at score 999 mapped to T9999.", "runbook": ["Do nothing."]}
    result = _fuse(_live_container(_FakeServer(json.dumps(lying))))
    assert "999" not in result.narrative
    assert f"score {result.incident.score}" in result.narrative


def test_the_draft_shape_asks_for_nothing_the_request_already_decides() -> None:
    assert set(DRAFT_SCHEMA["required"]) == {"narrative", "runbook"}
    assert "cited_ids" not in DRAFT_SCHEMA["properties"]


def test_an_unreachable_model_is_a_503_carrying_the_start_recipe() -> None:
    with pytest.raises(GenerationUnavailableError) as caught:
        _fuse(_live_container(_unreachable))
    assert caught.value.http_status == 503
    assert START_RECIPE in str(caught.value)


def test_a_model_that_never_answers_usably_is_a_502() -> None:
    server = _FakeServer("no json", "still none", "nope")
    with pytest.raises(GenerationUnavailableError) as caught:
        _fuse(_live_container(server))
    assert caught.value.http_status == 502
    assert len(server.bodies) == 3


# --------------------------------------------------------------------------------------- #
# The serving path: the laptop posture, and the model failure as an HTTP answer.
# --------------------------------------------------------------------------------------- #
@pytest.fixture()
def live_app(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.setenv("FRAUDFUSION_PROFILE", LIVE_PROFILE)
    # Port 9 (discard) on loopback: refused at once, so the test stays offline and fast.
    monkeypatch.setenv("LOCAL_MODEL_URL", "http://127.0.0.1:9/chat/completions")
    monkeypatch.delenv("FRAUDFUSION_ALLOW_INSECURE_DEMO", raising=False)
    return reimport("soc_fraud_fusion.api.app")


def test_live_serves_with_the_local_laptop_posture(live_app: ModuleType) -> None:
    with TestClient(live_app.app, client=LOOPBACK_PEER) as client:
        health = client.get("/healthz").json()
        assert (health["profile"], health["runtime"]) == (LIVE_PROFILE, "local")
        assert client.get("/openapi.json").status_code == 200, "docs are a laptop relaxation"
        assert client.get("/v1/personas").json(), "seeded personas serve under live"


def test_live_with_no_model_server_answers_503_with_the_recipe(live_app: ModuleType) -> None:
    with TestClient(live_app.app, client=LOOPBACK_PEER) as client:
        resp = client.post(
            "/v1/fuse",
            json={"subject": "user:acme-treasury", "scope": "ato-acme"},
            headers={"X-Dev-Persona": "analyst"},
        )
    assert resp.status_code == 503
    assert "mlx_vlm.server" in resp.json()["detail"]
