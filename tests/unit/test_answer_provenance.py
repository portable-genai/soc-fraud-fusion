"""The service half of the model pills: which model ANSWERED, and whether it searched.

The console shows two pills at the top right: the model that answered the last request, and
``Search`` when that answer used an online search tool. Both come from response headers the kit
emits (``install_answer_provenance`` in ``api/app.py``) for whatever the model adapters NOTED as
they called. Before a request is answered the pill shows ``generator_model`` from ``/healthz``,
so that value must be the model the bound adapter calls, never one a configuration flag names
while the adapter calls another.

The Gemini adapters are driven here through a FAKE ``google.genai`` module, so what is proved is
this repository's half: the model id each call notes, and the sampling each call sends
(narration free, so no temperature at all; the indicator verdict lookup pinned at 0.0).
"""

from __future__ import annotations

import dataclasses
import json
import sys
import types
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from hex_service_kit import provenance
from hex_service_kit.localmodel import LocalModelClient, LocalModelSettings

from soc_fraud_fusion import config
from soc_fraud_fusion.adapters.gcp.generation import GeminiGeneration
from soc_fraud_fusion.adapters.gcp.grounding import GroundingSearchAdapter
from soc_fraud_fusion.adapters.live.generation import LocalModelGeneration
from soc_fraud_fusion.adapters.local.generation import STUB_MODEL, LocalGeneration
from soc_fraud_fusion.config import Settings
from soc_fraud_fusion.domain.models import NarrationDraft, NarrationRequest
from soc_fraud_fusion.factory import build_fusion_service

from tests import REPO_ROOT
from tests.conftest import local_settings
from tests.fixtures import sample_cases

ANSWERED_BY = "x-answered-by"
SEARCH_USED = "x-search-used"


def _fuse(api_client: TestClient) -> dict[str, str]:
    case = sample_cases.ESCALATING_CASE
    response = api_client.post(
        "/v1/fuse",
        json={"subject": case.subject, "scope": case.scope},
        headers={"X-Dev-Persona": "analyst"},
    )
    assert response.status_code == 200, response.text
    return dict(response.headers)


def test_the_local_narrator_answers_as_the_stub_the_pill_first_names(
    api_client: TestClient,
) -> None:
    """Under ``local`` the pill before and after the answer name the same stub."""
    headers = _fuse(api_client)
    assert headers[ANSWERED_BY] == STUB_MODEL
    assert local_settings().generator_model == STUB_MODEL
    assert SEARCH_USED not in headers


def test_a_call_that_searched_says_so_and_the_next_request_starts_fresh(
    api_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = LocalGeneration.narrate

    def searching(self: LocalGeneration, request: NarrationRequest) -> NarrationDraft:
        provenance.note_model("fake-searching-model")
        provenance.note_search()
        return original(self, request)

    monkeypatch.setattr(LocalGeneration, "narrate", searching)
    headers = _fuse(api_client)
    assert headers[ANSWERED_BY] == f"fake-searching-model, {STUB_MODEL}"
    assert headers[SEARCH_USED] == "true"
    monkeypatch.setattr(LocalGeneration, "narrate", original)
    headers = _fuse(api_client)
    assert headers[ANSWERED_BY] == STUB_MODEL
    assert SEARCH_USED not in headers


# --------------------------------------------------------------------------------------- #
# The Gemini adapters, through a fake SDK.
# --------------------------------------------------------------------------------------- #
class _FakeModels:
    def __init__(self, text: str) -> None:
        self.calls: list[dict[str, Any]] = []
        self._text = text

    def generate_content(self, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        return SimpleNamespace(text=self._text)


def _fake_genai(monkeypatch: pytest.MonkeyPatch, text: str) -> _FakeModels:
    models = _FakeModels(text)
    genai = types.ModuleType("google.genai")
    genai_types = types.ModuleType("google.genai.types")
    genai_types.GenerateContentConfig = lambda **kw: SimpleNamespace(**kw)  # type: ignore[attr-defined]
    genai.types = genai_types  # type: ignore[attr-defined]
    genai.Client = lambda **_: SimpleNamespace(models=models)  # type: ignore[attr-defined]
    google = sys.modules.get("google") or types.ModuleType("google")
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setattr(google, "genai", genai, raising=False)
    monkeypatch.setitem(sys.modules, "google.genai", genai)
    monkeypatch.setitem(sys.modules, "google.genai.types", genai_types)
    return models


def _gcp_settings() -> Settings:
    return dataclasses.replace(local_settings(), profile="gcp")


def _request() -> NarrationRequest:
    service = build_fusion_service(config.build_container(local_settings()))
    incident = service._engine.correlate(  # noqa: SLF001 - the engine's own output
        tuple(
            service._alerts.fetch(  # noqa: SLF001
                sample_cases.ESCALATING_CASE.scope, tenant=sample_cases.TENANT
            )
        ),
        subject=sample_cases.ESCALATING_CASE.subject,
        as_of=sample_cases.AS_OF,
    )
    return NarrationRequest(incident=incident)


def test_the_gemini_narrator_notes_its_model_and_drafts_with_no_temperature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    models = _fake_genai(monkeypatch, "A drafted summary.\nRUNBOOK:\n- contain")
    settings = _gcp_settings()
    with provenance.scope() as record:
        GeminiGeneration(settings).narrate(_request())
    assert record.models == [settings.generation_model]
    assert record.search_used is False
    (call,) = models.calls
    assert call["model"] == settings.generation_model
    assert call["config"] is None, "narration is drafting: free sampling sends no temperature"


def test_a_pinned_request_reaches_the_gemini_config(monkeypatch: pytest.MonkeyPatch) -> None:
    models = _fake_genai(monkeypatch, "text")
    GeminiGeneration(_gcp_settings()).narrate(dataclasses.replace(_request(), temperature=0.0))
    assert models.calls[0]["config"].temperature == 0.0


def test_the_verdict_lookup_is_pinned_and_notes_its_model_but_no_search(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No online search tool is attached to the lookup, so it must never claim a search."""
    models = _fake_genai(monkeypatch, "malicious")
    settings = _gcp_settings()
    with provenance.scope() as record:
        GroundingSearchAdapter(settings).lookup(("198.51.100.7", "203.0.113.9"))
    assert record.models == [settings.generation_model]
    assert record.search_used is False
    assert [call["config"].temperature for call in models.calls] == [0.0, 0.0]
    assert all("tools" not in vars(call["config"]) for call in models.calls)


def test_the_live_narrator_sends_no_temperature_and_the_kit_notes_the_model() -> None:
    bodies: list[dict[str, Any]] = []
    draft = json.dumps({"narrative": "Summary.", "runbook": ["Contain."]})

    def transport(url: str, body: bytes | None, timeout: float) -> bytes:
        assert body is not None
        bodies.append(json.loads(body))
        return json.dumps(
            {"model": "a-local-model", "choices": [{"message": {"content": draft}}], "usage": {}}
        ).encode()

    client = LocalModelClient(LocalModelSettings(), transport=transport)
    with provenance.scope() as record:
        LocalModelGeneration(local_settings(), client=client).narrate(_request())
    assert "temperature" not in bodies[0]
    assert record.models == ["a-local-model"]


# --------------------------------------------------------------------------------------- #
# generator_model is the model the adapter calls.
# --------------------------------------------------------------------------------------- #
def test_generator_model_is_the_setting_the_gemini_adapters_read() -> None:
    settings = _gcp_settings()
    assert settings.generator_model == settings.generation_model


def test_no_flag_swaps_in_a_model_the_adapter_never_calls() -> None:
    """The latent false banner: a flag that moved the pill but not the model that answered."""
    models = SimpleNamespace(
        reasoning="the-model-the-adapter-calls",
        hard_reasoning="a-model-nobody-calls",
        use_hard_reasoning=True,
    )
    named = config._model_from_settings(SimpleNamespace(models=models), "models.reasoning")
    assert named == "the-model-the-adapter-calls"


def test_the_hard_reasoning_flag_does_not_exist() -> None:
    settings_file = (REPO_ROOT / "config" / "settings.yaml").read_text(encoding="utf-8")
    assert "use_hard_reasoning" not in settings_file
    for source in sorted((REPO_ROOT / "src").rglob("*.py")):
        assert "use_hard_reasoning" not in source.read_text(encoding="utf-8"), source
