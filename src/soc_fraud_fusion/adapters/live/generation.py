"""Live GenerationPort: narration from a local open-weight model (the laptop ``live`` profile).

Calls the fleet's shared local model server through ``hex_service_kit.localmodel``, the one
client every laptop ``live`` profile uses: ``LOCAL_MODEL_URL`` / ``LOCAL_MODEL`` /
``LOCAL_MODEL_TIMEOUT``, read in three states by the kit. The prompt carries ONLY the
engine-owned incident facts, the retrieved passages and the grounding verdicts, exactly the
material the Gemini adapter is given, and the orchestrator validates the returned draft against
those facts and discards it on failure, so a hallucinated figure never survives here either.

The port request carries no response schema, so this adapter states the draft's shape itself
and asks for JSON: a local server enforces no schema, and the kit validates the answer, feeds a
problem back and retries, instead of this adapter guessing where a free-text runbook starts.
The request's temperature is passed through: narration leaves it ``None``, so none is sent and
the server samples as it does, which is what the Gemini adapter does too. The kit client notes
the model that answered for the console's model pill itself.
"""

from __future__ import annotations

import logging
from typing import Any

from hex_service_kit.localmodel import (
    LocalModelClient,
    LocalModelOutputError,
    LocalModelSettings,
    LocalModelUnavailable,
)

from ...config import Settings
from ...domain.models import NarrationDraft, NarrationRequest
from ...ports.generation import GenerationUnavailableError

_log = logging.getLogger(__name__)

#: The draft's shape. ``cited_ids`` is not asked for: it is derived from the request, as the
#: Gemini adapter derives it, so the model cannot cite a source it was never given.
DRAFT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "narrative": {"type": "string", "minLength": 1},
        "runbook": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
            "minItems": 1,
        },
    },
    "required": ["narrative", "runbook"],
}

_SYSTEM = (
    "You are a SOC analyst. Summarise the incident and draft a response runbook using ONLY the "
    "facts given. Do not invent any figure, technique, indicator or source. The narrative is a "
    "short paragraph; the runbook is one concrete response step per entry, citing the source id "
    "in square brackets where a step comes from a passage or an indicator verdict."
)


class LocalModelGeneration:
    """Draft a cited incident summary and runbook through the shared local model client."""

    def __init__(self, settings: Settings, *, client: LocalModelClient | None = None) -> None:
        self._settings = settings
        self._client = client or LocalModelClient(LocalModelSettings.from_env())

    def narrate(self, request: NarrationRequest) -> NarrationDraft:
        messages = [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": self._facts(request)},
        ]
        try:
            completion = self._client.complete_json(
                messages, schema=DRAFT_SCHEMA, temperature=request.temperature
            )
        except LocalModelUnavailable as exc:
            raise GenerationUnavailableError(str(exc), http_status=503) from exc
        except LocalModelOutputError as exc:
            raise GenerationUnavailableError(str(exc), http_status=502) from exc
        _log.info("narration drafted by %s in %d attempt(s)", completion.model, completion.attempts)
        data = completion.data
        cited_ids = (
            *(hit.technique_id for hit in request.incident.techniques),
            *(p.source_id for p in request.passages),
            *(g.citation.source_id for g in request.grounding),
        )
        return NarrationDraft(
            narrative=str(data["narrative"]).strip(),
            runbook=tuple(str(step).strip() for step in data["runbook"]),
            cited_ids=cited_ids,
        )

    @staticmethod
    def _facts(request: NarrationRequest) -> str:
        incident = request.incident
        techniques = "; ".join(f"{h.technique_id} {h.name}" for h in incident.techniques)
        passages = "\n".join(f"[{p.source_id}] {p.title}: {p.snippet}" for p in request.passages)
        verdicts = "\n".join(
            f"[{g.citation.source_id}] indicator {g.indicator} is {g.verdict}"
            for g in request.grounding
        )
        return (
            f"Incident: {incident.incident_id} subject {incident.subject} "
            f"severity {incident.severity.value} score {incident.score}.\n"
            f"Recommended action (subject to human review): "
            f"{incident.recommended_action.value}.\n"
            f"Techniques: {techniques or 'none mapped'}.\n"
            f"Runbook passages:\n{passages or '(none retrieved)'}\n"
            f"Indicator verdicts:\n{verdicts or '(none)'}"
        )
