"""GCP SafetyPort: Model Armor screening (SDK imports stay lazy).

Implements :class:`SafetyPort` against Model Armor, the runtime AI-safety service of the Gemini
Enterprise Agent Platform. Inbound text is screened with ``:sanitizeUserPrompt`` and outbound
model text with ``:sanitizeModelResponse`` on the regional endpoint, so screening stays inside
the residency boundary. The request is BLOCKED when any filter reports a match.

All HTTP / auth SDK imports are lazy (inside :meth:`screen`) so the ``local``/``onprem`` profiles
import this module with no GCP SDK installed.
"""

from __future__ import annotations

from typing import Any

from ...config import Settings
from ...domain.models import Direction, SafetyVerdict

_MATCH_FOUND = "MATCH_FOUND"


class ModelArmorSafetyAdapter:
    """Screen text through Model Armor's REST API and return an allow/block verdict."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def screen(self, text: str, direction: Direction) -> SafetyVerdict:  # pragma: no cover
        # google-auth is imported FIRST so the offline profile refuses here (ImportError) rather
        # than reaching the network: a safety screen that silently no-ops is the worst failure.
        import google.auth  # noqa: PLC0415 - lazy
        import httpx  # noqa: PLC0415 - lazy
        from google.auth.transport.requests import Request  # noqa: PLC0415 - lazy

        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        credentials.refresh(Request())
        verb = "sanitizeUserPrompt" if direction is Direction.INPUT else "sanitizeModelResponse"
        host = f"modelarmor.{self._settings.region}.rep.googleapis.com"
        url = (
            f"https://{host}/v1/projects/{self._settings.project_id}"
            f"/locations/{self._settings.region}"
            f"/templates/{self._settings.model_armor_template}:{verb}"
        )
        payload = (
            {"userPromptData": {"text": text}}
            if direction is Direction.INPUT
            else {"modelResponseData": {"text": text}}
        )
        response = httpx.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {credentials.token}"},
            timeout=30.0,
        )
        response.raise_for_status()
        return self._parse(response.json(), direction)

    @staticmethod
    def _parse(response: dict[str, Any], direction: Direction) -> SafetyVerdict:
        result = response.get("sanitizationResult", {}) or {}
        filters = result.get("filterResults", {}) or {}
        matched = tuple(
            sorted(
                name
                for name, node in filters.items()
                if isinstance(node, dict) and _MATCH_FOUND in str(node)
            )
        )
        allowed = result.get("filterMatchState") != _MATCH_FOUND
        reason = "No blocking Model Armor filter matched." if allowed else "Blocked by Model Armor."
        return SafetyVerdict(
            allowed=allowed, direction=direction, reason=reason, categories=matched
        )
