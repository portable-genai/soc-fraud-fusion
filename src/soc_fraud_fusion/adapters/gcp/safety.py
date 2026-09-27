"""GCP SafetyPort: Model Armor screening (SDK imports stay lazy).

Implements :class:`SafetyPort` against Model Armor, the runtime AI-safety service of the Gemini
Enterprise Agent Platform. Inbound text is screened with ``:sanitizeUserPrompt`` and outbound
model text with ``:sanitizeModelResponse`` on the regional endpoint, so screening stays inside
the residency boundary.

The verdict FAILS CLOSED. Text is allowed ONLY when the response's ``sanitizationResult`` reports
``filterMatchState`` exactly ``NO_MATCH_FOUND`` AND ``invocationResult`` exactly ``SUCCESS``.
Everything else blocks: a match, a missing or empty result, an unspecified state, and a screen
that was ``PARTIAL`` or ``FAILURE``. The last two matter because a filter that was skipped (for
instance a prompt padded past the prompt-injection filter's token limit) reports
``NO_MATCH_FOUND``: that is not a pass, the text was not screened. An HTTP or transport error
propagates to the caller rather than turning into an allow, and every call carries a deadline.

All HTTP / auth SDK imports are lazy (inside the call path) so the ``local``/``onprem`` profiles
import this module with no GCP SDK installed.
"""

from __future__ import annotations

from typing import Any

from ...config import Settings
from ...domain.models import Direction, SafetyVerdict

_MATCH_FOUND = "MATCH_FOUND"
_NO_MATCH_FOUND = "NO_MATCH_FOUND"
_SUCCESS = "SUCCESS"

#: The deadline on every Model Armor call, in seconds. A screen that hangs must not hang the
#: request forever; when it expires the transport raises and the caller sees the error.
_TIMEOUT_SECONDS = 30.0


class ModelArmorSafetyAdapter:
    """Screen text through Model Armor's REST API and return an allow/block verdict."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def screen(self, text: str, direction: Direction) -> SafetyVerdict:
        # Credentials are resolved FIRST so the offline profile refuses here (ImportError) rather
        # than reaching the network: a safety screen that silently no-ops is the worst failure.
        token = self._access_token()
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
        return self._parse(self._post(url, payload, token), direction)

    @staticmethod
    def _access_token() -> str:  # pragma: no cover - needs Application Default Credentials
        import google.auth  # noqa: PLC0415 - lazy
        from google.auth.transport.requests import Request  # noqa: PLC0415 - lazy

        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        credentials.refresh(Request())
        return str(credentials.token)

    @staticmethod
    def _post(url: str, payload: dict[str, Any], token: str) -> Any:
        import httpx  # noqa: PLC0415 - lazy

        response = httpx.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _parse(response: Any, direction: Direction) -> SafetyVerdict:
        result = response.get("sanitizationResult") if isinstance(response, dict) else None
        if not isinstance(result, dict):
            result = {}
        filters = result.get("filterResults")
        matched = tuple(
            sorted(
                name
                for name, node in (filters.items() if isinstance(filters, dict) else ())
                if _reports_match(node)
            )
        )
        state = result.get("filterMatchState")
        invocation = result.get("invocationResult")
        # Exact string comparison against the REST enum names, never a substring test:
        # "MATCH_FOUND" is a substring of "NO_MATCH_FOUND".
        if state == _MATCH_FOUND:
            allowed, reason = False, "Blocked by Model Armor: a filter matched."
        elif state == _NO_MATCH_FOUND and invocation == _SUCCESS:
            allowed, reason = True, "No blocking Model Armor filter matched."
        else:
            allowed = False
            reason = (
                "Blocked: Model Armor returned no complete filter decision "
                f"(filterMatchState={state!r}, invocationResult={invocation!r})."
            )
        return SafetyVerdict(
            allowed=allowed, direction=direction, reason=reason, categories=matched
        )


def _reports_match(node: Any) -> bool:
    """True when any ``matchState`` under ``node`` is exactly ``MATCH_FOUND``.

    Model Armor nests per-filter results at different depths (``raiFilterResult.matchState``,
    ``sdpFilterResult.inspectResult.matchState`` ...), so the walk is recursive. This only
    LABELS the verdict's categories; the allow/block decision is the top-level state above.
    """
    if isinstance(node, dict):
        if node.get("matchState") == _MATCH_FOUND:
            return True
        return any(_reports_match(child) for child in node.values())
    if isinstance(node, list):
        return any(_reports_match(child) for child in node)
    return False
