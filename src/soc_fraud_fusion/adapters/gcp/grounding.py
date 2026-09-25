"""GCP GroundingPort: IOC / CVE resolution via a grounded lookup (SDK imports stay lazy).

The ``google`` GenAI import lives inside :meth:`lookup`, so the ``local``/``onprem`` profiles
import this module with no GCP SDK installed. Grounding is advisory to narration only, never to
the score or the band.
"""

from __future__ import annotations

from hex_service_kit import provenance

from ...config import Settings
from ...domain.kernel import Citation
from ...domain.models import GroundingHit, GroundingKind


class GroundingSearchAdapter:
    """Resolve indicators to cited IOC / CVE verdicts through a grounded model call."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def lookup(self, indicators: tuple[str, ...]) -> list[GroundingHit]:  # pragma: no cover
        from google import genai  # noqa: PLC0415 - lazy
        from google.genai import types  # noqa: PLC0415 - lazy

        client = genai.Client(vertexai=True, location=self._settings.region)
        model = self._settings.generation_model
        # A verdict is a classification that is cited and compared, so this call is PINNED.
        # No online search tool is attached to it, so it notes the model and never a search.
        config = types.GenerateContentConfig(temperature=0.0)
        out: list[GroundingHit] = []
        for indicator in indicators:
            response = client.models.generate_content(
                model=model,
                contents=f"Resolve the threat-intel verdict for indicator {indicator}.",
                config=config,
            )
            provenance.note_model(model)
            out.append(
                GroundingHit(
                    indicator=indicator,
                    kind=GroundingKind.IOC,
                    verdict=str(getattr(response, "text", "")),
                    citation=Citation(
                        source_id=f"intel:{indicator}",
                        title="Grounded threat-intel lookup",
                        snippet=str(getattr(response, "text", "")),
                    ),
                )
            )
        return out
