"""Local GroundingPort: deterministic fixture IOC / CVE resolution, no SDK, no network.

Resolves each indicator against the fixture intel set and returns a cited hit for every match.
An unresolved indicator simply produces no hit (grounding is advisory), so the set of hits is a
pure function of the indicators passed in.
"""

from __future__ import annotations

from ...config import Settings
from ...domain.models import GroundingHit
from ._fixtures import INTEL


class LocalGrounding:
    """Resolve indicators against a fixture threat-intel set for the ``local`` profile."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def lookup(self, indicators: tuple[str, ...]) -> list[GroundingHit]:
        seen: set[str] = set()
        out: list[GroundingHit] = []
        for indicator in indicators:
            if indicator in seen:
                continue
            seen.add(indicator)
            hit = INTEL.get(indicator)
            if hit is not None:
                out.append(hit)
        return out
