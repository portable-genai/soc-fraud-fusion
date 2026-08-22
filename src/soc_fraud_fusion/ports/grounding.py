"""GroundingPort: IOC and CVE lookups for incident indicators (slice 2).

A separate edge from :mod:`.retrieval`: retrieval grounds narration in runbook prose, grounding
resolves the incident's technical indicators (an IP / hash / domain to a threat-intel verdict, a
CVE id to its record). Advisory to the narration only, never to the score or the band. Primary
GCP adapter uses a grounded lookup with a lazy SDK import; the local adapter serves a fixture
intel set; the on-prem adapter fails fast. Every hit carries its own citation.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..domain.models import GroundingHit


@runtime_checkable
class GroundingPort(Protocol):
    def lookup(self, indicators: tuple[str, ...]) -> list[GroundingHit]:
        """Return cited IOC/CVE grounding for each resolvable indicator (advisory only)."""
        ...
