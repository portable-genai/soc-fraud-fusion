"""On-prem GroundingPort: fail-fast portability placeholder (the sovereign-exit proof, P-12).

The client resolves indicators against its own threat-intel platform, so this binding refuses at
call time rather than fabricating a verdict.
"""

from __future__ import annotations

from ...config import Settings
from ...domain.models import GroundingHit


class OnPremGrounding:
    """Satisfies GroundingPort but refuses: the client binds its own intel platform."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def lookup(self, indicators: tuple[str, ...]) -> list[GroundingHit]:
        raise NotImplementedError(
            "on-prem grounding is a portability placeholder: bind the client's own IOC / CVE "
            "intel platform (see docs/onprem-migration.md)."
        )
