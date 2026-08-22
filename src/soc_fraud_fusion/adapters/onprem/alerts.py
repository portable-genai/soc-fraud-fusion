"""On-prem AlertFeedPort: fail-fast portability placeholder (the sovereign-exit proof, P-12).

The client runs its own SIEM / fraud-alert store, so this binding refuses at call time rather
than inventing rows. Refusing is the correct failure: a feed that silently returned nothing would
correlate every incident down to LOW and hide real activity.
"""

from __future__ import annotations

from ...config import Settings
from ...domain.models import Alert


class OnPremAlertFeed:
    """Satisfies AlertFeedPort but refuses: the client binds its own alert store."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def fetch(self, scope: str, *, tenant: str) -> list[Alert]:
        raise NotImplementedError(
            "on-prem alert intake is a portability placeholder: bind the client's own SIEM / "
            "fraud-alert store (see docs/onprem-migration.md)."
        )
