"""Local AlertFeedPort: deterministic fictional alert rows, no SDK, no network.

Serves the fixture alerts keyed by scope. An unknown scope returns an empty list rather than
raising: "no alerts in this scope" is a valid answer the engine correlates into an empty, LOW
incident. The rows are byte-identical on every call, which is what makes the demo and the gate
replayable.
"""

from __future__ import annotations

from ...config import Settings
from ...domain.models import Alert
from ._fixtures import ALERTS


class LocalAlertFeed:
    """Return fixture alert rows for the SDK-free ``local`` profile."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def fetch(self, scope: str, *, tenant: str) -> list[Alert]:
        """Return only the rows whose data tag matches the verified principal's tenant.

        A foreign scope comes back empty, exactly as an unknown one does, so the answer discloses
        nothing about which scopes exist elsewhere. An untagged row matches nobody: the
        fail-closed reading of "we do not know who owns this" is "not you".
        """
        return [a for a in ALERTS.get(scope, ()) if tenant and a.tenant == tenant]
