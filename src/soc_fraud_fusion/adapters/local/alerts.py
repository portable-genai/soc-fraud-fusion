"""Local AlertFeedPort: the shipped alert book, in DuckDB, over the warehouse's schema.

This used to serve an in-process dictionary, and a store that runs no SQL cannot disagree with
the warehouse about anything: the managed adapter had no table to read and no tenant predicate
at all, and a green offline gate could see neither. The store here holds the SAME table in the
SAME column order as ``infra/terraform/bigquery.tf`` and answers the SAME statement the managed
adapter sends, tenant predicate included, so the two can be held against each other.

An unknown scope returns an empty list rather than raising: "no alerts in this scope" is a valid
answer the engine correlates into an empty, LOW incident. A foreign scope comes back empty in
exactly the same way, so the answer discloses nothing about which scopes exist elsewhere. An
untagged row matches nobody, because the fail-closed reading of "we do not know who owns this"
is "not you", and an empty tenant reads nothing rather than everything.
"""

from __future__ import annotations

from hex_service_kit.demobook import DuckDbStore

from ... import demo_book
from ...config import Settings
from ...domain.models import Alert

#: The managed adapter's own statement, in DuckDB's parameter style. Kept beside it on purpose:
#: two stores over one book and one column order can be compared, and a divergence in either is
#: a test failure rather than a surprise on a deployment.
_ALERTS_SQL = f"""
SELECT {", ".join(demo_book.ALERTS.columns)}
FROM alerts
WHERE scope = ? AND tenant = ?
ORDER BY observed_at
"""


class LocalAlertFeed:
    """Serve the shipped alert book from DuckDB for the SDK-free ``local`` profile."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._store = DuckDbStore(demo_book.BOOK, settings.book_path)

    def fetch(self, scope: str, *, tenant: str) -> list[Alert]:
        """Return only the rows whose data tag matches the verified principal's tenant."""
        if not tenant.strip():
            return []
        rows = self._store.connection.execute(_ALERTS_SQL, [scope, tenant]).fetchall()
        columns = demo_book.ALERTS.columns
        return [demo_book.to_alert(dict(zip(columns, row, strict=True))) for row in rows]

    def close(self) -> None:
        self._store.close()
