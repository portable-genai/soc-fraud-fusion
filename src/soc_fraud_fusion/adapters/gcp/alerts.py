"""GCP AlertFeedPort: a BigQuery alert table reader (SDK imports stay lazy).

The ``google-cloud-bigquery`` import lives inside :meth:`fetch`, so the ``local``/``onprem``
profiles import this module with no GCP SDK installed (the portability proof). The query is
pinned to the residency region and returns raw cited rows only; correlation and scoring stay in
the pure engine.

**The tenant predicate is the authorisation, and it was missing.** This adapter took the
verified principal's tenant as an argument and never used it: the statement was
``SELECT * FROM alerts WHERE scope = @scope``, so every tenant's alerts in a scope reached
whoever asked, on the profile that faces real users. The local adapter has always matched each
row's data tag against the principal and returned nothing else, and its docstring states the
fail-closed reading of an untagged row, so object-level authorization existed in one profile and
not in the other and no offline test could see the difference. The predicate is here now, an
empty tenant reads nothing rather than everything, and ``SELECT *`` is gone: the columns are
declared so a contract test can hold them against the Terraform that creates the table.
"""

from __future__ import annotations

from ... import demo_book
from ...config import Settings
from ...domain.models import Alert

#: The READ SET: every column this adapter names, in the SELECT list or the WHERE clause.
#: Declared rather than left inside a ``SELECT *`` because a read set no test can see is one
#: that drifts from the schema silently, and a sibling repository shipped a schema its own
#: adapter could not query for exactly that reason.
SELECTED_COLUMNS: dict[str, tuple[str, ...]] = {"alerts": demo_book.ALERTS.columns}

_ALERTS_SQL = """
SELECT {columns}
FROM `{table}`
WHERE scope = @scope AND tenant = @tenant
ORDER BY observed_at
"""


class BigQueryAlertFeed:
    """Read raw alert rows from a residency-pinned BigQuery table, scoped to one tenant."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def fetch(self, scope: str, *, tenant: str) -> list[Alert]:  # pragma: no cover - needs live GCP
        # An empty tenant reads NOTHING rather than everything. The principal is verified before
        # this point, so an empty value here means the identity adapter resolved no tenant, and
        # the fail-closed reading of "we do not know who is asking" is "nothing".
        if not tenant.strip():
            return []
        from google.cloud import bigquery  # noqa: PLC0415 - lazy

        client = bigquery.Client(project=self._settings.project_id or None)
        table = f"{self._settings.bigquery_dataset}.alerts"
        query = _ALERTS_SQL.format(columns=", ".join(SELECTED_COLUMNS["alerts"]), table=table)
        job = client.query(
            query,
            job_config=bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("scope", "STRING", scope),
                    bigquery.ScalarQueryParameter("tenant", "STRING", tenant),
                ],
                default_dataset=self._settings.bigquery_dataset or None,
            ),
        )
        return [demo_book.to_alert(dict(row)) for row in job.result()]
