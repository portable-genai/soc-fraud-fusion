"""GCP AlertFeedPort: a BigQuery alert table reader (SDK imports stay lazy).

The ``google-cloud-bigquery`` import lives inside :meth:`fetch`, so the ``local``/``onprem``
profiles import this module with no GCP SDK installed (the portability proof). The query is
pinned to the residency region and returns raw cited rows only; correlation and scoring stay in
the pure engine.
"""

from __future__ import annotations

from ...config import Settings
from ...domain.kernel import Citation
from ...domain.models import Alert


class BigQueryAlertFeed:
    """Read raw alert rows from a residency-pinned BigQuery table."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def fetch(self, scope: str, *, tenant: str) -> list[Alert]:  # pragma: no cover - needs live GCP
        from google.cloud import bigquery  # noqa: PLC0415 - lazy

        client = bigquery.Client(project=self._settings.project_id or None)
        table = f"{self._settings.bigquery_dataset}.alerts"
        query = f"SELECT * FROM `{table}` WHERE scope = @scope ORDER BY observed_at"  # noqa: S608
        job = client.query(
            query,
            job_config=bigquery.QueryJobConfig(
                query_parameters=[bigquery.ScalarQueryParameter("scope", "STRING", scope)],
                default_dataset=self._settings.bigquery_dataset or None,
            ),
        )
        rows: list[Alert] = []
        for row in job.result():
            rows.append(
                Alert(
                    alert_id=str(row["alert_id"]),
                    source_system=str(row["source_system"]),
                    entity=str(row["entity"]),
                    asset=str(row["asset"]),
                    indicator=str(row.get("indicator") or ""),
                    signal_type=str(row["signal_type"]),
                    observed_at=str(row["observed_at"]),
                    detail=str(row.get("detail") or ""),
                    citation=Citation(
                        source_id=f"alert:{row['alert_id']}",
                        title=f"{row['source_system']} alert",
                        snippet=str(row.get("detail") or ""),
                    ),
                )
            )
        return rows
