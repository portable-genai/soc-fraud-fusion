"""The shipped demo book: fictional alert rows, served the same way on both sides.

The rows live as newline-delimited JSON under ``soc_fraud_fusion/data/demo_book/``, one file
per BigQuery table and in that table's column order, so one set of files feeds the DuckDB store
the offline profiles read, the loader that fills the managed dataset, the fixture map the demo
and the eval read, and the tests. The reading, the overwrite guard and the tenant rule come from
:mod:`hex_service_kit.demobook`; what is here is about THIS system.

**The managed adapter had no dataset and no tenant filter.** Two things, and the second is the
one that matters. Nothing in ``infra/terraform/`` created the alert table the adapter queries,
so the ``gcp`` profile would have failed at the first request with a not-found. Underneath that,
the query was ``SELECT * FROM alerts WHERE scope = @scope``: it took the verified principal's
tenant as an argument and never used it, while the local adapter has always matched each row's
data tag against that principal and returned nothing else. Object-level authorization was
therefore present in one profile and absent in the other, on the profile that faces real users,
and no offline test could see it because the offline family does the right thing. The book ships
a SECOND tenant's alert inside a scope this tenant also uses, so the filter has something to
exclude and the guard has something to fail against.

Everything is fictional. See ``data/demo_book/README.md``.
"""

from __future__ import annotations

from typing import Any

from hex_service_kit.demobook import BookError, NdjsonBook, Table

from .domain.kernel import Citation
from .domain.models import Alert

#: The tenant the shipped alerts belong to, and the one other tenant the filter must exclude.
SHIPPED_TENANT = "demo-bank"
OTHER_TENANT = "other-bank"

#: Rows the loader must NOT fold into the deployment's tenant. The foreign alert exists so the
#: object-level authorization check has a row to withhold; stamping it with the hosted domain
#: would hand it to every principal and delete the only evidence the filter does anything.
CROSS_TENANT: dict[str, str] = {"A-9001": "-other"}

ALERTS = Table(
    name="alerts",
    columns=(
        "alert_id",
        "tenant",
        "scope",
        "source_system",
        "entity",
        "asset",
        "indicator",
        "signal_type",
        "observed_at",
        "detail",
    ),
    types={
        "alert_id": "TEXT NOT NULL",
        "tenant": "TEXT NOT NULL",
        "scope": "TEXT NOT NULL",
        "source_system": "TEXT NOT NULL",
        "entity": "TEXT NOT NULL",
        "asset": "TEXT NOT NULL",
        "indicator": "TEXT",
        "signal_type": "TEXT NOT NULL",
        "observed_at": "TEXT NOT NULL",
        "detail": "TEXT",
    },
    primary_key=("alert_id",),
)

TABLES = (ALERTS,)

BOOK = NdjsonBook("soc_fraud_fusion.data.demo_book", TABLES)


def validate() -> None:
    """The book's own invariants, on top of the shape the kit checks.

    The tenant rules are the load-bearing ones. An untagged row belongs to nobody and no
    principal may read it, so a blank tag is a row the fail-closed reading would silently drop
    rather than an oversight anyone would notice. And a book with one tenant cannot demonstrate
    a tenant filter at all: every row matches whoever asks, which is exactly the state that let
    the managed adapter ship without one.
    """
    BOOK.validate()
    rows = BOOK.rows("alerts")
    if not rows:
        raise BookError("the book ships no alerts")

    seen: set[str] = set()
    for row in rows:
        where = str(row["alert_id"])
        if where in seen:
            raise BookError(f"alert {where} appears twice; correlation would double-count it")
        seen.add(where)
        if not str(row["tenant"]).strip():
            raise BookError(
                f"alert {where} carries no tenant. An untagged row belongs to nobody and the "
                "fail-closed reading drops it, so it would vanish from the demo silently."
            )
        for column in ("scope", "signal_type", "observed_at", "source_system", "entity"):
            if not str(row[column]).strip():
                raise BookError(f"alert {where} has no {column}")

    tenants = {str(row["tenant"]) for row in rows}
    if OTHER_TENANT not in tenants:
        raise BookError(
            f"no alert belongs to {OTHER_TENANT!r}. With one tenant in the book every row "
            "matches whoever asks, and a missing tenant filter looks exactly like a working "
            "one. That is how the managed adapter shipped without one."
        )
    shared = {str(row["scope"]) for row in rows if str(row["tenant"]) == OTHER_TENANT} & {
        str(row["scope"]) for row in rows if str(row["tenant"]) == SHIPPED_TENANT
    }
    if not shared:
        raise BookError(
            "the two tenants share no scope, so a query filtered only by scope would return "
            "nothing foreign anyway and the tenant filter would still be untested"
        )


def to_alert(row: dict[str, Any]) -> Alert:
    """One warehouse row as the engine's alert, citation and data tag intact."""
    alert_id = str(row["alert_id"])
    detail = str(row.get("detail") or "")
    return Alert(
        alert_id=alert_id,
        source_system=str(row["source_system"]),
        entity=str(row["entity"]),
        asset=str(row["asset"]),
        indicator=str(row.get("indicator") or ""),
        signal_type=str(row["signal_type"]),
        observed_at=str(row["observed_at"]),
        detail=detail,
        citation=Citation(
            source_id=f"alert:{alert_id}",
            title=f"{row['source_system']} alert",
            snippet=detail,
        ),
        tenant=str(row["tenant"]),
    )
