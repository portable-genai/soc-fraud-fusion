"""The demo book: one alert intake, served the same way on the laptop and the deployment.

Pinned here, and each was watched failing first:

* **the managed adapter ignored the tenant it was given.** ``fetch`` takes the VERIFIED
  principal's tenant and the statement was ``SELECT * FROM alerts WHERE scope = @scope``, so
  every tenant's alerts in a scope reached whoever asked, on the profile that faces real users.
  The local adapter has always matched each row's data tag against the principal, so object-level
  authorization existed in one profile and not the other, and no offline test could see it
  because the offline family does the right thing. The book now ships a foreign alert inside a
  scope this tenant also uses, which is what gives the guard below something to fail against;
* **the dataset did not exist.** No file in ``infra/terraform/`` created it, and unlike the
  sibling repository that shipped the same gap, not even the API was enabled and no IAM role
  named BigQuery. The adapter referred to a store with no existence anywhere in the deployment;
* the adapter's read set is declared instead of hidden inside ``SELECT *``, every column in it is
  one the Terraform declares, and the book ships exactly those columns;
* the set held against the Terraform is ``load_order()`` -- the set the LOADER writes, which
  includes the manifest -- rather than the repository's own ``TABLES``.
"""

from __future__ import annotations

import dataclasses
import re

import pytest

from soc_fraud_fusion import demo_book
from soc_fraud_fusion.adapters.gcp import alerts as managed
from soc_fraud_fusion.adapters.local.alerts import LocalAlertFeed
from soc_fraud_fusion.config import Settings

from tests import REPO_ROOT
from tests.fixtures import sample_cases

_TF = REPO_ROOT / "infra" / "terraform" / "bigquery.tf"

#: The scope both tenants use. A scope is a label, not an entitlement.
_SHARED_SCOPE = "ato-acme"


def _settings() -> Settings:
    return dataclasses.replace(
        Settings.load(), profile="local", audit_path=":memory:", book_path=":memory:"
    )


@pytest.fixture
def feed() -> LocalAlertFeed:
    adapter = LocalAlertFeed(_settings())
    yield adapter
    adapter.close()


# --------------------------------------------------------------------------- #
# The shipped rows
# --------------------------------------------------------------------------- #
def test_the_shipped_book_is_internally_consistent() -> None:
    demo_book.validate()
    assert len(demo_book.BOOK.rows("alerts")) == 13
    assert demo_book.BOOK.manifest()["fictional"] is True


def test_a_book_with_one_tenant_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """One tenant cannot tell a working tenant filter from a missing one."""
    real = demo_book.BOOK.rows

    def one_tenant(name: str):  # type: ignore[no-untyped-def]
        return [row for row in real(name) if row.get("tenant") != demo_book.OTHER_TENANT]

    monkeypatch.setattr(demo_book.BOOK, "rows", one_tenant)
    with pytest.raises(demo_book.BookError, match="matches whoever asks"):
        demo_book.validate()


def test_two_tenants_in_separate_scopes_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without a SHARED scope, a scope-only query returns nothing foreign anyway."""
    real = demo_book.BOOK.rows

    def separated(name: str):  # type: ignore[no-untyped-def]
        return [
            dict(row, scope="somewhere-else")
            if row.get("tenant") == demo_book.OTHER_TENANT
            else row
            for row in real(name)
        ]

    monkeypatch.setattr(demo_book.BOOK, "rows", separated)
    with pytest.raises(demo_book.BookError, match="share no scope"):
        demo_book.validate()


def test_an_untagged_alert_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """An untagged row belongs to nobody, so it would vanish from the demo silently."""
    real = demo_book.BOOK.rows

    def untagged(name: str):  # type: ignore[no-untyped-def]
        rows = real(name)
        return [dict(rows[0], tenant=""), *rows[1:]]

    monkeypatch.setattr(demo_book.BOOK, "rows", untagged)
    with pytest.raises(demo_book.BookError, match="carries no tenant"):
        demo_book.validate()


def test_a_duplicated_alert_id_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    real = demo_book.BOOK.rows

    def duplicated(name: str):  # type: ignore[no-untyped-def]
        rows = real(name)
        return [rows[0], *rows] if name == "alerts" else rows

    monkeypatch.setattr(demo_book.BOOK, "rows", duplicated)
    with pytest.raises(demo_book.BookError, match="appears twice"):
        demo_book.validate()


# --------------------------------------------------------------------------- #
# The managed schema, which did not exist
# --------------------------------------------------------------------------- #
def _terraform_tables() -> dict[str, set[str]]:
    assert _TF.exists(), (
        "infra/terraform/bigquery.tf is missing. The adapter queries a dataset and a table; "
        "without this file nothing creates them and the managed profile fails at the first "
        "request."
    )
    text = _TF.read_text(encoding="utf-8")
    blocks = re.findall(
        r'resource\s+"google_bigquery_table"\s+"\w+"\s*\{(.*?)\n\}', text, flags=re.DOTALL
    )
    assert blocks, "no google_bigquery_table blocks found; the regex or the file moved"
    out: dict[str, set[str]] = {}
    for block in blocks:
        table_id = re.search(r'table_id\s*=\s*"(\w+)"', block)
        assert table_id is not None
        out[table_id.group(1)] = set(re.findall(r'name\s*=\s*"(\w+)"', block))
    return out


def test_the_dataset_the_settings_name_is_actually_created() -> None:
    """Nothing created it, no API enabled it, and no IAM role named it."""
    text = _TF.read_text(encoding="utf-8")
    assert 'dataset_id  = "fraud_fusion_alerts"' in text, (
        "no google_bigquery_dataset creates the dataset the adapter reads"
    )
    apis = (REPO_ROOT / "infra" / "terraform" / "apis.tf").read_text(encoding="utf-8")
    assert '"bigquery.googleapis.com"' in apis, "the BigQuery API is not enabled"
    iam = (REPO_ROOT / "infra" / "terraform" / "iam.tf").read_text(encoding="utf-8")
    assert "roles/bigquery.dataViewer" in iam, "the serving identity cannot read the dataset"
    kms = (REPO_ROOT / "infra" / "terraform" / "kms.tf").read_text(encoding="utf-8")
    assert "bigquery-encryption.iam.gserviceaccount.com" in kms, (
        "no CMEK binding for BigQuery: the dataset would encrypt under Google-managed keys and "
        "look identical in the console"
    )


def test_the_managed_adapter_reads_only_columns_the_terraform_declares() -> None:
    declared = _terraform_tables()
    for table, columns in managed.SELECTED_COLUMNS.items():
        assert table in declared, f"{table!r} is not a Terraform table"
        undeclared = sorted(set(columns) - declared[table])
        assert not undeclared, f"{table} reads columns Terraform never declares: {undeclared}"


def test_the_book_and_the_terraform_declare_the_same_columns() -> None:
    """``load_order()``, so the manifest the loader writes is held too."""
    declared = _terraform_tables()
    for table in demo_book.BOOK.load_order():
        assert table.name in declared, f"the book ships {table.name} and Terraform does not"
        book_columns, tf_columns = sorted(table.columns), sorted(declared[table.name])
        assert book_columns == tf_columns, (
            f"{table.name}: book {book_columns} vs terraform {tf_columns}"
        )


def test_the_tenant_column_is_required_rather_than_nullable() -> None:
    """A nullable tag would let a row exist that the fail-closed filter cannot classify."""
    text = _TF.read_text(encoding="utf-8")
    assert '{ name = "tenant", type = "STRING", mode = "REQUIRED" }' in text


# --------------------------------------------------------------------------- #
# The authorisation, which was in one profile only
# --------------------------------------------------------------------------- #
def test_the_managed_query_filters_on_tenant_and_not_on_scope_alone() -> None:
    """The predicate IS the authorisation, and it was absent.

    Asserted against the statement rather than a live warehouse, because what is under test is
    what the adapter asks for. Watched failing against the shipped
    ``SELECT * FROM alerts WHERE scope = @scope``.
    """
    assert "tenant = @tenant" in managed._ALERTS_SQL, (
        "the managed alert query does not filter on tenant, so every tenant's alerts in a scope "
        "reach whoever asks"
    )
    assert "SELECT *" not in managed._ALERTS_SQL, "the read set must be declared, not implied"


def test_the_store_serves_only_this_tenants_alerts_in_a_shared_scope(
    feed: LocalAlertFeed,
) -> None:
    """The row the foreign tenant owns is in this very scope, and must not come back."""
    alerts = feed.fetch(_SHARED_SCOPE, tenant=sample_cases.TENANT)
    assert alerts, "the shared scope has no alerts for this tenant"
    assert all(alert.tenant == sample_cases.TENANT for alert in alerts)
    assert "A-9001" not in {alert.alert_id for alert in alerts}


def test_the_foreign_tenant_sees_only_its_own_row_in_the_same_scope(
    feed: LocalAlertFeed,
) -> None:
    """The mirror of the case above, so the filter is proved to work in both directions."""
    alerts = feed.fetch(_SHARED_SCOPE, tenant=demo_book.OTHER_TENANT)
    assert [alert.alert_id for alert in alerts] == ["A-9001"]


def test_an_empty_tenant_reads_nothing_rather_than_everything(feed: LocalAlertFeed) -> None:
    """Fail-closed: "we do not know who is asking" answers nothing, never the whole table."""
    assert feed.fetch(_SHARED_SCOPE, tenant="") == []


def test_an_unknown_scope_is_empty_rather_than_an_error(feed: LocalAlertFeed) -> None:
    """No alerts in this scope is a valid answer the engine correlates into a LOW incident."""
    assert feed.fetch("no-such-scope", tenant=sample_cases.TENANT) == []


def test_the_store_orders_by_observed_at_the_way_the_warehouse_does(
    feed: LocalAlertFeed,
) -> None:
    alerts = feed.fetch(_SHARED_SCOPE, tenant=sample_cases.TENANT)
    observed = [alert.observed_at for alert in alerts]
    assert observed == sorted(observed)
    assert all(alert.citation.source_id.startswith("alert:") for alert in alerts)


# --------------------------------------------------------------------------- #
# The key the dataset stamps onto every table it creates
# --------------------------------------------------------------------------- #
# Watched failing first, on a copy of bigquery.tf with one table's block deleted: the per-table
# assertion names the table, and the count assertion catches a table added later with no block
# at all.
_TABLE_BLOCK = re.compile(r'resource\s+"google_bigquery_table"\s+"(\w+)"\s*\{(.*?)\n\}', re.DOTALL)
_TABLE_KEY = re.compile(r"\n\s*encryption_configuration\s*\{[^}]*?kms_key_name\s*=\s*([^\s#]+)")
_ANY_TABLE_BLOCK = re.compile(r"\n\s*encryption_configuration\s*\{")


def _dataset_default_key() -> str:
    """The key the dataset's ``default_encryption_configuration`` names."""
    block = re.search(
        r"default_encryption_configuration\s*\{(.*?)\n  \}",
        _TF.read_text(encoding="utf-8"),
        flags=re.DOTALL,
    )
    assert block is not None, "the dataset declares no default_encryption_configuration"
    key = re.search(r"kms_key_name\s*=\s*([^\s#]+)", block.group(1))
    assert key is not None, "the dataset's default_encryption_configuration names no key"
    return key.group(1)


def test_every_table_declares_the_key_the_dataset_would_stamp_on_it() -> None:
    """An inherited CMEK key is a REPLACEMENT waiting to happen, and a replaced table is empty.

    The dataset's ``default_encryption_configuration`` makes BigQuery stamp that key onto every
    table it creates in the dataset, so the live table carries an ``encryption_configuration``
    whether or not the Terraform declares one. Terraform then reads the undeclared block as a
    REMOVAL, and removing an encryption configuration FORCES REPLACEMENT: the table is destroyed
    and recreated, and a recreated table holds no rows. Proved by execution against a sibling
    deployment on 2026-09-12, where every loaded table planned as ``must be replaced`` with
    ``encryption_configuration { # forces replacement }`` as the cause.

    CMEK cascades in BigQuery's model and not in Terraform's, which is why the key is named
    twice, and why nothing but a check like this notices when it is named once.
    """
    text = _TF.read_text(encoding="utf-8")
    expected = _dataset_default_key()
    blocks = _TABLE_BLOCK.findall(text)
    assert blocks, "no google_bigquery_table blocks found; the regex or the file moved"

    for name, block in blocks:
        declared = _TABLE_KEY.search(block)
        assert declared is not None, (
            f"google_bigquery_table.{name} declares no encryption_configuration. The dataset "
            "stamps its key onto the table anyway, so the next plan reads the server-set block "
            "as a removal and REPLACES the table, which destroys every row it holds."
        )
        assert declared.group(1) == expected, (
            f"google_bigquery_table.{name} names {declared.group(1)} where the dataset stamps "
            f"{expected}. A table keyed differently from the dataset default is still a "
            "replacement at the next plan."
        )

    # The count is the half that catches a table added LATER with no block at all: iterating the
    # tables found cannot fail over a table nobody declared a key for if nobody looks at how many
    # keys were declared.
    assert len(_ANY_TABLE_BLOCK.findall(text)) == len(blocks), (
        f"{len(blocks)} google_bigquery_table resources and "
        f"{len(_ANY_TABLE_BLOCK.findall(text))} table-level encryption_configuration blocks; "
        "every table needs exactly one, naming the dataset's key."
    )
