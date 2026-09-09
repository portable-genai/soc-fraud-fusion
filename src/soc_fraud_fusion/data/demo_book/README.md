# The shipped alert book

Everything in these files is **fictional**. Every party is invented, every address is RFC 5737
(`192.0.2.0/24`) or RFC 3849 (`2001:db8::/32`), every domain is `.example`.

One file per managed BigQuery table, newline-delimited JSON, each row's keys in that table's
column order. The same files feed four readers, which is the point of them being files:

| Reader | How it reads them |
|---|---|
| the offline profiles | `adapters/local/alerts.py`, through DuckDB, over the same schema and the same statement the warehouse answers |
| the deployment | `scripts/load_demo_book.py`, into `fraud_fusion_alerts.alerts` |
| the demo and the eval | `adapters/local/_fixtures.py`, whose `ALERTS` map is built from these rows rather than declaring a second set |
| the tests | `tests/contract/test_demo_book.py`, which holds these columns against `infra/terraform/bigquery.tf` |

## The foreign alert

`A-9001` belongs to `other-bank`, and it sits in `ato-acme`: a scope this tenant also uses. That
overlap is the point. A scope name is a label, not an entitlement, so a query filtered only by
scope returns both tenants' rows, and that is exactly what the managed adapter used to do. The
loader stamps this row `<tenant>-other` rather than folding it in, because a book with one tenant
cannot tell a working tenant filter from a missing one: every row matches whoever asks.

Delete this row and the tenant test still passes while proving nothing.

## The as-of date

The book is written against `2026-08-05`, and `observed_at` is ISO 8601 text ordered as text.
Nothing here is measured from `CURRENT_DATE`, so the demo does not empty itself as it ages.
