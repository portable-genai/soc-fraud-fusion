# bigquery.tf : the alert intake dataset this vertical reads (CMEK, read-only).
#
# THIS FILE DID NOT EXIST. `adapters/gcp/alerts.py` has always queried
# `<FRAUDFUSION_BQ_DATASET>.alerts`, and nothing in this directory created the dataset or the
# table, so the managed profile would have failed at its first request with a not-found. Unlike
# the sibling repository that shipped the same gap, not even the API was enabled and no IAM role
# named BigQuery: the adapter referred to a store that had no existence anywhere in the
# deployment. The API (apis.tf), the two roles (iam.tf) and the CMEK service-agent binding
# (kms.tf) all arrive with this file, in one commit, because a dataset without them is a
# different kind of silent failure each time.
#
# General Principle map:
#   P-03 (residency): the dataset is created in the EFFECTIVE region, so alert rows about a
#         customer's accounts and devices never leave the deployment's country. `location` is
#         OPTIONAL on this resource, so a null would not fail the plan: it would silently create
#         the dataset in the US multi-region and break residency with a green gate. var.region
#         defaults to null; local.region is the resolved one.
#   P-09 (CMEK explicit): the dataset encrypts under the regional key from kms.tf. CMEK does not
#         cascade, so the BigQuery service-agent key binding is declared there alongside it. A
#         dataset created with no key binding encrypts under Google-managed keys and looks
#         identical in the console, which is why the binding is not left implicit.
#   P-04 (data minimisation): the columns below are exactly the ones the adapter reads
#         (`SELECTED_COLUMNS`), and a contract test holds the two together. The adapter used to
#         say `SELECT *`, which is a read set no test can see and a schema nothing constrains.
#
# The serving identity gets dataViewer and nothing more (iam.tf). This service correlates alerts
# and never writes one: in production the table is filled by the SIEM, the identity provider and
# the EDR that raise the alerts. For a DEMO deployment the rows come from
# `scripts/load_demo_book.py`, which runs as an operator and never as the service, and which
# fills tables rather than creating them.

resource "google_bigquery_dataset" "alerts" {
  dataset_id  = "fraud_fusion_alerts" # matches FRAUDFUSION_BQ_DATASET
  project     = var.project_id
  location    = local.region # P-03
  description = "Raw security and fraud alert intake for soc-fraud-fusion (internal, CMEK)."

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.cmek.id # CMEK does not cascade (P-09)
  }

  # Alert rows name customers, devices and addresses: never world-readable, and never dropped
  # with the stack.
  delete_contents_on_destroy = false

  depends_on = [
    google_project_service.required,
    google_kms_crypto_key_iam_member.bigquery,
  ]
}

# The raw alert rows the correlation engine reads.
#
# `tenant` is a REQUIRED column rather than a convention, and it is the whole authorisation. The
# adapter's WHERE clause matches it against the VERIFIED principal's tenant; a row that carries
# no tag belongs to nobody and no principal may read it, which is the fail-closed reading the
# local adapter has always documented. The adapter shipped without this predicate entirely, so
# the column being REQUIRED here is what stops the same gap reopening: a nullable tag would let a
# row exist that the filter cannot classify.
#
# `scope` is a LABEL, not an entitlement. Two tenants may use the same scope name, and the demo
# book deliberately ships exactly that so the predicate has something to exclude.
resource "google_bigquery_table" "alerts" {
  dataset_id          = google_bigquery_dataset.alerts.dataset_id
  table_id            = "alerts"
  project             = var.project_id
  deletion_protection = true

  # The same key the dataset names, declared again here on purpose. The dataset's
  # default_encryption_configuration makes BigQuery stamp that key onto every table it creates in
  # the dataset, so the live table carries an encryption_configuration whether or not this
  # resource declares one. Leaving it undeclared makes the next plan read the server-set block as
  # a REMOVAL, and removing an encryption configuration FORCES REPLACEMENT: the table is destroyed
  # and recreated, and a recreated table holds no rows. CMEK does not cascade in Terraform's model
  # even though it does in BigQuery's, which is why the key is named twice.
  encryption_configuration {
    kms_key_name = google_kms_crypto_key.cmek.id
  }

  schema = jsonencode([
    { name = "alert_id", type = "STRING", mode = "REQUIRED" },
    { name = "tenant", type = "STRING", mode = "REQUIRED" },
    { name = "scope", type = "STRING", mode = "REQUIRED" },
    { name = "source_system", type = "STRING", mode = "REQUIRED" },
    { name = "entity", type = "STRING", mode = "REQUIRED" },
    { name = "asset", type = "STRING", mode = "REQUIRED" },
    { name = "indicator", type = "STRING", mode = "NULLABLE" },
    { name = "signal_type", type = "STRING", mode = "REQUIRED" },
    # ISO 8601 text, deliberately: the row is pure, sortable and byte-identical on replay, and
    # the engine orders on it without a timezone conversion sitting between the two stores.
    { name = "observed_at", type = "STRING", mode = "REQUIRED" },
    { name = "detail", type = "STRING", mode = "NULLABLE" },
  ])
}

# The manifest the demo loader writes LAST, because it records the load that wrote the others.
# It is deliberately not one of this repository's own tables: `hex_service_kit.demobook` keeps it
# out of `TABLES` and appends it in `load_order()`, and the loader creates nothing, so a manifest
# missing from here is a load that exits on a not-found before writing a single row.
#
# `fictional` is what the overwrite guard reads. A demo loader truncates, which is right for a
# demo book and catastrophic for a real alert table, so it proceeds only when every table is
# empty or this row says what the dataset holds is fictional.
resource "google_bigquery_table" "book_manifest" {
  dataset_id          = google_bigquery_dataset.alerts.dataset_id
  table_id            = "book_manifest"
  project             = var.project_id
  deletion_protection = true

  # The same key the dataset names, declared again here on purpose. The dataset's
  # default_encryption_configuration makes BigQuery stamp that key onto every table it creates in
  # the dataset, so the live table carries an encryption_configuration whether or not this
  # resource declares one. Leaving it undeclared makes the next plan read the server-set block as
  # a REMOVAL, and removing an encryption configuration FORCES REPLACEMENT: the table is destroyed
  # and recreated, and a recreated table holds no rows. CMEK does not cascade in Terraform's model
  # even though it does in BigQuery's, which is why the key is named twice.
  encryption_configuration {
    kms_key_name = google_kms_crypto_key.cmek.id
  }

  schema = jsonencode([
    { name = "book_version", type = "STRING", mode = "REQUIRED" },
    { name = "as_of_date", type = "DATE", mode = "REQUIRED" },
    { name = "fictional", type = "BOOL", mode = "REQUIRED" },
    { name = "loaded_at", type = "TIMESTAMP", mode = "NULLABLE" },
    { name = "source_commit", type = "STRING", mode = "NULLABLE" },
    { name = "tenant", type = "STRING", mode = "REQUIRED" },
  ])
}
