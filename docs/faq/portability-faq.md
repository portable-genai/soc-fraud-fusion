# Portability FAQ

For architecture, cloud, and exit-planning reviewers who want to know how real the "no lock-in"
claim is and how an off-cloud or sovereign exit would work. Cross-references:
[`../../ARCHITECTURE.md`](../../ARCHITECTURE.md),
[`../onprem-migration.md`](../onprem-migration.md), [`../runbook.md`](../runbook.md).

## What is the no-lock-in claim, concretely?

`src/soc_fraud_fusion/domain/` is pure standard library plus the stdlib-only commons: no
Google Cloud SDK, no FastAPI, no httpx, no pydantic, no YAML. The consequential engine
(`domain/correlation_engine.py`) and the orchestrator (`domain/fusion_service.py`) live there, so
the part that decides anything has no cloud dependency to unwind. Even the pack loader is outside
the boundary: `packs.py` sits beside `domain/` rather than in it, precisely because it reads YAML
from disk, and it hands the engine a frozen `AttackMap` value. All infrastructure sits behind
`@runtime_checkable` `Protocol` ports in `ports/`, and adapters are chosen by one setting.
`tests/unit/test_core_purity.py` enforces the boundary by walking the imports rather than trusting
a convention, and it carries its own control case proving the scan can see a violation.

## What are the three profiles?

`FRAUDFUSION_PROFILE` selects the whole adapter stack, and it is read in exactly one place
(`config.py`, guarded by `tests/unit/test_profile_single_source.py`):

- **`local`** (the dev, test and CI stack): a real, working, SDK-free offline system. Fixture
  alerts, a fixture runbook and threat-intel corpus, a deterministic injection heuristic, a
  deterministic grounded narrator, a hash-chained SQLite WORM audit log from the commons, seeded
  dev personas, and a review-kit outbox that actually enqueues rather than no-opping.
- **`gcp`**: the managed services, with every SDK import lazy and inside the method, so the other
  two profiles import the same modules with no cloud SDK installed. BigQuery alerts, `enterprise-knowledge-base` governed
  retrieval, a grounded lookup, Model Armor screening, Gemini narration, Cloud Logging WORM, IAP
  identity, Cloud Trace or the `agent-observability` OTLP collector, and the `human-review-console` service intake over S2S.
- **`onprem`**: fail-fast placeholders that satisfy the same Protocols and raise
  `NotImplementedError` naming the migration target. They prove the ports are honest exit seams
  rather than decoration.

Unset is a fourth STATE rather than a fourth profile: the SDK-free adapters still bind, but the
seeded personas are refused, no service-to-service scheme is selected, the dev CORS allowlist and
the `X-Dev-Persona` header are withdrawn, and the exposure guard refuses every non-loopback peer.
Set-and-empty and set-and-unknown (including a mis-capitalised `Local`) both raise at import, so a
typo kills the process instead of silently picking a family.

## Is the portability claim tested, or just asserted?

Tested, and bounded. `make portability` (`scripts/portability_demo.py`) runs eight named checks
offline and exits non-zero on any failure: port map completeness, adapter construction and
Protocol conformance, the offline family actually ANSWERING a canonical call (not merely "did not
raise"), the exit family REFUSING, in-place rewrite detection, anchored truncation detection with
its control case, a JSONL export that reloads with its chain intact, and a probe that no `google.*`
module was imported by any of the above. It prints what it does NOT prove rather than
overclaiming. Alongside it, `tests/contract/test_port_parity.py` asserts set equality across all
FIVE homes of a port (the `PORT_PROTOCOLS` map, `config.DEFAULT_BINDINGS`, the `Container`
accessor, `config/settings.yaml` and the canonical-call table), and
`tests/contract/test_behavioral_parity.py` proves the offline family answers, the on-premises
family raises and the managed family refuses rather than silently succeeding offline.
`tests/contract/_sdk_free_probe.py` proves the lazy imports by BLOCKING the SDK in a fresh
interpreter, not by the SDK happening to be absent from the machine.

## How would a sovereign or on-prem exit actually go?

The `onprem` family is the scaffold, and every placeholder marks one seam: the client's own alert
warehouse (`alerts`), its own document search (`retrieval`), its own threat-intel service
(`grounding`), its own content-safety service (`safety`), its own hosted model (`generation`), its
own audit store (`audit`), its own IdP (`identity`), its own review console (`review_router`) and
its own quality authority (`evaluation`). Because the domain never changes, the exit is an adapter
exercise, not a rewrite: the score, the bands, the ATT&CK mapping and the escalation rule are the
same pure code on either side. Tracing is the one deliberate exception, absent rather than fatal
under `onprem`, because a missing span never changes a verdict. See
[`../onprem-migration.md`](../onprem-migration.md) for the step list.

## Is the ATT&CK mapping portable, or is it baked into the engine?

Portable, by construction. The signal-to-technique rows, the per-technique weights and the band
thresholds all live in `rulepacks/attack_map.yaml`, and `packs.py` loads them fail-closed into a
frozen `AttackMap`. `CorrelationEngine` takes that map as a constructor parameter and branches on
no signal name of its own, so a SOC that uses a different taxonomy points
`FRAUDFUSION_ATTACK_PACK` at its own file and the engine is unchanged.
`tests/unit/test_attack_pack.py` proves the loader refuses an undefined citation, a duplicate
signal mapping, a non-increasing band policy and a missing file, so a partly-parsed pack cannot
quietly under-score real incidents.

## How is data residency handled?

Selected once and shared. `config/settings.yaml` carries `region: ${GCP_REGION:-asia-southeast1}`
for the runtime, and Terraform derives its effective region from the same rendered constant in
`infra/terraform/render.tf.json`. On the deploy side it is ENFORCED rather than described:
`variables.tf` validates the effective region against the residency allowlist at plan time,
`org_policy.tf` pins `constraints/gcp.resourceLocations` to that region's location group, and
every regional resource (the CMEK key ring, the locked WORM bucket, the Cloud Run service and its
regional network endpoint group) is created in it.
`infra/terraform/production_edge.tftest.hcl` runs those claims as executable tests against a
mocked provider, so they need no project and no credentials. The honest caveat is the build
wiring: this repo has no `tf-check` make target and no `terraform` CI job, so
`terraform -chdir=infra/terraform test` runs only when somebody types it. Moving a fork to another
in-country region is a tfvars change (`region` plus `allowed_regions`), not a fork of the code.

## Can the data be exported in an open format?

Yes. The audit trail exports to JSON Lines with a self-describing anchor header and reloads with
its chain intact, which `scripts/portability_demo.py` proves as its "record leaves intact" check
rather than asserting it in prose. The domain artifacts are frozen, slotted dataclasses and
`LenientStrEnum` vocabularies whose members ARE their wire values, so serialised JSON carries the
enum strings and an unknown value from a future release does not crash a reader. The exit for the
audit store is therefore a file copy, which is the point of P-12.

## What is honestly NOT portable?

Three things, stated rather than hidden. First, tamper-evidence is scoped to what the local sink
can prove: hash chaining plus an external anchor catches edits, reorders, deletions and truncation,
but production tamper-evidence is the locked WORM bucket's job (`agent-observability` in the enterprise), and
`portability_demo.py` says so. Second, the managed narration and grounding paths depend on a
Gemini model id (`generation_model`, defaulting to the floating alias `gemini-3.5-flash`); a fork
that exits to its own hosted model gets different prose, though not different figures, because the
engine owns every number. Third, the `local` profile is a real offline system but it is not a
production one: fixture alerts, a marker-list safety heuristic and a template narrator are honest
stand-ins, not equivalents. See [`../model-card.md`](../model-card.md) for that boundary in full.
