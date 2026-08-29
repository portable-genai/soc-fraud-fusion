# Adopting this repo as your base

This repository (G5, the SOC Fraud Fusion Copilot) is a **common base** that a bank, insurer or
other regulated institution forks to build its own **fraud-and-security alert fusion service**: a
copilot that reconciles raw alerts from a SIEM, an identity provider and a fraud engine into ONE
correlated incident, maps each signal onto a MITRE ATT&CK technique by deterministic lookup, scores
and bands it with auditable arithmetic, drafts a cited summary and response runbook, and routes the
whole thing to a human responder instead of containing anything itself. Forking it gives you a
reusable hexagonal core (a pure-stdlib domain, `@runtime_checkable` ports, three swappable adapter
profiles, a green offline gate that needs no cloud and no credentials) plus a fully worked
ATT&CK-mapping vertical you can keep, retune from pack data, or replace with your own threat model.

This guide is the step-by-step for making it yours. It has two halves: a **mechanical rebrand**
(one script) and the **human decisions** the script cannot make for you.

> Related reading: [`ARCHITECTURE.md`](../ARCHITECTURE.md) (the port table, the request pipeline
> and the five-place port registration), [`CONTRIBUTING.md`](../CONTRIBUTING.md) (the file-by-file
> touch list for adding an adapter or a port), [`model-card.md`](model-card.md) (what the model
> does and does not do), the [`faq/`](faq/) directory.

---

## 1. What you keep vs what you rewrite

The domain is split physically, and the dependency direction is enforced (practices-audit check
A7, `tests/unit/test_core_purity.py`). `domain/kernel.py` holds the vertical-neutral machinery and
`domain/models.py` holds the SOC vertical's artifacts; `models.py` imports `kernel.py` and never
the reverse.

| Layer | Where | For a new threat model or vertical |
|---|---|---|
| **Vertical-neutral machinery** | `domain/kernel.py` (`Citation`, `AuditEvent`, `Decision`, `Severity`, `utcnow`), every Protocol in `ports/`, the `PORT_PROTOCOLS` map, the container wiring in `config.py`, the pack loader's fail-closed shape in `packs.py`, the redacted review conversion in `adapters/_review_payload.py` | keep untouched |
| **Policy (your numbers)** | the `policy:` block and every per-technique `weight` in `rulepacks/attack_map.yaml`, the `JURISDICTIONS` tuple in `domain/pii.py`, `_DUAL_CONTROL` in `adapters/_review_payload.py`, the `THRESHOLDS` map in `eval/run_eval.py` | change deliberately (see section 4) |
| **Vertical (the fusion artifacts)** | the artifact models in `domain/models.py` (`Alert`, `Incident`, `TechniqueHit`, `IncidentAssessment`, `NarrationDraft`, `RecommendedAction`, `GroundingKind`), the `techniques:` rows in `rulepacks/attack_map.yaml`, the prompt in `adapters/gcp/generation.py`, the fixture alerts / passages / intel in `adapters/local/_fixtures.py`, the golden set `eval/datasets/golden_cases.jsonl`, the demo arc in `scripts/demo.py`, the UI panels | rewrite / reseed for your data |

If your product is another *correlate-then-recommend* copilot (a fraud case builder, an insider
threat triage desk, a payments-abuse fusion cell), most of the hexagon, the three profiles, the
deterministic-score-plus-narrating-model pattern, the redact-before-audit rule, the eval gate and
the Hrz7 review routing transfer directly. You replace the signal-to-technique rows and the
artifact models, and retune the policy numbers.

## 2. Core-vs-adopter-owned files (so upstream merges stay mechanical)

Upstream keeps evolving these; avoid diverging from them so you can pull fixes cleanly:

- **Upstream-owned** (take our changes): `domain/kernel.py`, `domain/correlation_engine.py` (the
  algorithm, not the pack numbers it reads), `ports/`, `tests/contract/`, the eval harness
  mechanics in `eval/run_eval.py`, the identity and exposure posture in `api/`, the CI workflows,
  and the hexagon wiring (`config.py` `Container` and `DEFAULT_BINDINGS`).
- **Adopter-owned** (yours; expect to edit): the *values* in `config/settings.yaml`, the whole of
  `rulepacks/attack_map.yaml`, `domain/models.py`, `adapters/local/_fixtures.py`,
  `adapters/onprem/*`, `eval/datasets/golden_cases.jsonl` and the `THRESHOLDS` map, UI theming and
  branding, `infra/terraform/terraform.tfvars.example`, and the regulator crosswalk section of
  [`COMPLIANCE.md`](../COMPLIANCE.md).

Track upstream via git tags; rebase your adopter-owned changes onto each release rather than
merging `main` continuously, so conflicts stay in the files you were told to expect.

## 3. The mechanical rebrand (one script)

`scripts/rename_fork.py` rewrites the python package name `soc_fraud_fusion` (which is
ALSO the console-script name: see `[project.scripts]` in `pyproject.toml`), the `FRAUDFUSION`
environment prefix behind every `FRAUDFUSION_*` variable, the resource id
`soc-fraud-fusion`, and the Terraform `name_prefix` default, in one pass. Preview
first, then apply:

```bash
# Preview (writes nothing):
python scripts/rename_fork.py --package acme_fraud_fusion \
    --env-prefix ACMEFUSION --resource acme-fraud-fusion \
    --name-prefix acme-fusion --dry-run

# Apply:
python scripts/rename_fork.py --package acme_fraud_fusion \
    --env-prefix ACMEFUSION --resource acme-fraud-fusion \
    --name-prefix acme-fusion --yes

# Then recreate the environment (the distribution name changed) and prove it is green:
python3.12 -m venv .venv && source .venv/bin/activate
make install
make gate
```

Three things about the flags:

- There is deliberately **no `--cli` flag**. The console script is named after the package, so
  `--package` renames it too, and a second flag could only drift out of step.
- There is deliberately **no `--dist` flag**. `--resource` is one literal doing four jobs: the
  distribution name and the GitHub id in `pyproject.toml`, the A2A agent-card `name` in
  `agent/agent_card.py`, and the Hrz4 eval bundle id (`_BUNDLE` in `eval/run_eval.py`). They are
  the same string on purpose, so a fork's promotion record and its discovery card cannot disagree
  about which system they describe.
- `--name-prefix` is optional and is rewritten only inside its own `variable "name_prefix"` block
  in `infra/terraform/variables.tf` (default `g5-svc`). Set a per-repo prefix whenever more than
  one catalog service deploys into the same project: KMS key rings can never be deleted, so a
  destroy-and-redeploy needs a fresh prefix to get a fresh ring.

Add `--include-docs` to sweep Markdown prose too; a default run leaves it alone so the diff stays
reviewable. The script deliberately does NOT touch the human decisions below.

## 4. The human decisions (the script can't make these)

1. **Region and residency.** The region is chosen once and shared by the runtime and the infra:
   `region: ${GCP_REGION:-asia-southeast1}` in `config/settings.yaml` for the process, and the
   Terraform pair `region` / `allowed_regions` for the deploy. Both Terraform variables are
   nullable and default to the region this repo was rendered for, which is carried as
   `local.render_region` in `infra/terraform/render.tf.json` (`asia-southeast1`) and made effective
   in `naming.tf`. To move a fork in-country, set BOTH in your tfvars: `region` to your region and
   `allowed_regions` to the list it must be inside. The pair is validated at `terraform plan` by
   the cross-variable `validation` block on `var.region` in `variables.tf`, so an unapproved region
   fails at setup rather than putting regulated data out of jurisdiction, and
   `infra/terraform/production_edge.tftest.hcl` runs that claim as an executable test against a
   mocked provider (`residency_defaults_are_in_country`,
   `reject_region_outside_the_residency_allowlist`). The enforcement ships; what does not ship yet
   is the **build wiring**: this repo has no `tf-check` make target and no `terraform` CI job, so
   `terraform -chdir=infra/terraform test` only runs when somebody types it. Wire it into your own
   pipeline as part of adoption. See [`runbook.md`](runbook.md).
2. **Identity and the IdP.** This repo owns no login flow, and that is deliberate. Under `gcp`,
   `adapters/gcp/identity.py` verifies the assertion Cloud IAP injected at the edge: it calls
   `id_token.verify_token` with the configured `FRAUDFUSION_IAP_AUDIENCE`, with IAP's own key set
   rather than google-auth's OAuth2 default, and it checks the issuer itself. That variable is
   three-state and both unset and emptied REFUSE every caller, because `audience=None` means the
   audience is not verified at all. Under `local`, `adapters/local/identity.py` resolves seeded dev
   personas from `X-Dev-Persona`, which authenticate nobody and are offline demo and test only.
   Under `onprem`, `adapters/onprem/identity.py` refuses: it is a placeholder for the client's own
   IdP. So: configure auth ON the deployed service (`edge_iap_enabled` and `iap_members` in
   `infra/terraform/variables.tf`), read the `iap_audience` output after the first apply, set it
   back as a variable, and apply again. The exposure guard reads the identity BINDING and nothing
   else, so setting `FRAUDFUSION_S2S_TOKEN` closes the service-to-service routes and opens nothing.
3. **The scoring policy your SOC owns.** The consequential numbers are pack DATA, not engine code,
   and `rulepacks/attack_map.yaml` is the one file to diff: the `policy:` block (`baseline: 10`,
   `medium_at: 30`, `high_at: 55`, `critical_at: 80`) and the `weight` on each technique row.
   `packs.py` loads them fail-closed into a frozen `FusionPolicy` and `AttackMap`, and the engine
   branches on nothing else. Point `FRAUDFUSION_ATTACK_PACK` (read through `attack_pack_path`) at
   your own file rather than editing the shipped reference, and add a test that pins your values.
   Three related numbers live in code and need a deliberate decision too: `_SCORE_CEILING = 100`
   in `domain/correlation_engine.py` (the clamp that stops one noisy source dominating every
   incident), `_DUAL_CONTROL` in `adapters/_review_payload.py` (which bands demand two approvals,
   `CRITICAL` today), and `JURISDICTIONS` in `domain/pii.py` (which national-ID pattern rows the
   redactor loads, and in what order). The defaults are a reference, not your policy.
4. **Reference data is fictional, all of it.** Every alert, entity, asset and indicator in
   `adapters/local/_fixtures.py` is invented: parties suffixed FICTIONAL, addresses from RFC 5737
   (`192.0.2.0/24`) and RFC 3849 (`2001:db8::/32`), domains on `.example`. The fixture runbook
   passages and the IOC / CVE intel set are synthetic too. The one place real-world names appear is
   the ATT&CK technique ids and names in the pack, because a technique a responder cannot look up
   is useless; `url` on the citation is deliberately blank so you point it at your own ATT&CK
   mirror. Replace the fixtures with your own synthetic data before wiring a real alert feed, and
   **do not run this against live alert streams without your own security and model-risk
   sign-off.**
5. **The eval golden set and its thresholds.** `eval/datasets/golden_cases.jsonl` carries an
   INDEPENDENT oracle per case (`expected_score`, `expected_severity`, `expected_techniques`,
   `expected_action`, and a `planted` identifier for the leak check), hand-computed from the
   fixtures against the shipped pack and never read back from the pipeline. The six metrics and
   their thresholds are the `THRESHOLDS` map in `eval/run_eval.py`
   (`correlation_accuracy`, `technique_mapping_exactness`, `disposition_accuracy`,
   `runbook_groundedness`, `review_safety`, `pii_safety`, all at 0.99). There is no separate
   `rubrics/` directory in this repo: the thresholds are that map. A fork inherits a green gate
   that measures the WRONG threat model until you rebuild both the cases and your oracle;
   `tests/unit/test_not_falsely_green.py` is the guard that each metric can still go red, so keep
   it in step with whatever you change.
6. **Deployment posture.** Review the Dockerfile (multi-stage, digest-pinned base, non-root uid
   10001, `HEALTHCHECK` on `/healthz`) and the whole of `infra/terraform/` before you expose
   anything: `org_policy.tf` (resource-location pin, no exportable service-account keys, uniform
   bucket-level access), `kms.tf` (a regional CMEK key ring), `logging_worm.tf` (the locked WORM
   audit bucket, irreversible once `worm_locked = true`), `vpc_sc.tf` (dry-run first, then
   enforce), `monitoring.tf` and the opt-in `production_edge.tf`. Also decide the audit posture:
   `FRAUDFUSION_AUDIT_PATH` must leave `:memory:` for anything durable, and the moment it does,
   `FRAUDFUSION_AUDIT_ANCHOR` must point at a file on a DIFFERENT volume, because a hash chain
   alone cannot detect a truncated tail.

## 5. Do not duplicate the platform

This repo is one system in a catalog of composable GRC systems. Several concerns it *touches* are
owned by sibling platform services; integrate rather than rebuild them (see
[`faq/features-faq.md`](faq/features-faq.md) for the full map):

- **Hrz2** governed knowledge base: consumed by `adapters/gcp/retrieval.py`
  (`Hrz2RetrievalAdapter`) for runbook and threat-intel passages, pinned to the residency region.
  Passages inform NARRATION only; an incident's band is identical with retrieval stubbed empty.
- **Hrz3** agent registry: this agent publishes its A2A card at `/.well-known/agent-card.json`
  (`agent/agent_card.py`), built from the same tool table the runtime binds. Registering it and
  taking the agent's identity and entitlements from Hrz3 is the open R4 item in
  [`COMPLIANCE.md`](../COMPLIANCE.md).
- **Hrz4** AI-quality and model-risk gate: owns promotion. `eval/run_eval.py --mode gate`
  delegates the verdict to it through `agent_eval_kit.PromotionGateClient` under the bundle id
  `soc-fraud-fusion`, and refuses to run off the `gcp` profile. The offline
  `--mode smoke` run mirrors its thresholds.
- **Hrz5** observability and immutable WORM audit: `adapters/gcp/tracer.py` sends spans OTLP to
  the Hrz5 collector when `OTEL_EXPORTER_OTLP_ENDPOINT` is set and straight to Cloud Trace when it
  is not. Binding the audit stream to the shared sink is the open R2 item.
- **Hrz7** human-review and maker-checker console: EVERY incident is consequential, so every one
  is routed there over the shared `review-kit` (rule R8) in the same call that produced it.
  You wire your `HUMAN_REVIEW_URL`; you do not re-implement the console.

The guardrail gateway (**Hrz1**) is deliberately **not** in this path, and that is a real design
decision rather than an omission: this repo's catalog row names Model Armor in its stack and omits
Hrz1 from its dependencies, so screening runs through this repo's own `SafetyPort`
(`ports/safety.py`, bound to `adapters/gcp/safety.py` under `gcp`) rather than through the shared
gateway. If your institution standardises on Hrz1, that is an adapter swap behind the same port,
not a rewrite. Marketing and financial-promotions screening (**Mkt6**) is not applicable: this
service produces no customer-facing output. Recording an **Rsk3** intake validation reference is
an adoption action, not a code control (rule R6).

Where this repo's responsibility ends: it produces a correlated, cited, banded incident and a
drafted runbook, and it hands them to a human. It does not execute containment, it does not own
the alert sources, it does not own the review console, and it does not own the promotion verdict.

## 6. Adoption checklist

- [ ] Ran `scripts/rename_fork.py` (package, env prefix, resource id, Terraform `name_prefix`), recreated the venv, `make install` and `make gate` green.
- [ ] Set the Terraform `region` AND `allowed_regions` pair to your in-country region, and confirmed `terraform -chdir=infra/terraform test` passes.
- [ ] Wired `terraform test` into your own pipeline (this repo ships no `tf-check` target and no `terraform` CI job).
- [ ] Configured IAP on the deployed service and set `FRAUDFUSION_IAP_AUDIENCE` from the `iap_audience` output (this repo owns no login flow).
- [ ] Replaced `rulepacks/attack_map.yaml` with your signal-to-technique map and your bands, and pinned the numbers with a test.
- [ ] Reviewed the three in-code policy constants with your SOC and compliance functions: `_SCORE_CEILING`, `_DUAL_CONTROL`, `JURISDICTIONS`.
- [ ] Replaced every fixture in `adapters/local/_fixtures.py` with your own synthetic data.
- [ ] Rebuilt `eval/datasets/golden_cases.jsonl` and re-derived its oracle, and kept `tests/unit/test_not_falsely_green.py` honest.
- [ ] Moved `FRAUDFUSION_AUDIT_PATH` off `:memory:` and set `FRAUDFUSION_AUDIT_ANCHOR` on a different volume.
- [ ] Set `HUMAN_REVIEW_URL` and decided which sibling systems (Hrz2, Hrz3, Hrz4, Hrz5, Hrz7) you integrate vs stub.
- [ ] Reviewed the deploy posture: Dockerfile, `org_policy.tf`, `kms.tf`, `logging_worm.tf` retention and lock, `vpc_sc.tf` dry-run, and the bind address.
- [ ] Recorded your baseline upstream tag so you can take future fixes.
