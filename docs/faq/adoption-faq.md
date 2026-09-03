# Adoption FAQ

For an engineering lead forking this repo as their institution's fraud-and-security fusion base.
The step-by-step is [`../ADOPTING.md`](../ADOPTING.md); this answers the "will it hurt later?"
questions. See also [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md) for the extension touch
lists.

### How do I rebrand it for my organisation?

`scripts/rename_fork.py` does the mechanical half in one pass: the python package name
`soc_fraud_fusion` (`--package`), the `FRAUDFUSION` environment prefix (`--env-prefix`),
the resource id `soc-fraud-fusion` (`--resource`) and, optionally, the Terraform
`name_prefix` default (`--name-prefix`, currently `g5-svc`). Preview with `--dry-run`, apply with
`--yes`, add `--include-docs` to sweep Markdown prose. Then recreate the venv, `make install`, and
prove it with `make gate`. There is deliberately **no `--cli` flag** (the console script is named
after the package, per `[project.scripts]`) and **no `--dist` flag** (`--resource` is one literal
doing four jobs: the distribution name, the GitHub id, the A2A agent-card name and the Hrz4 eval
bundle id, kept identical so a fork's promotion record and its discovery card cannot disagree).
The human decisions the script does not make are the checklist in
[`../ADOPTING.md`](../ADOPTING.md) section 6.

### If several institutions fork this, how does each take upstream fixes?

Track upstream via **git tags**, and rebase your adopter-owned changes onto each release rather
than merging `main` continuously, so conflicts stay in files you were told to expect.
[`../ADOPTING.md`](../ADOPTING.md) section 2 draws the line: upstream owns `domain/kernel.py`, the
correlation ALGORITHM, `ports/`, `tests/contract/`, the eval harness mechanics, the identity and
exposure posture in `api/`, and the container wiring; you own `config/settings.yaml` values, the
whole ATT&CK pack, `domain/models.py`, the fixtures, `adapters/onprem/*`, the golden set, UI
theming, your tfvars, and the regulator crosswalk in `COMPLIANCE.md`.

### Is there a separate kernel module I keep untouched?

Yes, and it is enforced rather than described. `domain/kernel.py` holds the vertical-neutral
machinery (`Citation`, `AuditEvent`, `Decision`, `Severity`, `utcnow`); `domain/models.py` holds
this vertical's artifacts and imports `kernel`, never the reverse. A fork building a different
correlate-then-recommend vertical rewrites `models.py` and leaves `kernel.py` alone.
`tests/unit/test_core_purity.py` walks the import graph and fails the build on a violation, and
it carries a control case proving the scan can actually see one, so the boundary cannot decay into
a comment.

### Can I retune the bands and weights without touching code?

Yes, and this is the part most forks change first. The baseline, the three band thresholds and
every per-technique weight are DATA in `rulepacks/attack_map.yaml`, loaded by `packs.py` into a
frozen `FusionPolicy` and `AttackMap` that `CorrelationEngine` takes as a parameter. Point
`FRAUDFUSION_ATTACK_PACK` (read through `attack_pack_path`) at your own file rather than editing
the shipped reference, so upstream pack changes stay mergeable. The loader is fail-closed:
`tests/unit/test_attack_pack.py` proves it refuses a technique whose citation is not defined, a
signal type mapped twice, a non-increasing `medium < high < critical` policy, a non-integer or
negative weight, and a missing file. A partly-parsed pack would under-score real incidents, so it
must not start at all. Three numbers do still live in code and need a deliberate decision:
`_SCORE_CEILING` in `domain/correlation_engine.py`, `_DUAL_CONTROL` in
`adapters/_review_payload.py`, and `JURISDICTIONS` in `domain/pii.py`.

### How do I add a signal type or a new ATT&CK technique?

Add a row to the `techniques:` list in the pack with its `signal_type`, `technique_id`, `tactic`,
`name`, `weight` and a `citation` id that the pack's own `citations:` block defines. That is the
whole change: the engine indexes by signal type at construction (`AttackMap.by_signal`) and
branches on no signal name of its own, so there is no code to edit and nothing to register. Add a
fixture alert carrying the new signal type and a golden case with a hand-computed oracle, or the
new row is untested.

### How do I add a new outbound dependency (a new port)?

There is a fixed touch list and the contract test enforces it in BOTH directions, so a port that
is bound but unregistered cannot run with no enforcement. A port must appear in FIVE places:
`ports/__init__.py` (`PORT_PROTOCOLS`), `config.DEFAULT_BINDINGS`, a `Container` accessor,
`config/settings.yaml`, and a `PortCase` in `tests/contract/canonical.py`. Then bind it in all
three families, with `local` actually working, `gcp` importing its SDK lazily inside the method,
and `onprem` raising rather than pretending. Every adapter takes one constructor argument,
`Adapter(settings)`. `tests/contract/test_port_parity.py` asserts set equality across all five and
`tests/unit/test_settings_file.py` holds the two binding tables equal. The full walkthrough is in
[`../../CONTRIBUTING.md`](../../CONTRIBUTING.md).

### Will the demo rot after I diverge?

It is guarded, and the guard is outside `make gate` on purpose. A demo step exists in exactly two
places (`demo.STEPS` and `walkthrough.CHECKS`) and `tests/unit/test_demo_surface.py` holds the two
sets equal inside the offline gate, so a claim the demo narrates but nobody verifies cannot exist.
`make demo-selftest` then runs the whole eight-step arc headless against the REAL server over
loopback and exits non-zero when a claim stops being true; the hosted GitHub Actions check runs
it, plus `make portability`, `make demo-static` and `make docs-check`, on every push. Put the
numbers a check reads in the step's `facts` dict, never only in the rendered rows: a check that
parses prose breaks on a wording change. Do NOT move the demo into `make gate`; the gate proves the
service and must stay fast and offline.

### Does the CI run for my fork out of the box?

Yes. the hosted GitHub Actions check is a thin caller of a shared reusable hard-gate workflow pinned
to a TAG, and it references no `secrets.` at all, so a fork is green immediately with no org
secrets and no cloud project. The gate itself (`make gate` = `lint test eval`) is deliberately
offline and credential-free: no network, no cloud SDK. Anything that needs a live service lives in
`tests/integration/` and is marked, so `pytest -m 'not integration'` deselects it, and
`tests/unit/test_test_layout.py` fails the build if such a module is not marked. Two caveats worth
knowing. First, the eval gate measures the REFERENCE pack and golden set until you rebuild them,
so a fork inherits a green gate that scores the wrong threat model. Second, the residency posture
in `infra/terraform/production_edge.tftest.hcl` is executable but is NOT wired into any build here:
there is no `tf-check` make target and no `terraform` CI job, so add
`terraform -chdir=infra/terraform test` to your own pipeline.

### What does adoption NOT give me?

A production model path. The `local` profile is a real offline system, but the safety screen is a
marker-list heuristic and the narrator is a deterministic template, so `runbook_groundedness`
today scores a template rather than a live model. The managed path needs a pinned model snapshot,
generation parameters, budget and rate controls, a kill switch, and a `gcp`-profile eval run
through the Hrz4 gate before it is production-cleared. Those are named honestly in
[`../model-card.md`](../model-card.md) and tracked as the open P-08, P-10 and P-11 rows in
[`../../COMPLIANCE.md`](../../COMPLIANCE.md). Plan them as adoption work, not as a surprise.
