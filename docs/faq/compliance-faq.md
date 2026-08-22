# Compliance FAQ

For compliance, model-risk and privacy teams assessing this repo's regulatory posture.
Cross-references: [`../../COMPLIANCE.md`](../../COMPLIANCE.md) (the full P-01 to P-13 and R1 to R8
control map with an Evidence column naming real files), [`../../SPEC.md`](../../SPEC.md),
[`../model-card.md`](../model-card.md), [`../practices-audit.md`](../practices-audit.md).

### Is this making containment decisions autonomously?

No. It is a **decision-support** copilot. `MONITOR`, `INVESTIGATE` and `CONTAIN` are
RECOMMENDATIONS, and the system executes none of them. Every incident is treated as consequential,
so `requires_human_review` is unconditionally true and the result is ROUTED to the **Hrz7**
Human-Review and Maker-Checker Console via the shared `review-kit` (dependency rule R8) in the
same call that produced it, on the API, the CLI and the agent-tool surfaces alike. A `CRITICAL`
band requires two approvals rather than one. The flag alone is not the escalation, and the
distinction is enforced: `tests/unit/test_review_routing.py` asserts the outbound review on each
surface, proves the managed router REFUSES rather than swallowing an escalation when no console is
configured, and proves the on-premises placeholder refuses rather than dropping one. The API
response carries a `review_ref` so a caller can tell a routed escalation from one that stopped.

### How is customer PII handled?

Alert detail text is operational prose written by SIEM and fraud engines, so it can carry customer
identifiers; the repo assumes it does. Redaction therefore happens at every boundary crossing
rather than once, using the shared `pii-kit` with a jurisdiction selection and ORDER this
deployment owns (`JURISDICTIONS = ("SG", "HK", "JP", "AU")` in `domain/pii.py`, national-ID rows
first, universal email and phone rows last). It is applied before the safety screen, before the
WORM audit write, before the Hrz7 payload leaves the process (there against EVERY jurisdiction's
rows, because the console is a shared sink), and before an agent tool result returns, because a
tool result becomes model context. The generator itself is handed engine FACTS plus retrieved
passages, not raw alert rows. Trace spans carry a fixed structural attribute set with no content
at all. `tests/unit/test_span_emission.py` proves no planted identifier reaches a span, and the
eval's `pii_safety` metric is scored two independent ways, a pack scan plus a planted-literal
oracle, with `tests/unit/test_not_falsely_green.py` proving it can go red.

### How is the work auditable and reproducible?

Every claim carries a `Citation`, back to the alert row it came from, the ATT&CK framework
instrument the technique came from, the retrieved runbook passage, or the resolved indicator. The
score is not a black box: `uplifts` records one arithmetic line per step (`baseline = 10`, then
`+weight` per distinct technique, then the clamped total), so an auditor re-derives it by hand.
The whole engine is pure stdlib and holds no clock, taking `as_of` from the caller, so the same
alerts always produce the same score, band and `signal_key` fingerprint on replay. The audit trail
is append-only, hash-chained AND externally anchored: the chain catches an edit, a deletion or a
reorder, and only the external head anchor catches a truncated tail, because a truncated chain
still verifies. `tests/unit/test_audit_anchor.py` proves both halves plus the control case. In
production the locked WORM Cloud Logging bucket (`infra/terraform/logging_worm.tf`, minimum 180
day retention, irreversible once locked) is the real guarantee, with **Hrz5** as the enterprise
sink.

### What is the model-risk story?

Bounded, and documented in [`../model-card.md`](../model-card.md). The model narrates and never
decides: stub the generation adapter out and every figure is unchanged, which is a standing test.
A draft that mentions a technique the engine did not map, or restates a wrong score, is discarded
for a deterministic fallback, so a hallucinated number cannot reach a reviewer. On top of that,
`eval/run_eval.py --mode smoke` runs in the offline gate on every change and scores six metrics
against the golden set's own INDEPENDENT oracle rather than against the pipeline's answer
(`correlation_accuracy`, `technique_mapping_exactness`, `disposition_accuracy`,
`runbook_groundedness`, `review_safety`, `pii_safety`, all at 0.99). `--mode gate` delegates the
promotion verdict to the sibling **Hrz4** AI-quality system under the bundle
`soc-fraud-fusion` and refuses to run off the managed profile. Two gaps are open and
should be read as such: the bundle is not yet registered with Hrz4 (P-08, R5), and the offline
eval scores the deterministic narrator rather than a live model, so a managed-profile eval run is
still owed. The model id is also a floating alias today rather than a pinned snapshot.

### Is data residency enforced, or only described?

Enforced at deploy time, with one honest caveat. The region is chosen once
(`asia-southeast1`), carried by `config/settings.yaml`, reported by `/healthz` and printed on the
agent card, and pinned in the infrastructure: plan-time validation of the effective region against
a residency allowlist, a `gcp.resourceLocations` Org Policy, CMEK, the locked WORM bucket, a
dry-run-first VPC Service Controls perimeter, and a regional serving edge. The P-03 row in
[`../../COMPLIANCE.md`](../../COMPLIANCE.md) names each file and is the evidence to cite; do not
read a second copy of it here. `infra/terraform/production_edge.tftest.hcl` turns those claims
into plan-only tests against a mocked provider, so they need no project and no credentials. The
caveat is the build wiring: this repo has no `tf-check` make target and no `terraform` CI job, so
that test runs only when somebody types `terraform -chdir=infra/terraform test`. Wiring it into a
pipeline is an adoption step, not a code change.

### Which regulators does this map to?

[`../../COMPLIANCE.md`](../../COMPLIANCE.md) is aligned to MAS TRM, APRA CPS 234 and CPS 230, HKMA
and PDPA-class regimes, and maps every internal principle P-01 to P-13 and every dependency rule
R1 to R8 to a control with an Evidence column naming real files. Crucially it uses an explicit
status vocabulary and does not overclaim: `Covered` means a test fails the build if the control
regresses, `Partial` means the in-repo half exists and the named deploy-time or platform half does
not, and `TODO (repo owner)` means NOT covered, with the row naming exactly what is owed. The
regulatory crosswalk itself is adopter-owned: copy the appendix, swap the regulator-reference
column and re-review with local counsel. At scale the sibling control-mapping and
compliance-advisory toolkits maintain those crosswalks rather than a hand-kept table here.

### Can we run it against real alert data today?

Not without your own legal, security and model-risk sign-off. Every fixture is obviously
fictional: invented parties suffixed FICTIONAL, RFC 5737 (`192.0.2.0/24`) and RFC 3849
(`2001:db8::/32`) addresses, `.example` domains. The single place real-world names appear is the
ATT&CK technique ids and names in `rulepacks/attack_map.yaml`, because a technique a responder
cannot look up is useless, and even there the citation `url` is deliberately blank so an adopter
points it at their own mirror. The adoption checklist in [`../ADOPTING.md`](../ADOPTING.md)
section 6 lists what must precede any live use: replace the fixtures, own the pack numbers, wire
your IdP audience, set the residency pair, move the audit store off `:memory:` and give it an
anchor, and rebuild the golden set.

### Where does this repo's compliance responsibility end?

At the boundary of what it produces. G5 owns the correlation, the score, the band, the citations,
the redaction before every boundary crossing and the routing of the escalation. It does NOT own
the human-review workflow or the approval record itself (**Hrz7**), the enterprise immutable audit
store and telemetry (**Hrz5**), the model promotion verdict (**Hrz4**), the governed corpus its
runbook passages come from (**Hrz2**), or the agent registry entry and entitlements (**Hrz3**).
The **Hrz1** guardrail gateway is deliberately outside the path: the G5 catalog row names Model
Armor and omits Hrz1, so screening is this repo's own `SafetyPort`. Project intake validation is
**Rsk3** (rule R6), an action to record rather than a control to build, and marketing screening
(**Mkt6**, rule R7) is not applicable because this service produces no customer-facing output.
