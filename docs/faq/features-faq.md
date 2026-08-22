# Features FAQ

For product owners, SOC leads and fraud-operations teams: what this agent does, what is
deterministic vs LLM, and, importantly, where its responsibilities **stop** and a sibling catalog
system takes over. Cross-references: [`../../README.md`](../../README.md),
[`../../DEMO.md`](../../DEMO.md), [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md),
[`../../SPEC.md`](../../SPEC.md).

### What does G5 actually produce?

One cited, ATT&CK-mapped **incident**. Given a subject and a scope, it fetches the raw alerts that
scope holds (a SIEM row, an identity-provider row, a fraud-engine row) and reconciles them into a
single `Incident` carrying: the contributing alert ids, the deduplicated entities, assets and
timeline, the MITRE ATT&CK techniques the signals map to, an auditable score with one arithmetic
line per uplift, a severity band, a containment RECOMMENDATION, a stable `signal_key` fingerprint,
and a `Citation` for every claim. Around that it produces a drafted incident summary and a
grounded response runbook. The whole result is written to an already-redacted WORM audit record
and routed to a human reviewer. Fusing the same alerts twice produces the same `signal_key`, so a
replay diffs to nothing.

### What is deterministic vs done by the LLM?

Everything consequential is deterministic, pure stdlib and replayable in
`domain/correlation_engine.py`: the correlation itself, the signal-to-ATT&CK lookup from pack
data, the score, the severity band and the recommendation. The LLM only **narrates**: an incident
summary and a runbook draft, from facts the engine already produced. It never sets a number, a
band, a technique id or a recommendation, and the proof is a test rather than a promise:
`tests/unit/test_fusion_service.py::test_numbers_are_identical_with_the_generation_adapter_stubbed_out`
stubs generation out entirely and every figure is unchanged. A draft that restates a technique the
engine did not map, or a `score N` that is not the engine's score, is DISCARDED for a deterministic
fallback narrator (`_valid` and `_fallback` in `domain/fusion_service.py`). See
[`../model-card.md`](../model-card.md) for the full model boundary.

### How is the score computed, exactly?

`baseline` plus one `+weight` per DISTINCT contributing ATT&CK technique, clamped at 100. Distinct
matters: three alerts carrying the same signal type add the weight once, so a single flapping
sensor cannot inflate a band. An alert whose signal type is not in the pack contributes nothing at
all, because the engine never invents a mapping. Every step is kept as a human-readable
`uplifts` line (`baseline = 10`, then `+25 T1110.004 (credential_stuffing)`, then
`+30 T1078 (impossible_travel)`, then `= 65 (clamped to 100)`), so a reviewer re-derives the
number by hand. The numbers themselves are pack DATA in
`rulepacks/attack_map.yaml` (`baseline: 10`, `medium_at: 30`, `high_at: 55`, `critical_at: 80` and
a per-technique weight), which is what a SOC lead diffs when retuning.

### Is anything auto-executed? Does it contain a host or freeze an account?

No. `MONITOR`, `INVESTIGATE` and `CONTAIN` are RECOMMENDATIONS, named as such in
`RecommendedAction`. Every incident is treated as consequential, so `requires_human_review` is
unconditionally true and the result is ROUTED to the **Hrz7** Human-Review and Maker-Checker
Console through the shared `review-kit` in the same call that produced it (rule R8), on the
API, the CLI and the agent-tool paths alike. A `CRITICAL` band demands two approvals. The payload
is redacted before the wire and the verified principal is threaded as maker. The agent proposes;
a responder disposes; this system executes nothing.

### What happens if a source alert contains prompt-injected text?

It is screened before it can reach the generator, and on a block the generator is not called at
all: a deterministic fallback narration records the block instead. Screening runs through this
repo's own `SafetyPort` (Model Armor under `gcp`), on the way in and on the way out. Crucially the
correlation step is UNAFFECTED by the safety verdict: the score reflects the structured signal
types, not the free text, so injected prose can suppress the narration but cannot move a band.

### Which capabilities does this repo own vs integrate from the catalog?

This is one system in a catalog of composable GRC systems. It **owns** the fusion domain logic and
its outputs. It **integrates** several cross-cutting concerns owned by sibling systems. Do not
rebuild these in a fork:

| Concern | Owned by (catalog id) | G5's role |
|---|---|---|
| Governed RAG / ACL-aware knowledge base with citations | **Hrz2** | consumes it for runbook and threat-intel passages (`adapters/gcp/retrieval.py`), advisory to narration only |
| Agent registry, versioning, identity, entitlements | **Hrz3** | publishes its A2A card at `/.well-known/agent-card.json`; registering it is the open R4 item |
| AI-quality / eval / model-risk promotion gate | **Hrz4** | `eval/run_eval.py --mode gate` delegates the verdict under bundle `soc-fraud-fusion`; the offline smoke run mirrors its thresholds |
| Observability + immutable WORM audit + FinOps | **Hrz5** | exports spans OTLP to its collector when `OTEL_EXPORTER_OTLP_ENDPOINT` is set; the shared audit sink is the open R2 item |
| Human review / maker-checker console | **Hrz7** | routes EVERY incident's escalation to it (R8); you wire `HRZ_HUMAN_REVIEW_URL`, you do not build a console |
| Runtime guardrail gateway | **Hrz1** | deliberately NOT in this path: the G5 catalog row names Model Armor in the stack and omits Hrz1, so screening runs through this repo's own `SafetyPort` (`ports/safety.py`) |
| Architecture and requirements intake validation | **Rsk3** | an intake action, not a code control (rule R6): record the validation reference in `COMPLIANCE.md` |
| Marketing / financial-promotions claim check | **Mkt6** | not applicable (rule R7, P-13): this service produces no customer-facing output |

So the knowledge base, the registry, the eval platform, the audit sink and the review console are
*dependencies*, not features of this repo.

### Where exactly does this repo's responsibility end?

At the reviewer's inbox. G5 does not own the alert sources (it reads them through `AlertFeedPort`
and writes nothing back), it does not own case management or the investigation workflow after the
escalation is filed, it does not own any response or containment ACTION, it does not own the
enterprise identity provider (auth is configured ON the deployed service), and it does not own the
promotion decision for its own model (that is Hrz4's). If a capability you want sits past that
line, check whether a sibling catalog system already has a home for it before building it here.

### Can I use this for a different vertical?

Yes, and the seams are named. The reusable core (the hexagon, the three profiles, the
deterministic-engine-plus-narrating-model pattern, citations, the anchored audit trail, the eval
harness and the R8 routing) transfers to any correlate-then-recommend copilot. What you replace is
the pack (`rulepacks/attack_map.yaml`), the artifact models in `domain/models.py`, the fixtures and
the golden set. `domain/kernel.py` stays untouched:
[`../ADOPTING.md`](../ADOPTING.md) has the keep-vs-rewrite table and the checklist, and
[adoption-faq.md](adoption-faq.md) answers the "will it hurt later?" questions.

### How do I see it working?

Everything runs offline on synthetic data with no cloud and no API key.
`make demo` starts a loopback server and walks the presenter through eight steps, narrating each
on the terminal and never on the page; `make demo-server` serves the same panels for a
click-through; `make demo-static` renders the audit-first HTML for screenshots;
`make demo-selftest` runs the identical arc headless and asserts every step, which is what stops
the demo rotting. From the CLI, one fused incident end to end is
`soc_fraud_fusion fuse "user:acme-treasury" "ato-acme"`. Every party, address and domain
in the fixtures is fictional (RFC 5737 and RFC 3849 addresses, `.example` domains). See
[`../../DEMO.md`](../../DEMO.md).
