# Security FAQ

For an AppSec reviewer sizing up this repo. It explains what the attack surface is, what is
deliberately out of scope (and why that is honest, not a gap), and where the evidence lives.
Cross-references: [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md),
[`../../COMPLIANCE.md`](../../COMPLIANCE.md), [`../runbook.md`](../runbook.md).

## What does this system actually process?

Raw security-and-fraud alert rows fetched by scope through `AlertFeedPort`: an alert id, a source
system, an entity, an asset, an indicator, a canonical signal type, an ISO 8601 timestamp and a
free-text detail (`Alert` in `domain/models.py`). Those details are operational text written by
SIEM and fraud engines, so they CAN carry customer identifiers, which is why redaction is a
standing invariant rather than an option. The service produces one correlated incident with a
score, a severity band, ATT&CK technique ids, a containment recommendation, a drafted summary and
a drafted runbook. It never executes containment, and it writes nothing back to the alert sources.

## How is identity handled? Can a caller spoof the actor?

No. Identity is resolved server-side on every route. `api/schemas.py::FuseRequest` carries only
`subject` and `scope`, with no `actor` field to spoof, and the verified `Principal` is what becomes
the audit actor and the review maker. Under `gcp`, `adapters/gcp/identity.py` verifies the Cloud
IAP-injected assertion: `id_token.verify_token` is called with the configured
`FRAUDFUSION_IAP_AUDIENCE`, with IAP's own certificate set rather than google-auth's OAuth2
default, and the issuer is checked in the adapter because `verify_token` does not check it. That
audience is three-state and BOTH unset and emptied refuse every caller, because google-auth
documents `audience=None` as "the audience is not verified", which would accept any Google-signed
OIDC token from any project. `tests/unit/test_iap_identity.py` runs in every gate;
`tests/unit/test_iap_crypto_matrix.py` runs the real verifier over locally minted assertions in
the `iap-verifier` CI job (wired by the `iap-matrix-path` input in the hosted GitHub Actions check)
and fails if it skips. Under `local` the personas are seeded dev
identities from `X-Dev-Persona` that authenticate nobody; under `onprem` the adapter refuses.

## What stops an unauthenticated peer reaching it?

`add_loopback_exposure_guard` is bound at MODULE scope in `api/app.py`, not inside `main()`,
because the Dockerfile `CMD` and `make run-api` serve the app OBJECT. Its posture is derived from
the identity BINDING and from nothing else: an adapter declares `VERIFIED`, `CLIENT_ASSERTED` or
`UNIMPLEMENTED` (`ports/identity.py`) and silence reads as client-asserted. So the seeded-persona
posture, the unconfigured posture and the on-premises placeholder all bind loopback and refuse
non-loopback peers with a 503. Setting the inbound `FRAUDFUSION_S2S_TOKEN` closes the
service-to-service routes and opens nothing else: it authenticates a calling SERVICE and no end
user, and `tests/unit/test_end_user_auth_posture.py` walks the guard's argument through the
constants it names to fail the build if a credential ever reappears in that decision.
`tests/unit/test_serving_path_exposure.py` is the standing gate on the module-scope bind. As a
second consequence, `/docs`, `/redoc` and `/openapi.json` are registered only under the deliberate
`local` exposure profile: under `gcp` those routes are ABSENT rather than guarded.

## What screens prompt-injected alert text, and why is it not `agent-guardrail-gateway`?

This repo owns a `SafetyPort` (`ports/safety.py`) instead of routing through the `agent-guardrail-gateway`, and that is a recorded design decision: the G5 catalog row names Model Armor in its stack
and omits `agent-guardrail-gateway` from its dependencies. `FusionService._fuse` screens the joined alert detail on the
INPUT side before the generator could be reached, and on a block the generation port is **not
called at all**: a deterministic fallback narrator records the block instead
(`tests/unit/test_fusion_service.py::test_blocked_input_never_reaches_the_generation_port`). The
drafted narrative is screened on the OUTPUT side and a blocked draft is likewise replaced. Under
`gcp` this is Model Armor's regional REST endpoint (`:sanitizeUserPrompt` and
`:sanitizeModelResponse`, so screening stays in-region); the adapter imports `google.auth` FIRST so
an offline profile raises rather than silently passing text through unscreened. Under `local` the
screen is a deterministic marker heuristic, which exists to prove the block path in the offline
gate and is not a real screen. Two honest limits are listed in
[`../model-card.md`](../model-card.md): retrieved passages and grounding verdicts reach the prompt
unscreened, and the output screen covers the narrative but not the drafted runbook steps.

## Is PII ever written anywhere raw?

Not on any path the tests cover. Redaction happens at every boundary crossing, not once:
`FusionService._fuse` redacts the joined alert text with `domain/pii.py`'s pattern set BEFORE the
safety screen (so even a managed screening log never sees a raw identifier) and again before the
WORM audit write; `adapters/_review_payload.py` redacts subject, summary and every citation
snippet before the `human-review-console` wire, and it does so against EVERY jurisdiction's national-ID rows plus the
universal email and phone rows, because the console is a shared sink; `agent/tools.py` masks tool
results before they return, because a tool result becomes model context (P-04) while an API
response to the caller who supplied the text does not. Evidence:
`tests/unit/test_fusion_service.py::test_pii_is_redacted_before_the_audit_write`,
`tests/unit/test_review_routing.py::test_the_payload_is_redacted_before_it_leaves_the_process`,
and `tests/unit/test_not_falsely_green.py::test_pii_safety_can_go_red`, which proves the eval's
leak metric is capable of failing. Trace spans carry a fixed structural attribute set (action and
actor only), guarded by `tests/unit/test_span_emission.py`, because a trace backend has no
redaction stage and a wider read audience than the audit trail.

## Are there secrets in the repo?

No literal secret material. `config/settings.yaml` holds only `${VAR:-default}` interpolation
tokens (project id, region, datastore, Model Armor template, model id, local paths);
`.env.example` documents the non-secret names; `.env.secrets.example` documents the secret NAMES
with placeholders. Inbound and outbound credentials are deliberately distinct variables
(`FRAUDFUSION_S2S_TOKEN` for this service as callee, `HUMAN_REVIEW_S2S_TOKEN` and `HUMAN_REVIEW_S2S_SIGNING_KEY`
for the outbound `human-review-console` calls), so one cannot be reused as the other. On the deploy side,
`additional_secret_env` in `infra/terraform/variables.tf` mounts secrets by immutable version id
and refuses `"latest"`, and it refuses any name reserved by `naming.tf` so a secret cannot shadow
the residency, identity or routing wiring. Practices-audit check C10 covers this.

## What is the supply-chain posture?

Committed lockfiles (`requirements-dev.lock`, `requirements-gcp.lock`), installed by `make
install`, CI and the Dockerfile as "lock first, then the project with `--no-deps`", so the lock
stays authoritative. The four commons packages are declared by tag in `pyproject.toml` and pinned
in the lockfiles to the 40-character COMMIT each tag resolved to, because a tag can be moved and a
commit cannot; `tests/unit/test_repo_artifacts.py` asserts that three-way agreement offline.
Beyond that: a digest-pinned non-root image, SHA-pinned Actions, per-ecosystem dependabot, and
`pip-audit` plus `npm audit` as HARD CI failures. Checks D1, D2 and D4 in
[`../practices-audit.md`](../practices-audit.md) carry the detail.

## Is the audit trail tamper-evident?

Yes, within honest limits, and the limit is the interesting part. The local sink is append-only
and hash-chained via `hex_service_kit`, which catches an in-place edit, a deletion and a reorder.
It does NOT catch a truncated tail on its own, because dropping the newest rows leaves a shorter
chain that verifies perfectly. That is why `audit_anchor_path` (`FRAUDFUSION_AUDIT_ANCHOR`) writes
the chain head to a file on a different volume under different credentials on every append, and
why once store and anchor disagree the service refuses to append rather than re-anchoring.
`tests/unit/test_audit_anchor.py` proves the detection, proves the CONTROL case goes undetected
without an anchor, and proves the refusal. In production the managed WORM sink is the real
guarantee: a locked Cloud Logging bucket (`infra/terraform/logging_worm.tf`, irreversible once
`worm_locked = true`) fed by the audit sink, with `agent-observability` as the enterprise store.

## What is explicitly out of scope for this repo?

The governed knowledge base (`enterprise-knowledge-base`), the agent registry (`agent-registry`), the AI-quality and
model-risk promotion gate (`model-quality-gate`), the enterprise observability and WORM audit platform
(`agent-observability`), and the human-review and maker-checker console (`human-review-console`). This repo integrates those
through ports and thin adapters rather than re-implementing them. The `agent-guardrail-gateway` is
deliberately not in the path for the reason above. Also out of scope: the alert sources
themselves, any containment or response ACTION, and the enterprise IdP. See
[features-faq.md](features-faq.md) for the full boundary map.
