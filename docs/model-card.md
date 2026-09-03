# Model card: SOC Fraud Fusion Copilot (G5)

This is a STARTER model card. It records the model boundary as built and the controls that must be
completed before a managed deployment. The deterministic engine is the system of record; the model
is a bounded, replaceable component that narrates what the engine already decided.

## What the model does, and does not do

- **Does**: from the engine-owned incident FACTS (incident id, subject, severity, score and the
  mapped ATT&CK techniques) plus the retrieved runbook passages and the resolved indicators, it
  drafts two things through `GenerationPort` (`ports/generation.py`): a cited **incident summary**
  and a **response runbook** as an ordered list of steps. Under the `gcp` profile that is Gemini
  on Vertex AI: `config/settings.yaml` carries the key
  `generation_model: ${FRAUDFUSION_GENERATION_MODEL:-gemini-3.5-flash}`, and
  `adapters/gcp/generation.py` passes that value as `model=` to
  `client.models.generate_content`. The prompt is assembled in `GeminiGeneration._prompt` and
  instructs the model to use only the facts supplied and to invent no figure, technique or
  indicator.
- **Does NOT**: produce any number, band, technique id or decision. The correlation itself, the
  score arithmetic (`baseline` plus one `+weight` per distinct contributing technique, clamped at
  `_SCORE_CEILING = 100`), the severity band, the signal-to-ATT&CK mapping and the containment
  RECOMMENDATION (`MONITOR` / `INVESTIGATE` / `CONTAIN`) are all computed by
  `domain/correlation_engine.py` in pure stdlib from `rulepacks/attack_map.yaml` pack data, and
  the escalation is unconditional in `domain/fusion_service.py`. The model also never chooses what
  is retrieved or what an indicator resolves to.
  `tests/unit/test_fusion_service.py::test_numbers_are_identical_with_the_generation_adapter_stubbed_out`
  is the standing proof: stub the generation adapter out entirely and every figure is unchanged,
  so a model swap cannot move a band. The system never executes containment.

## Boundary and validation

- **Redaction before anything leaves.** `FusionService._fuse` redacts the joined raw alert text
  with the jurisdiction pattern set from `domain/pii.py` BEFORE it is screened, so even a managed
  screening log never sees a raw identifier, and it redacts again before the WORM audit write
  (`tests/unit/test_fusion_service.py::test_pii_is_redacted_before_the_audit_write`). The outbound
  review payload is redacted against EVERY jurisdiction's rows in `adapters/_review_payload.py`,
  because the Hrz7 console is a shared sink
  (`tests/unit/test_review_routing.py::test_the_payload_is_redacted_before_it_leaves_the_process`).
  The generator itself is handed a `NarrationRequest` of engine facts, retrieved passages and
  grounding hits, not the raw alert rows.
- **Injection screening around the model.** This repo owns a `SafetyPort` (`ports/safety.py`)
  rather than delegating to the Hrz1 guardrail gateway, because its catalog row names Model Armor
  in the stack and omits Hrz1 from its dependencies. Input is screened before the generator could
  ever be reached, and on a block the generator is **not called at all**: `_narrate` returns the
  deterministic `_fallback` narrator with the block recorded in the text
  (`tests/unit/test_fusion_service.py::test_blocked_input_never_reaches_the_generation_port`).
  Output is screened after drafting and a blocked draft is likewise replaced by the fallback.
  Under `gcp` this is Model Armor's regional REST endpoint, `:sanitizeUserPrompt` inbound and
  `:sanitizeModelResponse` outbound, so screening stays inside the residency boundary
  (`adapters/gcp/safety.py`); the adapter imports `google.auth` FIRST so an offline profile raises
  rather than silently passing text through unscreened. Under `local` it is a deterministic
  marker heuristic (`adapters/local/safety.py`), which exists so the offline gate can prove the
  block path, not because it is a real screen. Under `onprem` it refuses.
- **The draft is validated against the engine, then discarded on failure.** `_valid()` in
  `domain/fusion_service.py` rejects the whole draft if it mentions any `Txxxx` or `Txxxx.yyy`
  token that is not one of the engine's mapped techniques, or states a `score N` that is not the
  engine's score. A rejected draft is replaced by `_fallback()`, which restates only the incident,
  the passages and the grounding, so it cannot be ungrounded, and triage never waits on
  generation.
  `tests/unit/test_fusion_service.py::test_a_hallucinated_draft_is_discarded_for_the_deterministic_fallback`
  is the standing gate.
- **R8 routing, unconditionally.** Every incident is consequential, so `IncidentAssessment` always
  carries `requires_human_review=True`, and the API, the CLI and the agent tool each route it to
  the Hrz7 console through `ReviewRouterPort` in the same call that produced it. A `CRITICAL` band
  demands two approvals (`_DUAL_CONTROL` in `adapters/_review_payload.py`). Nothing auto-executes:
  `tests/unit/test_review_routing.py` covers the routing on all three surfaces, and
  `tests/unit/test_fusion_service.py::test_every_incident_requires_human_review_and_never_auto_contains`
  covers the flag.

## Adapters and profiles

The narration edge:

| Profile | Generation adapter | Behaviour |
|---|---|---|
| `local` | `adapters/local/generation.py` | Deterministic grounded template built from engine facts, passages and grounding. SDK-free, no network. Also the fallback the orchestrator uses when a managed draft fails validation. |
| `gcp` | `adapters/gcp/generation.py` | Gemini on Vertex AI through the Google GenAI SDK, imported lazily inside `narrate`. Model id from `generation_model`. |
| `onprem` | `adapters/onprem/generation.py` | Fail-fast placeholder: raises `NotImplementedError` naming the client-hosted model as the migration target. |

Two neighbouring ports change what the model sees, so they belong on this card:

| Profile | Grounding (`ports/grounding.py`) | Retrieval (`ports/retrieval.py`) |
|---|---|---|
| `local` | Pure fixture lookup against the synthetic intel set (`adapters/local/grounding.py`). **No model is involved**, and an unresolved indicator simply produces no hit. | Naive term-overlap ranking over a fixture runbook corpus (`adapters/local/retrieval.py`). No model, no network. |
| `gcp` | `adapters/gcp/grounding.py` makes a SECOND generative call per indicator, on the same `generation_model`, and stores the reply text as both the verdict and the citation snippet. | `adapters/gcp/retrieval.py` queries the Hrz2 governed knowledge base through Discovery Engine search. Not a model call. |
| `onprem` | Fail-fast placeholder. | Fail-fast placeholder. |

Both are advisory to narration only. An incident's score, band, techniques and recommendation are
identical with either stubbed empty, which
`tests/unit/test_fusion_service.py::test_the_band_is_identical_with_retrieval_stubbed_empty`
proves. There is no speech, audio or vision port in this repo, and no fine-tuning anywhere: the
model is used zero-shot behind a prompt built from validated facts.

## Remaining controls (TODO, repo owner)

- **Pin the model id and version, in one place** (P-07). `generation_model` defaults to the
  floating alias `gemini-3.5-flash`, which is not a version pin: what serves can change with no
  diff. Pin a dated snapshot and record it here. Note also that `eval/run_eval.py` hardcodes
  `model="gemini-3.5-flash"` in the `PromotionGateClient` call while the runtime reads the
  setting, so today the promotion record and the deployed model can drift apart; make them read
  one source.
- **Pin the generation parameters and the response shape.** No temperature, top-p, seed, token cap
  or `response_schema` is set on the managed call, and the draft is split from the reply by a
  string `partition("RUNBOOK:")`. A structured response schema would turn a parse failure into a
  typed rejection rather than an empty runbook that still passes `_valid()`.
- **Screen the retrieved passages and the grounded verdicts, and screen the whole draft**
  (R1, P-09). The input screen covers the joined alert detail and the output screen covers
  `narration.narrative`; the passages and grounding hits reach the prompt unscreened, and the
  drafted `runbook` steps are validated but not screened. Both are real widening surfaces once
  retrieval points at a live corpus.
- **Budget, rate controls and a kill switch** (P-10, P-11). None exist: no per-tenant token
  budget, no request rate limit, no timeout or circuit breaker on the generation, grounding or
  safety calls, and no switch that forces deterministic-only operation with the model disabled.
  The deterministic fallback makes that switch cheap to add, because the engine-only path is
  already the tested default.
- **Run a managed-profile eval through the Hrz4 gate** (P-08, R5). The offline gate scores the
  deterministic local narrator against the golden set, so `runbook_groundedness` today measures a
  template. Register the bundle `soc-fraud-fusion` with Hrz4 and add a `gcp`-profile
  run that scores the real draft for groundedness and technique fidelity against the same cases.
- **Report model spend and latency to Hrz5** (R2). `adapters/gcp/tracer.py` can export OTLP to the
  Hrz5 collector, but no token usage is recorded against the generation or grounding calls, so
  cost per incident is currently unmeasured.

Until these are complete the system is safe to run offline, on the `local` profile, where the
deterministic engine and the deterministic narrator produce byte-identical results on replay and
no text leaves the process. The managed model path is functional but is **not production-cleared**:
treat any `gcp`-profile draft as a reviewer's convenience, never as evidence, and remember that
the score, the band, the ATT&CK techniques and the recommendation on that same screen came from
the engine and not from the model.
