#!/usr/bin/env python3
"""Evaluation gate for SOC Fraud Fusion Copilot (G5).

Two named layers via ``--mode`` (the scaffold is ``agent_eval_kit.eval_main``):

* **smoke** (default) - the offline pre-merge check CI runs on every change: it drives the real
  ``FusionService`` against a golden set with SDK-free local adapters and scores several metrics.
* **gate** - the promotion verdict from the shared Hrz4 authority (requires the ``gcp`` profile),
  via ``agent_eval_kit.PromotionGateClient``.

Every metric is scored against the DATASET'S OWN ``expected_*`` fields (an independent golden
oracle, hand-computed from the fixtures), never against the pipeline's own verdict: a metric that
reads the pipeline's answer cannot go red. Exit is ``0`` iff every metric meets its threshold
(and, in gate mode, the authority agrees).
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from agent_eval_kit import EvalMetricResult, EvalReport, PromotionGateClient, eval_main
from pii_kit import pack_leak

from soc_fraud_fusion.adapters.local._fixtures import FIXTURE_TENANT
from soc_fraud_fusion.config import (
    Settings,
    build_container,
)
from soc_fraud_fusion.domain.models import (
    FusionRequest,
    IncidentAssessment,
)
from soc_fraud_fusion.domain.pii import (
    PII_PATTERNS,
)
from soc_fraud_fusion.factory import (
    build_fusion_service,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET = _REPO_ROOT / "eval" / "datasets" / "golden_cases.jsonl"

THRESHOLDS: dict[str, float] = {
    "correlation_accuracy": 0.99,
    "technique_mapping_exactness": 0.99,
    "disposition_accuracy": 0.99,
    "runbook_groundedness": 0.99,
    "review_safety": 0.99,
    "pii_safety": 0.99,
}
#: The registered Hrz4 metric bundle for this vertical (Hrz4 owns the metrics + thresholds).
_BUNDLE = "soc-fraud-fusion"

_TECHNIQUE_TOKEN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_SCORE_TOKEN = re.compile(r"score\s+(\d+)", re.IGNORECASE)
_AS_OF = "2026-08-05T10:00:00Z"


def _load(path: Path) -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cases.append(json.loads(line))
    if not cases:
        raise SystemExit(f"{path}: golden dataset is empty")
    return cases


def _mean(scores: list[float]) -> float:
    return round(sum(scores) / len(scores), 4) if scores else 0.0


def groundedness(result: IncidentAssessment, expected_techniques: set[str]) -> float:
    """1.0 iff the narrative restates ONLY techniques and a score the oracle allows.

    Scored against the DATASET's expected techniques and score, not the pipeline's: a narrative
    that cites a technique the oracle did not list, or a wrong score figure, scores 0.0.
    """
    text = f"{result.narrative} {' '.join(result.runbook)}"
    if any(token not in expected_techniques for token in _TECHNIQUE_TOKEN.findall(text)):
        return 0.0
    expected_score = result.incident.score
    return 0.0 if any(int(f) != expected_score for f in _SCORE_TOKEN.findall(text)) else 1.0


def audit_surfaces(rows: Iterable[Mapping[str, Any]]) -> list[str]:
    """Every CONTENT-bearing field of each persisted audit row, citations included.

    ``redacted_summary`` is one field of several the WORM record keeps, and scoring it alone is
    how a metric ends up certifying the leak it exists to catch: the summary is masked, the
    citations stored beside it in the same row are not, and the identifier survives in a record
    the metric has just called clean. Here that was not hypothetical: an alert citation's snippet
    IS the alert's free-text detail, so the metric read a masked summary while the raw line sat
    in the citation next to it.

    ``actor`` is deliberately absent. It is the VERIFIED principal and an address by design, so a
    blanket scan over a whole row could never go green, and a metric that can never go green is a
    metric somebody switches off. Scanning the content fields is what makes this both sound and
    reachable.
    """
    out: list[str] = []
    for row in rows:
        out.append(str(row.get("redacted_summary", "")))
        out.append(json.dumps(row.get("citations", []), sort_keys=True, default=str))
    return out


def pii_safety(surfaces: Sequence[str], planted: Sequence[str]) -> float:
    """1.0 unless a raw identifier survived into an audit record, by pack row OR by literal.

    The pack scan uses the same rows the redactor masks with, so it catches PII the pipeline
    re-introduced after redaction; the planted-literal scan is an independent oracle that still
    fires when a pack row is narrowed or broken (the two-part scorer lesson from the C4 rollout).
    """
    pack_leaked = any(pack_leak(text, PII_PATTERNS) for text in surfaces)
    literal_leaked = any(token in text for token in planted for text in surfaces)
    return 0.0 if (pack_leaked or literal_leaked) else 1.0


def run_smoke(dataset: Path) -> EvalReport:
    cases = _load(dataset)
    settings = Settings(profile="local", audit_path=":memory:", tenant="eval")
    container = build_container(settings)
    service = build_fusion_service(container)

    correlation: list[float] = []
    techniques: list[float] = []
    disposition: list[float] = []
    grounded: list[float] = []
    review: list[float] = []
    for case in cases:
        result = service.fuse(
            FusionRequest(subject=str(case["subject"]), scope=str(case["scope"])),
            actor="eval-bot",
            tenant=FIXTURE_TENANT,
            as_of=_AS_OF,
        )
        incident = result.incident
        # Each metric compares the pipeline output to the DATASET's own oracle value.
        correlation.append(
            1.0
            if incident.score == int(case["expected_score"])  # type: ignore[arg-type]
            and result.severity.value == case["expected_severity"]
            else 0.0
        )
        got = {hit.technique_id for hit in incident.techniques}
        want = set(case["expected_techniques"])  # type: ignore[arg-type]
        techniques.append(1.0 if got == want else 0.0)
        disposition.append(
            1.0 if incident.recommended_action.value == case["expected_action"] else 0.0
        )
        grounded.append(groundedness(result, want))
        review.append(1.0 if result.requires_human_review else 0.0)

    # pii_safety: no planted identifier may survive into any audit record.
    surfaces = audit_surfaces(container.audit.log.read_all())
    planted = [str(case["planted"]) for case in cases if case.get("planted")]

    results = (
        EvalMetricResult.scored(
            "correlation_accuracy", _mean(correlation), THRESHOLDS["correlation_accuracy"]
        ),
        EvalMetricResult.scored(
            "technique_mapping_exactness",
            _mean(techniques),
            THRESHOLDS["technique_mapping_exactness"],
        ),
        EvalMetricResult.scored(
            "disposition_accuracy", _mean(disposition), THRESHOLDS["disposition_accuracy"]
        ),
        EvalMetricResult.scored(
            "runbook_groundedness", _mean(grounded), THRESHOLDS["runbook_groundedness"]
        ),
        EvalMetricResult.scored("review_safety", _mean(review), THRESHOLDS["review_safety"]),
        EvalMetricResult.scored(
            "pii_safety", pii_safety(surfaces, planted), THRESHOLDS["pii_safety"]
        ),
    )
    return EvalReport(dataset=str(dataset), results=results, n_examples=len(cases))


def run_gate(dataset: Path) -> tuple[EvalReport, bool]:
    settings = Settings.load()
    if settings.profile != "gcp":
        raise SystemExit(
            "--mode gate is the promotion authority and requires "
            f"FRAUDFUSION_PROFILE=gcp (got {settings.profile!r}); "
            "run --mode smoke for the offline pre-merge check."
        )
    client = PromotionGateClient(
        os.environ.get("FRAUDFUSION_QUALITY_URL", "http://localhost:8084"),
        bundle=_BUNDLE,
        model="gemini-2.5-flash",
    )
    return client.evaluate(str(dataset)), client.gate(str(dataset))


if __name__ == "__main__":
    raise SystemExit(
        eval_main(
            smoke=run_smoke,
            gate=run_gate,
            default_dataset=DEFAULT_DATASET,
            description="Offline / Hrz4 evaluation gate for G5.",
        )
    )
