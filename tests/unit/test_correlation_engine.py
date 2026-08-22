"""The deterministic correlation engine: scoring arithmetic, ATT&CK mapping, replayability.

The engine owns the consequential decision, so this is where the score arithmetic, the band
thresholds and the technique mapping are pinned. A model produces none of them.
"""

from __future__ import annotations

from soc_fraud_fusion.adapters.local._fixtures import ALERTS
from soc_fraud_fusion.domain.correlation_engine import CorrelationEngine
from soc_fraud_fusion.domain.kernel import Severity
from soc_fraud_fusion.domain.models import RecommendedAction
from soc_fraud_fusion.packs import attack_map_for


def _engine() -> CorrelationEngine:
    return CorrelationEngine(attack_map_for())


def test_the_score_is_baseline_plus_one_uplift_per_distinct_technique_clamped() -> None:
    incident = _engine().correlate(ALERTS["ato-acme"], subject="user:acme-treasury", as_of="t")
    # baseline 10 + 25 + 30 + 25 + 20 + 35 = 145, clamped to 100.
    assert incident.score == 100
    assert incident.severity is Severity.CRITICAL
    assert incident.recommended_action is RecommendedAction.CONTAIN
    assert incident.uplifts[0] == "baseline = 10"
    assert incident.uplifts[-1].endswith("(clamped to 100)")


def test_each_alert_maps_to_its_attack_technique_by_pure_lookup() -> None:
    incident = _engine().correlate(ALERTS["ato-acme"], subject="user:acme-treasury", as_of="t")
    ids = {hit.technique_id for hit in incident.techniques}
    assert ids == {"T1110.004", "T1078", "T1621", "T1098.005", "T1041"}
    for hit in incident.techniques:
        assert hit.citation.source_id, "every technique hit must carry a framework citation"


def test_a_signal_absent_from_the_pack_maps_to_no_technique_and_adds_no_score() -> None:
    incident = _engine().correlate(ALERTS["routine-beta"], subject="user:beta-ops", as_of="t")
    assert incident.techniques == ()
    assert incident.score == 10  # baseline only
    assert incident.severity is Severity.LOW
    assert incident.recommended_action is RecommendedAction.MONITOR


def test_a_repeated_signal_type_is_counted_once() -> None:
    engine = _engine()
    alerts = ALERTS["ato-acme"]
    doubled = alerts + (alerts[0],)  # the same credential_stuffing signal twice
    once = engine.correlate(alerts, subject="s", as_of="t")
    twice = engine.correlate(doubled, subject="s", as_of="t")
    assert twice.score == once.score, "alert volume must not inflate the score, only techniques do"


def test_the_signal_key_is_stable_across_replays_and_ignores_as_of() -> None:
    engine = _engine()
    first = engine.correlate(ALERTS["mule-gamma"], subject="account:gamma-99", as_of="2026-01-01")
    second = engine.correlate(ALERTS["mule-gamma"], subject="account:gamma-99", as_of="2026-12-31")
    assert first.signal_key == second.signal_key, "the fingerprint must not depend on the clock"
    assert first.incident_id == second.incident_id


def test_an_empty_alert_set_is_a_low_empty_incident_not_an_error() -> None:
    incident = _engine().correlate((), subject="user:nobody", as_of="t")
    assert incident.severity is Severity.LOW
    assert incident.alert_ids == ()
    assert incident.techniques == ()
