"""The ATT&CK map pack loads fail-closed: a malformed pack must never start the engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from soc_fraud_fusion.packs import AttackPackError, attack_map_for, load_pack

_GOOD = """
version: "t"
citations:
  attack: {title: "MITRE ATT&CK"}
policy: {baseline: 10, medium_at: 30, high_at: 55, critical_at: 80}
techniques:
  - {signal_type: s1, technique_id: T1000, tactic: x, name: n, weight: 25, citation: attack}
"""


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "pack.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_the_reference_pack_loads_and_maps_every_shipped_signal() -> None:
    attack = attack_map_for()
    by_signal = attack.by_signal()
    assert "credential_stuffing" in by_signal
    assert by_signal["credential_stuffing"].technique_id == "T1110.004"
    assert attack.policy.critical_at == 80


def test_a_good_pack_round_trips(tmp_path: Path) -> None:
    attack = load_pack(_write(tmp_path, _GOOD))
    assert attack.by_signal()["s1"].weight == 25


def test_a_technique_with_an_undefined_citation_is_refused(tmp_path: Path) -> None:
    body = _GOOD.replace("citation: attack", "citation: missing")
    with pytest.raises(AttackPackError, match="citation"):
        load_pack(_write(tmp_path, body))


def test_a_non_increasing_band_policy_is_refused(tmp_path: Path) -> None:
    body = _GOOD.replace("high_at: 55", "high_at: 20")
    with pytest.raises(AttackPackError, match="increasing"):
        load_pack(_write(tmp_path, body))


def test_a_duplicate_signal_mapping_is_refused(tmp_path: Path) -> None:
    body = _GOOD + (
        "  - {signal_type: s1, technique_id: T1001, tactic: x, name: n, weight: 5, "
        "citation: attack}\n"
    )
    with pytest.raises(AttackPackError, match="twice"):
        load_pack(_write(tmp_path, body))


def test_a_missing_pack_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(AttackPackError, match="does not exist"):
        load_pack(tmp_path / "nope.yaml")
