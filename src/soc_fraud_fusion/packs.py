"""Loader for the ATT&CK map and scoring pack (config into pure-domain values).

Lives OUTSIDE ``domain/`` because it reads YAML from disk, and the domain core stays pure stdlib
with no I/O. It turns the reference pack shipped at ``rulepacks/attack_map.yaml`` (or an adopter's
own file, selectable by ``attack_map.pack_path`` in ``config/settings.yaml``) into one immutable
:class:`~soc_fraud_fusion.domain.models.AttackMap` that the correlation engine takes as a
parameter.

Why a pack file rather than constants in the engine: which signal maps to which ATT&CK technique,
its score weight, and where the band thresholds sit are policy, not algorithm. Tuning them, or
adding a signal, must be a config change a SOC lead can read and diff. The engine never learns a
signal's name.

Loading is fail-closed: an unreadable file, a technique with no citation, a citation id the pack
does not define, a non-integer weight or a missing policy number raises
:class:`AttackPackError`. A fusion engine running on a silently empty or partly-parsed pack would
under-score real incidents, so it must not start at all.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .domain.kernel import Citation
from .domain.models import AttackMap, FusionPolicy, TechniqueDef

DEFAULT_PACK_PATH = Path(__file__).resolve().parent / "rulepacks" / "attack_map.yaml"

_POLICY_KEYS = ("baseline", "medium_at", "high_at", "critical_at")


class AttackPackError(RuntimeError):
    """Raised when the ATT&CK map pack is missing, malformed or internally inconsistent."""


def _fail(message: str) -> Any:
    raise AttackPackError(f"attack-map pack: {message}")


def _citations(doc: dict[str, Any]) -> dict[str, Citation]:
    raw = doc.get("citations") or {}
    if not isinstance(raw, dict) or not raw:
        _fail("no 'citations' block; every technique must name the framework it comes from")
    out: dict[str, Citation] = {}
    for citation_id, spec in raw.items():
        if not isinstance(spec, dict) or not str(spec.get("title", "")).strip():
            _fail(f"citation {citation_id!r} has no title (a citation must name its framework)")
        out[str(citation_id)] = Citation(
            source_id=str(citation_id),
            title=str(spec.get("title", "")).strip(),
            snippet=" ".join(str(spec.get("snippet", "")).split()),
        )
    return out


def _policy(doc: dict[str, Any]) -> FusionPolicy:
    raw = doc.get("policy") or {}
    if not isinstance(raw, dict):
        _fail("'policy' must be a mapping of the scoring numbers")
    numbers: dict[str, int] = {}
    for key in _POLICY_KEYS:
        if key not in raw:
            _fail(f"'policy' is missing {key!r}")
        try:
            numbers[key] = int(raw[key])
        except (TypeError, ValueError):
            _fail(f"'policy.{key}' must be an integer, got {raw[key]!r}")
    if not (numbers["medium_at"] < numbers["high_at"] < numbers["critical_at"]):
        _fail("'policy' band thresholds must be strictly increasing medium < high < critical")
    return FusionPolicy(
        baseline=numbers["baseline"],
        medium_at=numbers["medium_at"],
        high_at=numbers["high_at"],
        critical_at=numbers["critical_at"],
    )


def _techniques(doc: dict[str, Any], citations: dict[str, Citation]) -> tuple[TechniqueDef, ...]:
    raw = doc.get("techniques") or []
    if not isinstance(raw, list) or not raw:
        _fail("no 'techniques' block; the map cannot correlate without signal->technique rows")
    out: list[TechniqueDef] = []
    seen: set[str] = set()
    for spec in raw:
        if not isinstance(spec, dict):
            _fail("each technique must be a mapping")
        signal_type = str(spec.get("signal_type", "")).strip()
        technique_id = str(spec.get("technique_id", "")).strip()
        if not signal_type or not technique_id:
            _fail("a technique row needs both 'signal_type' and 'technique_id'")
        if signal_type in seen:
            _fail(f"signal_type {signal_type!r} is mapped twice; a signal maps to one technique")
        seen.add(signal_type)
        citation_id = str(spec.get("citation", "") or "")
        if citation_id not in citations:
            _fail(f"{signal_type}: citation {citation_id!r} is not defined in the pack")
        try:
            weight = int(spec.get("weight"))
        except (TypeError, ValueError):
            _fail(f"{signal_type}: 'weight' must be an integer, got {spec.get('weight')!r}")
        if weight < 0:
            _fail(f"{signal_type}: 'weight' must not be negative")
        out.append(
            TechniqueDef(
                signal_type=signal_type,
                technique_id=technique_id,
                tactic=str(spec.get("tactic", "")).strip(),
                name=str(spec.get("name", "")).strip(),
                weight=weight,
                citation=citations[citation_id],
            )
        )
    return tuple(out)


def load_pack(path: str | Path | None = None) -> AttackMap:
    """Load and validate the ATT&CK map pack from ``path`` (default: the reference pack)."""
    pack_path = Path(path) if path else DEFAULT_PACK_PATH
    if not pack_path.exists():
        _fail(f"pack file {pack_path} does not exist; the fusion engine cannot run without it")
    try:
        doc = yaml.safe_load(pack_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise AttackPackError(f"attack-map pack: {pack_path} is not valid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        _fail(f"{pack_path} must contain a mapping")
    citations = _citations(doc)
    return AttackMap(
        version=str(doc.get("version", "")),
        techniques=_techniques(doc, citations),
        policy=_policy(doc),
    )


@lru_cache(maxsize=4)
def _cached_pack(resolved: str) -> AttackMap:
    return load_pack(resolved)


def attack_map_for(pack_path: str = "") -> AttackMap:
    """Resolve the active ATT&CK map (adopter override, else the shipped reference pack)."""
    return _cached_pack((pack_path or "").strip() or str(DEFAULT_PACK_PATH))
