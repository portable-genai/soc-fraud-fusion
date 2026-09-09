"""Deterministic, obviously fictional fixtures shared by the SDK-free local adapters.

Every party is invented, every address is RFC 5737 (``192.0.2.0/24``) / RFC 3849
(``2001:db8::/32``), every domain is ``.example``. The alert scopes here are the ones the demo,
the eval golden set and the tests fetch, so a single change to the scenario stays consistent
across all three. Alerts carry a source ``signal_type`` that the ATT&CK pack maps to a technique;
the fixtures never carry a score or a technique id, because the engine owns those.
"""

from __future__ import annotations

from ... import demo_book
from ...domain.kernel import Citation
from ...domain.models import (
    Alert,
    GroundingHit,
    GroundingKind,
    RetrievedPassage,
)

#: The tenant every fixture alert belongs to. It matches the seeded personas' tenant, because
#: object-level authorization compares a row's data tag against the VERIFIED principal, and the
#: seeded personas are what the offline profile verifies.
FIXTURE_TENANT = "demo-bank"


def _book_alerts() -> dict[str, tuple[Alert, ...]]:
    """The shipped alerts, grouped by scope, straight from the book.

    They are NOT declared here any more. They live in
    ``soc_fraud_fusion/data/demo_book/alerts.ndjson``, because the deployment reads them from
    BigQuery and the offline profiles read them from DuckDB, and a third copy in Python is what
    made those two incomparable: a change to the demo moved what was narrated without moving
    what the gate measured. This module still owns the grounding corpus and the passages, which
    no warehouse table holds.
    """
    grouped: dict[str, list[Alert]] = {}
    for row in demo_book.BOOK.rows("alerts"):
        grouped.setdefault(str(row["scope"]), []).append(demo_book.to_alert(row))
    return {scope: tuple(alerts) for scope, alerts in grouped.items()}


#: scope -> the raw alerts an intake feed would return for it, read from the shipped book so
#: the demo, the eval and the two stores are all about the same rows.
ALERTS: dict[str, tuple[Alert, ...]] = _book_alerts()


#: A tiny runbook / threat-intel corpus the retrieval adapter serves.
PASSAGES: tuple[RetrievedPassage, ...] = (
    RetrievedPassage(
        source_id="runbook:ato-containment",
        title="Account-takeover containment runbook",
        snippet=(
            "On confirmed account takeover: force credential reset, revoke active sessions, "
            "quarantine newly enrolled devices, and open a fraud recovery case."
        ),
        locator="RB-ATO-3",
    ),
    RetrievedPassage(
        source_id="runbook:exfil-response",
        title="Data-exfiltration response runbook",
        snippet=(
            "On suspected exfiltration: block the egress destination, preserve host artefacts, "
            "and notify the data-protection officer within the incident SLA."
        ),
        locator="RB-EXF-2",
    ),
    RetrievedPassage(
        source_id="intel:mule-typology",
        title="Money-mule fan-out typology note",
        snippet=(
            "Rapid fan-out to many new payees shortly after inbound credit is a classic "
            "mule-laundering pattern; freeze onward payments pending review."
        ),
        locator="TI-MULE-1",
    ),
)


#: Indicator -> a fictional grounding verdict the grounding adapter resolves.
INTEL: dict[str, GroundingHit] = {
    "192.0.2.201": GroundingHit(
        indicator="192.0.2.201",
        kind=GroundingKind.IOC,
        verdict="known credential-stuffing proxy (FICTIONAL feed)",
        citation=Citation(
            source_id="intel:ioc-192.0.2.201",
            title="Threat-intel IOC record",
            snippet="Listed on a fictional brute-force proxy feed.",
        ),
    ),
    "malware.example": GroundingHit(
        indicator="malware.example",
        kind=GroundingKind.IOC,
        verdict="malware distribution host (FICTIONAL feed)",
        citation=Citation(
            source_id="intel:ioc-malware.example",
            title="Threat-intel IOC record",
            snippet="Fictional malware C2 / distribution domain.",
        ),
    ),
    "2001:db8::7": GroundingHit(
        indicator="2001:db8::7",
        kind=GroundingKind.IOC,
        verdict="beaconing C2 endpoint (FICTIONAL feed)",
        citation=Citation(
            source_id="intel:ioc-2001-db8-7",
            title="Threat-intel IOC record",
            snippet="Fictional command-and-control endpoint.",
        ),
    ),
}
