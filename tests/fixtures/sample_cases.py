"""Canonical synthetic cases, shared by the unit and contract suites.

Every party is obviously fictional and every address is an ``.example`` domain or an RFC 5737 /
RFC 3849 literal. One canonical high-severity scope and one canonical routine scope are enough for
the suites: parity means the SAME request through every implementation, so the request has one
home rather than being retyped per test.
"""

from __future__ import annotations

from soc_fraud_fusion.domain.models import (
    FusionRequest,
)

#: The verified principal the tests attribute work to (never a client-asserted actor).
ACTOR = "analyst@bank.example"

#: A tenant partition, so the outbound-review assertions are not all on the empty string.
TENANT = "demo-bank"

#: A fixed clock the tests pass in, so the engine holds none and results are byte-identical.
AS_OF = "2026-08-05T10:00:00Z"

#: A scope whose fixture alerts correlate into a CRITICAL incident (rule R8 always applies).
ESCALATING_CASE = FusionRequest(subject="user:acme-treasury", scope="ato-acme")

#: A scope whose one alert carries no mapped signal, so it stays LOW.
ROUTINE_CASE = FusionRequest(subject="user:beta-ops", scope="routine-beta")

#: A scope that also carries a money-mule fan-out plus a malware beacon.
MULE_CASE = FusionRequest(subject="account:gamma-99", scope="mule-gamma")

#: A planted identifier, so a redaction assertion has an independent literal to look for rather
#: than trusting the pattern pack to agree with itself. It is injected into a fixture alert detail
#: (see ``adapters/local/_fixtures.py`` scope ``pii-delta``) for the redact-before-write proofs.
PLANTED_NRIC = "S1234567D"

#: The address planted in the same fixture alert, so the proof has two independent literals: a
#: national id the pack matches by checksum and an address it matches by shape.
PLANTED_EMAIL = "ops@delta.example"

#: A scope carrying an alert whose free text contains the planted national id.
PII_CASE = FusionRequest(subject="user:delta-fx", scope="pii-delta")
