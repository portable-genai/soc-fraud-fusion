"""GenerationPort: the narration edge (slice 4). The model narrates; it never decides.

Given only the engine-owned incident facts plus retrieved passages and grounding, the adapter
drafts an incident summary and a response runbook. The orchestrator VALIDATES the draft against a
schema (every figure and technique it restates must be present in the engine output) and DISCARDS
it on failure, falling back to a deterministic template, so a hallucinated number never survives
and interdiction never waits on generation. Primary GCP adapter calls Gemini with a lazy SDK
import; the local adapter is a deterministic grounded template; the on-prem adapter fails fast.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..domain.models import NarrationDraft, NarrationRequest


@runtime_checkable
class GenerationPort(Protocol):
    def narrate(self, request: NarrationRequest) -> NarrationDraft:
        """Draft a cited incident summary and response runbook from engine-owned facts only."""
        ...
