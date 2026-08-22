"""Assemble the :class:`FusionService` from a container and the loaded ATT&CK pack.

Lives outside ``domain/`` because it reaches the config layer (the container and the pack loader).
The domain service stays pure and takes its ports and its engine by constructor injection; this is
the single place that wires them, so every surface (API, CLI, agent, demo, eval) builds the
service the same way.
"""

from __future__ import annotations

from .config import Container, Settings, build_container
from .domain.correlation_engine import CorrelationEngine
from .domain.fusion_service import FusionService
from .packs import attack_map_for


def build_fusion_service(
    container: Container | None = None, settings: Settings | None = None
) -> FusionService:
    """Build the fusion service over the given container (or a freshly loaded one)."""
    resolved = settings or (container.settings if container else Settings.load())
    box = container or build_container(resolved)
    engine = CorrelationEngine(attack_map_for(resolved.attack_pack_path))
    return FusionService(
        alerts=box.alerts,
        safety=box.safety,
        retrieval=box.retrieval,
        grounding=box.grounding,
        generation=box.generation,
        audit=box.audit,
        tracer=box.tracer,
        engine=engine,
    )
