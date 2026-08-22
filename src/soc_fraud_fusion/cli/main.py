"""Minimal stdlib CLI: fuse a scope of alerts into an incident (argparse, no extra deps)."""

from __future__ import annotations

import argparse
import sys

from hex_service_kit.logging import configure_logging

from ..config import build_container
from ..domain.models import FusionRequest
from ..factory import build_fusion_service


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soc_fraud_fusion")
    sub = parser.add_subparsers(dest="command", required=True)

    fuse_cmd = sub.add_parser("fuse", help="Fuse the alerts in a scope into one incident.")
    fuse_cmd.add_argument("subject", help="The primary entity or case the incident is about.")
    fuse_cmd.add_argument("scope", help="The alert scope to fetch and correlate.")
    fuse_cmd.add_argument("--actor", default="cli-user@bank.example")
    fuse_cmd.add_argument(
        "--tenant",
        default="",
        help="Tenant whose alerts to read, and the partition asserted to Hrz7.",
    )

    args = parser.parse_args(argv)
    container = build_container()
    # Idempotent: a process that is both an API app and a CLI configures once.
    configure_logging(container.settings.profile, service="soc-fraud-fusion")

    if args.command == "fuse":
        service = build_fusion_service(container)
        result = service.fuse(
            FusionRequest(subject=args.subject, scope=args.scope),
            actor=args.actor,
            tenant=args.tenant or container.settings.tenant,
        )
        incident = result.incident
        print(f"{incident.incident_id}: {result.severity.value} ({result.decision.value})")
        print(f"  score arithmetic: {' '.join(incident.uplifts)}")
        techniques = ", ".join(t.technique_id for t in incident.techniques) or "none"
        print(f"  ATT&CK techniques: {techniques}")
        print(f"  recommended action: {incident.recommended_action.value}")
        print(f"  requires_human_review: {result.requires_human_review}")
        # Rule R8 on the CLI path too: the same escalation, the same router. Every incident is
        # consequential, so this always routes. A surface that only printed the flag would be a
        # second place for an escalation to stop.
        ref = container.review_router.route(result, maker=args.actor, tenant=args.tenant)
        print(f"  routed to human review: {ref}")
        return 0

    return 2  # pragma: no cover - argparse requires a subcommand


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
