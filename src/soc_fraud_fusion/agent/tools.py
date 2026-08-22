"""Tool functions an agent runtime calls: thin, side-effect-honest wrappers on the services.

Design rules, in the order they matter:

* **No business logic here.** The domain service decides HOW; the model only decides WHICH tool
  to call. A rule that lives in a tool wrapper is a rule the CLI and the API do not have.
* **Rule R8 applies on this path too.** Every incident is consequential, so it is ROUTED from
  inside the tool, in the same call that produced it. An agent surface that only returned the
  flag would be a third place an escalation can quietly stop, after the API and the CLI.
* **Import-safe without a runtime.** ``google.adk`` is imported lazily inside
  :func:`build_function_tools`, so these callables are importable, testable and runnable with
  no ADK and no cloud SDK installed.
* **Typed and documented.** A runtime derives each tool's name, description and JSON parameter
  schema from the signature and the docstring, so both are part of the contract.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from hex_service_kit.serialization import to_jsonable
from pii_kit import redact

from ..config import Container, Settings, build_container
from ..domain.models import FusionRequest
from ..domain.pii import PII_PATTERNS
from ..factory import build_fusion_service

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from google.adk.tools import FunctionTool

#: The identity a tool call is attributed to when the runtime propagates none. It names the
#: SERVICE, not a person, so an unattributed action is never mistaken for a human's.
DEFAULT_ACTOR = "soc-fraud-fusion-agent"


def _container(settings: Settings | None) -> Container:
    return build_container(settings)


def _redacted(node: Any) -> Any:
    """Mask personal data in every string of a tool result, however deeply it is nested.

    A tool result is not an API response: it goes into a model's context, and P-04 says minimise
    what reaches a model. Walking the whole structure rather than named fields means a future
    field cannot arrive unredacted just because nobody remembered to add it.
    """
    if isinstance(node, str):
        return redact(node, PII_PATTERNS)
    if isinstance(node, dict):
        return {key: _redacted(value) for key, value in node.items()}
    if isinstance(node, list):
        return [_redacted(value) for value in node]
    return node


def triage_incident(
    subject: str,
    scope: str,
    actor: str = DEFAULT_ACTOR,
    tenant: str = "",
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Fuse a scope of alerts into one incident and route it for human review.

    Correlates the raw alerts into a deterministic, ATT&CK-mapped incident, drafts a cited
    summary and runbook, writes an already-redacted audit event, and submits the result to the
    human-review console (rule R8). The system never executes containment.

    Args:
      subject: The primary entity or case the incident is about.
      scope: The alert scope to fetch and correlate.
      actor: The verified identity this call is attributed to.
      tenant: The tenant whose alerts to read, and the partition asserted on the outbound
        review. Empty falls back to the configured tenant. A scope name is a label, not an
        entitlement, and this tool is the widest read surface in the repo: the MODEL chooses
        the argument, so the scope is not the tool's to widen.

    Returns:
      A JSON-safe result dict with every string masked for personal data (P-04), plus
      ``review_ref``: where the escalation WENT.
    """
    container = _container(settings)
    service = build_fusion_service(container)
    result = service.fuse(
        FusionRequest(subject=subject, scope=scope),
        actor=actor,
        tenant=tenant or container.settings.tenant,
    )
    review_ref = container.review_router.route(result, maker=actor, tenant=tenant)
    payload = _redacted(to_jsonable(result))
    if not isinstance(payload, dict):  # pragma: no cover - dataclasses serialise to objects
        raise TypeError("an incident assessment must serialise to a JSON object")
    # Attached after the redaction pass: it is a routing reference, not narrative text.
    payload["review_ref"] = review_ref
    return payload


def draft_runbook(
    subject: str,
    scope: str,
    actor: str = DEFAULT_ACTOR,
    tenant: str = "",
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Return the drafted, grounded response runbook for a fused incident.

    A read-only projection of :func:`triage_incident` for the case where the caller wants only
    the runbook steps. It still runs the full deterministic pipeline (the runbook is grounded in
    the correlated incident and retrieved passages), but it does not itself route: use
    :func:`triage_incident` for the consequential path.

    Args:
      subject: The primary entity or case the incident is about.
      scope: The alert scope to fetch and correlate.
      actor: The verified identity this call is attributed to.
      tenant: The tenant whose alerts to read. Empty falls back to the configured tenant; a
        tenant that owns nothing reads nothing, which is the fail-closed direction.

    Returns:
      A JSON-safe dict with the incident id, the grounded ``runbook`` steps and the ``grounded``
      flag, every string masked for personal data (P-04).
    """
    container = _container(settings)
    service = build_fusion_service(container)
    result = service.fuse(
        FusionRequest(subject=subject, scope=scope),
        actor=actor,
        tenant=tenant or container.settings.tenant,
    )
    payload = {
        "incident_id": result.incident.incident_id,
        "severity": result.severity.value,
        "recommended_action": result.incident.recommended_action.value,
        "runbook": list(result.runbook),
        "grounded": result.grounded,
        "requires_human_review": result.requires_human_review,
    }
    masked = _redacted(payload)
    if not isinstance(masked, dict):  # pragma: no cover - a dict always redacts to a dict
        raise TypeError("a runbook projection must be a JSON object")
    return masked


#: The tool table. The agent card advertises exactly these, by function name.
TOOL_FUNCTIONS = (triage_incident, draft_runbook)


def build_function_tools() -> list[FunctionTool]:
    """Wrap each callable as a runtime FunctionTool (the only ADK-dependent code path).

    The import is deliberately here rather than at module scope: without it this module, the
    card and every tool would need an agent runtime installed to be imported at all, and the
    offline gate installs none.
    """
    from google.adk.tools import FunctionTool

    return [FunctionTool(func=function) for function in TOOL_FUNCTIONS]
