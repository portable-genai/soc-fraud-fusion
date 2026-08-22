"""AlertFeedPort: raw cited security-and-fraud alert rows (the intake edge, slice 1).

The port RETURNS raw rows and computes nothing: correlation, scoring and ATT&CK mapping are the
deterministic engine's job, so a port that scored would move consequential logic out of the pure
core. Primary GCP adapter reads a BigQuery alert table with a lazy SDK import; the local adapter
serves deterministic fictional fixtures; the on-prem adapter fails fast.

**Every read is tenant-scoped, and the tenant is a required argument.** This port took a scope
name and nothing else, so an authenticated caller from any tenant who named a scope received
another bank's whole alert set, correlated into an incident with its detail lines quoted back.
Object-level authorization cannot live at the call site, because there are several of them and
only one has to forget; making ``tenant`` a keyword-only parameter of the protocol means a caller
with no tenant to pass does not compile rather than silently reading everything.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..domain.models import Alert


@runtime_checkable
class AlertFeedPort(Protocol):
    def fetch(self, scope: str, *, tenant: str) -> list[Alert]:
        """Return ``tenant``'s raw, cited alert rows in ``scope`` (never scored, correlated).

        A scope that belongs to another tenant returns the same EMPTY list an unknown scope
        returns. "No alerts in this scope" is already this port's valid answer, so reusing it
        means the response cannot be read as "that scope exists, but not for you", which is what
        a distinct refusal would say.
        """
        ...
