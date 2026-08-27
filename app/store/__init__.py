"""scanspot's own store of record.

Deliberately independent of whichever backend is being synced to. See
`docs/design/store.md` for the schema rationale; the two properties worth
remembering here:

  * identity is `(site_id, mac)`, never `mac` alone — RFC1918 ranges and even
    hardware repeat across offices;
  * current state lives in `endpoints`, change history in `events`. There is no
    per-cycle snapshot, because at a few thousand endpoints that grows without
    bound.
"""

from .db import Database, database_url, session_scope
from .models import (
    ApiKey,
    BackendSync,
    Base,
    Collector,
    CredentialProfile,
    DhcpPool,
    Endpoint,
    EndpointAddress,
    Event,
    Prefix,
    Run,
    Site,
    Target,
    Vlan,
)

__all__ = [
    "ApiKey",
    "BackendSync",
    "Base",
    "Collector",
    "CredentialProfile",
    "Database",
    "DhcpPool",
    "Endpoint",
    "EndpointAddress",
    "Event",
    "Prefix",
    "Run",
    "Site",
    "Target",
    "Vlan",
    "database_url",
    "session_scope",
]
