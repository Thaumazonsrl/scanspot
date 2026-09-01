"""HTTP API over scanspot's store.

The store is the only thing this reads: an API that forwarded to NetBox would
be a NetBox client, not a discovery service, and would have nothing to say the
day the backend is phpIPAM.
"""

from .app import create_app, ensure_bootstrap_key, log_bootstrap_key, serve_in_background

__all__ = [
    "create_app",
    "ensure_bootstrap_key",
    "log_bootstrap_key",
    "serve_in_background",
]
