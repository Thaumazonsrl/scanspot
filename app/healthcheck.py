"""Container healthcheck.

Healthy when the scanner completed a cycle recently enough. "Recently" is two
missed intervals plus a 10 minute allowance for a slow poll, so a single long
SNMP walk never flaps the container.

A cycle that ran but found every data source unreachable is reported as
unhealthy: the scanner is alive, but it is not doing its job.
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

from .config import env_int, env_str
from .utils import from_iso, utcnow


def main() -> int:
    heartbeat = Path(env_str("STATE_DIR", "/app/state")) / "last_run.json"
    interval = max(1, env_int("SCAN_INTERVAL_MINUTES", 20))
    allowance = timedelta(minutes=interval * 2 + 10)

    if not heartbeat.is_file():
        print("no cycle has completed yet")
        return 1

    try:
        payload = json.loads(heartbeat.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"unreadable heartbeat: {exc}")
        return 1

    finished = from_iso(payload.get("finished"))
    if finished is None:
        print("heartbeat has no timestamp")
        return 1

    stale_for = utcnow() - finished
    if stale_for > allowance:
        print(f"last cycle finished {stale_for} ago (allowance {allowance})")
        return 1

    status = payload.get("status", "unknown")
    if status == "failed":
        print("last cycle reached no data source")
        return 1

    print(f"ok — last cycle {status} at {payload.get('finished')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
