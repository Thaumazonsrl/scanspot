"""Entry point.

    python -m app.main            run forever on the configured interval
    python -m app.main --once     run a single cycle and exit (for testing)
    python -m app.main --check    validate configuration and connectivity only

One cycle:
    collect FortiGate  ->  collect SNMP  ->  correlate  ->  push to NetBox
    ->  age out stale records
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import logging
import signal
import sys
import time

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from . import __version__
from .backends.netbox import targets
from .backends.netbox.cleanup import run_cleanup
from .backends.netbox.client import TAG_SCAN_TARGET, NetBoxClient
from .backends.netbox.sync import (
    build_prefix_index,
    sync_dhcp_pools,
    sync_endpoints,
    sync_infrastructure,
    sync_prefixes,
    sync_vlans,
)
from .collectors import fortigate, snmp
from .config import AppConfig, ConfigError, load_config
from .logging_setup import setup_logging
from .models import CollectionResult, SwitchInfo
from .utils import to_iso, utcnow

log = logging.getLogger("scanner")

_shutdown = False


# ───────────────────────────────────────────────────────────── collection ──
def collect_all(config: AppConfig) -> CollectionResult:
    result = CollectionResult()

    for fgt in config.fortigates:
        try:
            fortigate.collect(fgt, result)
            result.firewalls_ok += 1
        except Exception as exc:  # a dead firewall must not abort the cycle
            result.firewalls_failed += 1
            log.error("FortiGate '%s' (%s) failed: %s", fgt.name, fgt.host, exc)

    for switch in config.switches:
        try:
            result.switches.append(snmp.collect(switch, result))
            result.switches_ok += 1
        except Exception as exc:
            result.switches_failed += 1
            result.switches.append(
                SwitchInfo(
                    name=switch.name,
                    host=switch.host,
                    vendor=switch.vendor,
                    reachable=False,
                    error=str(exc),
                )
            )
            log.error("switch '%s' (%s) failed: %s", switch.name, switch.host, exc)

    log.info("collected %s", result.summary())
    return result


# ─────────────────────────────────────────────────────────────────── cycle ──
@contextlib.contextmanager
def cycle_lock(config: AppConfig):
    """Serialise cycles across processes.

    The scheduler already refuses to overlap itself (`max_instances=1`), but the
    documented way to force a scan is `docker exec … --once` *while the daemon
    is running*. Two cycles then walk the same switch at the same time, neither
    sees the other's writes, and both create a Device for the same MAC — the
    second one landing under a "-a1b2" suffix because the name is taken. An
    advisory lock on the state directory is what makes that command safe.
    """
    config.scanner.state_dir.mkdir(parents=True, exist_ok=True)
    handle = open(config.scanner.state_dir / "cycle.lock", "w")
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        handle.close()


def run_cycle(config: AppConfig, client: NetBoxClient) -> dict:
    with cycle_lock(config) as acquired:
        if not acquired:
            log.warning(
                "another scan cycle is already running — skipping this one "
                "(the heartbeat is left untouched)"
            )
            return {"status": "skipped"}
        return _run_cycle(config, client)


def _run_cycle(config: AppConfig, client: NetBoxClient) -> dict:
    started = utcnow()
    log.info("─" * 72)
    log.info("scan cycle started")

    outcome: dict = {"started": to_iso(started), "synced": False, "cleaned": False}

    # The target list lives in NetBox, so it is re-read every cycle: a switch
    # added from the GUI is picked up without restarting the container.
    try:
        client.bootstrap()
        targets.seed(client, config)
        config.fortigates, config.switches = targets.load_targets(client, config)
    except Exception as exc:
        log.exception("could not load the scan targets: %s", exc)
        outcome["status"] = "error"
        outcome["error"] = str(exc)[:300]
        _write_heartbeat(config, outcome, started)
        return outcome

    if not config.fortigates and not config.switches:
        log.warning(
            "no scan target defined — add a device in NetBox, tag it '%s' and "
            "fill in its 'Scan address' custom field",
            TAG_SCAN_TARGET,
        )
        outcome["status"] = "idle"
        _write_heartbeat(config, outcome, started)
        return outcome

    result = collect_all(config)
    sources_ok = result.firewalls_ok + result.switches_ok

    outcome.update(
        {
            "macs": len(result.observations),
            "firewalls_ok": result.firewalls_ok,
            "firewalls_failed": result.firewalls_failed,
            "switches_ok": result.switches_ok,
            "switches_failed": result.switches_failed,
        }
    )

    if sources_ok == 0:
        # Never let a total collection outage look like "the network is empty".
        log.error(
            "no data source responded — skipping the NetBox sync and the cleanup "
            "so that existing records are not aged out by a connectivity problem"
        )
        outcome["status"] = "failed"
        _write_heartbeat(config, outcome, started)
        return outcome

    try:
        index = build_prefix_index(
            client, result.l3_interfaces, config.netbox.default_prefix_len
        )

        sync_vlans(client, result)
        sync_prefixes(client, result)
        sync_dhcp_pools(client, result, index)
        sync_infrastructure(client, config, result, index, started)
        sync_endpoints(client, result, index, started)
        outcome["synced"] = True

        stats = run_cleanup(client, config.lifecycle, started)
        outcome["cleaned"] = True
        outcome["cleanup"] = stats.summary()
    except Exception as exc:
        log.exception("NetBox synchronisation failed: %s", exc)
        outcome["status"] = "error"
        outcome["error"] = str(exc)[:300]
        _write_heartbeat(config, outcome, started)
        return outcome

    duration = (utcnow() - started).total_seconds()
    outcome["status"] = "degraded" if (result.firewalls_failed or result.switches_failed) else "ok"
    outcome["duration_seconds"] = round(duration, 1)
    log.info("scan cycle finished in %.1fs — %s", duration, outcome["status"])
    _write_heartbeat(config, outcome, started)
    return outcome


def _write_heartbeat(config: AppConfig, outcome: dict, started) -> None:
    """The healthcheck reads this file; it is the container's liveness proof."""
    try:
        config.scanner.state_dir.mkdir(parents=True, exist_ok=True)
        payload = {**outcome, "finished": to_iso(utcnow()), "version": __version__}
        config.heartbeat_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as exc:
        log.warning("could not write heartbeat file: %s", exc)


# ───────────────────────────────────────────────────────────────── startup ──
def describe(config: AppConfig) -> None:
    log.info("scanspot %s", __version__)
    log.info("client              : %s", config.netbox.client_name)
    log.info("netbox site         : %s", config.netbox.site_name)
    log.info("netbox url          : %s", config.netbox.url)
    log.info("scan targets        : read from NetBox (tag '%s')", TAG_SCAN_TARGET)
    log.info(
        "credential profiles : %s",
        ", ".join(sorted(config.credentials)) or "none",
    )
    log.info(
        "seed devices        : %s",
        ", ".join(f"{s.name}@{s.host}" for s in config.seeds) or "none",
    )
    log.info("interval            : every %d minutes", config.scanner.interval_minutes)
    log.info(
        "retention           : offline after %dh, delete after %dd (auto-delete %s)",
        config.lifecycle.offline_after_hours,
        config.lifecycle.delete_after_days,
        "on" if config.lifecycle.enable_auto_delete else "off",
    )
    log.info("static reservations : never auto-deleted")
    if config.scanner.dry_run:
        log.warning("DRY_RUN is enabled — nothing will be written to NetBox")


def _handle_signal(signum, _frame) -> None:
    global _shutdown
    log.info("received signal %s — shutting down after the current cycle", signum)
    _shutdown = True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scanspot")
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"scanspot {__version__}",
        help="print the version and exit",
    )
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    parser.add_argument(
        "--check", action="store_true", help="validate config and connectivity, then exit"
    )
    args = parser.parse_args(argv)

    try:
        config = load_config()
    except ConfigError as exc:
        setup_logging("INFO")
        log.error("configuration error: %s", exc)
        return 2

    setup_logging(config.scanner.log_level)
    describe(config)

    client = NetBoxClient(config.netbox, dry_run=config.scanner.dry_run)

    # NetBox may still be applying migrations when the scanner starts.
    for attempt in range(1, 31):
        try:
            client.connect()
            break
        except Exception as exc:
            if attempt == 30:
                log.error("NetBox is not reachable at %s: %s", config.netbox.url, exc)
                return 3
            log.info("waiting for NetBox (%d/30): %s", attempt, exc)
            time.sleep(10)

    if args.check:
        log.info("configuration and NetBox connectivity are OK")
        return 0

    if args.once:
        outcome = run_cycle(config, client)
        return 0 if outcome.get("status") in ("ok", "degraded", "idle", "skipped") else 1

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(
        run_cycle,
        trigger=IntervalTrigger(minutes=config.scanner.interval_minutes),
        args=[config, client],
        id="scan",
        name="network scan",
        max_instances=1,          # never overlap two cycles
        coalesce=True,            # a missed run is executed once, not N times
        misfire_grace_time=300,
    )
    scheduler.start()
    log.info("scheduler started — next cycle in %d minutes", config.scanner.interval_minutes)

    if config.scanner.run_on_start:
        try:
            run_cycle(config, client)
        except Exception:
            log.exception("initial cycle failed")

    while not _shutdown:
        time.sleep(1)

    scheduler.shutdown(wait=True)
    log.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
