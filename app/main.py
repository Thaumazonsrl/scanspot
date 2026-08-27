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

from . import __version__, targets
from .api import (
    create_app,
    ensure_bootstrap_key,
    log_bootstrap_key,
    serve_in_background,
)
from .backends.netbox.cleanup import run_cleanup
from .backends.netbox.client import NetBoxClient
from .backends.netbox.import_targets import import_targets
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
from .store.bootstrap import ensure_site, run_migrations
from .store.db import Database
from .store.persist import begin_run, finish_run, mark_stale_offline, persist_result
from .store.repository import Repository
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


def run_cycle(config: AppConfig, client: NetBoxClient, database: Database) -> dict:
    with cycle_lock(config) as acquired:
        if not acquired:
            log.warning(
                "another scan cycle is already running — skipping this one "
                "(the heartbeat is left untouched)"
            )
            return {"status": "skipped"}
        return _run_cycle(config, client, database)


def prepare_store(config: AppConfig, database: Database) -> None:
    """Create the site and the credential profiles.

    Runs at startup rather than inside the first cycle, because the cycle waits
    for NetBox. Without this the API would come up early — as designed — and
    then refuse every write with "no site exists yet", which is exactly the
    situation it was brought forward to avoid.
    """
    with database.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, config.netbox.site_name)
        targets.sync_credentials(repo, config, site)


def prepare_targets(config: AppConfig, client: NetBoxClient, database: Database) -> None:
    """Refresh the target list from the store, seeding or importing if empty.

    Re-read every cycle so a target added through the API is picked up without
    restarting the container — the same property the NetBox tag used to give.
    """
    with database.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, config.netbox.site_name)
        targets.sync_credentials(repo, config, site)

        # NetBox keeps offering targets every cycle, so tagging a device still
        # puts it under scan without a restart. One-way and idempotent: see
        # import_targets for the ownership rule.
        import_targets(client, repo, site, config)

        # The seed is a first-run convenience only, and must not shadow devices
        # an existing 1.x deployment already has in NetBox.
        if repo.target_count(site) == 0:
            targets.apply_seed(repo, config, site)

        config.fortigates, config.switches = targets.load_targets(repo, config, site)


def _run_cycle(config: AppConfig, client: NetBoxClient, database: Database) -> dict:
    started = utcnow()
    log.info("─" * 72)
    log.info("scan cycle started")

    outcome: dict = {"started": to_iso(started), "synced": False, "cleaned": False}

    try:
        client.bootstrap()
        prepare_targets(config, client, database)
    except Exception as exc:
        log.exception("could not load the scan targets: %s", exc)
        outcome["status"] = "error"
        outcome["error"] = str(exc)[:300]
        _write_heartbeat(config, outcome, started)
        return outcome

    if not config.fortigates and not config.switches:
        log.warning(
            "no scan target defined — add one through the API, or tag a device "
            "'scan-target' in NetBox and restart to import it"
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
        _record_run(config, database, result, started, "failed")
        _write_heartbeat(config, outcome, started)
        return outcome

    # The store is written first, and unconditionally: what the network reported
    # is recorded even if NetBox is unreachable a moment later. The backends are
    # exporters of this data, not the place it lives.
    run_id = None
    try:
        run_id = _record_run(config, database, result, started, "ok", persist=True)
        outcome["stored"] = True
    except Exception as exc:
        # A store failure must not cost the NetBox sync — that is still the
        # thing the operator is looking at today.
        log.exception("could not write the scanspot store: %s", exc)
        outcome["error"] = str(exc)[:300]

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

    if run_id is not None:
        try:
            with database.session_scope() as session:
                finish_run(session, run_id, outcome["status"], utcnow(), round(duration, 1))
        except Exception as exc:
            log.warning("could not close the run record: %s", exc)

    log.info("scan cycle finished in %.1fs — %s", duration, outcome["status"])
    _write_heartbeat(config, outcome, started)
    return outcome


def _record_run(
    config: AppConfig,
    database: Database,
    result: CollectionResult,
    started,
    status: str,
    persist: bool = False,
) -> int | None:
    """Open a run record, and optionally merge the collection into the store."""
    with database.session_scope() as session:
        site = ensure_site(session, config.netbox.site_name)
        run = begin_run(session, site, result, started)
        if not persist:
            run.status = status
            run.finished_at = utcnow()
            return run.id
        persist_result(
            session, site, run, result, started, config.netbox.default_prefix_len
        )
        mark_stale_offline(
            session, site, started, config.lifecycle.offline_after_hours
        )
        return run.id


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
    log.info("scan targets        : scanspot store")
    log.info(
        "api                 : %s",
        f"http://{config.api.host}:{config.api.port}/api/v1"
        if config.api.enabled
        else "disabled (API_ENABLED=false)",
    )
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

    # The container migrates its own store: no separate step for an operator to
    # forget, and no window in which the code is newer than the schema.
    try:
        database = Database()
        run_migrations(database)
        prepare_store(config, database)
    except Exception as exc:
        log.exception("could not open the scanspot store: %s", exc)
        return 4

    client = NetBoxClient(config.netbox, dry_run=config.scanner.dry_run)

    daemon = not (args.check or args.once)

    # Started before NetBox is waited on, deliberately. A fresh NetBox takes
    # three to five minutes to apply its own migrations, and that is exactly
    # when an operator wants /health to answer and targets to be manageable.
    # The API only needs the store, which is already open.
    if daemon and config.api.enabled:
        # Issued before the server starts, so the key lands in the log above the
        # first request rather than buried after it.
        bootstrap_key = ensure_bootstrap_key(database)
        if bootstrap_key:
            log_bootstrap_key(bootstrap_key)
        api = create_app(
            database,
            scan_trigger=lambda: run_cycle(config, client, database),
        )
        serve_in_background(api, config.api.host, config.api.port)

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
        log.info("configuration, store and NetBox connectivity are OK")
        return 0

    if args.once:
        outcome = run_cycle(config, client, database)
        return 0 if outcome.get("status") in ("ok", "degraded", "idle", "skipped") else 1

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(
        run_cycle,
        trigger=IntervalTrigger(minutes=config.scanner.interval_minutes),
        args=[config, client, database],
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
            run_cycle(config, client, database)
        except Exception:
            log.exception("initial cycle failed")

    while not _shutdown:
        time.sleep(1)

    scheduler.shutdown(wait=True)
    log.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
