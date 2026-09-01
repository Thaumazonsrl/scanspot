"""The FastAPI application and the server that hosts it.

Served from the same process as the scheduler, on purpose. "One container,
point it at your NetBox" is the whole appeal of this thing, and splitting into
api + worker + a message broker buys nothing until there is more than one
replica. APScheduler already runs cycles on a background thread, so a long SNMP
walk does not block a request.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Callable

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from .. import __version__
from ..store.db import Database
from ..store.models import ApiKey
from .keys import generate_key, hash_key, redact
from .routes import router

log = logging.getLogger("api")

DESCRIPTION = """
Network discovery, served from scanspot's own store.

Nothing here proxies a backend: the payload is scanspot's model, so an
integration that writes into LibreNMS, Zabbix or an in-house CMDB gets the same
data NetBox does — serials, VLANs and switch-port location included.

Authenticate with `X-API-Key: <key>` or `Authorization: Bearer <key>`.
"""


def create_app(
    database: Database, scan_trigger: Callable[[], object] | None = None
) -> FastAPI:
    app = FastAPI(
        title="scanspot",
        version=__version__,
        description=DESCRIPTION,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.database = database
    app.state.scan_trigger = scan_trigger
    app.include_router(router)

    ui_file = Path(__file__).parent / "static" / "ui.html"

    @app.get("/", include_in_schema=False)
    @app.get("/ui", include_in_schema=False)
    def management_ui() -> HTMLResponse:
        """A small management page for targets and credentials.

        Deliberately one static file talking to the same /api/v1 endpoints as
        any other client: whatever the UI can do, an integrator can do too, and
        there is no second code path to keep in step.

        The key lives in the browser's localStorage and travels as a header —
        no cookie, so there is nothing for CSRF to attack.
        """
        if not ui_file.is_file():
            return HTMLResponse("<h1>UI not bundled in this image</h1>", status_code=404)
        return HTMLResponse(ui_file.read_text(encoding="utf-8"))

    return app


def ensure_bootstrap_key(database: Database) -> str | None:
    """Create a first API key if none exists, and return it.

    Returned — and logged — exactly once. Only the hash is stored, so an
    operator who misses it must issue a new key rather than recover this one.
    """
    with database.session_scope() as session:
        if session.query(ApiKey).filter(ApiKey.revoked_at.is_(None)).count():
            return None
        key = generate_key()
        session.add(
            ApiKey(name="bootstrap", key_hash=hash_key(key), scopes={"admin": True})
        )
    return key


def log_bootstrap_key(key: str) -> None:
    line = "─" * 72
    log.warning(line)
    log.warning("A first API key has been generated. It is shown ONCE:")
    log.warning("")
    log.warning("    %s", key)
    log.warning("")
    log.warning("Store it now. Only its hash is kept, so it cannot be recovered.")
    log.warning("Issue another and revoke this one with the /api/v1 endpoints.")
    log.warning(line)


class _ThreadedServer(uvicorn.Server):
    """uvicorn installs SIGINT/SIGTERM handlers, which only the main thread may
    do. The scheduler owns those signals here, so this server must not."""

    def install_signal_handlers(self) -> None:
        return


def serve_in_background(app: FastAPI, host: str, port: int) -> threading.Thread:
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        # Keep uvicorn's own logging out of the way: the application already
        # configures a formatter and access logs would drown the cycle output.
        log_config=None,
        access_log=False,
    )
    server = _ThreadedServer(config)
    thread = threading.Thread(target=server.run, name="api", daemon=True)
    thread.start()
    log.info("API listening on http://%s:%d/api/v1 (docs at /api/docs)", host, port)
    return thread
