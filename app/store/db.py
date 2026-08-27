"""Engine and session handling.

One knob: `SCANSPOT_DB_URL`.

    sqlite:////app/state/scanspot.db     default — no extra service to run
    postgresql+psycopg://user:pw@host/db opt-in — required for multi-replica

The choice of engine and the choice of locking travel together. SQLite means a
single node and the existing `fcntl` cycle lock; PostgreSQL makes
`pg_advisory_lock()` available, which is the same guarantee across pods.
"""

from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

log = logging.getLogger("store")

DEFAULT_SQLITE_PATH = "/app/state/scanspot.db"


def database_url() -> str:
    """Resolve the DSN, defaulting to SQLite inside the state volume."""
    explicit = (os.environ.get("SCANSPOT_DB_URL") or "").strip()
    if explicit:
        return explicit
    state_dir = (os.environ.get("STATE_DIR") or "/app/state").strip()
    return f"sqlite:///{Path(state_dir) / 'scanspot.db'}"


def is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def is_postgres(url: str) -> bool:
    return url.startswith("postgres")


def _configure_sqlite(engine: Engine) -> None:
    """SQLite needs three pragmas to behave like a real database here."""

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection, _record):  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        # Off by default in SQLite. Without it every ON DELETE CASCADE in the
        # schema is silently ignored and orphan rows accumulate.
        cursor.execute("PRAGMA foreign_keys=ON")
        # The scheduler polls on a background thread while the API reads; WAL
        # lets readers proceed during a write instead of getting SQLITE_BUSY.
        cursor.execute("PRAGMA journal_mode=WAL")
        # Wait rather than fail if a write is genuinely in flight.
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()


class Database:
    """Owns the engine and hands out sessions."""

    def __init__(self, url: str | None = None, echo: bool = False):
        self.url = url or database_url()
        kwargs: dict = {"echo": echo, "future": True, "pool_pre_ping": True}

        if is_sqlite(self.url):
            # APScheduler runs cycles on a background thread, so connections
            # cross threads by design.
            kwargs["connect_args"] = {"check_same_thread": False}
            self._ensure_parent_directory()

        self.engine = create_engine(self.url, **kwargs)
        if is_sqlite(self.url):
            _configure_sqlite(self.engine)

        self._session_factory = sessionmaker(
            bind=self.engine, expire_on_commit=False, future=True
        )
        log.info("store: %s", self.safe_url)

    def _ensure_parent_directory(self) -> None:
        path = self.url.split("sqlite:///", 1)[-1]
        if path and path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)

    @property
    def safe_url(self) -> str:
        """The DSN with any password removed, for logging."""
        if "@" not in self.url:
            return self.url
        scheme, _, rest = self.url.partition("://")
        credentials, _, host = rest.rpartition("@")
        user = credentials.split(":", 1)[0]
        return f"{scheme}://{user}:***@{host}"

    def session(self) -> Session:
        return self._session_factory()

    @contextlib.contextmanager
    def session_scope(self) -> Iterator[Session]:
        """Commit on success, roll back on failure, always close."""
        session = self.session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def dispose(self) -> None:
        self.engine.dispose()


@contextlib.contextmanager
def session_scope(database: Database) -> Iterator[Session]:
    with database.session_scope() as session:
        yield session
