"""Bringing the store up on startup.

The container migrates itself: there is no separate migration step for an
operator to forget, and no window in which the code is newer than the schema.

Alembic is driven programmatically rather than by shelling out, so a failure
surfaces as an exception with a stack trace instead of an exit code.
"""

from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config

from .db import Database
from .models import Site
from ..utils import slugify

log = logging.getLogger("store")

# app/store/bootstrap.py -> app/store -> app -> <root>
_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = _ROOT / "alembic.ini"
MIGRATIONS = _ROOT / "app" / "store" / "migrations"


def alembic_config(url: str) -> Config:
    if not ALEMBIC_INI.is_file():
        raise RuntimeError(
            f"alembic.ini not found at {ALEMBIC_INI}. In a container this means "
            "the image was built without it — check the Dockerfile COPY."
        )
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(MIGRATIONS))
    # The application owns logging; env.py must not reconfigure it. Without
    # this the whole process goes silent after the first migration.
    config.attributes["configure_logger"] = False
    # env.py leaves this alone when it is already set, so migrations and the
    # application can never disagree about which database they are touching.
    config.set_main_option("sqlalchemy.url", url)
    return config


def run_migrations(database: Database) -> None:
    log.info("applying database migrations")
    command.upgrade(alembic_config(database.url), "head")


def ensure_site(session, name: str) -> Site:
    """Get or create a site by slug. The slug is derived from the name, so the
    same NETBOX_SITE value always resolves to the same row."""
    slug = slugify(name)
    site = session.query(Site).filter_by(slug=slug).one_or_none()
    if site is None:
        site = Site(slug=slug, name=name)
        session.add(site)
        session.flush()
        log.info("created site '%s'", name)
    return site
