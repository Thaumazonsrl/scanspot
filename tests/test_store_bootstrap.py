"""Tests for store bootstrap.

The logging test exists because of a real bug: Alembic's `fileConfig()` runs
with `disable_existing_loggers=True` by default, which silences every logger
created before it. The symptom was a scanner that worked perfectly and printed
nothing at all after applying its first migration.
"""

import logging

from app.logging_setup import setup_logging
from app.store.bootstrap import alembic_config, ensure_site, run_migrations
from app.store.db import Database
from app.store.models import Site


def test_migrations_create_the_schema(tmp_path):
    database = Database(url=f"sqlite:///{tmp_path / 'm.db'}")
    run_migrations(database)

    from sqlalchemy import inspect

    tables = inspect(database.engine).get_table_names()
    assert "alembic_version" in tables
    assert "targets" in tables
    assert "endpoints" in tables
    database.dispose()


def test_migrations_do_not_silence_application_logging(tmp_path):
    """A regression here makes the whole container go quiet."""
    setup_logging("INFO")
    before = logging.getLogger().level
    scanner = logging.getLogger("scanner")

    database = Database(url=f"sqlite:///{tmp_path / 'log.db'}")
    run_migrations(database)
    database.dispose()

    assert logging.getLogger().level == before, "root log level was reconfigured"
    assert scanner.disabled is False, "application loggers were disabled"
    assert scanner.isEnabledFor(logging.INFO), "INFO logging was lost"


def test_alembic_config_opts_out_of_logging_configuration(tmp_path):
    config = alembic_config(f"sqlite:///{tmp_path / 'x.db'}")
    assert config.attributes.get("configure_logger") is False


def test_migrations_are_idempotent(tmp_path):
    database = Database(url=f"sqlite:///{tmp_path / 'i.db'}")
    run_migrations(database)
    run_migrations(database)  # already at head
    database.dispose()


def test_ensure_site_is_stable_for_the_same_name(tmp_path):
    database = Database(url=f"sqlite:///{tmp_path / 's.db'}")
    run_migrations(database)

    with database.session_scope() as session:
        first = ensure_site(session, "Head Office")
        first_id = first.id

    with database.session_scope() as session:
        again = ensure_site(session, "Head Office")
        assert again.id == first_id
        assert session.query(Site).count() == 1

    database.dispose()


def test_ensure_site_slugifies_the_name(tmp_path):
    database = Database(url=f"sqlite:///{tmp_path / 'sl.db'}")
    run_migrations(database)
    with database.session_scope() as session:
        assert ensure_site(session, "Head Office").slug == "head-office"
    database.dispose()
