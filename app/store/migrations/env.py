"""Alembic environment.

The DSN comes from `app.store.db.database_url()` rather than alembic.ini, so
`alembic upgrade head` always targets the same database the application uses.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.store.db import database_url, is_sqlite
from app.store.models import Base

config = context.config

# Only configure logging for a bare `alembic upgrade head` on the command line.
#
# When the application drives Alembic it has already set up its own logging, and
# fileConfig() would tear it down: the default disable_existing_loggers=True
# silences every logger created beforehand, which is all of ours. The symptom is
# a scanner that runs perfectly and prints nothing at all after its first
# migration.
if config.config_file_name is not None and config.attributes.get(
    "configure_logger", True
):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# When Alembic is driven programmatically (app.store.bootstrap) the caller has
# already set the URL; only fall back to the environment for a bare
# `alembic upgrade head` on the command line.
if not config.get_main_option("sqlalchemy.url", None):
    config.set_main_option("sqlalchemy.url", database_url())

target_metadata = Base.metadata


def _configure(**kwargs) -> None:
    context.configure(
        target_metadata=target_metadata,
        compare_type=True,
        # SQLite cannot ALTER most things in place; batch mode rewrites the
        # table instead, which is what makes future migrations possible at all
        # on the default engine.
        render_as_batch=is_sqlite(config.get_main_option("sqlalchemy.url") or ""),
        **kwargs,
    )


def run_migrations_offline() -> None:
    _configure(
        url=config.get_main_option("sqlalchemy.url"),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        _configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
