"""SQLAlchemy models for the local store.

Schema and rationale: `docs/design/store.md`.

Conventions:
  * every discovery table carries `site_id`; nothing is globally unique by IP or
    MAC alone, because different offices legitimately reuse both;
  * "enum" columns are plain strings with a CHECK constraint rather than a
    native enum type — portable between SQLite and PostgreSQL, and far easier to
    extend in a migration;
  * timestamps are timezone-aware UTC (`app.utils.utcnow`).
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from ..utils import utcnow

# ── vocabularies ────────────────────────────────────────────────────────────
SCAN_METHODS = ("snmp", "fortios")
CREDENTIAL_KINDS = ("snmp", "fortios")

# Which fields of a credential are secret, per kind. Everything else lives in
# `params` as plain settings. SNMPv3 is why this is a mapping and not a single
# value: it carries two passphrases.
SECRET_FIELDS: dict[str, tuple[str, ...]] = {
    "snmp": ("community", "v3_auth_password", "v3_priv_password"),
    "fortios": ("api_token",),
}
CREDENTIAL_STORAGE = ("inline", "env_ref")
TARGET_SOURCES = ("manual", "imported", "seed")
RUN_STATUSES = ("ok", "degraded", "failed", "idle", "error", "skipped")
ENDPOINT_STATUSES = ("active", "offline", "deprecated")
ADDRESS_KINDS = ("active", "dhcp", "reserved")


def _in(column: str, values: tuple[str, ...]) -> str:
    joined = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({joined})"


class Base(DeclarativeBase):
    pass


def _pk() -> Mapped[int]:
    return mapped_column(Integer, primary_key=True, autoincrement=True)


def _ts(**kw) -> Mapped[dt.datetime]:
    return mapped_column(DateTime(timezone=True), **kw)


# ── tenancy ─────────────────────────────────────────────────────────────────
class Site(Base):
    """The tenancy boundary.

    Everything discovered belongs to exactly one site. This exists from the very
    first migration on purpose: retrofitting it would mean rewriting every
    uniqueness constraint in the schema.
    """

    __tablename__ = "sites"

    id: Mapped[int] = _pk()
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[dt.datetime] = _ts(default=utcnow)

    # passive_deletes lets the database perform the ON DELETE CASCADE. Without
    # it SQLAlchemy first tries to null out the children's site_id, which is
    # NOT NULL, so deleting a site fails outright.
    targets: Mapped[list[Target]] = relationship(
        back_populates="site", cascade="all, delete", passive_deletes=True
    )
    endpoints: Mapped[list[Endpoint]] = relationship(
        back_populates="site", cascade="all, delete", passive_deletes=True
    )


class Collector(Base):
    """A polling agent: either the central instance itself or a remote site."""

    __tablename__ = "collectors"
    __table_args__ = (UniqueConstraint("site_id", "name", name="uq_collector_name"),)

    id: Mapped[int] = _pk()
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(200))
    # Only ever the hash. The key itself is shown once, at creation.
    api_key_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    last_seen_at: Mapped[dt.datetime | None] = _ts(nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


# ── credentials ─────────────────────────────────────────────────────────────
class CredentialProfile(Base):
    """A named credential that targets point at.

    Two storage modes, both needed:

      inline    encrypted in this table (Fernet, key from SCANSPOT_SECRET_KEY),
                manageable through the API without a restart;
      env_ref   the profile names environment variables and the values are read
                at use time — for anyone injecting secrets from Kubernetes
                Secrets or Vault, who does not want them in a database.

    Secrets are a *mapping*, not a single value: SNMPv3 has two passphrases
    (auth and priv) alongside the community string, so one column per secret
    would not have survived first contact.

      inline  -> secret_encrypted = Fernet({"community": "...", ...})
      env_ref -> secret_refs      = {"community": "SNMP_COMMUNITY", ...}

    `params` holds the non-secret settings: snmp_version, v3_username, security
    level, port, vdom, timeout, and so on.
    """

    __tablename__ = "credential_profiles"
    __table_args__ = (
        UniqueConstraint("site_id", "name", name="uq_credential_name"),
        CheckConstraint(_in("kind", CREDENTIAL_KINDS), name="ck_credential_kind"),
        CheckConstraint(_in("storage", CREDENTIAL_STORAGE), name="ck_credential_storage"),
    )

    id: Mapped[int] = _pk()
    # NULL means the profile is available to every site.
    site_id: Mapped[int | None] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(100))
    kind: Mapped[str] = mapped_column(String(20))
    storage: Mapped[str] = mapped_column(String(20), default="env_ref")
    secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    secret_refs: Mapped[dict] = mapped_column(JSON, default=dict)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = _ts(default=utcnow)
    updated_at: Mapped[dt.datetime] = _ts(default=utcnow, onupdate=utcnow)

    @property
    def has_secret(self) -> bool:
        """What the API exposes instead of the secret itself."""
        if self.storage == "inline":
            return self.secret_encrypted is not None
        return bool(self.secret_refs)


# ── scan targets ────────────────────────────────────────────────────────────
class Target(Base):
    """A device to poll. This is what used to be a NetBox device tagged
    `scan-target`; from 2.0 the store owns it."""

    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint("site_id", "address", "method", name="uq_target_address"),
        CheckConstraint(_in("method", SCAN_METHODS), name="ck_target_method"),
        CheckConstraint(_in("source", TARGET_SOURCES), name="ck_target_source"),
    )

    id: Mapped[int] = _pk()
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(200))
    address: Mapped[str] = mapped_column(String(255))
    method: Mapped[str] = mapped_column(String(20))
    credential_profile_id: Mapped[int | None] = mapped_column(
        ForeignKey("credential_profiles.id", ondelete="SET NULL"), nullable=True
    )
    vendor_override: Mapped[str | None] = mapped_column(String(50), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(20), default="manual")
    # Where an imported target came from, e.g. a NetBox device id. Makes the
    # one-shot import idempotent.
    external_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[dt.datetime] = _ts(default=utcnow)
    updated_at: Mapped[dt.datetime] = _ts(default=utcnow, onupdate=utcnow)

    site: Mapped[Site] = relationship(back_populates="targets")
    credential: Mapped[CredentialProfile | None] = relationship()


# ── cycles ──────────────────────────────────────────────────────────────────
class Run(Base):
    """One scan cycle. Replaces state/last_run.json; the healthcheck reads the
    newest row."""

    __tablename__ = "runs"
    __table_args__ = (
        CheckConstraint(_in("status", RUN_STATUSES), name="ck_run_status"),
        Index("ix_runs_site_started", "site_id", "started_at"),
    )

    id: Mapped[int] = _pk()
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    collector_id: Mapped[int | None] = mapped_column(
        ForeignKey("collectors.id", ondelete="SET NULL"), nullable=True
    )
    started_at: Mapped[dt.datetime] = _ts(default=utcnow)
    finished_at: Mapped[dt.datetime | None] = _ts(nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="idle")
    firewalls_ok: Mapped[int] = mapped_column(Integer, default=0)
    firewalls_failed: Mapped[int] = mapped_column(Integer, default=0)
    switches_ok: Mapped[int] = mapped_column(Integer, default=0)
    switches_failed: Mapped[int] = mapped_column(Integer, default=0)
    mac_count: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float | None] = mapped_column(nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


# ── discovery state ─────────────────────────────────────────────────────────
class Endpoint(Base):
    """Current state of one discovered host, anchored on its MAC.

    `(site_id, mac)` is the identity — not `mac`, because the same hardware may
    legitimately appear at two sites over its life, and not the IP, because
    those change with every lease.
    """

    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("site_id", "mac", name="uq_endpoint_mac"),
        CheckConstraint(_in("status", ENDPOINT_STATUSES), name="ck_endpoint_status"),
        Index("ix_endpoints_last_seen", "site_id", "last_seen_at"),
    )

    id: Mapped[int] = _pk()
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    mac: Mapped[str] = mapped_column(String(17))
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active")
    static_reservation: Mapped[bool] = mapped_column(Boolean, default=False)
    switch_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    switch_port: Mapped[str | None] = mapped_column(String(100), nullable=True)
    vlan: Mapped[str | None] = mapped_column(String(20), nullable=True)
    firewall: Mapped[str | None] = mapped_column(String(200), nullable=True)
    firewall_interface: Mapped[str | None] = mapped_column(String(100), nullable=True)
    first_seen_at: Mapped[dt.datetime] = _ts(default=utcnow)
    last_seen_at: Mapped[dt.datetime] = _ts(default=utcnow)
    last_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("runs.id", ondelete="SET NULL"), nullable=True
    )

    site: Mapped[Site] = relationship(back_populates="endpoints")
    addresses: Mapped[list[EndpointAddress]] = relationship(
        back_populates="endpoint", cascade="all, delete-orphan", passive_deletes=True
    )


class EndpointAddress(Base):
    """An IP currently held by an endpoint."""

    __tablename__ = "endpoint_addresses"
    __table_args__ = (
        UniqueConstraint("endpoint_id", "ip", name="uq_endpoint_ip"),
        CheckConstraint(_in("kind", ADDRESS_KINDS), name="ck_address_kind"),
    )

    id: Mapped[int] = _pk()
    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE")
    )
    ip: Mapped[str] = mapped_column(String(45))
    prefix_len: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kind: Mapped[str] = mapped_column(String(20), default="active")
    first_seen_at: Mapped[dt.datetime] = _ts(default=utcnow)
    last_seen_at: Mapped[dt.datetime] = _ts(default=utcnow)

    endpoint: Mapped[Endpoint] = relationship(back_populates="addresses")


class Event(Base):
    """Append-only change log — this is what "tracking" means.

    Kept separate from `endpoints` so that current state stays small and bounded
    while history can be pruned on its own schedule.
    """

    __tablename__ = "events"
    __table_args__ = (Index("ix_events_site_created", "site_id", "created_at"),)

    id: Mapped[int] = _pk()
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    endpoint_id: Mapped[int | None] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=True
    )
    run_id: Mapped[int | None] = mapped_column(
        ForeignKey("runs.id", ondelete="SET NULL"), nullable=True
    )
    type: Mapped[str] = mapped_column(String(50))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = _ts(default=utcnow)


# ── infrastructure findings ─────────────────────────────────────────────────
class Prefix(Base):
    __tablename__ = "prefixes"
    __table_args__ = (UniqueConstraint("site_id", "cidr", name="uq_prefix_cidr"),)

    id: Mapped[int] = _pk()
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    cidr: Mapped[str] = mapped_column(String(49))
    source_device: Mapped[str | None] = mapped_column(String(200), nullable=True)
    source_interface: Mapped[str | None] = mapped_column(String(100), nullable=True)
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_seen_at: Mapped[dt.datetime] = _ts(default=utcnow)
    last_seen_at: Mapped[dt.datetime] = _ts(default=utcnow)


class Vlan(Base):
    __tablename__ = "vlans"
    __table_args__ = (UniqueConstraint("site_id", "vid", name="uq_vlan_vid"),)

    id: Mapped[int] = _pk()
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    vid: Mapped[int] = mapped_column(Integer)
    name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen_at: Mapped[dt.datetime] = _ts(default=utcnow)
    last_seen_at: Mapped[dt.datetime] = _ts(default=utcnow)


class DhcpPool(Base):
    __tablename__ = "dhcp_pools"
    __table_args__ = (
        UniqueConstraint("site_id", "start_ip", "end_ip", name="uq_pool_range"),
    )

    id: Mapped[int] = _pk()
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    firewall: Mapped[str | None] = mapped_column(String(200), nullable=True)
    interface: Mapped[str | None] = mapped_column(String(100), nullable=True)
    start_ip: Mapped[str] = mapped_column(String(45))
    end_ip: Mapped[str] = mapped_column(String(45))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen_at: Mapped[dt.datetime] = _ts(default=utcnow)
    last_seen_at: Mapped[dt.datetime] = _ts(default=utcnow)


class RawObservation(Base):
    """What a device actually replied, before interpretation.

    Off by default (`CAPTURE_RAW`). Turn it on when a device is being
    identified wrongly and you want to work out why from your desk instead of
    going back to the site: the walk can be re-read, and a corrected parser
    replayed against it.

    Kept for the last few runs only. A full forwarding database per switch per
    cycle is not something to accumulate.
    """

    __tablename__ = "raw_observations"
    __table_args__ = (Index("ix_raw_site_created", "site_id", "created_at"),)

    id: Mapped[int] = _pk()
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    run_id: Mapped[int | None] = mapped_column(
        ForeignKey("runs.id", ondelete="CASCADE"), nullable=True
    )
    device: Mapped[str] = mapped_column(String(200))
    source: Mapped[str] = mapped_column(String(20))        # snmp | fortios
    kind: Mapped[str] = mapped_column(String(100))         # which walk / endpoint
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = _ts(default=utcnow)


# ── backend synchronisation ─────────────────────────────────────────────────
class BackendSync(Base):
    """Local object -> remote id, per backend.

    Makes pushes idempotent, survives a backend renumbering its objects, and
    lets a backend that *cannot* hold an object type simply have no rows for it.
    Nothing is lost locally, which is what makes a partial backend acceptable
    rather than lossy.
    """

    __tablename__ = "backend_syncs"
    __table_args__ = (
        UniqueConstraint(
            "backend", "object_type", "local_id", name="uq_backend_sync_local"
        ),
    )

    id: Mapped[int] = _pk()
    backend: Mapped[str] = mapped_column(String(50))
    object_type: Mapped[str] = mapped_column(String(50))
    local_id: Mapped[int] = mapped_column(Integer)
    remote_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_synced_at: Mapped[dt.datetime | None] = _ts(nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(50), nullable=True)


# ── API access ──────────────────────────────────────────────────────────────
class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = _pk()
    name: Mapped[str] = mapped_column(String(200))
    key_hash: Mapped[str] = mapped_column(String(128), unique=True)
    scopes: Mapped[dict] = mapped_column(JSON, default=dict)
    # NULL means every site. A collector's key is scoped to its own site.
    site_id: Mapped[int | None] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=True
    )
    created_at: Mapped[dt.datetime] = _ts(default=utcnow)
    last_used_at: Mapped[dt.datetime | None] = _ts(nullable=True)
    revoked_at: Mapped[dt.datetime | None] = _ts(nullable=True)
