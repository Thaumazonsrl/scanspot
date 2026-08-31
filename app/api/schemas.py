"""Request and response shapes.

Two rules hold this file together:

  * **A secret is never returned.** Credential responses carry `has_secret` and
    nothing else. There is no field, no query parameter and no debug mode that
    reveals a community string or an API token once it has been stored.
  * **The payload is scanspot's model, not NetBox's.** Trimming it to what
    NetBox happens to hold would silently rob anyone integrating LibreNMS,
    Zabbix or an in-house CMDB of serials, VLANs and switch-port location.
"""

from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..store.models import CREDENTIAL_KINDS, SCAN_METHODS


class _ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ── health ──────────────────────────────────────────────────────────────────
class Health(BaseModel):
    status: str = Field(description="ok when a cycle has completed recently")
    version: str
    store: str = Field(description="the database engine in use, without credentials")
    sites: int
    targets: int
    devices: int = 0
    last_run: dt.datetime | None = None
    last_run_status: str | None = None


# ── sites ───────────────────────────────────────────────────────────────────
class Site(_ORM):
    id: int
    slug: str
    name: str
    created_at: dt.datetime


# ── credentials ─────────────────────────────────────────────────────────────
class Credential(_ORM):
    id: int
    site_id: int | None
    name: str
    kind: str
    storage: str
    params: dict
    # Deliberately not the secret, and deliberately not the referenced variable
    # names either — those describe your infrastructure.
    has_secret: bool
    created_at: dt.datetime
    updated_at: dt.datetime


class CredentialCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    kind: str
    site_id: int | None = None
    params: dict = Field(default_factory=dict)
    secret_refs: dict[str, str] = Field(
        default_factory=dict,
        description="field -> environment variable name (storage=env_ref)",
    )
    secrets: dict[str, str] = Field(
        default_factory=dict,
        description="field -> value, encrypted at rest (storage=inline). "
        "Requires SCANSPOT_SECRET_KEY. Write-only: never returned.",
    )

    @field_validator("kind")
    @classmethod
    def _known_kind(cls, value: str) -> str:
        if value not in CREDENTIAL_KINDS:
            raise ValueError(f"kind must be one of {', '.join(CREDENTIAL_KINDS)}")
        return value


# ── targets ─────────────────────────────────────────────────────────────────
class Target(_ORM):
    id: int
    site_id: int
    name: str
    address: str
    method: str
    credential_profile_id: int | None
    vendor_override: str | None
    enabled: bool
    source: str
    external_ref: str | None
    created_at: dt.datetime
    updated_at: dt.datetime


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    address: str = Field(min_length=1, max_length=255)
    method: str
    site_id: int | None = None
    credential: str | None = Field(
        default=None, description="credential profile name; defaults by method"
    )
    vendor_override: str | None = None
    enabled: bool = True

    @field_validator("method")
    @classmethod
    def _known_method(cls, value: str) -> str:
        if value not in SCAN_METHODS:
            raise ValueError(f"method must be one of {', '.join(SCAN_METHODS)}")
        return value


class CredentialUpdate(BaseModel):
    params: dict | None = None
    secret_refs: dict[str, str] | None = None
    secrets: dict[str, str] | None = Field(
        default=None, description="Write-only. Replaces the stored secrets."
    )


class TargetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    address: str | None = Field(default=None, min_length=1, max_length=255)
    credential: str | None = None
    vendor_override: str | None = None
    enabled: bool | None = None


# ── discovery ───────────────────────────────────────────────────────────────
class Address(_ORM):
    ip: str
    prefix_len: int | None
    kind: str = Field(description="active | dhcp | reserved")
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime


class Device(_ORM):
    """A discovered endpoint, anchored on its MAC.

    Everything the collectors learned is here — switch port, VLAN, firewall
    interface, reservation state — not only the subset a given backend can
    store. That is what makes an integration with LibreNMS or a CMDB worth
    writing.
    """

    id: int
    site_id: int
    mac: str
    hostname: str | None
    status: str
    static_reservation: bool
    switch_name: str | None
    switch_port: str | None
    vlan: str | None
    firewall: str | None
    firewall_interface: str | None
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime
    addresses: list[Address] = Field(default_factory=list)


class Prefix(_ORM):
    id: int
    site_id: int
    cidr: str
    source_device: str | None
    source_interface: str | None
    vlan_id: int | None
    description: str | None
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime


class Vlan(_ORM):
    id: int
    site_id: int
    vid: int
    name: str | None
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime


class Run(_ORM):
    id: int
    site_id: int
    started_at: dt.datetime
    finished_at: dt.datetime | None
    status: str
    firewalls_ok: int
    firewalls_failed: int
    switches_ok: int
    switches_failed: int
    mac_count: int
    duration_seconds: float | None
    error: str | None


class Event(_ORM):
    id: int
    site_id: int
    endpoint_id: int | None
    run_id: int | None
    type: str
    payload: dict
    created_at: dt.datetime


# ── scan ────────────────────────────────────────────────────────────────────
class ScanAccepted(BaseModel):
    accepted: bool
    detail: str
