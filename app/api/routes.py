"""API endpoints.

Everything reads and writes scanspot's own store. Nothing here proxies NetBox:
an API that forwarded to a backend would be a NetBox client, not a discovery
service, and would stop working the moment the backend is phpIPAM.
"""

from __future__ import annotations

import logging
import threading

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session

from .. import __version__
from ..store.crypto import SecretError
from ..store.models import ApiKey, Endpoint, Event, Prefix, Run, Site, Target, Vlan
from ..store.repository import Repository
from . import schemas
from .auth import get_session, require_key

log = logging.getLogger("api")

router = APIRouter(prefix="/api/v1")

DEFAULT_PROFILE = {"fortios": "fortigate-default", "snmp": "default"}


def _repo(session: Session) -> Repository:
    return Repository(session)


def _site_or_default(session: Session, site_id: int | None) -> Site:
    if site_id is not None:
        site = session.get(Site, site_id)
        if site is None:
            raise HTTPException(404, f"no site with id {site_id}")
        return site
    site = session.query(Site).order_by(Site.id).first()
    if site is None:
        raise HTTPException(409, "no site exists yet; run one cycle first")
    return site


# ── health ──────────────────────────────────────────────────────────────────
@router.get("/health", response_model=schemas.Health, tags=["meta"])
def health(request: Request, session: Session = Depends(get_session)):
    """Unauthenticated on purpose: this is what a load balancer or a
    Kubernetes probe calls, and it exposes no infrastructure detail."""
    repo = _repo(session)
    latest = session.query(Run).order_by(Run.started_at.desc()).first()
    return schemas.Health(
        status="ok",
        version=__version__,
        store=request.app.state.database.safe_url,
        sites=len(repo.sites()),
        targets=repo.target_count(),
        devices=session.query(Endpoint).count(),
        last_run=latest.started_at if latest else None,
        last_run_status=latest.status if latest else None,
    )


# ── sites ───────────────────────────────────────────────────────────────────
@router.get("/sites", response_model=list[schemas.Site], tags=["sites"])
def list_sites(session: Session = Depends(get_session), _key: ApiKey = Depends(require_key)):
    return _repo(session).sites()


# ── credentials ─────────────────────────────────────────────────────────────
@router.get("/credentials", response_model=list[schemas.Credential], tags=["credentials"])
def list_credentials(
    session: Session = Depends(get_session), _key: ApiKey = Depends(require_key)
):
    from ..store.models import CredentialProfile

    return session.query(CredentialProfile).order_by(CredentialProfile.name).all()


@router.post(
    "/credentials",
    response_model=schemas.Credential,
    status_code=status.HTTP_201_CREATED,
    tags=["credentials"],
)
def create_credential(
    payload: schemas.CredentialCreate,
    session: Session = Depends(get_session),
    _key: ApiKey = Depends(require_key),
):
    if payload.secrets and payload.secret_refs:
        raise HTTPException(422, "a credential is either env_ref or inline, not both")

    site = _site_or_default(session, payload.site_id) if payload.site_id else None
    try:
        return _repo(session).upsert_credential(
            payload.name,
            payload.kind,
            site=site,
            params=payload.params,
            secret_refs=payload.secret_refs,
            secrets=payload.secrets,
        )
    except SecretError as exc:
        # Almost always "SCANSPOT_SECRET_KEY is not set" — a configuration
        # problem the caller can act on, not a server fault.
        raise HTTPException(409, str(exc)) from exc


# ── targets ─────────────────────────────────────────────────────────────────
@router.get("/targets", response_model=list[schemas.Target], tags=["targets"])
def list_targets(
    site_id: int | None = None,
    enabled_only: bool = False,
    session: Session = Depends(get_session),
    _key: ApiKey = Depends(require_key),
):
    site = session.get(Site, site_id) if site_id is not None else None
    if site_id is not None and site is None:
        raise HTTPException(404, f"no site with id {site_id}")
    return _repo(session).targets(site, enabled_only=enabled_only)


@router.get("/targets/{target_id}", response_model=schemas.Target, tags=["targets"])
def get_target(
    target_id: int,
    session: Session = Depends(get_session),
    _key: ApiKey = Depends(require_key),
):
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(404, f"no target with id {target_id}")
    return target


@router.post(
    "/targets",
    response_model=schemas.Target,
    status_code=status.HTTP_201_CREATED,
    tags=["targets"],
)
def create_target(
    payload: schemas.TargetCreate,
    session: Session = Depends(get_session),
    _key: ApiKey = Depends(require_key),
):
    repo = _repo(session)
    site = _site_or_default(session, payload.site_id)

    profile_name = payload.credential or DEFAULT_PROFILE[payload.method]
    profile = repo.credential(profile_name, site)
    if profile is None:
        raise HTTPException(422, f"no credential profile named '{profile_name}'")

    existing = repo.find_target(site, payload.address, payload.method)
    if existing is not None:
        raise HTTPException(
            409,
            f"{payload.method} target {payload.address} already exists at this site "
            f"(id {existing.id})",
        )

    target, _ = repo.upsert_target(
        site,
        name=payload.name,
        address=payload.address,
        method=payload.method,
        credential=profile,
        vendor_override=payload.vendor_override or "",
        source="manual",
        enabled=payload.enabled,
    )
    log.info("target '%s' created through the API", target.name)
    return target


@router.patch("/targets/{target_id}", response_model=schemas.Target, tags=["targets"])
def update_target(
    target_id: int,
    payload: schemas.TargetUpdate,
    session: Session = Depends(get_session),
    _key: ApiKey = Depends(require_key),
):
    repo = _repo(session)
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(404, f"no target with id {target_id}")

    if target.source == "imported":
        # Editing it would be pointless: the next import overwrites the change.
        raise HTTPException(
            409,
            "this target is owned by the NetBox import. Edit it in NetBox, or "
            "remove its 'scan-target' tag and create it here instead.",
        )

    if payload.credential is not None:
        profile = repo.credential(payload.credential, target.site)
        if profile is None:
            raise HTTPException(422, f"no credential profile named '{payload.credential}'")
        target.credential_profile_id = profile.id

    for field in ("name", "address", "vendor_override", "enabled"):
        value = getattr(payload, field)
        if value is not None:
            setattr(target, field, value)

    session.flush()
    return target


@router.delete(
    "/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["targets"]
)
def delete_target(
    target_id: int,
    session: Session = Depends(get_session),
    _key: ApiKey = Depends(require_key),
):
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(404, f"no target with id {target_id}")
    if target.source == "imported":
        raise HTTPException(
            409,
            "this target is owned by the NetBox import. Remove its 'scan-target' "
            "tag in NetBox and it will be disabled on the next cycle.",
        )
    session.delete(target)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── discovery ───────────────────────────────────────────────────────────────
# Read-only: these describe what the network reported. Correcting them means
# fixing the network or the poll, not editing a row.


@router.get("/devices", response_model=list[schemas.Device], tags=["discovery"])
def list_devices(
    site_id: int | None = None,
    status: str | None = Query(default=None, description="active | offline | deprecated"),
    switch: str | None = Query(default=None, description="exact switch name"),
    mac: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
    _key: ApiKey = Depends(require_key),
):
    query = session.query(Endpoint)
    if site_id is not None:
        query = query.filter(Endpoint.site_id == site_id)
    if status is not None:
        query = query.filter(Endpoint.status == status)
    if switch is not None:
        query = query.filter(Endpoint.switch_name == switch)
    if mac is not None:
        query = query.filter(Endpoint.mac == mac.upper())
    return (
        query.order_by(Endpoint.last_seen_at.desc()).offset(offset).limit(limit).all()
    )


@router.get("/devices/{mac}", response_model=schemas.Device, tags=["discovery"])
def get_device(
    mac: str,
    site_id: int | None = None,
    session: Session = Depends(get_session),
    _key: ApiKey = Depends(require_key),
):
    query = session.query(Endpoint).filter(Endpoint.mac == mac.upper())
    if site_id is not None:
        query = query.filter(Endpoint.site_id == site_id)
    endpoint = query.first()
    if endpoint is None:
        raise HTTPException(404, f"no device with MAC {mac}")
    return endpoint


@router.get("/prefixes", response_model=list[schemas.Prefix], tags=["discovery"])
def list_prefixes(
    site_id: int | None = None,
    session: Session = Depends(get_session),
    _key: ApiKey = Depends(require_key),
):
    query = session.query(Prefix)
    if site_id is not None:
        query = query.filter(Prefix.site_id == site_id)
    return query.order_by(Prefix.cidr).all()


@router.get("/vlans", response_model=list[schemas.Vlan], tags=["discovery"])
def list_vlans(
    site_id: int | None = None,
    session: Session = Depends(get_session),
    _key: ApiKey = Depends(require_key),
):
    query = session.query(Vlan)
    if site_id is not None:
        query = query.filter(Vlan.site_id == site_id)
    return query.order_by(Vlan.vid).all()


@router.get("/runs", response_model=list[schemas.Run], tags=["discovery"])
def list_runs(
    site_id: int | None = None,
    limit: int = Query(default=20, ge=1, le=200),
    session: Session = Depends(get_session),
    _key: ApiKey = Depends(require_key),
):
    query = session.query(Run)
    if site_id is not None:
        query = query.filter(Run.site_id == site_id)
    return query.order_by(Run.started_at.desc()).limit(limit).all()


@router.get("/events", response_model=list[schemas.Event], tags=["discovery"])
def list_events(
    site_id: int | None = None,
    endpoint_id: int | None = None,
    type: str | None = Query(default=None, description="discovered | moved | ip_added | …"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
    _key: ApiKey = Depends(require_key),
):
    """The change log. This is what "tracking" means: not health polling, but a
    record of what moved, when, and to where."""
    query = session.query(Event)
    if site_id is not None:
        query = query.filter(Event.site_id == site_id)
    if endpoint_id is not None:
        query = query.filter(Event.endpoint_id == endpoint_id)
    if type is not None:
        query = query.filter(Event.type == type)
    return query.order_by(Event.created_at.desc()).offset(offset).limit(limit).all()


# ── scan ────────────────────────────────────────────────────────────────────
@router.post(
    "/scan",
    response_model=schemas.ScanAccepted,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["scan"],
)
def trigger_scan(request: Request, _key: ApiKey = Depends(require_key)):
    """Start a cycle and return immediately.

    A cycle takes minutes, so this cannot be synchronous. The advisory lock
    means a request that arrives mid-cycle is a no-op rather than a second
    concurrent scan.
    """
    trigger = getattr(request.app.state, "scan_trigger", None)
    if trigger is None:
        raise HTTPException(503, "this instance cannot trigger scans")

    threading.Thread(target=trigger, name="api-scan", daemon=True).start()
    return schemas.ScanAccepted(
        accepted=True,
        detail="scan started; it is skipped if a cycle is already running",
    )
