"""Tests for the HTTP API.

The properties defended here are the ones a mistake would make expensive:
secrets never leave the process, an unauthenticated caller sees nothing, and
targets owned by the NetBox import cannot be edited into a state the next
import silently reverts.
"""

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app, ensure_bootstrap_key
from app.api.keys import generate_key, hash_key
from app.store.bootstrap import ensure_site
from app.store.db import Database
from app.store.models import ApiKey, Base
from app.store.repository import Repository


@pytest.fixture
def db(tmp_path):
    database = Database(url=f"sqlite:///{tmp_path / 'api.db'}")
    Base.metadata.create_all(database.engine)
    yield database
    database.dispose()


@pytest.fixture
def key(db):
    value = generate_key()
    with db.session_scope() as session:
        session.add(ApiKey(name="test", key_hash=hash_key(value)))
    return value


@pytest.fixture
def seeded(db):
    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")
        repo.upsert_credential(
            "default", "snmp", secret_refs={"community": "SNMP_COMMUNITY"}
        )
        repo.upsert_credential(
            "fortigate-default", "fortios", secret_refs={"api_token": "FORTIGATE_API_TOKEN"}
        )
        return site.id


@pytest.fixture
def client(db, seeded):
    return TestClient(create_app(db))


@pytest.fixture
def auth(key):
    return {"X-API-Key": key}


# ── authentication ──────────────────────────────────────────────────────────


def test_health_needs_no_key(client):
    """A Kubernetes probe cannot carry credentials."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_health_does_not_leak_the_database_password(db, seeded):
    database = Database(url="sqlite:///:memory:")
    database.url = "postgresql://scanspot:sup3rs3cret@db:5432/scanspot"
    app = create_app(db)
    app.state.database.url = database.url
    body = TestClient(app).get("/api/v1/health").json()
    assert "sup3rs3cret" not in body["store"]
    assert "***" in body["store"]


@pytest.mark.parametrize("path", ["/api/v1/targets", "/api/v1/sites", "/api/v1/credentials"])
def test_endpoints_reject_an_absent_key(client, path):
    assert client.get(path).status_code == 401


def test_a_wrong_key_is_rejected(client):
    assert client.get("/api/v1/targets", headers={"X-API-Key": "nope"}).status_code == 401


def test_bearer_is_accepted_too(client, key):
    response = client.get("/api/v1/targets", headers={"Authorization": f"Bearer {key}"})
    assert response.status_code == 200


def test_a_revoked_key_fails_like_an_unknown_one(db, client, key):
    from app.utils import utcnow

    with db.session_scope() as session:
        session.query(ApiKey).one().revoked_at = utcnow()

    response = client.get("/api/v1/targets", headers={"X-API-Key": key})
    assert response.status_code == 401
    # Revoked and unknown must be indistinguishable to a prober.
    assert response.json()["detail"] == "a valid API key is required"


def test_the_bootstrap_key_is_issued_once(db):
    first = ensure_bootstrap_key(db)
    assert first and first.startswith("scanspot_")
    assert ensure_bootstrap_key(db) is None


def test_the_bootstrap_key_is_stored_only_as_a_hash(db):
    issued = ensure_bootstrap_key(db)
    with db.session_scope() as session:
        stored = session.query(ApiKey).one()
        assert stored.key_hash != issued
        assert issued not in stored.key_hash


# ── targets ─────────────────────────────────────────────────────────────────


def test_create_and_list_a_target(client, auth):
    created = client.post(
        "/api/v1/targets",
        headers=auth,
        json={"name": "sw-01", "address": "10.0.0.10", "method": "snmp"},
    )
    assert created.status_code == 201
    assert created.json()["source"] == "manual"

    listed = client.get("/api/v1/targets", headers=auth).json()
    assert [t["name"] for t in listed] == ["sw-01"]


def test_creating_a_duplicate_address_conflicts(client, auth):
    body = {"name": "sw-01", "address": "10.0.0.10", "method": "snmp"}
    assert client.post("/api/v1/targets", headers=auth, json=body).status_code == 201
    assert client.post("/api/v1/targets", headers=auth, json=body).status_code == 409


def test_an_unknown_method_is_rejected_before_it_reaches_the_store(client, auth):
    response = client.post(
        "/api/v1/targets",
        headers=auth,
        json={"name": "x", "address": "10.0.0.1", "method": "telnet"},
    )
    assert response.status_code == 422


def test_an_unknown_credential_profile_is_rejected(client, auth):
    response = client.post(
        "/api/v1/targets",
        headers=auth,
        json={
            "name": "sw-01",
            "address": "10.0.0.10",
            "method": "snmp",
            "credential": "does-not-exist",
        },
    )
    assert response.status_code == 422


def test_update_and_delete(client, auth):
    target_id = client.post(
        "/api/v1/targets",
        headers=auth,
        json={"name": "sw-01", "address": "10.0.0.10", "method": "snmp"},
    ).json()["id"]

    patched = client.patch(
        f"/api/v1/targets/{target_id}", headers=auth, json={"enabled": False}
    )
    assert patched.status_code == 200
    assert patched.json()["enabled"] is False

    assert client.delete(f"/api/v1/targets/{target_id}", headers=auth).status_code == 204
    assert client.get(f"/api/v1/targets/{target_id}", headers=auth).status_code == 404


def test_an_imported_target_cannot_be_edited_through_the_api(db, client, auth, seeded):
    """The next import would revert the change, so refusing is more honest than
    accepting an edit that silently disappears."""
    with db.session_scope() as session:
        repo = Repository(session)
        site = session.get(type(repo.sites()[0]), seeded)
        target, _ = repo.upsert_target(
            site,
            name="from-netbox",
            address="10.0.0.50",
            method="snmp",
            source="imported",
            external_ref="7",
        )
        target_id = target.id

    patched = client.patch(
        f"/api/v1/targets/{target_id}", headers=auth, json={"name": "renamed"}
    )
    assert patched.status_code == 409
    assert "NetBox" in patched.json()["detail"]

    assert client.delete(f"/api/v1/targets/{target_id}", headers=auth).status_code == 409


# ── credentials ─────────────────────────────────────────────────────────────


def test_credentials_never_return_a_secret(client, auth, monkeypatch):
    monkeypatch.setenv("SCANSPOT_SECRET_KEY", __import__(
        "app.store.crypto", fromlist=["generate_key"]
    ).generate_key())

    created = client.post(
        "/api/v1/credentials",
        headers=auth,
        json={
            "name": "inline-profile",
            "kind": "snmp",
            "secrets": {"community": "TOP-SECRET-COMMUNITY"},
        },
    )
    assert created.status_code == 201

    body = created.text + client.get("/api/v1/credentials", headers=auth).text
    assert "TOP-SECRET-COMMUNITY" not in body
    assert created.json()["has_secret"] is True


def test_env_ref_credentials_do_not_expose_the_variable_names(client, auth):
    """Which variables you use is infrastructure detail; has_secret is enough."""
    client.post(
        "/api/v1/credentials",
        headers=auth,
        json={
            "name": "env-profile",
            "kind": "snmp",
            "secret_refs": {"community": "SOME_PRIVATE_VAR_NAME"},
        },
    )
    body = client.get("/api/v1/credentials", headers=auth).text
    assert "SOME_PRIVATE_VAR_NAME" not in body


def test_inline_and_env_ref_together_are_rejected(client, auth):
    response = client.post(
        "/api/v1/credentials",
        headers=auth,
        json={
            "name": "confused",
            "kind": "snmp",
            "secrets": {"community": "x"},
            "secret_refs": {"community": "Y"},
        },
    )
    assert response.status_code == 422


def test_storing_a_secret_without_a_key_is_a_readable_conflict(client, auth, monkeypatch):
    monkeypatch.delenv("SCANSPOT_SECRET_KEY", raising=False)
    response = client.post(
        "/api/v1/credentials",
        headers=auth,
        json={"name": "p", "kind": "snmp", "secrets": {"community": "x"}},
    )
    assert response.status_code == 409
    assert "SCANSPOT_SECRET_KEY" in response.json()["detail"]


# ── scan ────────────────────────────────────────────────────────────────────


def test_scan_returns_202_and_runs_in_the_background(db, seeded):
    calls: list[int] = []
    app = create_app(db, scan_trigger=lambda: calls.append(1))
    value = generate_key()
    with db.session_scope() as session:
        session.add(ApiKey(name="k", key_hash=hash_key(value)))

    client = TestClient(app)
    response = client.post("/api/v1/scan", headers={"X-API-Key": value})
    assert response.status_code == 202
    assert response.json()["accepted"] is True


def test_scan_is_unavailable_when_no_trigger_is_wired(client, auth):
    assert client.post("/api/v1/scan", headers=auth).status_code == 503


# ── discovery ───────────────────────────────────────────────────────────────


@pytest.fixture
def discovered(db, seeded):
    """One cycle's worth of findings, written the way the scanner writes them."""
    from app.models import CollectionResult, L3Interface, SwitchInfo, SwitchPortLocation
    from app.store.bootstrap import ensure_site
    from app.store.persist import begin_run, persist_result
    from app.utils import utcnow

    result = CollectionResult()
    obs = result.observation("AA:BB:CC:DD:EE:01")
    obs.ips.add("10.0.0.5")
    obs.hostname = "laptop-01"
    obs.location = SwitchPortLocation(switch="sw-01", port="Gi1/0/1", vlan="10")

    other = result.observation("AA:BB:CC:DD:EE:02")
    other.ips.add("10.0.0.6")

    result.l3_interfaces.append(
        L3Interface(device="fw", name="lan", address="10.0.0.1", prefix_len=24)
    )
    switch = SwitchInfo(name="sw-01", host="10.0.0.10", vendor="cisco")
    switch.vlans = {"10": "users"}
    result.switches.append(switch)

    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        run = begin_run(session, site, result, utcnow())
        persist_result(session, site, run, result, utcnow())


def test_devices_carry_the_full_model_not_a_netbox_subset(client, auth, discovered):
    """Switch port, VLAN and reservation state are exactly what makes an
    integration with LibreNMS or a CMDB worth writing."""
    devices = client.get("/api/v1/devices", headers=auth).json()
    by_mac = {d["mac"]: d for d in devices}

    laptop = by_mac["AA:BB:CC:DD:EE:01"]
    assert laptop["hostname"] == "laptop-01"
    assert laptop["switch_name"] == "sw-01"
    assert laptop["switch_port"] == "Gi1/0/1"
    assert laptop["vlan"] == "10"
    assert [a["ip"] for a in laptop["addresses"]] == ["10.0.0.5"]


def test_devices_can_be_filtered(client, auth, discovered):
    assert len(client.get("/api/v1/devices", headers=auth).json()) == 2
    filtered = client.get("/api/v1/devices?switch=sw-01", headers=auth).json()
    assert [d["mac"] for d in filtered] == ["AA:BB:CC:DD:EE:01"]
    assert client.get("/api/v1/devices?status=offline", headers=auth).json() == []


def test_a_single_device_by_mac(client, auth, discovered):
    response = client.get("/api/v1/devices/aa:bb:cc:dd:ee:01", headers=auth)
    assert response.status_code == 200
    assert response.json()["hostname"] == "laptop-01"


def test_an_unknown_mac_is_404(client, auth, discovered):
    assert client.get("/api/v1/devices/00:11:22:33:44:55", headers=auth).status_code == 404


def test_prefixes_and_vlans_are_exposed(client, auth, discovered):
    assert [p["cidr"] for p in client.get("/api/v1/prefixes", headers=auth).json()] == [
        "10.0.0.0/24"
    ]
    vlans = client.get("/api/v1/vlans", headers=auth).json()
    assert [(v["vid"], v["name"]) for v in vlans] == [(10, "users")]


def test_runs_and_events_are_exposed(client, auth, discovered):
    assert len(client.get("/api/v1/runs", headers=auth).json()) == 1

    events = client.get("/api/v1/events", headers=auth).json()
    assert {e["type"] for e in events} >= {"discovered", "ip_added"}

    filtered = client.get("/api/v1/events?type=discovered", headers=auth).json()
    assert all(e["type"] == "discovered" for e in filtered)


def test_health_reports_the_last_cycle(client, auth, discovered):
    body = client.get("/api/v1/health").json()
    assert body["devices"] == 2
    assert body["last_run"] is not None


def test_discovery_endpoints_require_a_key(client, discovered):
    for path in ("/api/v1/devices", "/api/v1/prefixes", "/api/v1/runs", "/api/v1/events"):
        assert client.get(path).status_code == 401


def test_device_listing_is_paginated(client, auth, discovered):
    page = client.get("/api/v1/devices?limit=1", headers=auth).json()
    assert len(page) == 1
    assert client.get("/api/v1/devices?limit=1&offset=1", headers=auth).json()[0][
        "mac"
    ] != page[0]["mac"]


# ── contract ────────────────────────────────────────────────────────────────


def test_openapi_document_is_generated(client):
    """Third parties integrate against this; if it stops generating, the
    contract stops being publishable."""
    document = client.get("/api/openapi.json")
    assert document.status_code == 200
    paths = document.json()["paths"]
    for expected in ("/api/v1/health", "/api/v1/targets", "/api/v1/scan"):
        assert expected in paths
