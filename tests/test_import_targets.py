"""Tests for the NetBox -> store target import.

No NetBox is involved: a stub stands in for the pynetbox client, because what
is being tested is the ownership rule, not the HTTP call.

The rule: imported targets belong to NetBox and are refreshed from it; targets
created any other way are never touched. And a NetBox outage must never look
like "every device was untagged".
"""

import pytest

from app.backends.netbox.import_targets import import_targets
from app.store.bootstrap import ensure_site
from app.store.db import Database
from app.store.models import Base, Target
from app.store.repository import Repository


# ── stubs ───────────────────────────────────────────────────────────────────
class _Choice:
    def __init__(self, value):
        self.value = value


class _Role:
    def __init__(self, slug):
        self.slug = slug


class FakeDevice:
    def __init__(self, id, name, address=None, method=None, credential=None,
                 vendor=None, status="active", role="network-switch"):
        self.id = id
        self.name = name
        self.status = _Choice(status)
        self.role = _Role(role)
        self.primary_ip4 = None
        self.custom_fields = {
            "scanner_address": address,
            "scanner_method": method,
            "scanner_credential": credential,
            "scanner_vendor": vendor,
        }


class FakeClient:
    """Mimics only what import_targets touches."""

    def __init__(self, devices=None, fail=False):
        self._devices = devices or []
        self._fail = fail
        outer = self

        class _Devices:
            def filter(self, **_kw):
                if outer._fail:
                    raise ConnectionError("NetBox is unreachable")
                return list(outer._devices)

        class _Dcim:
            devices = _Devices()

        class _Api:
            dcim = _Dcim()

        self.api = _Api()


# ── fixtures ────────────────────────────────────────────────────────────────
@pytest.fixture
def db(tmp_path):
    database = Database(url=f"sqlite:///{tmp_path / 'import.db'}")
    Base.metadata.create_all(database.engine)
    yield database
    database.dispose()


@pytest.fixture
def repo_site(db):
    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")
        repo.upsert_credential("default", "snmp", secret_refs={"community": "SNMP_COMMUNITY"})
        repo.upsert_credential(
            "fortigate-default", "fortios", secret_refs={"api_token": "FORTIGATE_API_TOKEN"}
        )
        yield repo, site, session


# ── importing ───────────────────────────────────────────────────────────────


def test_imports_tagged_devices(repo_site):
    repo, site, _ = repo_site
    client = FakeClient([FakeDevice(1, "sw-01", address="10.0.0.10")])

    assert import_targets(client, repo, site, None) == 1

    target = repo.targets(site)[0]
    assert target.name == "sw-01"
    assert target.address == "10.0.0.10"
    assert target.method == "snmp"
    assert target.source == "imported"
    assert target.external_ref == "1"


def test_the_role_decides_the_method_when_unset(repo_site):
    repo, site, _ = repo_site
    client = FakeClient(
        [
            FakeDevice(1, "fw-01", address="10.0.0.1", role="firewall"),
            FakeDevice(2, "sw-01", address="10.0.0.10", role="network-switch"),
        ]
    )
    import_targets(client, repo, site, None)

    by_name = {t.name: t for t in repo.targets(site)}
    assert by_name["fw-01"].method == "fortios"
    assert by_name["sw-01"].method == "snmp"


def test_an_explicit_method_beats_the_role(repo_site):
    repo, site, _ = repo_site
    client = FakeClient(
        [FakeDevice(1, "l3-sw", address="10.0.0.5", method="snmp", role="firewall")]
    )
    import_targets(client, repo, site, None)
    assert repo.targets(site)[0].method == "snmp"


def test_reimporting_updates_instead_of_duplicating(repo_site):
    repo, site, _ = repo_site
    client = FakeClient([FakeDevice(1, "sw-01", address="10.0.0.10")])
    import_targets(client, repo, site, None)

    # Renamed and readdressed in NetBox, same device id.
    client._devices = [FakeDevice(1, "sw-01-renamed", address="10.0.0.99")]
    assert import_targets(client, repo, site, None) == 0

    targets = repo.targets(site)
    assert len(targets) == 1
    assert targets[0].name == "sw-01-renamed"
    assert targets[0].address == "10.0.0.99"


def test_a_device_without_an_address_is_skipped(repo_site):
    repo, site, _ = repo_site
    client = FakeClient([FakeDevice(1, "sw-01", address=None)])
    assert import_targets(client, repo, site, None) == 0
    assert repo.target_count(site) == 0


def test_a_decommissioned_device_is_not_imported(repo_site):
    repo, site, _ = repo_site
    client = FakeClient(
        [FakeDevice(1, "sw-01", address="10.0.0.10", status="decommissioning")]
    )
    assert import_targets(client, repo, site, None) == 0


def test_an_unknown_credential_profile_skips_the_device(repo_site):
    repo, site, _ = repo_site
    client = FakeClient(
        [FakeDevice(1, "sw-01", address="10.0.0.10", credential="typo-profile")]
    )
    assert import_targets(client, repo, site, None) == 0
    assert repo.target_count(site) == 0


# ── ownership ───────────────────────────────────────────────────────────────


def test_untagging_a_device_disables_its_target(repo_site):
    repo, site, session = repo_site
    client = FakeClient([FakeDevice(1, "sw-01", address="10.0.0.10")])
    import_targets(client, repo, site, None)

    client._devices = []
    import_targets(client, repo, site, None)

    target = session.query(Target).one()
    assert target.enabled is False
    # Disabled, not deleted: the device may come back and its history matters.
    assert repo.target_count(site) == 1


def test_a_manual_target_survives_an_import_that_omits_it(repo_site):
    """Ownership rule: NetBox owns what it imported, and nothing else."""
    repo, site, session = repo_site
    repo.upsert_target(
        site, name="manual", address="10.0.0.99", method="snmp", source="manual"
    )
    import_targets(FakeClient([]), repo, site, None)

    manual = session.query(Target).filter_by(name="manual").one()
    assert manual.enabled is True


def test_a_netbox_outage_does_not_disable_anything(repo_site):
    """The failure mode that would silently stop every scan."""
    repo, site, session = repo_site
    client = FakeClient([FakeDevice(1, "sw-01", address="10.0.0.10")])
    import_targets(client, repo, site, None)

    assert import_targets(FakeClient(fail=True), repo, site, None) == 0

    target = session.query(Target).one()
    assert target.enabled is True


def test_retagging_a_device_re_enables_its_target(repo_site):
    repo, site, session = repo_site
    device = FakeDevice(1, "sw-01", address="10.0.0.10")
    client = FakeClient([device])
    import_targets(client, repo, site, None)

    client._devices = []
    import_targets(client, repo, site, None)

    client._devices = [device]
    import_targets(client, repo, site, None)

    assert session.query(Target).one().enabled is True
