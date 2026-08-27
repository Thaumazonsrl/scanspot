# Contributing

Thanks for looking. The most useful contributions to this project are small and
concrete.

## The easiest useful contribution: vendor coverage

scanspot identifies hardware from SNMP, and that knowledge lives in one file
with no I/O in it: `app/identity.py`.

**Adding a manufacturer.** If your kit shows up in NetBox as
`Enterprise 12345`, that IANA Private Enterprise Number is not in the table yet.
Add it to `ENTERPRISES` and send a PR:

```python
12345: "Example Networks",
```

Please add only mappings you have **verified against a real device**. A wrong
entry silently writes a wrong Manufacturer into somebody's source of truth,
which is worse than an honest placeholder. Include the `sysObjectID` you
observed in the PR description.

**Adding a `sysDescr` rule.** If a device's model or OS version is not being
picked up, add a rule to `_SYSDESCR_RULES` with a matching entry in `_OS_BY_RULE`,
plus a test using the **real `sysDescr` string, verbatim**. Rules are ordered and
the first match wins, so put specific patterns before general ones.

## Running the tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

They need neither a NetBox nor a network. CI runs them on Python 3.11 and 3.12,
then builds the image and smoke-tests the CLI.

## Things to know before changing the sync

A few behaviours are load-bearing. Please keep them:

* **Every write goes through `NetBoxClient.write()`.** That single funnel is what
  makes `DRY_RUN=true` airtight and turns an API error into a log line instead of
  an aborted cycle. A direct `.create()` or `.save()` outside it breaks both.
* **Objects without the `auto-discovered` tag were created by a human.** Stamp
  the discovery custom fields on them if you like, but never rewrite their
  status, description or tags, and never delete them.
* **Static DHCP reservations are never deleted**, and a cycle in which no data
  source responded must skip the sync *and* the cleanup entirely. Both exist so
  that a connectivity problem cannot empty someone's IPAM.
* **NetBox version tolerance.** `app/backends/netbox/client.py` handles the ≥4.2
  first-class `MACAddress` object as well as the ≤4.1 interface attribute, and
  the `role`/`device_role` and `object_types`/`content_types` renames. Keep both
  paths when you touch it.
* **Keep the backend seam clean.** Everything outside `app/backends/` is
  storage-agnostic: the collectors, the domain model in `app/models.py` and the
  pure logic in `app/identity.py`, `app/utils.py` and `app/prefixes.py`. Nothing
  in those should import from `app/backends/`. That property is what will make
  Nautobot and phpIPAM support possible later.

## Style

Match the surrounding code. Comments explain *why*, not *what* — the existing
ones document the traps (the per-request `verify=`, the advisory lock, the
device-name collision retry), and that is the most valuable documentation in the
repository.

## Reporting a problem

Please include the scanspot version, your NetBox version, the vendor and model
of the device involved, and the relevant log lines with `LOG_LEVEL=DEBUG`.
**Redact your community strings and API tokens** before pasting logs.
