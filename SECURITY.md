# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |
| < 1.0 | ❌ (pre-release) |

## Reporting a vulnerability

**Please do not open a public issue.**

Report privately to **T-SOC@thaumazon.com**, or use GitHub's
[private vulnerability reporting](https://github.com/Thaumazonsrl/scanspot/security/advisories/new)
on this repository.

Please include:

* what an attacker can achieve, and what access they need to start
* affected version (`docker compose exec scanner python -m app.main --version`)
* reproduction steps
* any logs or proof of concept — **with community strings, SNMPv3 passphrases
  and API tokens redacted**

You can expect an acknowledgement within **5 working days** and an assessment
within **15 working days**. We will keep you informed while a fix is prepared,
and credit you in the advisory and the changelog unless you would rather stay
anonymous.

Please give us reasonable time to release a fix before disclosing publicly.

## Scope

scanspot holds read credentials for network devices and a write token for an
IPAM. Anything that leaks those, escalates them, or lets an attacker write to
the IPAM without them is in scope. So is anything that lets a *polled device*
influence scanspot beyond the data it is supposed to report — a malicious SNMP
agent should not be able to do more than record wrong inventory.

Particularly interesting:

* credential disclosure through logs, error messages or the NetBox objects
  scanspot creates
* injection through attacker-controlled SNMP or FortiOS response data
  (`sysDescr` and DHCP hostnames are the obvious candidates — they reach device
  names, descriptions and comments)
* anything that defeats `DRY_RUN`, or causes deletion of records that the
  documented exemptions say are protected

## Known limitations — please don't report these as new

These are documented design trade-offs, not undiscovered bugs:

* **SNMP credentials appear on the command line.** scanspot shells out to
  `snmpbulkwalk`, so the community string and SNMPv3 passphrases are visible in
  `/proc/<pid>/cmdline` to anything sharing the container's PID namespace. The
  container runs as a single unprivileged user and does not share its namespace
  by default. A design change here is welcome as a feature PR — but it is a
  known limitation, not a report.
* **TLS verification is off by default** for the FortiGate
  (`FORTIGATE_VERIFY_SSL=false`) and NetBox (`NETBOX_VERIFY_SSL=false`), because
  both are typically reached over a management LAN with self-signed
  certificates. Both are configurable and can be turned on.
* **scanspot trusts what devices report.** It records the inventory the network
  describes; it does not authenticate endpoints. A host that spoofs a MAC will
  be recorded as that MAC.
* **`.env` holds plaintext secrets.** That is the documented configuration
  mechanism. Protect the file and the host.

## Testing

Please only test against infrastructure you own or are authorised to assess.
Do not probe systems belonging to Thaumazon SRL or its customers.
