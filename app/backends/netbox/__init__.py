"""NetBox backend.

    client.py    pynetbox session, idempotent bootstrap, MAC anchor, write funnel
    targets.py   reads the scan targets out of NetBox; applies the first-run seed
    sync.py      writes prefixes, VLANs, DHCP pools, infrastructure and endpoints
    cleanup.py   ages out stale records, with the documented exemptions
"""
