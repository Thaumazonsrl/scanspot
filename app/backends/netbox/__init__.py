"""NetBox backend.

    client.py          pynetbox session, idempotent bootstrap, MAC anchor,
                       write funnel
    sync.py            writes prefixes, VLANs, DHCP pools, infrastructure and
                       endpoints
    cleanup.py         ages out stale records, with the documented exemptions
    import_targets.py  one-shot 1.x migration: devices tagged `scan-target`
                       become rows in scanspot's own store

Note what is *not* here any more: reading the scan target list. From 2.0 that
lives in `app/targets.py` and comes from the store, so it works with any
backend — including ones with no DCIM model to hold a target.
"""
