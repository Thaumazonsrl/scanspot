"""Sources of truth that scanspot reads scan scope from and writes findings to.

A backend is bidirectional: it supplies the list of devices to poll and it
receives the correlated result. `netbox` is the only implementation today.

There is deliberately no abstract base class yet. The right interface is not
knowable from a single implementation, and an abstraction shaped around NetBox
would simply be NetBox's API wearing a hat. Define it when the second backend
lands — see the Direction section of CLAUDE.md.
"""
