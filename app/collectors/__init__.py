"""Data sources.

A collector reads one kind of device and merges what it learns into the shared
`CollectionResult`. Collectors know nothing about where the data will be stored:
they speak only the domain model in `app/models.py`, which is what allows the
same collection pass to feed any backend.
"""
