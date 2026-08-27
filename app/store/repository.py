"""Domain-shaped access to the store.

Everything above this layer talks in scanspot's vocabulary — sites, targets,
credentials — and never writes SQL or touches a Session directly. That is what
will let the API, the scan cycle and the backends share one implementation.
"""

from __future__ import annotations

import logging
from typing import Iterable

from sqlalchemy.orm import Session

from .crypto import encrypt_secrets, resolve_secrets
from .models import CredentialProfile, Site, Target

log = logging.getLogger("store")


class Repository:
    """Operations on one session. Cheap to construct; do not hold across cycles."""

    def __init__(self, session: Session):
        self.session = session

    # ── credentials ─────────────────────────────────────────────────────────
    def credential(self, name: str, site: Site | None = None) -> CredentialProfile | None:
        """Look up a profile by name, preferring one scoped to `site`.

        Matching tolerates case and stray whitespace, because the name is
        typed by a human — historically into a NetBox custom field.
        """
        wanted = (name or "").strip()
        if not wanted:
            return None

        candidates: list[CredentialProfile] = list(
            self.session.query(CredentialProfile).all()
        )
        site_id = site.id if site is not None else None

        def matches(profile: CredentialProfile) -> bool:
            return profile.name.strip().lower() == wanted.lower()

        # A site-specific profile wins over a global one of the same name.
        for profile in candidates:
            if matches(profile) and profile.site_id == site_id:
                return profile
        for profile in candidates:
            if matches(profile) and profile.site_id is None:
                return profile
        return None

    def upsert_credential(
        self,
        name: str,
        kind: str,
        *,
        site: Site | None = None,
        params: dict | None = None,
        secret_refs: dict[str, str] | None = None,
        secrets: dict[str, str] | None = None,
    ) -> CredentialProfile:
        """Create or update a profile.

        Pass `secret_refs` for env_ref storage, or `secrets` for inline storage
        (which encrypts them). Passing both is a programming error.
        """
        if secret_refs and secrets:
            raise ValueError("a credential is either env_ref or inline, not both")

        profile = self.credential(name, site)
        if profile is None:
            profile = CredentialProfile(
                name=name, kind=kind, site_id=site.id if site else None
            )
            self.session.add(profile)

        profile.kind = kind
        profile.params = dict(params or {})
        if secrets:
            profile.storage = "inline"
            profile.secret_encrypted = encrypt_secrets(secrets)
            profile.secret_refs = {}
        else:
            profile.storage = "env_ref"
            profile.secret_refs = dict(secret_refs or {})
            profile.secret_encrypted = None

        self.session.flush()
        return profile

    @staticmethod
    def credential_settings(profile: CredentialProfile | None) -> dict:
        """Flatten a profile into the keyword form the poller configs expect.

        Secrets are resolved here and nowhere else, so there is exactly one
        place where a plaintext credential comes into existence.
        """
        if profile is None:
            return {}
        settings = dict(profile.params or {})
        settings.update(
            resolve_secrets(
                profile.storage, profile.secret_encrypted, profile.secret_refs
            )
        )
        return settings

    # ── sites ───────────────────────────────────────────────────────────────
    def sites(self) -> list[Site]:
        return list(self.session.query(Site).order_by(Site.slug).all())

    # ── targets ─────────────────────────────────────────────────────────────
    def targets(self, site: Site | None = None, enabled_only: bool = True) -> list[Target]:
        query = self.session.query(Target)
        if site is not None:
            query = query.filter(Target.site_id == site.id)
        if enabled_only:
            query = query.filter(Target.enabled.is_(True))
        return list(query.order_by(Target.name).all())

    def target_count(self, site: Site | None = None) -> int:
        query = self.session.query(Target)
        if site is not None:
            query = query.filter(Target.site_id == site.id)
        return query.count()

    def find_target(self, site: Site, address: str, method: str) -> Target | None:
        return (
            self.session.query(Target)
            .filter_by(site_id=site.id, address=address, method=method)
            .one_or_none()
        )

    def find_by_external_ref(self, site: Site, external_ref: str) -> Target | None:
        return (
            self.session.query(Target)
            .filter_by(site_id=site.id, external_ref=str(external_ref))
            .one_or_none()
        )

    def upsert_target(
        self,
        site: Site,
        *,
        name: str,
        address: str,
        method: str,
        credential: CredentialProfile | None = None,
        vendor_override: str = "",
        source: str = "manual",
        external_ref: str | None = None,
        enabled: bool = True,
    ) -> tuple[Target, bool]:
        """Create or update a target. Returns `(target, created)`.

        Identity is `(site, address, method)`, with `external_ref` consulted
        first so that re-running an import updates rather than duplicates — even
        if the device was renamed or readdressed at the source.
        """
        target = None
        if external_ref:
            target = self.find_by_external_ref(site, str(external_ref))
        if target is None:
            target = self.find_target(site, address, method)

        created = target is None
        if created:
            target = Target(site_id=site.id, address=address, method=method)
            self.session.add(target)

        target.name = name
        target.address = address
        target.method = method
        target.credential_profile_id = credential.id if credential else None
        target.vendor_override = vendor_override or None
        target.enabled = enabled
        if created:
            target.source = source
            target.external_ref = str(external_ref) if external_ref else None

        self.session.flush()
        return target, created

    def disable_missing(self, site: Site, seen_ids: Iterable[int]) -> int:
        """Disable imported targets that were not seen in the latest import.

        Disabled rather than deleted: a target removed at the source may come
        back, and its discovery history should survive the round trip.
        """
        keep = set(seen_ids)
        stale = [
            target
            for target in self.targets(site, enabled_only=True)
            if target.source == "imported" and target.id not in keep
        ]
        for target in stale:
            target.enabled = False
            log.info("target '%s' disabled: no longer present at the source", target.name)
        if stale:
            self.session.flush()
        return len(stale)
