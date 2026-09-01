<!--
Thanks for contributing. Keep the description short; the checklist matters more.
-->

## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] Commits are signed off (`git commit -s`) — see CONTRIBUTING.md
- [ ] `python -m pytest` passes
- [ ] No secrets, real IP addresses or customer hostnames in the diff, the
      tests or the PR description

<!-- If you added a vendor mapping or a sysDescr rule: -->
- [ ] The mapping was **verified against a real device**, and the observed
      `sysObjectID` / `sysDescr` is quoted below
- [ ] A test using the real string, verbatim, was added

<!-- If you touched the sync or cleanup layer: -->
- [ ] Every write still goes through `NetBoxClient.write()` (so `DRY_RUN` holds)
- [ ] Objects without the `auto-discovered` tag are still never modified or deleted
- [ ] A cycle with no responding data source still skips both the sync and the cleanup

## Device details

<!-- For vendor support PRs. Delete this section otherwise. -->

```
sysObjectID:
sysDescr:
```
