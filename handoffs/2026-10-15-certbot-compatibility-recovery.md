# certify-manage — Certbot compatibility and interrupted-operation recovery

**Date:** 2026-10-15
**Repository:** `zog144/certify-manage`, branch `unstable`
**Scope:** source-only security and regression pass; not live ACME acceptance.

## Completed in certify-manage

- The review-only `integration/box-control/application.py` now includes
  a separately selected `stage` program (identical certificate state
  mount and trusted policy destination, bounded command).
- Added AST-based declaration test to prevent missing `stage`, duplicate
  program names, or silent policy/mount drift.
- Strengthened policy parser against duplicate ACME Renewal Information,
  unexpected option/section formats and unsafe key/challenge preferences.
- Added Certbot 5.8.0 ConfigObj serialization smoke, including nested
  `[[webroot_map]]` and ARI metadata, under the pinned Certbot CI job.
- Revalidate the private Cloudflare credential file on `renew`, not only
  on issuance.
- Require explicit recovery acknowledgement. A recovered existing valid
  certificate is reported as `recovered-unverified`, *never* issuance
  success; automatic staging/refreshed HTTPS readiness is forbidden.
- Keep incomplete/failing operations uncertain, sanitize subprocess timeout
  errors in the CLI, and test journal fsync failures, false exit-zero
  results, wrong SAN/account, invalid successor, and post-side-effect failure.

## Cross-owner work and acceptance gates

**box-control/root-control Regular:** Verify current selected `stage`
operation policy is bound to the *specific* issuance authorization, with
the exact prepared UID/storage/host read-only binding. Include stages in
native transient-unit tests and reject an unselected full-app launch.
An explicit `recover` administrative capability, if introduced, must
not be bundled into unattended selected program permissions.

**host-deploy Regular:** Wire the selected `stage` command only after
trusted issuer observation indicates newly validated material and the
previous controller renewal request is resolved. Reject
`recovered-unverified` (and any `uncertain`) as readiness. Preserve
request IDs and do not reissue if previous Certbot reply was lost. Use the
owner-bound delivery bridge, nginx validation, reload and rollback; never
mount Certbot account state into nginx.

**image-build Regular:** Pin the exact Certbot/core/provider dependency
closure and actual executable/plugin paths in the immutable software
view. Re-execute renewal serialization and CLI smoke against that image
instead of only GitHub's pip environment.

**host-deploy Work / isolated acceptance:** Run staging ACME issuance and
renewal for an operator-approved hostname and challenge route, verify
persisted real Certbot renewal options, selected systemd units and
non-root ownership, lost reply/reboot, changed vs unchanged fingerprints,
private staging, nginx activation and TLS/SNI end to end. Use local Zog
as TLS terminator; never select an arbitrary DNS name or expose provider
secrets. Fail closed if the strict saved-renewal policy validator rejects
an actual pinned-version record: capture a **redacted** fixture and add
a narrow compatibility rule, not a wildcard key exemption.

**Status:** production unattended certificate issuance remains NO-GO
until live native systemd and ACME acceptance is completed.
