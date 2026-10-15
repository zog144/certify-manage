# Phase 1.1 security review — source boundary (2026-10-14)

## Closed in source

- Validate persisted Certbot renewal file, including pinned ACME directory, account identity, authenticator, webroot map/path or Cloudflare credential path and approved lineage.
- Reject unexpected renewal parameters (including hooks), unknown sections, installer plugins, global cli.ini, directory hooks, and other renewal lineages; pass `--no-directory-hooks` and `--disable-renew-updates`.
- Enforce exact Certbot relative live symlink targets, read archive bytes via anchored no-follow file descriptors, verify key/certificate/SAN/expiry and bound account identity. Keep generated material private and redact status/logs.
- Execute Certbot with fixed executable location and reduced environment; version 5.8.0 and Cloudflare plugin 5.8.0 receive an **offline CLI smoke** job. No live ACME requests in CI.

## Open security gates before production

1. Host-level execution identity and mounted `STATE` provenance/owner verified by root-control, including restart and reboot.
2. More root-relative directory-fd hardening of the preparation path and symlink/race fault injection; journal publication and lock checks now use no-follow descriptors. A compromised same-UID issuer can mutate its own state. Live root-controlled mount isolation must be observed.
3. Certbot 5.8.0 real **staging issuance/renewal** of reviewed names, checking exact persisted config fields against this fail-closed parser. Fail if Certbot adds new options; do not relax checks generically.
4. Identify how policy contents are securely bound from an admin-owned read-only directory via the controller. Never embed the authority inside the writable application state.
5. Verify issuer-only DNS token permissions and HTTP-01 challenge directory exposure through exact host owner capability. No shell DNS hook.
6. Establish host-owned certificate publication with atomic generation selection, PEM fsync, read-only consumer permissions, nginx -t + reload and rollback evidence. No raw certbot account/key access in the consumer.
7. ACME renewal failure, expired-cert recovery, account migration/rotation, and compromised/missing state runbooks. Issuer storage deletion must not be triggered by application stop.
8. Current `CertificateStatus.health="valid"` is *cryptographic local inspection*, **not** verification of public CA trust, active nginx load, chain path or browser readiness.

## Compatibility note

Renewal options are restored from on-disk ConfigObj-style records; Certbot supports nested `[[webroot_map]]`. The validator is deliberately strict; actual certbot revisions beyond the pinned baseline require regression fixtures before permitting issuance.

## External references

- https://github.com/certbot/certbot/blob/main/certbot/docs/using.rst
- https://certbot-dns-cloudflare.readthedocs.io/en/stable/

## Certbot 5.8 compatibility and recovery regression expansion (2026-10-15)

Additional source regression coverage includes validated ConfigObj
serialization of Certbot's nested `[[webroot_map]]` and optional
`[acme_renewal_info]`, pinned-version safe key preferences,
challenge policy and Cloudflare credential controls. Unknown hooks,
unreviewed nested sections, duplicated ARI records, unsafe webroots,
invalid cryptographic preferences, symlinked/missing credentials and
unauthorized authenticators fail closed before Certbot starts.

Fault injection covers a nonzero exit **after** the lineage changed,
timeouts, incomplete/invalid new material, wrong SAN/account despite
exit zero, journal fsync failures, explicit recovery acknowledgement,
and refusal to stage an `recovered-unverified` certificate. These tests
do not make real ACME requests and do not certify that another Certbot
version's renewal records are compatible.

The `stage` program is declared in the review-only application alongside
`issue`, `renew` and `inspect`. Its exact root-control
selected-operation grant and host-deploy certificate-delivery interface
require independent deployment/acceptance. Do not enable production
issuance solely from CI or a successful source-parser test.
