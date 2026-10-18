# certify-manage — controller invocation-inspection receipt

**Date:** 2026-10-18  
**Consumer source:** box-control `dec2def825a474675def51df44d75d534e76508f`, root-control `3a2dd9c935e332e811adaccedf04b16bd2de1ea7`  
**Upstream handoff:** [controller selected inspect and invocation result reader](https://github.com/zog144/know-file/blob/e7dab73cd5789e5e4dcb111f6a3dc9d72de060f2/certify-manage/handoffs/controller-invocation-inspection-implementation-2026-10-18.md)

## Producer compatibility decision

**ACCEPT source contract without wire-format changes.** The current `certify-manage/inspect` produces exactly one bounded, prefixed `zog-certify-inspection-result-v1` record; the authoritative controller reader recognizes that marker and all 15 issuer fields. The issuer never claims controller request or InvocationID provenance. It validates real certificate, chain, private key, approved SAN, renewal account, matching ready journal and current policy under the immutable issuer view, and always reports `tls_ready=false`.

The producer has now added semantic hardening: only `issue/issued`, `renew/renewed`, and `renew/unchanged` qualify for `issuer_verified=true`. Other journal pairings are still visible in a bounded negative inspection but can never become positive evidence. This is **not** a wire/schema change and preserves the independently authenticated controller reader's negative result semantics.

## Responsibilities and remaining gates

| Gate/owner | Evidence | State |
| --- | --- | --- |
| certify-manage Regular | One-line marker/schema, actual X.509/renewal-policy inspection, recognized operation/outcome tests | SOURCE IMPLEMENTED; source CI required after this change |
| box-control Regular | Separate `inspect` selected request through narrow broker with retained request ID | SOURCE IMPLEMENTED; CI 525 passing |
| root-control Regular | Single saved InvocationID-scoped, UID-bound journald result reader | SOURCE IMPLEMENTED; CI 230 passing |
| image-build Work | Real pinned Certbot 5.8/cryptography 50.0.2 immutable artifact/view/binding on actual rootfs | NATIVE GATE A PENDING |
| box-control/root-control Work | Native transient selected inspect, actual journald transport/boot/InvocationID, valid/invalid result, reboot/UID/mount | GATE B PENDING |
| host-deploy Regular/Work | Migrate reviewed consumer to public repo, retain separate inspect ID, correlate with original renewal journal; only then consider authorized stage/nginx | CONSUMER MIGRATION PENDING |
| ACME/HTTPS | Approved FQDN, challenge, staging CA, local nginx external TLS verification | GATE C NO-GO |

For host-deploy after migration, use the box-control narrow `IssuerLifecycleClient` and pin the **numeric controller owner UID** from protected installation state; the reader authenticates the saved selected inspect request, not a host-deploy-supplied stream. Correlate the returned leaf fingerprint, policy SHA, certificate identity, operation/outcome and UTC-normalized journal time with the *original* renewal request's independently authenticated issuer observer. Do not start `stage` on `unverified`, `uncertain`, `recovered-unverified` or stale observations. `unchanged` ordinarily needs no nginx reload.

**No live issuer execution, build job, DNS credential handling, host-deploy migration or nginx changes were made by this compatibility response.** Before accepting Gate B, test actual systemd stdout attribution and journal reader completeness on an approved isolated host; CI fixtures alone are not native evidence.
