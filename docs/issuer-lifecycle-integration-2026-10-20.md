# Issuer lifecycle integration boundary — 2026-10-20

**Status:** source hardening completed; native and ACME production gates **NO-GO**.
**Owners:** certify-manage Regular (issuer), box-control/root-control (execution and credential authority), host-deploy (consumer publication), station-access (administrator/hostname intent), image-build (immutable runtime).

## Runtime and issuer observation

- Each `prepare`, `issue`, `renew`, `inspect`, `stage` is an **exact selected program**, not an implicit application launch. The controller retains immutable software view, issuer UID/GID, storage/grant identity and durable request ID. No unmanaged permanent inspector service.
- Finite `inspect` emits one bounded `ZOG_CERTIFY_INSPECT_RESULT_V1 ` record with existing `zog-certify-inspection-result-v1` fields and `tls_ready:false`. This interface is unchanged.
- Root-control's `zog-trusted-issuer-inspection-v1` binds the exact selected inspect request to frozen systemd unit, boot, InvocationID, UID and fully bounded journald stdout. A process exit code cannot establish certificate health.
- Host-deploy must generate **another** inspect request ID, compare its authenticated leaf, policy, certificate ID, SAN set, `operation`/`outcome` and UTC-normalized journal timestamp against the original `renew` request's authenticated journal-ready observation. The issuer cannot attest the controller ID. Stale (over 15 minutes) or unverified evidence is not usable; a fresh request must be issued after recovering the previous request state.
- `issued`, `renewed`, `unchanged`, `failed`, `uncertain`, and `recovered-unverified` remain distinct. Only `issue/issued`, `renew/renewed`, and `renew/unchanged` may produce `issuer_verified:true`; negative outcomes never authorize stage/consumer readiness.
- Read-only snapshot uses the existing issuer flock and does not create lock/state files. A running renewal blocks it. Root-control's actual systemd journal/UID tests are still required.

## DNS-01 and Cloudflare credential ownership

Root-control independently authorizes `zog-issuer-cloudflare-credential-v1` with reviewed assignment/credential revisions, zone and approved hostnames, issuer grant/storage, protected policy digest and expiry. Its **offline**, root-only provisioning reads token bytes only from an explicitly approved private FD or a separately authenticated station credential-reader transfer, not a generic daemon RPC. It refuses unresolved issuer operations, pending provisioning and mismatched revisions before writing `dns/cloudflare.ini` atomically under the issuer UID/GID, mode 0600.

certify-manage's **only** credential input is that exact file inside the preexisting private `certificate-data` mount. This pass adds a limited issuer-side check:

- Read by anchored, no-symlink protected file access; require exactly mode 0600 and one `dns_cloudflare_api_token = <token>` line, LF-terminated, with token bytes in the same restricted character/length envelope as root-control's installer.
- Reject global API key/email, hooks, multiple directives, bad permissions, missing/symlinked/wrong owner and unexpected values. No secret contents or provider response enter stdout, receipt or exception details.
- Validate a digest before selected Certbot `issue`/`renew` and after it returns. If the file disappears or changes during execution, retain the pre-written `uncertain` operation and block subsequent unattended mutation. A validator cannot retrospectively prove no temporary swap occurred, so exact zone scope, authorization revision and prohibition of concurrent provisioning remain **root-control admission obligations**.
- Rotation/revocation requires a **new approved station/local or managed owner intent** and a root-authorized credential installation receipt. An updated file alone, a station UI switch, or a path passed to the issuer **does not authorize use of a new zone or certificate name**. Provider-side token revocation must be separately performed by the authorized provider account; local mode changes do not revoke it upstream.
- The supported Certbot plugin and immutable path are fixed: `/applications/certify-manage/bin/certbot`, Certbot/cloudflare DNS plugin 5.8.0 according to the pinned image-build producer lock. Actual installed ABI/plugin/CA acceptance is still owned by image-build Work.

## Issuer-private staging and host-owned publication

Selected `stage` is a **read-only-from-lineage, private-writer** operation. It requires the ready matching issuer journal, previously validated ACME account and valid certificate. It stages into `publications/<certificate_id>/<leaf_sha256>/` with `fullchain.pem`, `privkey.pem` and `receipt.json` (0700 directory, 0600 files). The exact PEM bytes about to be frozen are independently rechecked for chain ordering/signatures, leaf fingerprint, private/public-key match, SAN set and date validity **after reading** them, closing the interval between preflight lineage inspection and final read. It neither reloads nginx nor grants certificate consumer authority.

The secret-free receipt remains **`zog-certify-publication-candidate-v1`** exactly:
`schema`, `certificate_id`, `policy_sha256`, `certificate_fingerprint_sha256`, `hostnames`, `expires_at`, `fullchain_sha256`, `key_sha256`, `state="issuer-private-unbound"`. No ACME account, Cloudflare credential, arbitrary source path or consumer authorization is included. Identical fingerprint re-stage is idempotent only if private bytes and receipt match; a mismatch rejects.

On crash while writing `.pending-<nonce>`, the partial directory is **preserved**. Any such leftover blocks subsequent `stage` until a separately authorized operator reviews/disposes of it; the issuer will **not** silently remove evidence or mark an uncertain selected stage satisfied. The controller/host-deploy must also recover the **original stage request ID** before deciding whether another stage can be authorized. Merely removing the staging directory is not evidence that the controller request completed.

**Only the host-owner's fixed delivery bridge** reads a specific fingerprint-bound candidate under the established issuer UID/storage binding. The existing host-deploy `zog-host-deploy-cert-delivery-v1` contract must authenticate the bound service/certificate, stage request and authorized peer, reopen the exact candidate via safe no-follow descriptors, recheck receipt digests, SAN, leaf/private key, expiry and policy, then copy into a *different*, consumer-owned TLS generation with atomic swap, `nginx -t`, fixed-unit reload and rollback. nginx must never see `certbot/config`, `operations`, `dns`, ACME account private keys or issuer storage.

The actual HTTPS connection must terminate at the local Zog host (including NAT/TLS-passthrough network-traverse). Only the independently CA-verifying SNI and presented-leaf probe may establish externally verified HTTPS readiness. `tls_ready` remains false in every issuer/observer/stage result.

## Recovery / negative acceptance

1. Lost reply or reboot: controller and host-deploy preserve original selected operation and request ID; issuer does not invent a second request namespace. Recover controller frozen runtime evidence before new request.
2. Renewal timeout/nonzero/side effect: saved uncertain journal remains; future issue/renew/stage blocked; old installed nginx generation may continue if independently still trusted. Explicit manual `recover` produces `recovered-unverified`, never success/publication.
3. Replaced/invalid lineage after validation: exact staged PEM revalidation fails without promoting any private candidate. Unknown journal or policy refuses inspection/stage.
4. Credential rotation during Certbot: even on process exit 0, a missing/invalid/different secret after execution leaves the attempt uncertain. Root-control must prohibit mutation during running selected operations and verify installation revisions at admission.
5. Interrupted staging: partial pending directory persists as evidence; no automatic cleanup or duplicate effect. Failed nginx delivery/CA/SNI verification belongs to host-deploy rollback; the issuer-private candidate does not imply any delivery success.
6. Expiry, revoked FQDN/credential, lost issuer mount, changed ACME account: fail closed on fresh issuance and publication until a separately reviewed host-owner recovery/migration; never automatically reset account or policy.

## Acceptance gates

| Gate | State | Owner |
| --- | --- | --- |
| Source tests / static controller compatibility | **Source only** | certify-manage + box-control/root-control |
| Native immutable Certbot 5.8.0 / Cloudflare plugin / Python ABI / rootfs software-view | NOT ACCEPTED here | image-build Work |
| Three-UID selected runtime, exact systemd/journald InvocationID, mounts, credential bridge/rotation and reboot | NOT ACCEPTED here | box-control/root-control Work + station-access |
| Exact staged receipt → host-owned nginx generation, config check/reload/rollback + local CA/SNI proof | NOT ACCEPTED here | host-deploy Work/Regular |
| ACME staging-issued/renewed cert and production unattended renewal | **NO-GO** | separate reviewed host owner authorization |

Do not allow passing source CI to trigger live ACME, DNS writes, nginx changes or unattended renewal.
