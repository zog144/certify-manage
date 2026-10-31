# Cloudflare HTTPS v1: issuer-side private credential readback

**2026-10-31 — certify-manage PR #3 (source-only).** This source does not fetch or install credentials, authorize Certbot, issue certificates or publish nginx.

## Canonical protocol and owners

Use **`zog.host_identify.credential_delivery`**, source pin `host-identify@4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b`, not a second HTTPS protocol. The authenticated exchange consists of:

- `zog-credential-authorization-v1` with independently verified Credential Authority Ed25519 signature, monotonic revision, expiry and revocation; exact `host_id`, `host_fingerprint`, `installation_id`, `state_volume_id`, `registry_id`, consumer `certify-manage`, purpose `issuer-cloudflare-dns01`, and credential ID/revision.
- `zog-credential-request-v1` signed by the HostIdentity (separate persistent operation request ID and ≤120-second lifetime). The selected HTTPS receiver verifies TLS authority, exact Host and authorization, persistent HTTP nonce and request ledger, and independently approved hostname / zone.
- `zog-credential-delivery-v1` is Credential Authority-signed with a ≤120-second delivery lifetime. Only the root-owned receiver may process token bytes, via a private FD to **existing** `root_control.issuer_credentials.install_from_fd`. No Certbot CLI invocation, browser, web application or ordinary host-discover process may fetch or install the token.
- `zog-credential-installation-receipt-v1` is signed by the HostIdentity **after** root-owned installation. The request/delivery/receipt IDs and persistent ledger must have been independently verified by host-identify before being passed to the readback. Delivery without an installed receipt is uncertain; redelivery without recovery or rotation is forbidden.

The exact receiving Host/STATE, signed certificate assignment and second owner ledger are validated and installed by host-install and host-deploy PRs #3/#6. The issuer module does **not** duplicate their signer verification or pretend that an arbitrary JSON dictionary is a trusted signed assignment.

## Issuer source boundary

`cloudflare_https_contract.verify_installed(state, policy, *, approved, installed, root_inspection, owner, canonical_authorization, canonical_receipt, installation, issuer_uid, now)` is a **read-only correlation check**. Its arguments must originate from root-owned protected inodes, active signed owner/assignment checks and the canonical verified HTTPS protocol; none can be accepted from request JSON, an unprivileged caller, an issuer application launch or a mere station browser response.

It requires simultaneously:

- current `zog-issuer-cloudflare-credential-v1` root-approved authorization and exact actual `zog-issuer-cloudflare-installation-v1` installed ledger, with the same field values, expiry, grant/storage/assignment/credential revisions; distinct root inspection must agree;
- root-installed `zog-host-deploy-certificate-owner-authority-v1` with managed `signed-host-discover` provenance, approved/non-revoked current revision, exact certificate/FQDN/policy fingerprint/challenge, DNS zone and Cloudflare credential ID/revision;
- independent installed Host/installation/STATE/registry witness, owner receipt digest, policy fingerprint, original root grant/storage, the actual **nonroot** issuer UID and the independently installed private-file generation witness, not invented software-layer identities;
- current independently verified `zog-credential-authorization-v1` and signed `zog-credential-installation-receipt-v1` with **exact** common binding, credential revision, authorization ID/revision, installed outcome, original request, delivery and receipt UUIDs, and safe timestamps;
- exact DNS-01 single FQDN below the approved zone and the existing issuer-owned `dns/cloudflare.ini` (dedicated UID, 0700 parent, 0600 regular non-symlink, bounded single API-token line, protected anchored descriptor read). It does **not** return token bytes or any credential digest.

The returned status is `issuer-private-file-source-correlated` with `can_issue=false`, `can_renew=false`, `tls_ready=false` and `requires_selected_controller_admission=true`. This is **not** a signed installation receipt, proof of installed token origin, evidence of no same-revision file swap, or an acceptable input for unattended renewal.

Root-control's selected-program admission and durable state, actual original installer ledger, private FD, current mounted STATE, grant and quiescence remain mandatory. Its installed receipt does not presently record canonical `request_id`/`delivery_id` or a separately attested immutable private-file generation. The protected receiver must correlate these in **its own current ledger and exact installed-byte checks**, not infer them from the issuer's successful file readback.

The new **`file_generation_sha256` root witness** hashes only `st_dev:st_ino:st_uid:st_gid:mode:st_ctime_ns:st_mtime_ns:st_size` from a no-follow opened descriptor, never the provider token. The issuer checks the generation before and after its private credential read. Root-control/host-install must independently produce the exact witness immediately after their real protected FD installation, persist it root-only alongside the native request/receipt correlation, and refresh it **only on an explicitly approved rotation**. A replacement of `cloudflare.ini` (even with identical token bytes and revision) now fails source readback against the previously root-installed witness. A caller-calculated witness from an untrusted file is **not** authorization. This detects file-generation drift, not upstream Cloudflare token revocation, a replacement that occurred before the independent witness was attested, or a trusted issuer/root compromise.

The existing canonical protocol deliberately does not retain a reusable secret/token digest, and this witness does not add one. The issuer's before/after Certbot snapshot separately protects renewal against changes *during* execution; only the root receiver can authenticate the token's original signed delivery. Native root ledger/witness and installed-source acceptance remain **NOT RUN**.

## Rotation / denial tests

`tests/test_cloudflare_https_contract.py` uses synthetic non-live token bytes to reject stale/expired/revoked root authorization, mismatched saved root install and inspection, conflicting signed owner/assignment revision, wrong policy digest, partial-zone confusion, Host/STATE/issuer UID/grant/storage drift, wrong canonical consumer/purpose, credential/revision conflict and receipt that is not installed. Symlink, missing, wrong-mode, unsafe-parent, wrong UID, replaced private inode-generation and extra-secret-key inputs fail closed.

The issuer's existing `issue`, `renew`, `inspect`, `recover` and `stage` source remain untouched: **no implicit HTTPS token refresh on retries or certificate operations**. Keep staged PEM fingerprint and HTTPS nginx publication outside this source pass.

## Remaining acceptance gates

**host-deploy Regular:** re-review PR #6's current HTTPS client `zog-issuer-https-credential-client-v1` and signed owner/ledger/delivery checks. Bind canonical `issuer-cloudflare-dns01` purpose, root receiver, exact installed Host/STATE witness and persistent original request/delivery IDs; do not equate a JSON receipt with validated Ed25519 signatures.

**root-control / host-install Regular:** authenticate and persist canonical HTTPS v1 approvals, signatures, nonce/replay, installed-byte/RECORD, quiescence and private-file generation, and correlate it with the exact root installer ledger across reboot and rotation. Require current assignment, root-owner policy and protected grant before and after delivery/install.

**station-access / host-discover:** independently authenticate the managed FQDN assignment, DNS owner and station Credential Authority; attest its key and grant through independently approved pins. No issuer-side authority derivation from a beacon.

**Work:** real root-owned HTTPS/token transfer and separate native immutable Certbot/Cloudflare-plugin/ACME staging, selected InvocationID inspection and nginx/SNI/CA acceptance remain **NOT RUN / NO-GO**.
