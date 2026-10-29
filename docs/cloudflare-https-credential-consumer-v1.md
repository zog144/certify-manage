# Cloudflare DNS-01 credential consumer over unified protected HTTPS (source v1)

**Date:** 2026-10-29  
**Implementation owner:** certify-manage Regular  
**Consumers:** host-deploy Regular [PR #6](https://github.com/zog144/host-deploy/pull/6), host-install [#2](https://github.com/zog144/host-install/issues/2), root-control [#12](https://github.com/zog144/root-control/issues/12), station-access/host-discover HTTPS credential authority  
**Status:** **source-only, not a network transport or native authorization**. No issued cert, token request, provider API write, SSH daemon, root receiver deployment, nginx reload or production renewal.

## Decision and security boundary

Option B is approved: the command-center Credential Authority releases a purpose-scoped, zone-scoped **Cloudflare token** to an independently enrolled, authorized Zog Host over the **common authenticated HTTPS credential-delivery protocol**, with TLS terminating at the receiving Host's approved interface as appropriate. The token is deposited by the Host's **separately privileged root-owned receiver**, never by the issuer command, host-deploy web process or station browser. A local standalone Host may use an independently approved local producer subject to the same private root install and revision rules. The station registry and the managed Host are distinct installations.

**No issuer-side HTTPS socket/client implementation is introduced.** The common protocol's station endpoint, Host identity proof, signed response, anti-replay storage, TLS trust and receipt persistence belong to host-identify/host-discover, station-access, root-control and host-install owners. This module defines only the **Cloudflare purpose-specific selector** and nonsecret root-install reconciliation interface. Adding an independent Python `requests`/urllib client here or invoking it on Certbot retry is forbidden.

The reviewed source remains unchanged for:
- immutable Certbot with **certbot-dns-cloudflare**, fixed `/applications/certify-manage/bin/certbot`;
- dedicated issuer UID/GID and persistent `certificate-data` STATE 0700;
- root-control `issuer_credentials.install_from_fd(project, token_fd, expected_authorization_id=...)`, atomic private `dns/cloudflare.ini` 0600, root-approved authorization/installed/blocked ledgers;
- issuer `cloudflare_credential_snapshot` before/after Certbot to detect replacement/drift; uncertain renewal blocks automatic retry;
- saved ACME renewal account, read-only selected `inspect` with InvocationID evidence and `tls_ready:false`;
- private fingerprint-bound `stage` and independently controlled host-deploy nginx delivery/reload/rollback.

## New producer API

`src/zog/certify_manage/credential_https.py` defines:

1. `zog-certify-cloudflare-https-consumer-v1` — **exact nonsecret, root-installed client selection fields**, including signed owner receipt and independent witness hashes, HostIdentity fingerprint, Host/install/STATE/registry, issuer grant/storage/UID/software-view, selected certificate/FQDN/zone, credential and assignment IDs/revisions, receipt digest and independently installed **HTTPS authority pin SHA256**. A source-only test cannot authenticate a JSON file; the privileged owner must verify protected installed bytes, wheel RECORD, source/approval signer, monotonic owner-ledger and current state **before and after** transfer. No SSH identity, key, known_hosts, forced-command or endpoint path is accepted.
2. `select_https_cloudflare(client, admission, root_approval, installation, issuer_policy, now)` — checks exact independent identities against the **host-deploy PR #6** `zog-host-deploy-cross-host-issuer-admission-v1` nonsecret candidate and the existing `zog-issuer-cloudflare-credential-v1` root authorization, canonical digest and exact issuer policy. Requires DNS-01 with `dns-cloudflare`, one exact approved FQDN below exact zone, current revision/expiry, dedicated non-root issuer, and exact independently recorded Host/STATE witness.
3. `selection.request(request_id, nonce)` — yields the bounded, secret-free `zog-certify-cloudflare-https-request-v1` **consumer-specific body** with `purpose=certify-manage-dns-cloudflare`, never an alternate top-level common transport wire protocol. The common protocol owner must wrap this body in its versioned authenticated HTTPS envelope and bind signed request/response, Host, consumer UID, current grant, original one-time request ID, nonce, delivery revision/expiry and credential purpose. **The issuer does not call HTTPS itself.** Caller must allocate and persist an original request ID before any transfer, recover that same operation after lost reply/reboot, and NEVER allocate a new one on an ordinary `renew`/`issue` retry. Local `request_id` is distinct from assignment ID; durable anti-replay is the trusted receiver's job.
4. `check_installed_credential(selection, root_ledger, root_inspection, now)` — reconciles the root-owned **existing** `zog-issuer-cloudflare-installation-v1` installed ledger and redacted root inspection against the request selection. It returns only `root-install-ledger-correlated-only` with `credential_transferred=false`, `issuer_ready=false`, `tls_ready=false`. It does **not** prove installed bytes, TLS, current signed station assignment, or automatic issuance. Root-control must still re-open the exact issuer file through protected descriptors and separately attest owner UID, 0600, symlink rejection, content/source revision, pending markers and protected installer provenance. Actual network/installed-byte acceptance is separate.

## Explicit host-deploy PR #6 adaptation

The current PR #6 source at `1658d57329dca6630a6d58423addc2a4b5b00c33` is a **draft** on PR #3. Keep all of its nonsecret signed host-owner, second monotonic owner-ledger, immutable delivery policy, station projection, current root approval, grant/storage/UID and exact DNS-01 hostname/zone/credential checks and negative tests. Its existing `CLIENT=zog-issuer-cross-host-client-v1` and `ssh_host/ssh_port/ssh_identity/ssh_known_hosts` fields are obsolete for Option B: replace them with independently root-installed HTTPS client and trusted authority pins, without relaxing any common identity comparison or deriving trust from an untrusted station candidate. Validate exact HostIdentity/installation/STATE/registry and the signed owner revision **on each authorized provisioning selection**, not only on initial enrollment.

The PR #6 result `source-bound-nonsecret-admission` must **never** be treated as sufficient to fetch or install a token, and no caller-provided admission JSON is an attestation. A privileged root process must consume independently authenticated, protected inodes and checked installed source+RECORD. A new HTTPS client profile needs fresh host-install/root-control source and installed-byte review; the old SSH client JSON/keys are not automatically valid authority.

## Required root receiver operation (separate owner)

1. A privileged operator/owner **explicitly selects** Cloudflare provisioning or rotation once, with saved fresh request ID. It is *not* coupled to Certbot `renew`, `issue`, `inspect`, staging or routine host beacon.
2. Read current signed assignment, independent root pin, monotonic second owner ledger, destination and delivery policy, prepared issuer grant/storage and station credential authorization/projection via separately authenticated protected interfaces. Verify `managed` approved, unexpired, not revoked, current host and exact owner of zone; reject unknown, conflicting or changed revision. Select this exact Cloudflare HTTPS consumer body.
3. The **common HTTPS client** connects to the independently authenticated command-center authority (port 443), uses pinned TLS trust/Host identity, purpose-limited request and signed response, bounded encrypted transfer and persistent replay ledger; no redirect or browser session. The receiver validates original request, response receipt, state, install grant and revision; no password/token in a public Django/API/browser/journal response.
4. Recheck root-approved nonsecret owner inputs **after response**; then hand token bytes via an anonymous FD to the **existing** `issuer_credentials.install_from_fd` under the root owner's lock and exact `expected_authorization_id`. It checks controller quiescence and retains its original installed/pending/blocked history. Do not bypass that installer, write `dns/cloudflare.ini` from host-deploy, or log token bytes.
5. Verify installer receipt and exact issuer-owned private file under the original non-root UID, with protected installed bytes/RECORD attestation and current policy. Persist only redacted transport/installation receipts and replay history across reboot. For uncertain delivery retain the same request ID; for rotation require a separately authorized **new** credential revision and an idle issuer.
6. Certbot continues reading only the issuer-owned `dns/cloudflare.ini` on a separately authorized selected operation. A failed/rotated/removed credential must not trigger automatic secret refresh. ACME account and lineage remain persistent, `issuer_verified` and `tls_ready` independent. Stage/nginx publication and outside-in HTTPS CA/SNI verification remain host-deploy gates.

## Source tests, exclusions and acceptance

`tests/test_credential_https.py` covers fixed purpose, bounded nonsecret request, exact Host/STATE witness, current root approval and PR #6 candidate comparison, expiry, revoked approval, revision drift, arbitrary/SSH client shape, changed grant, wrong hostname/zone, stale signer pin, incorrect request ID and installation ledger mismatch. A test asserts regular Certbot command construction and selected inspection have no HTTPS hook.

**Source acceptance only:** HTTP transport, browser/API isolation, station provenance, root approval rechecks, cryptographic signed exchange, durable anti-replay across reboot, real token FD transfer, native issuer 0600 file/UID and Cloudflare plugin runtime are NOT performed here. Do not mark either credential or certificate `ready` based on these test fixtures. The common protocol has its own version, and its exact envelope schema should be referenced only after approved by host-identify/host-discover; this file does not try to invent it.

## Remaining owner gates

- **host-identify/host-discover Regular:** approve the versioned, purpose-scoped common HTTPS credential envelope, Host identity and signed response, nonce/idempotency/TTL/revocation rules. No beacon expansion or generic root command RPC.
- **station-access Regular:** authenticated HTTPS authority and private vault broker; bind current DNS owner, signed assignment, zone-scoped credential revision, installed source and revocation, without exposing secret to Django/web browser.
- **root-control + host-install Regular:** explicitly selected *root-only* HTTPS receipt operation, pinned authority/certificate trust and owner/install/STATE, anonymous descriptor to existing private installer; NO unmanaged sshd, no generic root-control remote action.
- **host-deploy Regular:** supersede SSH-specific part of PR #6 with above selection/admission contract, retain PR #3 ledger/delivery checks and durable provisioning workflow; certificate path remains unchanged.
- **Work:** isolated, independent installed-byte, real TLS and nonsecret/real credential acceptance with negative replay/rotation/reboot and CA/SNI/ACME staging only after separate approvals.

**NO-GO for production credential transfer and ACME/HTTPS activation.**
