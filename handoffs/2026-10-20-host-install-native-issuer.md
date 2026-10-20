# Handoff: native issuer installation and controller admission

**Date:** 2026-10-20  
**Producer/owner:** certify-manage Regular, source `8f09d5712c6ab4e487069e91f26c0e8fdd91d753`  
**Primary next owner:** host-install Regular, reviewed `unstable` `bd265c061040e8aa52f6939ed1e97783e82e03fa`  
**Supporting owners:** image-build Work, box-control/root-control Regular/Work, station-access and host-discover Regular  
**Acceptance executor after prerequisites:** host-deploy Work.  
**Status:** **GO for source/native installer integration planning on isolated host only. NO-GO for live ACME, production nginx cutover or PR #3 merge**.

## Producer artifact (new)

The certify-manage source now publishes
[issuer-installation-requirements-v1.json](../integration/host-install/issuer-installation-requirements-v1.json)
as a **non-secret, requirements-only** integration profile. It fixes:

- persistent controller-granted application `certify-manage` with exact separate selected commands `prepare`, `issue`, `renew`, `inspect`, `stage`; original durable request ID and selected frozen launch binding;
- `application-software-consumer-v1` and immutable `/applications/certify-manage/bin/python3`, `/applications/certify-manage/bin/certbot`;
- `certificate-data` 0700 under dedicated nonroot issuer UID/GID, guest `/var/lib/zog-certify-manage` bound to persistent STATE; no rootfs fallback;
- root-owner nonsecret policy `/etc/zog/certify-policy/policy.json` bound at guest `/run/zog-host/certify-policy/policy.json` read-only;
- narrow Cloudflare credentials root-installed at issuer private `dns/cloudflare.ini`, exact owner and 0600;
- short-lived selected `inspect` one-line 4096-byte marker with `tls_ready:false`, authenticated by the **controller** from the saved systemd invocation;
- never auto-issue on boot, infer hostname from a beacon, reset an existing ACME account, bypass held controller state, run Certbot as root, expose any issuer secrets, or deploy nginx.

The profile does **not** contain hostname, token, grant ID, UID, storage ID, issuer operation/request ID, secret or installed receipt. Treat it only as source expectations. [Detailed contract](../docs/native-issuer-installation-2026-10-20.md).

CI: [run 39499151670](https://github.com/zog144/certify-manage/actions/runs/39499151670), six jobs **PASS**, Python 3.11/3.12 each **127 passed, 3 skipped**, Certbot CLI smoke **3 passed**. The new tests parse the literal application DSL and fail on drift in program selection, executable paths, policy mount, state grant and result schema.

## host-install Regular — requested implementation

1. Inspect `docs/host-install/certificate-enablement.md`, `src/zog/host_install/certificate_lifecycle.py`, `certificate_gate.py` and the current simulated durable `certificate-lifecycle-record`. Preserve all existing fail-closed operator-pending/hold semantics and observed ACME identity preservation.
2. Define and implement a **trusted native observation adapter**, not an alternate certificate launcher. It gathers from authenticated box-control/root-control/STATE + image-build producer evidence: software consumer/view ID + accepted rootfs compatibility, controller-issued numeric UID/GID and fixed grant/storage identity, selected preparation revision/terminal completion, root policy mount/digest and owner-assignment state. Do **not** synthesize `grant=verified` from a JSON file, call `CertificateManager.prepare()` directly or use the review-only profile as authority.
3. Host-install's actual installer should arrange only the **approved deployment of exact controller, root-control and software view prerequisites** with validated systemd unit/socket files under their respective owners. Existing `host-install` service/layout conventions control deployment; no new persistent inspector service or issuer root shell. Use no static `certify-manage.service`: controller-selected programs remain transient.
4. Admit one controller preparation binding only after current STATE (no `mutation-incomplete`/recovery marker), controller grant + persistent mount, approved immutable view and protected owner policy have been independently verified. Where the owner hostname has not arrived, report `awaiting-operator-approved-hostname-challenge` without DNS issuance; preparation of persistent state must not imply authority to issue.
5. On reboot, reinstall or rootfs generation change, independently prove existing `storage_id`/issuer UID/GID and ACME account/lineage presence, retain preparation revision. Refuse missing/replaced mount, changed UID, different policy revision, uncertain original selected request, generation/policy mismatch and unexpected `recovered-unverified`. Never silently recreate a private account or choose a substitute view.
6. Expose only **redacted authenticated readiness evidence** to host-install and station-access/host-deploy. Keep the existing `certificate-lifecycle-record` as *status*, not a certificate execution grant. A positive issuer `inspect` requires controller's separate InvocationID-scoped reader, and host-deploy's later original renew-to-inspect correlation.

## Independent producer gates

**image-build Work** must provide *actual* immutable view/artifact/consumer IDs from native wheel/ELF/Certbot 5.8.0/Cloudflare plugin checks. Source simulated software generation cannot satisfy native acceptance.

**box-control/root-control** must supply installed frozen controller and privileged root-control revisions (PR #3 reviewed box-control `a3e939b7a22ef6277ae9712961ffbd5a18ccac39`; root-control inspect reader `3a2dd9c935e332e811adaccedf04b16bd2de1ea7`, reverify current compatible revision) and root-approved issuer UID, grant/storage, policy RO mount, narrow lifecycle socket, issuer-only Cloudflare installer, exact systemd InvocationID. No direct generic evaluator from host-deploy.

**station-access + host-discover** must provide one authenticated assignment source: a versioned outgoing managed FQDN authority, **or** standalone approved local zone/credential/consumer intent. Both produce protected host-owner policy via the reviewed root-controlled path. A signed beacon, Cloudflare token or UI proposal alone is never sufficient. For NAT or network-traverse, the TLS endpoint stays at local Zog.

**host-deploy Work** runs **only after** above evidence is pinned: isolated selected prepare/renew/inspect/stage; real split-UID systemd, denied cross-UID access, lost reply and reboot recovery, real approved staging ACME challenge, local nginx delivery rollback and CA-valid SNI fingerprint. [PR #3 Work review](https://github.com/zog144/host-deploy/pull/3#issuecomment-6301521377) reports 138 coordinator fixtures, 10 real-client/simulated-broker tests and 22 confined peer/delivery fixtures passed, but **no live issuer view/controller socket or native Gate B/C evidence**. PR #3 stays draft.

## Required installer return to certify-manage

Provide exact source pins, native host disposable identity (nonsecret), boot and SYSTEMD InvocationID, installed rootfs view/consumer hashes, actual SELinux/DAC or DAC ownership/mode, issuer UID/GID and storage/grant opaque IDs, policy assignment revision + digest, preparation revision, request/result replay behavior, reboot/mount rejection tests, and explicit **PASS/BLOCKED/NOT-RUN** per subgate.

Never include PEM/private key, Certbot ACME account material, provider tokens, station vault contents or a production FQDN guess in a public report. Do not clear a preexisting mutation hold or modify active production nginx/DNS/80/443.

**End state requested:** installed, grant-bound and observable **issuer readiness to perform an operator-authorized selected operation**—not a production certificate or an automatic issuance policy.
