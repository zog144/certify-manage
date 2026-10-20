# Handoff: certify-manage issuer lifecycle hardening completed

**Date:** 2026-10-20  
**Target:** host-deploy Regular and Work, box-control/root-control Regular, station-access Regular, image-build Work  
**Branch:** `zog144/certify-manage/unstable`  
**Scope:** issuer-side source hardening, not live host acceptance.

## Source deliverables

- DNS-01 credential checks now match root-control's **exact one-line token format** and require issuer-owned 0600, protected/no-follow file. Certbot `issue` and `renew` snapshot both token digest and issuer-owned file-generation identity before launch, recheck after Certbot, and leave the operation `uncertain` if it changes or disappears. No secret material in stdout, argv, operation journal or receipt. An approved root-control credential/zone/revision receipt remains essential; the issuer cannot independently infer Cloudflare token zone permissions.
- `stage` now revalidates the **exact PEM bytes** being frozen (leaf/chain/key/SAN/time) after its prior issuer-journal/account verification. Crash-left `.pending-*` staging directories block automatic replay until reviewed. Existing fingerprint-bound `zog-certify-publication-candidate-v1` metadata schema is unchanged.
- Finite `inspect` stdout marker/`zog-certify-inspection-result-v1` schema and `tls_ready:false` are unchanged. Root-control's saved InvocationID reader and narrow selected controller broker remain the only approved transport; the old persistent inspector socket prototype is deferred.
- Source test matrix adds malformed/global-key/multi-line/symlink/wrong-mode credential rejection, change-during-renewal, staging swapped key/chain, pending crash, private-generation tampering and replay behavior. No provider writes or real systemd service were executed.

## Exact integration requirements

**host-deploy Regular:** Use the migrated public `host-deploy/unstable` to retain the original `renew` request and a **different** selected `inspect` request. Consume root-control's authenticated `zog-trusted-issuer-inspection-v1`; match it with the original renewal's authenticated journal-ready observation and the current policy, fingerprint, outcome and identity. `unchanged` means no unnecessary reload; `recovered-unverified` and `uncertain` cannot authorize selected stage. For changed `renewed`, issue and durably retain a **new selected `stage` request ID**, then call the existing separately authorized delivery bridge with exact certificate/service/fingerprint binding. Do not read arbitrary issuer directories or force a new request after an unknown result.

**box-control/root-control:** Admit DNS-01 operations only with current `zog-issuer-cloudflare-credential-v1` root-approved zone, assignment/credential revision, issuer grant/storage and safe installed token. Reject rotation when any issuer operation is queued/running/uncertain and preserve the root-controlled host-policy digest. Prove the selected inspect's saved InvocationID, UID, systemd stdout and mount identity in native Gate B.

**station-access:** Produce approved local or managed hostname + credential intent/projection with distinct revisions and revocations. Do not expose the station credential vault, token, arbitrary policy or paths to the web process or issuer; root-control's authenticated FD transfer and issuer-private installation are separate capabilities.

**image-build Work:** Verify actual immutable certbot-dns-cloudflare 5.8.0 plugin, cryptography and OpenSSL dependencies against accepted Python/rootfs; install/exercise selected immutable Python/Certbot paths. The issuer source tests do not prove runtime installation.

**host-deploy Work:** Revalidate `zog-certify-publication-candidate-v1` under the issuer-only identity, publish/rollback a fixed local nginx generation and prove CA-valid SNI/fingerprint with TLS ending at local Zog; include crash/restart/reboot, revoked token/FQDN, replaced lineage, pending stage, invalid cert and delivery rollback. No production ACME enablement without separate GO.

See [full issuer/consumer contract](../docs/issuer-lifecycle-integration-2026-10-20.md).

**Remaining NO-GO:** accepted native immutable Certbot view, real split-UID systemd/journald InvocationID, verified local Cloudflare provisioning/rotation, native delivery and staging CA HTTPS readiness.
