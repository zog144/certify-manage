# certify-manage Regular → host-deploy Regular: protected HTTPS Cloudflare consumer

**Date:** 2026-10-29  
**Transport decision:** Option B HTTPS, **not SSH**.  
**Producer:** `certify-manage/unstable`, `src/zog/certify_manage/credential_https.py`.  
**Tracking:** [host-deploy PR #6](https://github.com/zog144/host-deploy/pull/6), [host-deploy PR #3](https://github.com/zog144/host-deploy/pull/3), [host-install #2](https://github.com/zog144/host-install/issues/2), [root-control #12](https://github.com/zog144/root-control/issues/12).  
**Status:** source-only nonsecret consumer request/receipt validation; **no transport or secret installation execution**.

Use [the full consumer contract](../docs/cloudflare-https-credential-consumer-v1.md).

Action for host-deploy Regular: preserve PR #6's signed owner + second monotonic root owner ledger + authorized nginx delivery-policy + root-approved issuer grant/storage + assignment/credential/zone/revision comparisons, but replace the SSH client `zog-issuer-cross-host-client-v1` fields/transport assumptions with a separately root-attested `zog-certify-cloudflare-https-consumer-v1` HTTPS selector. The new issuer source exposes `select_https_cloudflare`, `HttpsCloudflareSelection.request`, and `check_installed_credential`; **none** executes HTTPS or reads/returns a token. The new request's `purpose=certify-manage-dns-cloudflare` must be wrapped in the versioned **common** authenticated HTTPS protocol (not an independent wire protocol).

The root receiver owner must perform the actual HTTPS request, authenticate both parties, verify current signed request/response and durable one-time request ID, then provide token only to the **existing root-control** issuer installer over an anonymous file descriptor. Recheck before/after request and installation, retain protected UID/0600 persistent state and recovery history. Provision/rotate only under an explicit separate owner-authorized action; Certbot issuance, renewal retry, inspect, stage and nginx reload must **never** auto-fetch secrets.

Request return: exact host-deploy branch commit, nonsecret owner/client/issuer ledger fixtures and HTTPS-specific negative tests, source/RECORD pinned consumed interfaces, and a native acceptance handoff; keep original PR #6 and PR #3 draft until independent reviews are complete. No nginx, real token, live ACME, station API or DNS-provider work authorized.
