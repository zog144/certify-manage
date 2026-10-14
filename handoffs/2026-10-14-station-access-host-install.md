# Handoff to station-access and host-install Regular — initialization and status

**Source:** `zog144/certify-manage` `unstable`; policy model `zog-certify-manage-v1`.

**station-access:** certificate management is a separate core application. During initial configuration, ask the administrator/controller for an approved HTTPS hostname, ACME directory and challenge provider, then *request authorized preparation/issue/reconcile* through the host owner. Never give the web process arbitrary CLI arguments, Certbot account keys, DNS tokens or nginx reload permission. Display redacted certificate expiry, failed renewal and delivered/loaded/verified statuses independently; keep the UI usable while issuance is pending, with a pre-HTTPS restricted bootstrap interface selected by host owner. Do not signal readiness solely because local certificate SAN/expiry checks pass.

**host-install:** define a core-app enablement/dependency order: verified STATE, controller issued app grant, immutable software generation, protected host-owner policy and chosen challenge capability, one-time application preparation, issuance, host-deploy publication then external HTTPS readiness. Preserve certificates/ACME account identity across reboot and image upgrade, and never regenerate existing ACME identities in first boot. Do not embed secrets or credentials in installation images. Report "awaiting operator-approved hostname/challenge" rather than guessing an address. Headless servers must support equivalent status through a non-browser management path.

Both consumers: add contract-level tests showing failure states do not cause unsafe fallback to self-signed/public auto-issuance, proxy exposure, or archive-role changes. Remain separate from the station observer mTLS client certificate.
