# Handoff to station-access and host-install Regular — initialization and status

**Source:** `zog144/certify-manage` `unstable`; policy model `zog-certify-manage-v1`.

**station-access:** certificate management is a separate core application. During initial configuration, ask the administrator/controller for an approved HTTPS hostname, ACME directory and challenge provider, then *request authorized preparation/issue/reconcile* through the host owner. Never give the web process arbitrary CLI arguments, Certbot account keys, DNS tokens or nginx reload permission. Display redacted certificate expiry, failed renewal and delivered/loaded/verified statuses independently; keep the UI usable while issuance is pending, with a pre-HTTPS restricted bootstrap interface selected by host owner. Do not signal readiness solely because local certificate SAN/expiry checks pass.

**host-install:** define a core-app enablement/dependency order: verified STATE, controller issued app grant, immutable software generation, protected host-owner policy and chosen challenge capability, one-time application preparation, issuance, host-deploy publication then external HTTPS readiness. Preserve certificates/ACME account identity across reboot and image upgrade, and never regenerate existing ACME identities in first boot. Do not embed secrets or credentials in installation images. Report "awaiting operator-approved hostname/challenge" rather than guessing an address. Headless servers must support equivalent status through a non-browser management path.

Both consumers: add contract-level tests showing failure states do not cause unsafe fallback to self-signed/public auto-issuance, proxy exposure, or archive-role changes. Remain separate from the station observer mTLS client certificate.

## Additional supported topology: local installation is not a command center

Do not require a central command center for local installation HTTPS.
Standalone station-access may already provide Cloudflare credentials and
managed DNS from its own web UI. Add an explicit locally administered
certificate intent: approved FQDN, selected DNS zone, locally managed
provider credential ID/revision, local HTTPS consumer and challenge policy.
The web proposal still has **no authority** to run Certbot: a constrained
host-owner capability validates the administrator, exact DNS ownership
and bound policy before issuing the trusted root-owned policy and
issuer-only provider token. Keep raw DNS secrets out of issuer API
responses, the control plane and deployment manifest.

For an enrolled command-center-managed host, use its authenticated outbound
assignment rather than requesting arbitrary FQDN input. A host can remain
pending until the command center actually assigns and enables its name.
Do not conflate local credential *availability* with permission to use
that provider to issue arbitrary certificates. Maintain explicit conflict,
revocation and version-migration gates when switching local/central ownership.
In both cases local Zog is the HTTPS TLS endpoint even when NAT traversed.
