# Handoff: local and command-center certificate assignment

**Owners:** station-access Regular, host-discover Regular,
box-control/root-control Regular, host-deploy Regular.
**Source:** `zog144/certify-manage` `unstable`,
`docs/deployment-modes.md`.
**Status:** architecture/integration request; not live acceptance.

Implement two equally supported authority origins without requiring a
command-center enrollment of standalone installations:

1. **Managed host:** station-access command center issues a versioned,
   explicitly authorized per-host DNS/FQDN/consumer/challenge assignment,
   derived from approved host identity and central DNS records.
   host-discover retrieves it outbound through an authenticated,
   replay-protected bounded interface. A mere beacon receipt does not
   authorize installing a certificate.
2. **Standalone local:** an authenticated local station-access
   administrator explicitly selects the exact DNS zone, FQDN,
   Cloudflare credential identity/revision and this machine's
   local HTTPS service. The host owner turns *approved local intent*
   into its own protected policy binding. It cannot accept an
   arbitrary web payload as an authorized policy.

Keep the issuer's v1 policy schema unchanged unless a cross-owner
review requires migration. Produce a separately trusted provenance
receipt with authority origin, exact installation/Host UUID where
applicable, credential/zone binding (never token), certificate ID,
hostnames, ACME endpoint/challenge, local consumer identity,
monotonic revision, approval/revocation status and expiry, plus
idempotent request identity. Only a root-controlled owner installs
the resulting read-only policy and launches a named issuer program.

For a locally managed Cloudflare zone, design a minimal audited
secret-provisioning capability into the issuer-only 0600
`dns/cloudflare.ini`. Existing Certbot plugin consumes that exact
file. Do **not** pass Cloudflare credentials as CLI arguments or let
certify-manage read the local station-access vault wholesale.
Review credential scope, rotation, revocation, parent directories,
cross-UID denial, host restart, and loss of replies. A command-center
DNS-01 challenge broker may be an alternate mode, not a mandate.

Reject conflicting local/central grants, mismatched Host UUID,
changed credential versions without revalidation, unapproved zones,
expired authority, absent provider access, duplicate operation IDs
with differing payloads, and attempted web-auth-to-root privilege
escalation. The issuer private key always stays at the local
installation and is published only into its local nginx service.
The command center never needs a copy for this architecture.

Acceptance: tests for standalone local configuration without
command-center connectivity; managed outbound retrieval without an
initial FQDN; scoped Cloudflare issuance in a disposable staging
context; refusal of stale/conflicting authority; exact program
selection; local TLS consumer/readiness. No production DNS/provider
writes or public CA issuance from source tests.
