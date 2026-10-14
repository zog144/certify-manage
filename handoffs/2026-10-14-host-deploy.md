# Handoff to host-deploy Work/Regular — protected publication and isolated HTTPS acceptance

**Source:** `zog144/certify-manage` `unstable`, contracts/docs and image-build + box-control handoffs. **Priority:** after owner-issued grant, immutable view and read-only policy capability; coordinate with existing station/archive acceptance owner.

Host-deploy retains authority for DNS verification, authorized hostname, external port-80 challenge route (if HTTP-01), provider credential injection (if Cloudflare DNS-01), one named nginx front-door owner, certificate consumer binding, TLS/reload readiness and final traffic switch. `certify-manage` must not choose ingress, archive role, HTTPS target, signed leases, or mutate nginx.

Design an explicitly approved **versioned certificate delivery bridge**: issuer validates bound SAN, private/public key and chain locally; a narrowly authorized privileged transfer copies only leaf/fullchain and private key for an exact consumer/service ID, not Certbot accounts, raw config or DNS credentials. Validate file identity/permissions/size, write into protected new generation, fsync, use atomic generation pointer/symlink swap, run `nginx -t`, reload authorized nginx unit, verify normal hostname + CA trust and active presentation, and on failure restore previous generation with observed rollback/reload evidence. The bridge needs independent owner/peer authentication and service binding; do NOT grant nginx the issuer's writable state or a broad controller socket. Issuer-only read access to private material is insufficient authorization to publish to arbitrary nginx. Stage readiness as issued / delivered / nginx-loaded / browser-verified separate states.

For the **isolated acceptance endpoint**, use an operator-approved real FQDN and the reviewed candidate 18090/18091 wiring, never existing portal's 80/443 cutover prematurely. Start with a staging ACME directory where suitable, avoid rate-limit risk, and confirm the full DNS-01 or HTTP-01 path. Keep original nginx/443 and archive writer untouched until owners authorize the broader E–F transfer. Retain grant, mount, operation, renewal file, boot, controller, fingerprints and browser trust evidence across explicit restart and coordinated reboot.

Return to this chat: selected challenge/authenticator, exact authorized FQDN and cert consumer, protected policy binding contract, versioned publication protocol, issuer-to-owner transfer and rollback semantics, offline + live acceptance evidence, and any API changes requested in certify-manage.

### Available issuer-side primitive

The issuer's new `stage` operation creates the private versioned candidate
at `publications/<certificate-id>/<fingerprint>/`. It returns metadata only.
The host-owner delivery bridge must independently authenticate the requested
service, open the approved private candidate through a limited capability,
revalidate PEM/receipt/owner/digest, and make its **own** atomic consumer
publication. The issuer has no nginx permission or service reload action.

## Revised topology: always terminate TLS at local Zog

The public HTTPS certificate's bound consumer is the **local Zog nginx
front door**, not the central command center. Direct access and NAT/LAN
access through `network-traverse` must result in the same local SNI,
certificate, trust and key ownership. In transit mode the relay forwards
opaque TLS bytes (or an equivalently non-terminating transport): it
must never hold the certificate private key or terminate the public TLS.
If another TLS-terminating proxy topology is later proposed, treat it
as a distinct design requiring explicit approval, not this contract.

Accept either a centrally authorized hostname assignment delivered over
the existing outbound host channel, or an explicitly local administrator
approved hostname, but both must be **verified by a trusted host owner**
before provisioning the exact protected issuer policy. Do not require a
command-center Cloudflare token on standalone installations. The DNS
challenge is either (a) issuer-local Cloudflare plugin with a separately
provisioned, narrowly scoped credential, or (b) an explicitly authorized
central broker when DNS authority is central. For NAT, prefer DNS-01.
Request source identity/provenance/authority revisions from the relevant
host binding, refuse policy conflicts and never silently reissue for a
hostname advertised by an unauthenticated beacon.
