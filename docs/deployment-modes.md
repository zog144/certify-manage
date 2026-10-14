# Certificate installation modes and TLS termination

Architecture decision, 2026-10-14. **The local Zog installation terminates
public HTTPS.** The command center, when present, supplies control-plane
information, not the Zog HTTPS private key or browser-facing TLS endpoint.
`network-traverse` may carry ciphertext between an external connection
and a LAN/NAT host; it is a **non-TLS-terminating tunnel** for this design.

## Three independent axes

| Axis | Supported intent |
| --- | --- |
| FQDN authority | Centrally assigned by the enrolled host's command center **or** locally approved by the standalone host administrator |
| DNS-01 provider access | Centrally executed through a future restricted challenge broker **or** locally executed with a dedicated issuer-owned Cloudflare plugin credential |
| Public HTTPS route | Direct access to local host **or** a non-terminating `network-traverse` encrypted TCP/TLS path to that same local host |

Do **not** couple these axes. A centrally assigned FQDN can have an
authorized local DNS-01 provider binding; a standalone local installation
can be behind NAT. A TLS-terminating central HTTPS reverse proxy, shared
private key or command-center-issued frontend certificate would be a
different architecture, not an implicit fallback.

## Managed host lifecycle

1. An unconfigured Zog installation has its existing registry origin and
   trusted host identity; it beacons **outbound** without guessing a FQDN.
2. The command center approves the host and centrally reserves/publishes
   its exact DNS assignment. Approval of host identity alone is insufficient.
3. A separately authenticated, monotonic, expiring assignment is delivered
   through a bounded outbound host control-plane retrieval. This **producer
   and retrieval endpoint do not yet exist** and must not piggyback
   arbitrary commands onto the signed heartbeat.
4. Host owner verifies host ID/key/authority, FQDN, TLS consumer, zone,
   ACME directory, challenge strategy, revision and absence of conflict.
   It prepares a root-controlled v1 authorization policy, never an
   application-writable copy, and a separate credential/challenge grant.
5. The program selector starts exactly `certify-manage issue` or `renew`;
   after the issuer validates it, `stage` creates a private generation.
   Host-deploy validates and publishes only to the **local** HTTPS owner.
6. End-to-end SNI/CA/leaf checks through the selected route establish HTTPS
   presentation, not just local certificate validity. Missing assignments
   remain pending. Revocation and reassignments require explicit migration.

## Standalone / locally managed lifecycle

1. Local station-access web UI allows an administrator to configure a
   Cloudflare zone/account securely and explicitly choose the FQDN that
   should serve this *installation*. The local web UI need not be a
   command center or fleet registry.
2. Local host-owner checks the exact operator approval, provider/zone
   authority, credential revision and local HTTPS service binding. UI
   persistence alone is a proposal, never execution authorization.
3. A narrowly scoped host-owner secret bridge produces/updates only
   `/var/lib/zog-certify-manage/dns/cloudflare.ini` (0600, issuer identity)
   from an approved dedicated token. It must not mount the web app's
   entire encrypted credential store inside the issuer.
4. The **already implemented** Certbot `dns-cloudflare` adapter can
   use this file for DNS-01; there is no command-center dependency.
   The UI-to-host-owner secret bridge and automatic owner request are
   **pending cross-repository integration**, not implemented here.
5. Issued/staged certificates go through the *same* host-deploy consumer
   publication/reload, again at the local Zog server.

Prefer DNS-01 behind NAT because public validation uses DNS TXT and does
not require a live inbound HTTP-01 port 80. A credential may be restricted
to the exact zone; never transfer a broad command-center provider API
token to every host as a convenience. Recheck scoped authority before
initial issue and future renewals.

## Browser route and NAT

Direct: browser --TLS--> local Zog nginx.

Traversed: browser --TLS bytes--> `network-traverse` TCP/tunnel relay
--same TLS bytes--> local Zog nginx. The browser observes the local
certificate, subject to the relay's reviewed SNI/address routing.

An L7 reverse proxy that decrypts HTTPS at the relay violates this
contract. Avoid proxy protocol headers or plaintext HTTP as a substitute
for an authenticated end-to-end TLS channel. Port-443 readiness must
measure actual SNI presentation at the local endpoint via that route.
The ACME DNS provider endpoint is independent of browser routing.

## Conflict and failure behavior

- No approved name, no provider authority, or conflicting local/central
  assignments: block issuance; do not auto-fallback to a guess.
- Controller policy changes or token rotation: retain existing ACME
  lineage/keys and require reviewed revision binding/migration.
- Command-center outage: preserve approved local state; ordinary
  renewal may continue *only* while its bound policy and provider
  authorization remain valid, not by treating cached stale assignments
  as fresh authorization.
- Local standalone installations are not required to enroll into
  command-center infrastructure to get HTTPS. Credential storage and
  local admin authentication remain independent privileges.

## Ownership and current status

- station-access local/central registry: operator UI, selected hostname
  and provider credential binding; no direct Certbot execution.
- host-discover: authenticated outbound assignment transport only.
- box-control/root-control: protected policy, scoped secret material,
  storage/identity grant and exact selected program.
- certify-manage: pinned ACME policy validation and local Cloudflare
  plugin issuance/renewal and issuer-only certificate staging.
- host-deploy: local certificate consumer, atomic publication, nginx
  validation/reload, actual TLS presentation.
- network-traverse: non-terminating transport, no private key, no
  certificate authority.

Only the **local Certbot Cloudflare credential-file backend**, not
the web UI-to-issuer bridge, is implemented in certify-manage today.
Command-center assignment retrieval, central DNS broker and traversal
integration are outstanding cross-repository work. No live public
certificate issuance or direct/traversed HTTPS acceptance is claimed.
