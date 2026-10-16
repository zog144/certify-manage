# zog-certify-manage-v1 — owner and consumer contract

Status: **Phase 0 + Phase 1 source implementation**; not host acceptance, TLS routing, certificate delivery or automatic boot readiness.

## Host-owner authorization

An operator-controlled policy file contains exactly these keys:

```json
{
  "schema": "zog-certify-manage-v1",
  "certificate_id": "station-web",
  "hostnames": ["station.example.org"],
  "email": "acme-operator@example.org",
  "acme_directory": "https://acme-v02.api.letsencrypt.org/directory",
  "challenge": "http-01",
  "dns_plugin": null
}
```

A DNS-01 policy has `challenge: "dns-01"` and `dns_plugin: "dns-cloudflare"`. Policy names and domains must be canonical ASCII DNS labels; IPs, wildcard HTTP-01, localhost, path-like IDs, shell fragment strings and incomplete/unknown fields fail. A wildcard is allowed only for DNS-01. The ACME directory must be explicitly specified as an HTTPS URL, not silently default to production. Do not use a staging account in production.

**The policy is authority, not a request payload.** The standalone CLI verifies a root-owned, non-group/other-writable, non-symlink policy file and secure ancestor directories; the future controller must deliver an equivalent privileged binding. Changes in the policy fingerprint block re-use of an issued lineage until a separately reviewed migration. An application caller cannot choose `--server`, a hostname, an authenticator, a hook or private-key destination.

## Durable storage

The root of the dedicated writable mount must exist, be owned by the executing identity, contain no symlink ancestors, and deny group/other access. Preparation creates only subordinate directories. Owner-managed mount configuration (and controller persistence) is external to this component.

- `certbot/config`: account registration, renewal lineage, keys, Certbot live/archive symlinks.
- `certbot/work`, `certbot/logs`: local Certbot scratch and logs.
- `challenges/<certificate_id>`: HTTP-01 webroot, not itself automatically published.
- `dns/cloudflare.ini`: operator-provisioned 0600 provider token, never embedded in policy, arguments, status or Git.
- `operations/<certificate_id>.json`: bounded atomic status/operation record, with trusted policy fingerprint and generation evidence.
- `locks/issuer.lock`: one-writer process lock.

Do **not** mount the issuer's persistent directory into nginx or station-access. Certbot's archive, key material and provider tokens must stay private.

## Operations and crash boundaries

`issue` creates a fresh lineage; `renew` uses the existing policy-bound lineage. Both acquire one state-wide flock, record an `uncertain` outcome **before** the Certbot subprocess, run Certbot without a shell, then record a terminal state only after inspection and verification of SANs, validity and private/public key match. Any timeout or unexpected interruption retains uncertainty. Subsequent mutations refuse an uncertain record; `recover` now also requires an explicit acknowledgement and inspection of a valid, matching lineage. It records `recovered-unverified` rather than fabricating an issued/renewed result, and such recovery is not a publication grant. A failed renew attempt retains the previous valid certificate where possible but keeps the new attempt `uncertain` until reviewed.

`inspect` is side-effect free and never reveals PEM bytes, secrets, account credentials, private key paths or command output. It reports certificate ID, authorized hostnames, validity window, fingerprint and health. For successful `renew`, unchanged fingerprints mean "not due" rather than a new certificate. A successful exit code is not proof of issuance.

## Separation from routing and signed leases

The issuer never chooses archive role, grants a registry lease, switches ingress, edits proxy configuration, changes another application's execution identity, or reloads a service itself. Host-deploy owns deployment and certificate consumer binding. Phase 3 needs an administrator-approved versioned bundle handoff, matching key/SAN/chain validation, atomic activation and privileged consumer reload; none of those capabilities is implied by Phase 1.

## Deferred acceptance

1. Immutable Certbot+DNS plugin build and controller-owned persistent mount, single non-root grant across preparation and renewals.
2. Protected origin policy, DNS credential injection, and actual port-80 HTTP challenge route or DNS API capabilities.
3. Live ACME issuance, renewal and inspection with failure/restart/reboot recovery.
4. Versioned service publication, TLS trust and hostname validation, reload rollback and readiness.
5. Station-access and archive-mirror end-to-end acceptance while preserving original production traffic.

Do not use Phase 0/1 records as authoritative deployment readiness.

## Private publication staging, not consumer activation

`certify-manage stage` requires a ready, policy- and account-bound, locally
verified certificate and creates `publications/<id>/<cert-fingerprint>/`
containing private `fullchain.pem`, `privkey.pem` and a secret-free
`receipt.json`. The generation directory is created and fsynced before
same-filesystem atomic rename; identical staging is idempotent. It is **not**
a consumer-ready certificate, CA trust assertion, service binding, or permission
to reload nginx. The receipt deliberately labels it
`issuer-private-unbound`. A trusted bridge must revalidate source receipt,
fingerprints and service authorization, then atomically publish a consumer-owned
version and reload the exact HTTPS service with rollback support.

Never place `publications` under a public static path or grant nginx direct
access to the issuer's persistent mount. Future producer needs to handle
interrupted `.pending-*` evidence without silent automatic deletion.

## Hostname assignment and TLS endpoint scope

The issuer policy's `hostnames` are **outputs** of a trusted provisioning
decision, not names invented by Certbot, host-deploy, or a beacon. This v1
schema intentionally does not encode the upstream authority: the host owner
must authenticate, version and retain the **provenance of that policy** before
installing it as root-owned read-only content. Two valid sources exist:

- **Command-center-managed:** an enrolled host retrieves an exact, approved
  FQDN/service binding through an authenticated outbound host-assignment
  interface. The command center owns the name; a signed heartbeat alone is
  not permission to issue certificates.
- **Locally managed:** an administrator of a standalone Zog installation
  explicitly approves the DNS zone/FQDN, TLS consumer and ACME challenge
  policy from its *local* management interface. A local UI proposal or saved
  Cloudflare secret is not by itself the protected owner policy.

When both kinds of authority exist or change, do not choose one implicitly.
Conflicting assignments, expired/revoked authority, unexpected policy
revision changes, or missing trusted host-owner binding block new issuance.
Preserve old cert/account state for inspection and explicit migration.

The certificate consumer is the **local Zog HTTPS front door**. In
`network-traverse` mode, an intermediary may transport encrypted TCP/TLS
traffic, but it must **not terminate TLS or possess the Zog private key**.
TLS SNI, certificate verification and HTTPS readiness are checked against
the local server reached through the reviewed route. A conventional
TLS-terminating HTTPS reverse proxy is not an implementation of this mode.
The ordinary public ACME challenge may be DNS-01, avoiding inbound
port-80 reachability for hosts behind NAT.

Read [deployment-modes.md](deployment-modes.md) for the separate axes of
hostname authority, DNS credential location and connection transport.

## Selected-program issuer outcome acceptance

The controller launches one exact selected program and retains its request
identity. The issuer journals an uncertain Certbot attempt *before* invoking
the subprocess. A nonzero exit, timeout, interrupted launch, malformed renewal
configuration, changed ACME account or invalid X.509 leaves the attempt
uncertain; an unattended timer must **not** blindly resubmit.

After exit zero, issuance also requires exact authorized SAN, X.509 validity,
private/public key match, persisted lineage policy and stable ACME account.
A successful `renew` reports `renewed` only if the leaf fingerprint changed;
`unchanged` means the currently valid certificate remained intact.
Neither result proves nginx loaded the certificate. Host-deploy must bind
a separately authorized issuer observation to the original controller
request and consumer publication evidence before declaring HTTPS readiness.

## Selected stage runtime and recovery limitation (2026-10-15)

The review-only `integration/box-control/application.py` now declares
`stage` as its **own** runtime program beside `issue`, `renew`, and
`inspect`. It uses the same issuer-owned `certificate-data` mount and
the same protected owner policy directory but must be launched with
`program_name="stage"` and a **separately authorized** controller grant.
It cannot be launched by starting the entire application, and it never
authorizes nginx deployment on its own.

`recover` is a manual administrative operation. It requires explicit
acknowledgement and leaves a distinct `recovered-unverified` outcome.
An older valid certificate after a failed renewal does **not** prove that
the ACME operation succeeded; recovered status is not eligible for
`stage`, controller renewal verification, or consumer publication.
Manual approval of a later fresh operation is an owner workflow.

## Selected certificate inspection result (2026-10-16)

The existing short-lived `inspect` program now produces exactly one
bounded `ZOG_CERTIFY_INSPECT_RESULT_V1` stdout record with the strict
`zog-certify-inspection-result-v1` schema. It reuses the original
issuer-UID private certificate/X.509/key/Certbot/ACME validation and
read-only shared lock. `issuer_verified` is true only for valid
locally observed material consistent with the ready issuer journal.
A successful selected-program exit is merely a **completed
observation**, not proof that `issuer_verified` is true.

The issuer cannot attest which controller request/runtime/invocation
called it. box-control/root-control must bind the stdout line to
one saved selected `inspect` request and exact native systemd
invocation, reject missing/duplicate/malformed records, then
host-deploy independently cross-checks the trusted original
`renew` request/journal observation. Never make an inspector request
under the **renew** request ID, and never use raw host-deploy
journal searches or trust `tls_ready` as true. Details:
[selected inspect v1](selected-inspect-result-v1.md).
