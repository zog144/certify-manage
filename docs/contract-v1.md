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

`issue` creates a fresh lineage; `renew` uses the existing policy-bound lineage. Both acquire one state-wide flock, record an `uncertain` outcome **before** the Certbot subprocess, run Certbot without a shell, then record a terminal state only after inspection and verification of SANs, validity and private/public key match. Any timeout or unexpected interruption retains uncertainty. Subsequent mutations refuse an uncertain record; `recover` requires explicit operator inspection of an already valid matching lineage. A failing renew attempt retains the previous valid certificate but reports a renewal failure.

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
