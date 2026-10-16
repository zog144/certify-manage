# certify-manage

Zog's core certificate lifecycle application. Phase 0 defines a narrow `zog-certify-manage-v1` authorization and status contract; Phase 1 supplies an isolated **Certbot** ACME adapter. The component does **not** own proxy routing, hostnames, archive leases, systemd identities, ACME challenge exposure or nginx configuration.

## Boundary

- **Software:** Certbot, its plugins and Python code belong in a reviewed immutable image-build software view. Never `pip install` into persistent application state.
- **Data:** one dedicated application-owned persistent mount at `/var/lib/zog-certify-manage`, expected to be 0700 under a controller-issued, non-root application identity; Certbot uses only its `certbot/{config,work,logs}` directories within this mount.
- **Authority:** a trusted administrator/controller supplies a root-owned, protected policy. A hostname in an application request is **not** authorization. The library also accepts a previously trusted policy object for integration tests and a future bounded controller service.
- **Challenge integration:** HTTP-01 uses a private application webroot that an authorized front door must expose as `/.well-known/acme-challenge/` on port 80. DNS-01 initially uses the packaged Certbot Cloudflare authenticator with its own 0600 credentials file. No dynamic shell hooks or caller-supplied plugin arguments.
- **Publication:** certificates stay inside the issuer-owned mount. No consumer gets the Certbot account key, archive, or writable state. A versioned certificate export and controlled nginx reload are **Phase 3**, not implemented here.
- **Trust:** Certbot is an external tool, not included in this source tree. TLS issuance requires explicitly authorized reachable HTTP-01 or DNS-01 infrastructure and must not be presumed successful from unit tests.

See [the interface and deployment contract](docs/contract-v1.md) and [operating instructions](docs/operations.md).

## Development

Requires Python 3.11+, `cryptography>=43` and `pytest>=8` for tests; does not invoke live ACME in CI.

```sh
python -m pip install -e '.[test]'
python -m pytest -q
python -m zog.certify_manage --help
```

The host owner prepares a protected state mount and a separately trusted policy document before enabling the CLI. All certificate operations are serialized per state mount, write durable status records before starting Certbot, and deliberately block uncertain interrupted work until operator recovery.

## Public-source and release boundary

First-party material is dual-licensed `BSD-3-Clause OR GPL-3.0-only`; Certbot and provider plugins retain their independent licenses (see `THIRD-PARTY-NOTICES.md`). This component is **not** published on PyPI independently; Zog's aggregate `zog` release process selects verified components.

## Follow-on source work (2026-10-14)

The `unstable` branch additionally contains account-bound renewal hardening,
real Certbot 5.8.0 offline CLI/plugin smoke tests, and a review-only
box-control declaration under `integration/box-control/application.py`.
The `stage` action atomically prepares an **issuer-private** versioned
certificate/key generation, returning only redacted metadata. It does not
publish to an HTTPS consumer or reload nginx.

Owner handoffs: [image-build](handoffs/2026-10-14-image-build.md),
[box-control/root-control](handoffs/2026-10-14-box-control-root-control.md),
[host-deploy](handoffs/2026-10-14-host-deploy.md),
[station-access/host-install](handoffs/2026-10-14-station-access-host-install.md).
The [security review](docs/security-review-2026-10-14.md) lists outstanding
live integration and safety acceptance gates.

## Installation topology and DNS authority

Public HTTPS terminates at the **local Zog installation**, including hosts
behind LAN/NAT reached through a non-terminating `network-traverse` tunnel.
The command center is neither a mandatory TLS terminator nor a mandatory
DNS credential holder. Two supported **intended deployment contracts** are:
a centrally assigned FQDN retrieved by an approved outbound host, and a
standalone locally approved FQDN configured through local station-access.
Both converge on one protected host-owner issuer policy. The existing
Cloudflare DNS-01 adapter accepts an issuer-owned 0600 credential file;
**web-interface credential-to-issuer binding is still an integration task**,
not a currently working unattended feature.

See [deployment modes and certificate authority](docs/deployment-modes.md),
plus the [host-assignment/local-DNS handoff](handoffs/2026-10-14-local-certificate-assignment.md)
and [network-traverse handoff](handoffs/2026-10-14-network-traverse-tls.md).

## Issuer-UID authenticated certificate inspection

A separate read-only `zog.certify_manage.inspection` service and
`IssuerInspectionClient` now provide bounded, peer-UID-authenticated
Unix-socket access to the existing issuer-owned X.509/lineage validation,
without sharing the issuer's 0700 state with host-deploy. This is
**source-only**: the reviewed controller owner must bind and activate
the exact socket/service under the original issuer grant; no direct
systemd unit or live endpoint is installed here. Its `issuer_verified`
does not authenticate a selected controller request or prove nginx TLS
readiness. See [issuer inspection contract](docs/issuer-inspection-v1.md).

## Controller-owned short-lived certificate inspection (2026-10-16)

The **preferred v1 integration** is the already-declared finite
`certify-manage/inspect` selected program. It now emits one bounded
`ZOG_CERTIFY_INSPECT_RESULT_V1` stdout record after actual issuer-UID
X.509, account and renewal-policy validation. This record is **not**
authenticated until box-control/root-control's planned request/runtime/
systemd-invocation-specific reader attaches it to the original selected
inspect request. Certificate validation and nginx/browser readiness
remain distinct.

See [selected inspect result v1](docs/selected-inspect-result-v1.md).
The previous [issuer inspection socket](docs/issuer-inspection-v1.md)
is source-only and **not approved for deployment as a static service**
under current Zog lifecycle/UID rules.
