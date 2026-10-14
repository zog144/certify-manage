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
