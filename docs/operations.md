# Source-only operator instructions

Install this component and Certbot/optional provider plugin together in a **reviewed immutable software view**. The executable default is `/usr/bin/certbot`, overridable only by a trusted application composition, not an untrusted API request. Certbot should run as its controller-issued dedicated non-root application identity and not be allowed to reconfigure nginx.

1. Have box-control/root-control create a persistent application mount at `/var/lib/zog-certify-manage` (0700, owned by its grant), with an empty mount target in the image.
2. Provision an exact policy at `/etc/zog/certify-manage/policy.json` from trusted deployment configuration, root-owned and not writable by group/other. Do **not** put that authority file inside the writable application state. This path needs a deliberate controller-owned read-only binding when integration is implemented.
3. For DNS Cloudflare, separately provision `dns/cloudflare.ini` inside the protected state as the application identity, mode 0600, then install the exact pinned Certbot DNS plugin in the software view. Restrict DNS token scope at the provider.
4. For HTTP, publish only the authorized challenge directory contents through the pre-existing port-80 TLS front door, with a narrowly scoped authorized read-only capability. Neither this component nor Certbot opens port 80.
5. Run `python -m zog.certify_manage prepare` to create subdirectories, `issue` for a new approved lineage, `renew` for a due existing lineage, `inspect` for redacted read-only metadata and `recover` only after explicit operator inspection of an interrupted issuance. The CLI never takes hostnames or challenge commands on its command line.
6. Schedule renewal through the host owner after native service lifecycle acceptance, not via an ad-hoc unbounded background thread. Reload/export is not implemented; Certbot's successful local issuance alone does not enable HTTPS readiness.

Commands default to the state mount and privileged policy location above. For source-only tests, construct `CertificateManager` with a synthetic `Authorization` and a fake runner; never call a public ACME endpoint from CI.

No issuance, privileged host-side installation or service restart is performed by this repository.
