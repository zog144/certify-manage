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

## Issuer-private stage operation

After a verified, policy-bound `issue` or `renew`, invoke
`python -m zog.certify_manage stage`. This creates an atomic immutable-named
candidate containing `fullchain.pem`, `privkey.pem` and a secret-free
receipt under the **issuer-only protected mount**. It is idempotent for
identical bytes, rejects conflicting generations and never exports the
private key to nginx, reloads any service or declares browser readiness.
The host-deploy handoff owns the remaining authorized delivery bridge.

## Standalone local Cloudflare mode versus managed assignment

The Cloudflare authenticator path already implemented by this repository uses
a mode-0600 file at `<issuer-state>/dns/cloudflare.ini`, opened only under
the dedicated issuer identity. This is valid for a *standalone* Zog host
whose administrator has configured a Cloudflare zone/token in the **local
station-access web interface**; the command center need not hold that token.
The local UI's stored credentials must not be read opportunistically by
certify-manage. The trusted local host owner must validate an explicit
administrator-approved FQDN, zone and provider-credential binding and
provision a dedicated, narrowly scoped credential to the issuer mount.
Revisions and rotation must be bound to the provider and host-owner intent.
This local UI-to-issuer exchange is **not yet implemented**.

When the command center owns the DNS zone, a future narrowly scoped
challenge broker may perform DNS-01 updates centrally instead, without
giving the host a Cloudflare token. The two designs are alternatives,
not mutual prerequisites. No caller can switch them through arbitrary
Certbot command flags, ambient environment or an untrusted policy path.

If the host is behind NAT, favor authorized DNS-01: validation of a TXT
record does not require forwarding public port 80 to the host. Port-443
HTTPS may be reached either directly or through a reviewed encrypted
`network-traverse` transport. The **local** nginx/front door holds the
published key and terminates TLS in both cases. The separate host-deploy
bridge is still required for publication and reload.

## Interrupted ACME recovery and safe results

An unknown Certbot result stays `uncertain` even when an older certificate
remains cryptographically valid. Inspect the retained journal and exact
lineage/account/authorization using the trusted host owner before attempting
the privileged recovery path. The CLI requires
`recover --confirm-uncertain-recovery`; this argument is **only an
acknowledgement**, not a substitute for a separate administrator-authorized
root-control policy binding. No automatic timer should invoke recovery.

A reconciled result reports `recovered-unverified` rather than `issued`,
`renewed`, or `unchanged`. It cannot be staged or published automatically.
If the saved account differs, a certificate is invalid, or the previous
renewal baseline is absent, recovery remains blocked. All unexpected
subprocess failures are reported as a single redacted CLI error, with the
preflight journal retained. Renewing via Cloudflare requires the current
issuer-owned 0600 credential file to pass checks **before** calling Certbot.

The review-only box-control application now includes a separate `stage`
runtime program. This source declaration is not proof of a root-control
permission grant or native systemd acceptance.
