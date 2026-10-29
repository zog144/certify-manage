# Certify-manage Cloudflare HTTPS consumer contract (Option B)

2026-10-29 · draft certify-manage PR #3 · host-deploy draft PR #6

The **Enrolled Host's protected root owner**, not certify-manage and not a
browser, requests a Cloudflare DNS-01 credential from the Command-Center
Host's common authenticated HTTPS Credential Authority on port 443.
The issuer uses the existing Certbot `dns-cloudflare` authenticator and
issuer-owned `/var/lib/zog-certify-manage/dns/cloudflare.ini`.

The source-only `cloudflare_https_contract.verify_installed` reads the
root-installed authorization and installation receipt, checks current
certificate ID, exact one-hostname FQDN, DNS zone, issuer UID, assignment
and credential revision, then checks the existing private 0600 file using
`cloudflare_credential_snapshot`. It returns only a nonsecret observation.
It does not grant `issue`/`renew`, access transport, execute Certbot,
update Cloudflare or publish nginx output.

The actual root-to-issuer installation remains
`root_control.issuer_credentials.install_from_fd`, with protected 0700
STATE, dedicated UID/GID, nonsecret pending/installed ledger, one-time
request admission and 0600 atomic file replacement. Selected Certbot
operation admission and existing saved renewal account/lineage/credential
snapshot checks remain mandatory.

Explicit `host-deploy` HTTPS consumer selection must verify the current
signed assignment, HostIdentity/installation/STATE, second owner ledger,
station HTTPS trust, FQDN/zone/credential revision and protected issuer
grant before and after one bounded anonymous-FD transfer. It must never
request a new token simply because Certbot was retried or renewal failed.

No token in argv/environment/journald/JSON, source repository, browser
response or HTTP diagnostic. The native HTTPS client and protected receiver,
actual dual-host authorization, token delivery, DNS/ACME and nginx
execution are **not performed** or authorized by this source change.
