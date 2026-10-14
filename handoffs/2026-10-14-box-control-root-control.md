# Handoff to box-control / root-control Regular — certify-manage isolated persistent application

**Source:** `zog144/certify-manage` `unstable`, prototype declaration `integration/box-control/application.py`. **Priority:** after approved immutable image closure, before live issuance.

Provision an independent controller-issued non-root `execution_identity="application"`, one durable `certificate-data` mount at guest `/var/lib/zog-certify-manage`, 0700 and owned by that grant, reused across preparation/issuance/renewal, runtime replacement, host reboot and immutable generation changes. Never share station/archive grants or put secrets in images. Source preparation and commands are only an unactivated candidate; validate current parser/schema and exact image/import paths. Define an **admin-owned read-only directory capability** at guest `/run/zog-host/certify-policy`, containing root-owned policy.json, with exact application/program binding and immutable owner-supplied intent; application declarations must not choose arbitrary source directories. If existing host-capability grant validation cannot provide this without broader rights, stop and propose a least-privilege extension instead of passing `--policy` to untrusted state.

Implement a host scheduler/authorized caller that launches `renew` according to explicitly approved cadence. Current `externally-controlled` candidate does not implement an unattended scheduler. Systemd unit lifecycle must not infer certificate readiness from an exited CLI alone. Concurrency and journal uncertainty must block blind retries; preserve saved ACME account/private key with backup and restoration policy. Confirm failure of symlink mounts, UID drift, missing binding, revoked owner and unavailable STATE.

Required evidence: controller-authorized numeric grant and actual /proc identity, systemd and mount inventories, protected policy source directory, exact prepared state ID, denial of cross-app key reads, renewal after restart/reboot, read-only inspection, and recovery behavior. No system-wide root bind of /etc/letsencrypt, no manual host chown, and no certificate key in station-access data.

## Local DNS credential/policy binding extension

Support a **standalone-local authority** as well as an authenticated
command-center assignment. The root-controlled certificate policy remains
the same exact reviewed v1 schema. Its provisioning receipt must bind
authority type, host identity, FQDN, DNS-zone/provider binding, approval
revision, certificate consumer and selected challenge, without putting
any DNS secret in the receipt or issuer policy. The local station-access
UI may be used to configure credentials but does **not** gain the power to
write root-owned policy or execute Certbot by supplying an arbitrary FQDN.

For issuer-local Cloudflare mode, provide a **narrow audited secret
provisioning capability** from the local encrypted credential store (or
administrator-provisioned dedicated secret) to the issuer-only
`dns/cloudflare.ini`. Enforce exact zone scope, revision, ownership 0600,
no logs, no broad vault export, no read by unrelated application identities,
revocation/rotation checks and recovery across restart/reboot. Fail closed
if safe capability delegation cannot be constructed; do not mount the
station web application's entire database/vault into the issuer.
