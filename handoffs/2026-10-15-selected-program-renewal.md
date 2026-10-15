# Handoff: selected program renewal, issuer evidence and native ACME

**Date:** 2026-10-15. **Producer:** `zog144/certify-manage` unstable,
after `caae72c3f2f6a79c860d4f05f0470f6ddd8eacda`.
**Controller:** box-control `acbdf3896281d83d14a2c0cdba0267586b42f3d9`
and root-control `60e61aded8c4fdfdc689a6fa6f915aac24b0c3f1`.
**Consumer:** host-deploy source coordinator
`zog144/host-deploy` `19562a81f03ee9a75e1b819ee021156a9e396942`
(or later).

The issuer now retains `uncertain` for nonzero Certbot exits, timeouts and
unverified lineage results; it does not silently reset/retry ACME.
Its secret-free inspect result includes current certificate health, fingerprint,
`outcome=renewed/unchanged`, policy SHA256 and operation journal update time.
A verified fingerprint change is not equivalent to nginx TLS readiness.

Host-deploy has a bounded, journaled selected `renew` coordinator which saves
the exact controller-issued request ID *before* request submission; repeats
that exact ID and selector after lost reply; rejects changed application,
program, identity, policy and unverified results. It is source-only and
does not start a timer, acquire ACME credentials or operate production nginx.

## Remaining cross-owner work

**host-deploy Regular:** wire the coordinator under a reviewed owner-controlled
systemd oneshot/timer and exact bound controller image/socket/project; choose an
approved cadence, authorize new request only when due, run bounded evaluator,
keep journal across reboot, and provide a trusted issuer observer before marking
verified. On `renewed`, request a separate selected `stage` and invoke the
existing certificate delivery bridge, then confirm local nginx CA/SNI/fingerprint.
On `unchanged`, do not force unnecessary deployment. Never claim readiness
from systemd exit alone.

**box-control/root-control Regular:** approve the `stage` action's exact
host-binding/policy capability (current reserved certificate scope documents
only issue/renew/inspect). Provide an authenticated *read-only* issuer observation
bridge that binds selected controller request ID, root-controlled persistent
storage/grant, issuer UID, host policy, journal updated_at and certificate
fingerprint. The caller must not be able to forge that evidence by sending
arbitrary JSON. The bridge must distinguish ongoing/stale/uncertain outcomes.

**certify-manage Regular (this component):** keep strict persisted renewal
policy pinning and issuer-only private staging. If actual Certbot 5.8.0
staging issuance records a different safe renewal parameter format, make a
reviewed narrow compatibility fix with a captured redacted fixture; never
switch to permissive command-line or unknown ConfigObj options.

**host-deploy Work on isolated host:** acceptance with real approved ACME
staging FQDN (or test CA), provider authorization, exact selector and retained
controller ID; inspect native systemd transient unit, identity/mount,
Certbot exit and real X.509/renewal config; exercise lost reply/kill/reboot,
unchanged/not due, changed renewal and private stage, host-deploy nginx
reload/rollback, CA-verifying SNI and leaf fingerprint. Do not use command
center as TLS endpoint and do not expose local Cloudflare tokens. Distinguish
staging CA trust from production browser trust.

**Production NO-GO:** pending approved native schedule, exact issuer
observation transport, stage host-binding grant and real systemd/ACME tests.

## Follow-up confirmation: stage declaration present

certify-manage now declares an independently selected
`stage` program in `integration/box-control/application.py`, with
the same persistent certificate-data mount and read-only certificate
policy path. Source tests inspect the AST and enforce the exact
`stage` command. This closes the **declaration** omission;
the host owner must still validate actual box-control/root-control
stage policy, prepared unit, UID/mount, authenticated transfer and
nginx activation on an isolated systemd host. The source-level
Certbot regression matrix does not constitute live acceptance.
