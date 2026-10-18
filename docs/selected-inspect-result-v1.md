# Selected inspect v1: one-shot issuer certificate result

**Date:** 2026-10-16  
**Producer:** certify-manage Regular  
**Status (2026-10-18):** selected-program result producer implemented. The separately authenticated invocation-bound result reader is now implemented in box-control/root-control **source** (box-control `dec2def825a474675def51df44d75d534e76508f`; root-control `3a2dd9c935e332e811adaccedf04b16bd2de1ea7`), but **native systemd acceptance, migrated host-deploy consumer, and HTTPS readiness are still pending**.

## Controller-preferred runtime

Use the existing **finite** `certify-manage/inspect` program declared in
`integration/box-control/application.py`, selected with its own durable
controller-issued request ID. It runs in the same box-control-managed
application identity, immutable generation/view and private certificate
mount as `issue`/`renew`/`stage`. No new systemd static unit, manually
shared UID or persistent `inspect-server` application is authorized.

The older `zog.certify_manage.inspection` socket server remains source
code for a potential future reviewed controller-managed companion, but
the current architecture **must not deploy** it as an unmanaged service.

## Exactly one result record on stdout

On `certify-manage inspect` the process emits **one UTF-8/ASCII line**
ending with a newline. The record begins with the literal marker:

```text
ZOG_CERTIFY_INSPECT_RESULT_V1 {"certificate_fingerprint_sha256":"<64 lower hex or null>",...}
```

The marker is followed by one sorted, compact JSON object with
**exactly** these fields, no extensions or private data:

| Field | Meaning |
| --- | --- |
| `schema` | exact `zog-certify-inspection-result-v1` |
| `certificate_id`, `hostnames`, `policy_sha256` | exact **root-provisioned** issuer policy; never chosen through CLI |
| `health` | `valid`, `missing`, `invalid`, `uncertain`, `expired-or-not-yet-valid` |
| `certificate_fingerprint_sha256` | validated local leaf fingerprint (or null) |
| `valid_from`, `expires_at`, `days_remaining` | local X.509 validity evidence, not public trust |
| `operation`, `outcome`, `operation_updated_at` | issuer operation journal; `recovered-unverified` is never positive |
| `issuer_verified` | boolean; true only for locally valid leaf, private-key/fullchain/SAN and account/renewal policy, and exact ready matching journal |
| `observed_at` | timezone-aware observation timestamp |
| `tls_ready` | **always false**; no nginx/public browser assertion |

All fields are bounded, payload is **maximum 4096 bytes including marker**. A positive result also requires the coherent operation/outcome combinations `issue → issued` or `renew → renewed|unchanged`; any other pair is reported unverified and cannot be made positive by the serializer.\n\nThe payload
and JSON is single-line with escaped control characters. No FQDN/path/key
arguments, arbitrary issuer user, controller request ID or runtime ID are
accepted from callers. Certificate health may be invalid while process exit
is zero: that means the read-only inspection finished successfully, **not**
that the certificate is valid. On a missing/untrusted state, busy lock,
unsafe policy, unsupported schema or parser error, `inspect` emits **no
success marker** and the existing CLI generic rejection on stderr;
the controller result reader must fail closed.

The single process calls `inspection.inspect_once()`, which acquires an
existing nonblocking shared issuer lock without creating a file. It calls
`CertificateManager.inspect()` under the issuer's original UID. Existing
validation checks certificate SANs, chain order/signatures, private/public
key matching, validity, persisted Certbot renewal configuration and ACME
account identity. The operation journal is captured in the *same* snapshot;
its identity, fingerprint and outcome must agree before
`issuer_verified=true`.

## Host-deploy and controller authentication boundary

The issuer record **does not** name a controller request ID or systemd
invocation ID, because these are not issuer-authenticated facts. The
controller/root-owned result adapter must derive both from saved
controller state. Only it may return an **authenticated** result.

**box-control/root-control Regular work:**

1. Extend the **fixed** `IssuerLifecycleBroker` with a specifically
   selected `inspect` invocation and its own caller-issued/retained
   request ID. Preserve existing `renew`/`stage` scope; do **not**
   expose `issue`, `prepare`, `recover`, raw `BoxControl.evaluate`,
   an arbitrary command, or root-control socket.
2. Reuse selected application singleton admission; pending/uncertain
   `renew`, cleaning runtime or unresolved `stage` block `inspect`.
   Never cancel an operation to satisfy a probe.
3. Implement a *root/controller authenticated* result reader using
   the saved successful selected `inspect` request, runtime identity,
   exact systemd unit **InvocationID**, effective issuer UID/GID,
   storage/grant, rootfs/policy/generation and terminal cleanup.
   Read only that invocation's bounded **stdout** journald records
   behind an invocation-scoped barrier; refuse 0 or >1 matching
   records, extra trailing text, truncated records, wrong source
   streams, malformed/duplicate JSON keys or wrong schema. Do not
   scan an entire unit history or accept a supplied JSON string.
4. Return a redacted, bounded result with immutable, authenticated
   **inspect** request/runtime/invocation identities and the exact
   decoded issuer values, with `issuer_verified` unchanged.
   Success process exit alone can NEVER set `issuer_verified`.
5. Retain original `renew` request and inspector-result evidence
   across lost reply, cleanup, reboot and the 48-hour controller
   request window. Protect history from the default 25-entry cap.

**host-deploy Regular work:**

1. Persist separately issued `inspect` request ID; retain it after
   a lost reply, and never reuse the **renew** request ID for inspect.
2. Verify the selected inspector request/result with the narrow broker
   and the authenticated invocation-scoped result reader. Do **not**
   parse arbitrary host journal output or accept caller-supplied
   inspection JSON.
3. Correlate the resulting exact policy SHA, certificate ID, SAN set,
   leaf fingerprint, operation/outcome and UTC-normalized journal time
   against the **original renew** request's separate trusted
   `journal-ready` observation. Match issuer UID/grant/storage and
   generation through authenticated controller metadata, not through
   issuer stdout.
4. `issuer_verified=false`, `health!=valid`, changed policy,
   untrusted invocation, stale result, mismatched fingerprint/time
   or uncertain prior request all block staging. For `unchanged`
   do not reload nginx unnecessarily. For `renewed` use only
   separately selected authorized stage/delivery.
5. Bound inspector cadence and durable request/history retention;
   restore pending and uncertain probes without duplicate new IDs.

**Work acceptance:** use a real controller-selected inspect transient
systemd service, compare InvocationID and exact journal record,
test wrong/multiple/missing stdout, exit-zero invalid result, lost
reply, process restart/reboot, distinct UIDs, tampered issuer state,
overlapping renewal, actual Certbot staging and local nginx public
SNI/CA leaf check. No public TLS cutover until all stages pass.

This schema **supersedes the long-running socket as the preferred v1
integration path**, but does not authorize removing historical source
or launching an uncontrolled inspector companion.

## Controller integration receipt (2026-10-18)

The [box-control/root-control invocation reader implementation handoff](https://github.com/zog144/know-file/blob/e7dab73cd5789e5e4dcb111f6a3dc9d72de060f2/certify-manage/handoffs/controller-invocation-inspection-implementation-2026-10-18.md) reports source-level support for the narrow `renew/inspect/stage` broker and saved-InvocationID journald reader. The two controller CI suites reported **525** box-control and **230** root-control tests passed, respectively. They use simulated systemd/journal evidence and **do not establish native acceptance**.

The producer's wire marker, 15 fields, order-independent JSON interpretation, size bound, and `tls_ready:false` invariant are **unchanged**. Additional producer regression tests reject the semantically impossible positive operation/outcome pairs without modifying the schema. Native Gate B still requires actual journal `_SYSTEMD_INVOCATION_ID` and `_TRANSPORT=stdout` evidence bound to the saved runtime, current protected policy, and separate issuer UID. The consuming host-deploy project awaits its public repository migration; it must issue a new durable selected `inspect` ID and correlate the result with the **original renew** request/issuer journal observation. The root reader's result freshness is limited to 15 minutes; use a new inspect request after expiry, never repurpose the renewal ID.

Source compatibility is not a grant for ACME issuance, automatic renewal, certificate staging, or nginx reload. The short-lived selected inspect remains the only approved v1 runtime topology; the independent socket prototype is deferred.
