# Certificate renewal: one selected operation, two authoritative records (v1)

**Owners:** certify-manage Regular (issuer journal and certificate validation);
box-control/root-control Regular (selected runtime and request recovery);
host-deploy Regular (owner-controlled scheduling and publication).

**Scope:** source-only contract. No automatic timer, live ACME, DNS changes,
nginx reload or new root privilege is authorized by this document.

## 1. Admission / immutable intent

The host owner allocates **one controller request ID**, durably records it
alongside the exact operation selector `certify-manage/renew`, host/policy
authority and prior observed certificate identity, **before** submission.
Use the authorized issuer lifecycle broker's `start` action with only
`{request_id, program:"renew"}` or the controller's existing selected
`launch_application(..., request_id=..., program_name="renew")`; never
start both paths for a new intent. Neither the issuer CLI nor a caller may
choose an alternate command, environment, policy file, state mount, UID,
generation, account or FQDN. The shared application is a prepared
unprivileged persistent singleton, with one immutable selected-program
snapshot and one root-controlled read-only `certify-policy` binding.

If the reply is lost, query **the original request ID** and its exact
selector, then recover its original authoritative operation. Do not create
another ID, switch to `inspect` under the old ID, or start another
renewal to discover whether the previous one ran. Request/result retention
is bounded to 48 hours; after expiry without proven outcome, block for
operator reconciliation rather than manufacturing fresh success.

## 2. One Certbot invocation, issuer-private journal

The issuer locks its pre-existing private state, checks protected policy,
lineage, ACME account, renewal configuration and any approved Cloudflare
credential, then **durably writes** an `uncertain` journal entry with the
old fingerprint/account **before** entering the fake or real Certbot runner.

That uncertain entry is intentional: a failed exit, timeout, crash, lost
response, credential rotation, invalid postflight lineage, changed account
or failure persisting a successful result **cannot establish a no-effect
retry**. No automatic second `renew` and no `stage` is allowed.

Only a zero exit followed by successful X.509/SAN/account/credential
postflight and durable `ready` journal replacement may report
`renewed` (fingerprint changed) or `unchanged` (fingerprint equal).
An old valid certificate does not turn an uncertain renewal into success.
The issuer journal records certificate ID through its protected filename,
policy digest, operation, outcome, fingerprint, account identity and
update timestamp. **It does not attest the controller request ID.**

## 3. Controller outcome is not certificate outcome

| Controller evidence | Issuer evidence | Decision |
| --- | --- | --- |
| Unknown, pending, lost reply, or ambiguous | Any | Hold original request; reconcile, do not resubmit a new ID |
| Failed, cancelled or abandoned | Any | No positive renewal claim; inspect retained side effects |
| Satisfied selected `renew` | Missing, stale, uncertain, invalid, or mismatched | No success, no publication |
| Satisfied selected `renew` | Authenticated fresh `renew/unchanged`, same identity and policy | Recorded successful no-op; do not needlessly stage/reload |
| Satisfied selected `renew` | Authenticated fresh `renew/renewed`, same identity and policy | Eligible for **separate** selected `stage` and host-owned delivery; NOT TLS readiness |

The trusted observer must use a **separate selected `inspect` request ID**
and root-control's exact unit/boot/InvocationID/UID/journald attribution.
The issuer's `ZOG_CERTIFY_INSPECT_RESULT_V1` alone does not attest the
controller request. The host owner compares the expected certificate ID,
SAN set, policy digest, storage/grant/UID binding, journal update time and
leaf fingerprint with the original renewal evidence. The authenticated
inspection has a 15-minute freshness limit. The issuer must always report
`tls_ready:false`. Local nginx delivery and independent CA/SNI/leaf
verification remain later host-deploy gates.

## 4. Failure and recovery surface

CLI failure emits **only** a fixed redacted error and nonzero exit;
subprocess stderr, token contents, private paths and operation arguments
must not reach public response or logs. An exception before the
pre-Certbot journal does not authorize running Certbot; the previous
journal stays unchanged. An exception **after** the uncertain write must
leave it blocking new issuance, renewal and stage, even if the previous
leaf remains valid. Read-only inspection may show the retained uncertain
state without publishing secrets.

A separately authorized manual `recover --confirm-uncertain-recovery`
may reconcile a still-valid same-account lineage but produces
`recover/recovered-unverified`, **never** `renewed`, `unchanged`,
`issuer_verified:true` or automatic publication. It cannot turn the old
request into a satisfied verified renewal.

## 5. Synthetic acceptance (no live workspace/ACME)

- Exact selected `renew`, request-ID reuse, rejected selector change,
  immutable runtime/grant/storage and terminal-request result identity.
- Zero + unchanged leaf; zero + changed leaf; invalid leaf/account despite
  exit zero; nonzero; timeout; failed final journal sync.
- Inspect returns verified renewal evidence only from ready matching
  journal/lineage; uncertain/recovered states never grant publication.
- Broker/client reject misbound responses and do not leak exception text.
- Host-deploy must separately test its durable single-operation coordinator,
  15-minute observer freshness and stage/nginx gates before production use.

These tests are source acceptance only. Native systemd 252, real
Certbot 5.8.0 + Cloudflare plugin, credential rotation, reboot and ACME
staging remain separate, explicitly blocked acceptance gates.
