# Single selected renewal operation — source contract v1

**2026-10-31 · owners: certify-manage Regular and box-control Regular.** The producer remains one finite selected `certify-manage/renew` program per separately approved host-owner operation. This is a contract for existing interfaces, **not** a new transport, duplicate Certbot engine, static systemd service, unapproved automation or production activation.

## Owner-to-controller-to-issuer sequence

| Phase | Authority | Durable source / rule |
| --- | --- | --- |
| Authorize | host-deploy scheduler/Host owner | Independently approve a due renewal for one certificate/policy, original protected issuer grant/storage and approved hostname/credential. A due date or timer event alone cannot grant a new issuance. |
| Allocate | authenticated box-control controller | Issue one opaque controller request ID (max 200 characters, original request identity). host-deploy fsyncs `zog-host-deploy-cert-renewal-v1` intent **before** making a launch request. |
| Start | `IssuerLifecycleBroker` | Accept only exact `start(program="renew", request_id=original)`; immutable `certify-manage` application, selected `renew` command, prepared software view, non-root issuer UID and persistent STATE. No shell, generic `evaluate`, arbitrary flags/policy, static issuer service or direct root-control socket from host-deploy. |
| Execute | issuer selected process | Hold existing issuer exclusive flock, validate owner-approved policy/X.509 lineage/ACME renewal account, current dedicated Cloudflare credential when applicable; record `zog-certify-operation-v1` `status=uncertain` on protected disk **before** invoking one pinned Certbot operation. |
| Commit | issuer | On validated Certbot exit 0 plus valid authorized leaf, unchanged ACME account and stable private credential, durably fsync/replace issuer record `status=ready, operation=renew, outcome=renewed|unchanged`. `renewed` requires a different leaf SHA-256; `unchanged` requires an identical leaf. Process exit 0 without the lineage/account proof leaves `uncertain`. |
| Reconcile | controller + host-deploy | Retrieve **same original request ID** and authenticate original systemd/boot/InvocationID, program, grant, storage and issuer journal. Controller `satisfied` means the transient program completed; it is not X.509, issuance or TLS proof. |
| Inspect | distinct selected issuer `inspect` request | One independent short-lived `ZOG_CERTIFY_INSPECT_RESULT_V1 ` record, max 4096 bytes. box-control/root-control bind it to its own selected request + InvocationID. Host-deploy compares authorized certificate/SANs/policy/leaf/issuer `operation=renew`, exact `renewed|unchanged` and UTC-normalized `operation_updated_at` with the original trusted renewal journal. No reused inspect request ID, general journal scrape or old socket inspector. |
| Publish | host-deploy, only after independent proof | `unchanged`: no stage/reload. `renewed`: separate selected `stage` ID, protected fingerprint-bound candidate, nginx validation + authorized reload/rollback, then outside-in CA/SNI local endpoint proof. The issuer always returns `tls_ready=false`. |

The two issuer-side durable producer facts are **not** controller/request receipts: (a) the private operation record `operations/<certificate_id>.json`, schema `zog-certify-operation-v1`, fields `schema,policy_sha256,operation,status,certificate_fingerprint,account_id,outcome,updated_at`; (b) separate one-shot selected `inspect` schema `zog-certify-inspection-result-v1`. The protected issuer record contains the Certbot account identity and MUST NEVER be exposed as a public broker result. The selected-inspect summary is redacted and contains no account, request ID, runtime or systemd invocation: **only root-control can bind the original selected request to the provenance**. Its successful process exit alone can mean `issuer_verified=false`.

## Terminal and uncertain outcomes

| Origin of result | Private journal | Selected inspect | Host-owner decision |
| --- | --- | --- | --- |
| Certbot exit 0, exact new authorized leaf, account and token stable | `ready / renewed` | `valid, renew, renewed, issuer_verified=true` (if same evidence) | Eligible for **separately** selected stage |
| Certbot exit 0, unchanged exact authorized leaf, account and token stable | `ready / unchanged` | `valid, renew, unchanged, issuer_verified=true` | No new stage/nginx reload |
| **Known nonzero Certbot exit** | `uncertain / failed` (durably saved **after** the originally fsynced uncertain preflight) | `uncertain, renew, failed, issuer_verified=false` | Block retries and staging; failed process does not prove no ACME side effect |
| Crash, kill, timeout, lost reply, exception or failed fsync | `uncertain / null` (or last durable uncertain record) | `uncertain, issuer_verified=false` | Recover original controller request, do not allocate a second ID or resubmit after retained result may be pruned |
| Preflight rejection before saved uncertain record | Previous state remains | Separate inspection reports existing state | No Certbot run; controller records selected launch failure, does not fabricate issuer outcome |
| Explicit operator `recover --confirm-uncertain-recovery` | `ready / recovered-unverified`, operation `recover` | `valid` lineage is possible, but `issuer_verified=false` | Never stage automatically; retain original failed/uncertain controller history |
| Invalid leaf, SAN/account/policy mismatch or Cloudflare credential rotation *during* Certbot | `uncertain / null` | `issuer_verified=false` | Block without changing provider token, resetting Certbot account, retrying or publishing |
| Failed nginx publication after verified `renewed` | Issuer's verified private record unchanged | Issuer `tls_ready=false` | Host-deploy retains original delivery ID, rollback state and independent client TLS readiness evidence; no implicit issuer rerun |

The known-nonzero `outcome=failed` is a **process-level negative result under `status=uncertain`**, not a declaration that the previous lineage is absent or the provider did nothing. A crash before the second journal write retains `outcome=null`, never a false success. Neither status can authorize publication.

## Bounded retry and retention

- On a lost launch reply or unknown controller request **within the controller's retained idempotent request window**, reconcile the saved ID and exact selected program. It is not permission for a new Certbot subprocess: box-control must reconcile or reject the original transaction. On expired/pruned evidence, hold for operator review, never create a replacement ID. A different ID is permitted only after verified terminal prior result, explicit later owner authorization and minimum interval.
- Controller admission and issuer flock prevent overlapping operations; independent selected `inspect` is nonblocking on a busy writer. The Host owner refuses a pending/uncertain renewal and refuses `stage` without fresh authenticated original renew + subsequent selected inspect proof.
- A nonzero CLI exit returns a single fixed, secret-free stderr error and **no stdout success record**. A successful `renew` currently emits one legacy redacted `CertificateStatus.as_dict()` JSON line. Do not mistake that line for a signed systemd/journal result, or invent a new renewal wire marker before box-control agrees. The existing selected inspect record remains unchanged.
- Host-deploy owns scheduler cadence, selected request IDs, status journal, deliberate failure alerting, nginx and outside-in readiness. box-control owns exact invocation/Journald authentication. The issuer owns private Certbot state and its durable pre/post records; the issuer does **not** store a controller request ID, service UID, HostID or browser approval token.

## Source tests, owner gates

`tests/test_renewal_operation_contract.py` tests exact selected command declaration, single subprocess per selected issuer call, `renewed` versus `unchanged` fingerprints, protected durable issuer record and fresh selected inspect, known nonzero `failed` while uncertain, timeouts with null outcome, failed terminal write, explicit recovery never promoting success, and stdout/stderr redaction. Existing manager and selected-inspect negative suites remain active.

**box-control Regular next:** verify this contract against `box-control@73d64fb8b643e27667ac719080a37913c008b5dd`, the current `issuer_lifecycle_broker` and `IssuerLifecycleClient`: one saved request + program binding, idempotent same-ID restart, pending cleanup and root-controlled immutable view, finite selected inspect request and trusted InvocationID observation, bounded journal retention and failure result with no raw Certbot stderr. Add missing synthetic controller tests and independently review source/immutable pin. Do **not** broaden the broker to `recover`, arbitrary `issue` or direct `evaluate` just to handle failed renewal.

**host-deploy Regular next:** ensure current timers preserve request and evidence retention, distinguish controller `failed` from issuer `uncertain/failed`, defer re-authorization after lost reply, and explicitly require a separate selected inspect before staging. No automatic renewal after `recovered-unverified`.

**Native Work gates:** real systemd 252 issuer selected UID/mount/policy; journald InvocationID and original request reconciliation across restart/reboot; real Certbot staging, DNS-01 token handling, nginx rollback, CA/SNI. **All remain NO-GO / NOT RUN in this source-only pass.**
