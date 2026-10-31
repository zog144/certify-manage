# Certify-manage → box-control Regular: one selected renewal operation

**Date:** 2026-10-31  
**Issuer source:** `certify-manage@c8760c71d5af297e2f592c891805fc51f803ea64` (`unstable`), [source-only contract](../docs/single-renewal-operation-v1.md)  
**Controller review counterpart:** [box-control PR #14](https://github.com/zog144/box-control/pull/14), reviewed source head `f14f4985e039df06d21c7487ef8e74be44854b47`  
**Source CI:** [issuer six-job PASS](https://github.com/zog144/certify-manage/actions/runs/41248078441): Python 3.11/3.12 each 163 passed, 3 skipped; Certbot CLI smoke 3 passed; cryptography 47/50 and Python 3.15 compatibility PASS.

## Implemented at issuer

1. One exact selected `renew` command remains declared in `integration/box-control/application.py` with immutable launcher, non-root identity, dedicated `certificate-data`, fixed `--state`/root-owned `--policy` arguments; a separately selected `inspect` remains finite. No new service or evaluator.
2. The issuer must durably record `uncertain` **before** invoking Certbot. A witnessed nonzero return now durably records `status=uncertain,outcome=failed`; the prior baseline fingerprint/ACME account stay in the issuer's private journal. Lost reply/timeout or failed outcome-write keeps `outcome=null`. Neither case authorizes automatic retry or stage.
3. A successful `renewed|unchanged` result must pass real lineage, policy, ACME account and credential-change validation, then fsync a `ready` journal. Its successful one-line CLI JSON now includes the exact saved `policy_sha256` and `operation_updated_at`, as does explicit manual `recovered-unverified` (which is **not** verified). No private ACME account, request/runtime/invocation IDs, credential or token text appears in CLI status.
4. The existing selected `ZOG_CERTIFY_INSPECT_RESULT_V1 ` schema remains byte-compatible and `tls_ready=false`. With known nonzero renewal it now reports `health=uncertain,outcome=failed,issuer_verified=false`, preserving distinction from `recovered-unverified` and lost reply. Successful `renewed|unchanged` requires a *new* trusted selected inspect request scoped to the original renew's policy/fingerprint/journal timestamp.

## Specific box-control Regular review

- PR #14 adds direct request-ID/runtime equality and known controller result state validation. Its source CI presently passes; check exact-head pin and release-compatibility before merge.
- Independently confirm real `ApplicationRuntimeReference.request_id` is sourced from the saved launched request rather than a caller-controlled broker envelope. The runtime dataclass does expose `request_id` in `runtime/reference.py`; source compatibility alone does **not** establish real installed systemd admission.
- Preserve the original host-deploy fsynced controller ID on lost broker reply. Do not start a second selected Certbot runtime due to unknown status, returned `satisfied`, or expired controller evidence. `unknown` is not proof of absence. The saved request/program/runtime must be reconciled under the normal controller mutation/cleanup rules.
- Keep `result` strictly `{request_id,status,program,runtime_id}`, statuses `unknown|pending|satisfied|failed|abandoned|cancelled`. Do not add issuer `failed` or `renewed` as controller statuses; those are observed in the issuer's private journal and separate authenticated selected inspect.
- Check the PR #14 doc link to certify-manage: its current `regular/single-renewal-contract-20261031/docs/single-operation-renewal-v1.md` link is **not this producer's actual source path**. Use [`certify-manage@c8760c71/docs/single-renewal-operation-v1.md`](https://github.com/zog144/certify-manage/blob/c8760c71d5af297e2f592c891805fc51f803ea64/docs/single-renewal-operation-v1.md) and issuer tests `tests/test_renewal_operation_contract.py`. No source identity inference from similarly named branches.
- Return independent box-control PR #14 head, exact CI, any request/result compatibility findings, and explicit native gate. Do not allow `recover`, generic command execution, selected `issue` or direct root-control access through the lifecycle broker.

## Native gate

Source-level operation and failure reporting PASS on issuer; **native selected unit/boot/InvocationID/journal attribution, existing UID/STATE, real Certbot/ACME, credential provisioning, consumer nginx/CA/SNI and unattended timer remain NOT RUN/NO-GO**. The issuer's success JSON and private journal cannot substitute for root-control's original-request attestation. Stage/HTTPS publication remains separately authorized, and unchanged renewal never reloads nginx.
