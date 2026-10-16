# Issuer-UID authenticated X.509 inspection interface (source contract)

**Status:** read-only source implementation; GitHub Actions 38900854243 passed (Python 3.11/3.12 and pinned Certbot CLI smoke); **not deployed**
on real systemd, not live ACME, and not public TLS readiness.

## Why this exists

box-control/root-control expose `zog-trusted-issuer-observation-v1` by looking
up the *original selected controller request*, its terminal result and
issuer-private journal. That attests **provenance**, but deliberately
does not read the certificate's private key or validate the actual
Certbot fullchain. host-deploy cannot directly read 0700 issuer state
across the required split UIDs. The issuer now offers a separate
read-only private AF_UNIX inspection socket under the **issuer UID**.

The `zog.certify_manage.inspection` service:

- Is exclusively systemd socket-activated (one AF_UNIX/SOCK_STREAM
  listening FD 3), with exact pinned socket pathname and no TCP listener.
- Requires a **non-root dedicated issuer UID different from the exact
  allowed host-deploy UID**, authenticated by kernel `SO_PEERCRED`
  before request parsing. Socket DAC is an additional gate.
- Pins the one guest `/var/lib/zog-certify-manage` mount, the one
  root-owned read-only `/run/zog-host/certify-policy/policy.json`,
  and the approved peer UID at service start; rereads and checks policy
  identity on each request to prevent stale-authorization acceptance.
- Only accepts `{"schema":"zog-certify-inspection-v1","operation":"inspect","nonce":"<32 lower hex>"}`
  framed as one bounded newline-terminated JSON object. No request ID,
  certificate ID, FQDN, path, backend, command, or arbitrary options.
- Acquires a read-only, nonblocking shared flock on the existing issuer
  writer lock, without creating files. An ongoing issuer mutation
  returns a generic refusal; no partial mixed snapshot is considered
  ready.
- Runs `CertificateManager.inspect()` inside the issuer UID, which
  already verifies current Certbot leaf, chain order/signatures, SANs,
  private/public key match, dates, protected renewal config and ACME
  account binding. Checks that the post-operation journal fingerprint,
  authorized policy SHA, outcome and timestamp match this certificate.
- Returns strictly bounded **secret-free** fields only. It cannot
  issue, renew, stage, recover, delete, export PEM or reload nginx.
  All response failures are redacted, no stack trace or secret path.
  `tls_ready` is always `false`.

## Result schema

Success wrapper `{"ok":true,"result":{...}}`; errors are only
`{"ok":false,"error":"inspection-unavailable"}`. The fixed result
object has exactly:

| Field | Meaning |
| --- | --- |
| `schema`, `nonce` | fixed v1 and fresh caller challenge |
| `certificate_id`, `hostnames`, `policy_sha256` | locally authorized, not caller-selected |
| `health`, `certificate_fingerprint_sha256` | validated local leaf status and digest; missing/invalid/uncertain do not qualify |
| `valid_from`, `expires_at`, `days_remaining` | checked local X.509 time evidence, not CA/browser trust |
| `operation`, `outcome`, `operation_updated_at` | current issuer operation journal; `recovered-unverified` is not a positive result |
| `issuer_verified` | true **only** for valid current certificate and ready matching journal with `issued`/`renewed`/`unchanged` |
| `observed_at`, `tls_ready` | freshness timestamp; TLS readiness always false |

No controller `request_id` is accepted or echoed: the issuer cannot
independently authenticate that relationship. host-deploy **must** first
obtain the separate controller-owned `journal-ready` observation and
match expected certificate/policy/fingerprint/outcome/journal timestamp
to this fresh issuer-UID inspection. Neither alone is sufficient.
A `recovered-unverified` result must remain blocked.

## Native owner wiring (not installed here)

The controller/host-deploy owner must provision one **reviewed**
systemd socket/service with the issuer's existing numeric UID/GID,
same durable certificate-data mount and read-only host policy capability.
Do not start an unmanaged systemd unit against box-control-managed
STATE. The `--authorized-uid` is the separately approved dedicated
host-deploy caller UID, not chosen by an HTTP request.

The socket should be in a root-controlled parent directory with
`SocketUser=<issuer UID>`, `SocketGroup=<narrow authorized group>`,
`SocketMode=0660` (and explicit group membership only for the
approved host-deploy caller); other UIDs denied by DAC, and all peers
also checked by `SO_PEERCRED`. The issuer service must have exactly
one inherited listener and use the pinned form:

```sh
python3 -m zog.certify_manage.inspection \
  --authorized-uid <approved-host-deploy-uid> \
  --socket-path /run/zog/certify-inspect.sock \
  --state /var/lib/zog-certify-manage \
  --policy /run/zog-host/certify-policy/policy.json
```

Host-deploy calls
`IssuerInspectionClient("/run/zog/certify-inspect.sock", expected_issuer_uid=<grant UID>).inspect()`.
Its client independently checks the issuer's SO_PEERCRED, fresh random
nonce, strict response schema and observed timestamp. This is a client
library, **not yet consumed by host-deploy's coordinator**. Do not add
issuer raw mount permission to host-deploy or the controller observer.

### Acceptance required

1. In source tests: wrong UID before parsing, duplicate fields,
   hostile requests, nonce freshness, mismatched issuer UID, revoked
   policy, busy writer lock, invalid SAN/chain/key, corrupt journal,
   recovered-unverified and no state writes or PEM/account leakage.
2. On isolated host: root-owned protected policy binding, unprivileged
   issuer and **separate** host-deploy UID, real socket inode/DAC and
   `SO_PEERCRED` allow/deny, exact request-bound controller observer,
   real Certbot 5.8 staging issuance/renewal and validated leaf.
3. After matching independent observations, run selected `stage`
   through the separately authorized lifecycle broker; verify the
   issuer-private receipt and host-owned nginx delivery, rollback,
   external CA/SNI/fingerprint and reboot recovery.
4. Keep automatic production renewal and public TLS cutover **NO-GO**
   until the native owner gate actually passes.

**Compatibility:** consumer handoff belongs to host-deploy Regular;
box-control/root-control must review service activation and split-UID
mount/policy binding. No changes to their repositories were made here.
