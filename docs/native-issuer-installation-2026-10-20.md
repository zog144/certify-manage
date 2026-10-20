# Native issuer installation — required producer binding (2026-10-20)

**Owner:** `certify-manage` source producer, for **host-install** to consume.  
**Status:** versioned, *nonsecret, requirements-only* contract; not proof of installed software, authenticated hostname assignment, native execution or issuance authorization.

The machine-readable [issuer installation requirements](../integration/host-install/issuer-installation-requirements-v1.json) pin the exact **non-secret paths and boundaries** expected by the certifier. Host-install must consume this only after separately authenticating STATE, controller grants, immutable view, protected policy and installation execution. Do not accept a file or a `host-install certificate-status` JSON payload as an authority source.

## Native path and runtime duties

- The reviewed `certify-manage` declaration contains one preparation command `prepare` plus separately selected `issue`, `renew`, `inspect` and `stage`. It is a **single persistent application, not five independently installed systemd units**. Controller admission owns all transient services, admission locks and durable request IDs.
- Immutable view launcher: `/applications/certify-manage/bin/python3`; Certbot: `/applications/certify-manage/bin/certbot`. image-build must first publish an accepted `applications-v1` artifact, `application-software-view-v1` view and `application-software-consumer-v1` binding with actual Python SOABI/OpenSSL/native dependency verification. No host pip install or fallback to `/usr/bin/certbot`.
- Dedicated application UID/GID and controller-granted `certificate-data` persist across reboot/upgrade. The immutable rootfs has an empty real 0700 guest mount target `/var/lib/zog-certify-manage`, and the controller overlays the existing protected persistent storage. **Never** replace a missing mount with a newly created ordinary rootfs directory, re-chown existing private state, or share station/web credentials.
- Root-owned, administrator-approved nonsecret policy `/etc/zog/certify-policy/policy.json` must be separately admitted and bound read-only inside the guest at `/run/zog-host/certify-policy/policy.json`. An issuer launch cannot select hostnames or trusted policy at startup. Standalone local approval and outbound command-center assignment are independent authority sources; the controller must reject conflicts, expiry, revocation or policy migration without an approved replacement.
- Only the issuer reads an issuer-owned `dns/cloudflare.ini`; root-control authorizes exact zone, issuer UID/storage, assignment/credential revision and installs it through the reviewed offline/FD-only bridge. No web vault read or token provision from host-install.
- `prepare` may be invoked **once through controller-owned preparation**, against a verified mount/policy, preserving the same prepared identity. An existing ACME account must remain intact across reboot and image upgrade; never run first-boot implicit issue/renew or reset Certbot accounts.

## Native acceptance and evidence

| Boundary | What the trusted Work acceptance must prove |
|---|---|
| Producer | exact image-build artifact/view/consumer digests, imported modules, Certbot 5.8.0, optional Cloudflare plugin, Python/ELF ABI, immutable launchers and redacted source notices |
| Installer | verified STATE and mount, no recovery hold, original issuer storage ID and UID/GID, prepared revision frozen across reboot, no secret in installation artifact |
| Controller | separate selected program and durable request ID per operation, singleton admission, real issuer UID/GID, RO root-owned policy, private 0700 `certificate-data`, actual transient service and accepted result identity |
| Inspector | one bounded `ZOG_CERTIFY_INSPECT_RESULT_V1 ` marker, `issuer_verified` only after real local X.509/key/renewal validation, exact controller-saved systemd InvocationID + journald provenance; `tls_ready:false` |
| Recovery | unknown/lost reply, reboot, generation upgrade, interrupted `prepare`, pending `renew`, uncertain Certbot operation, no duplicate renewal or account loss, no premature staged candidate |
| Authority | missing/expired/revoked/conflicting FQDN becomes pending or blocked. No guessed hostname from outbound beacon, provider token or station UI alone |
| Consumer | separately authorized host-deploy delivery, nginx config validation, versioned leaf publication, reload/rollback, and CA/SNI proof from the **local Zog endpoint**. Not an issuer/installer readiness assertion |

Native tests must use an **isolated disposable host** and must never mutate the production controller when its `mutation-incomplete` marker or credential/STATE holds are present. A positive fixture, simulator or process exit is not installed evidence.

## Next owners and exact outputs

**host-install Regular:** implement the genuine host-install → controller/application-view provisioning and mounted-state observation path, using the source requirements only to test for drifts. Report protected installation state and opaque `persistent_state_id`, `prepared_revision`, verified software generation and a fail-closed status in the existing `certificate-lifecycle-record` schema. No host-install certificate execution engine, new UID allocator or privileged policy writer.

**station-access + host-discover Regular:** separately publish managed outbound hostname assignment and standalone local owner approval, verify authorizations and conflicts, then install the root-owned certificate-policy binding through a reviewed owner interface. Host-install and certify-manage cannot manufacture an FQDN.

**image-build Work:** supply a real installed artifact/view and consumer binding with pinned source hashes and runtime test evidence. Its source-only producer does not satisfy this requirement.

**host-deploy Work:** only after the prior gates, test actual split-UID transient services, selected request → authenticated inspection → separately authorized stage, ingress/ACME staging challenge, nginx rollback and local SNI/CA readiness. Keep PR #3 draft and all production HTTPS activation blocked until native proof.

**certify-manage Regular:** preserve the five exact paths, strict inspection and issuer-private stage receipts; coordinate incompatible native execution issues back to image-build/controller rather than introducing untracked services. Run schema/profile drift tests each producer revision.

See the existing [issuer lifecycle contract](issuer-lifecycle-integration-2026-10-20.md). No changes to Certbot, nginx or host DNS are implied by this requirements publication.
