# REVIEW-ONLY source integration profile. Do not enable on production hosts.
# Requires an immutable rootfs/software view containing Certbot 5.8.0, optional
# Cloudflare plugin, cryptography and zog.certify_manage, plus a separately
# authorized root-owned policy read-only directory capability.
#
# Each runtime operation (including stage) requires an explicit program_name;
# stage needs its OWN separately reviewed root-control policy binding.
# The policy path below is only a proposed guest destination and MUST be bound
# by the host owner before any actual invocation. Do not use a writable mount
# as a replacement for this trusted policy.
application(
    name="certify-manage",
    description="ACME certificate issuance and renewal, no ingress control",
    persistent=True,
    multiple_instances=False,
    execution_identity="application",
    start_policy="externally-controlled",
    writable_mounts=("certificate-data",),
    preparation_revision="certify-manage-state-v1",
    preparation=(
        program(
            name="prepare",
            command=("/usr/bin/python3", "-m", "zog.certify_manage", "prepare",
                     "--state", "/var/lib/zog-certify-manage",
                     "--policy", "/run/zog-host/certify-policy/policy.json"),
            execution_timeout_seconds=120,
            mounts={"certificate-data": "/var/lib/zog-certify-manage"},
        ),
    ),
    programs=(
        program(
            name="issue",
            command=("/usr/bin/python3", "-m", "zog.certify_manage", "issue",
                     "--state", "/var/lib/zog-certify-manage",
                     "--policy", "/run/zog-host/certify-policy/policy.json"),
            mounts={"certificate-data": "/var/lib/zog-certify-manage"},
        ),
        program(
            name="renew",
            command=("/usr/bin/python3", "-m", "zog.certify_manage", "renew",
                     "--state", "/var/lib/zog-certify-manage",
                     "--policy", "/run/zog-host/certify-policy/policy.json"),
            mounts={"certificate-data": "/var/lib/zog-certify-manage"},
        ),
        program(
            name="stage",
            command=("/usr/bin/python3", "-m", "zog.certify_manage", "stage",
                     "--state", "/var/lib/zog-certify-manage",
                     "--policy", "/run/zog-host/certify-policy/policy.json"),
            execution_timeout_seconds=120,
            mounts={"certificate-data": "/var/lib/zog-certify-manage"},
        ),
        program(
            name="inspect",
            command=("/usr/bin/python3", "-m", "zog.certify_manage", "inspect",
                     "--state", "/var/lib/zog-certify-manage",
                     "--policy", "/run/zog-host/certify-policy/policy.json"),
            mounts={"certificate-data": "/var/lib/zog-certify-manage"},
        ),
    ),
)
