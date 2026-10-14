import pytest
from zog.certify_manage.model import Authorization, PolicyError

def policy(**kw):
    d = dict(schema="zog-certify-manage-v1", certificate_id="station-web",
             hostnames=["station.example.org"], email="admin@example.org",
             acme_directory="https://acme-staging-v02.api.letsencrypt.org/directory",
             challenge="http-01", dns_plugin=None)
    d.update(kw)
    return d

def test_contract_fingerprint_stable():
    a = Authorization.from_dict(policy())
    assert a == Authorization.from_dict(policy())
    assert len(a.fingerprint) == 64
    assert a.hostnames == ("station.example.org",)

@pytest.mark.parametrize("change", [
    {"hostnames": ["STATION.example.org"]},
    {"hostnames": ["127.0.0.1"]},
    {"hostnames": ["*.example.org"]},
    {"hostnames": ["localhost"]},
    {"hostnames": ["a.example.org", "a.example.org"]},
    {"certificate_id": "../key"},
    {"challenge": "tls-alpn-01"},
    {"dns_plugin": "dns-cloudflare"},
    {"acme_directory": "http://example.org/directory"},
    {"acme_directory": "https://user:pass@example.org/directory"},
    {"email": "nobody"},
    {"hostnames": ["-bad.example.org"]},
    {"hostnames": ["station.example.org", "a.example.org"]},
]):
def test_reject_bad_authority(change):
    with pytest.raises(PolicyError):
        Authorization.from_dict(policy(**change))

def test_dns_wildcard():
    value = policy(challenge="dns-01", dns_plugin="dns-cloudflare",
                   hostnames=["*.example.org", "station.example.org"])
    assert Authorization.from_dict(value).hostnames[0] == "*.example.org"

def test_unknown_field_rejected():
    with pytest.raises(PolicyError):
        Authorization.from_dict({**policy(), "debug": True})
