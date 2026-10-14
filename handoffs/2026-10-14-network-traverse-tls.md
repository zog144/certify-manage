# Handoff: network-traverse end-to-end local HTTPS

**Owner:** network-traverse Regular; consumers: host-deploy,
certify-manage, station-access. **Status:** design constraint
requiring implementation/acceptance in that separate project.

Zog public HTTPS **terminates at the local machine's HTTPS service**.
When a remote client reaches a LAN/NAT installation via
network-traverse, any relay/proxy forwards **opaque TLS bytes**:
no public TLS termination at the relay, no local private key stored
there, no HTTP plaintext forwarding across the tunnel, and no
substitution of relay SNI certificates for local Zog certificates.

Define the permitted L4 TCP/TLS transport, connection identity,
access/routing authorization and SNI handling without authorizing
arbitrary host ports or arbitrary tunnels. Certify-manage owns
local ACME issuance/renewal and host-deploy publishes to local nginx.
DNS-01 with either centrally brokered or locally managed Cloudflare
credentials works with an outbound-only NAT host, independent of
incoming port 80. No local hosting of the Cloudflare token at
command center is required.

Acceptance: CA-verifying remote client connects through traversed
route with approved FQDN/SNI; inspect observed leaf fingerprint and
confirm it equals the **local** nginx-selected generation; end-to-end
TLS remains encrypted across relay and no private key or PEM is
accessible there. Exercise expired/revoked cert, wrong SNI, tunnel
loss/recovery, reconnect and local nginx rotation, fail closed on
misrouting. No acceptance until real LAN/NAT environment is available.
