# Third-party notices

This repository contains **no bundled Certbot executable, ACME account, TLS private key, Cloudflare credential or issued certificate**.

The runtime depends on **cryptography** (Python package; Apache-2.0 OR BSD-3-Clause upstream license) and an externally packaged **Certbot** distribution (Apache-2.0 upstream). Optional Certbot DNS authenticator plugins, including `certbot-dns-cloudflare`, retain their own distribution licenses and dependency obligations. Consult exact locked package inventories and licenses when image-build assembles an immutable view.

Nothing in this repository grants use of a DNS provider API credential or authorization for a domain.
