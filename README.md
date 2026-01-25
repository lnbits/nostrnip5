<a href="https://lnbits.com" target="_blank" rel="noopener noreferrer">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://i.imgur.com/QE6SIrs.png">
    <img src="https://i.imgur.com/fyKPgVT.png" alt="LNbits" style="width:280px">
  </picture>
</a>

[![License: MIT](https://img.shields.io/badge/License-MIT-success?logo=open-source-initiative&logoColor=white)](./LICENSE)
[![Built for LNbits](https://img.shields.io/badge/Built%20for-LNbits-4D4DFF?logo=lightning&logoColor=white)](https://github.com/lnbits/lnbits)

# Nostr NIP-05 - <small>[LNbits](https://github.com/lnbits/lnbits) extension</small>

<small>For more about LNBits extension check [this tutorial](https://github.com/lnbits/lnbits/wiki/LNbits-Extensions)</small>

## Allow users to NIP-05 verify themselves at a domain you control

This extension allows users to sell NIP-05 verification to other nostr users on a domain they control.

## Usage

1. Create a Domain by clicking "NEW DOMAIN"\
2. Fill the options for your DOMAIN
   - select the wallet
   - select the fiat currency the invoice will be denominated in
   - select an amount in fiat to charge users for verification
   - enter the domain (or subdomain) you want to provide verification for
     - Note, you must own this domain and have access to a web server
3. You can then use share your signup link with your users to allow them to sign up

## Installation

In order for this to work, you need to have ownership of a domain name, and access to a web server that this domain is pointed to.

Then, you'll need to set up a proxy that points `https://{your_domain}/.well-known/nostr.json` to `https://{your_lnbits}/nostrnip5/api/v1/domain/{domain_id}/nostr.json`

Example nginx configuration

```
## Proxy Server Caching
proxy_cache_path /tmp/nginx_cache keys_zone=nip5_cache:5m levels=1:2 inactive=300s max_size=100m use_temp_path=off;

location /.well-known/nostr.json {
   proxy_pass https://{your_lnbits}/nostrnip5/api/v1/domain/{domain_id}/nostr.json;
   proxy_set_header Host {your_lnbits};
   proxy_ssl_server_name on;

   expires 5m;
   add_header Cache-Control "public, no-transform";

   proxy_cache nip5_cache;
   proxy_cache_lock on;
   proxy_cache_valid 200 300s;
   proxy_cache_use_stale error timeout invalid_header updating http_500 http_502 http_503 http_504;
}
```

### Example Caddy configuration

```
my.lnbits.instance {
    reverse_proxy {your_lnbits}
}

nip.5.domain {
    route /.well-known/nostr.json {
        rewrite * /nostrnip5/api/v1/domain/{domain_id}/nostr.json
        reverse_proxy {your_lnbits}
    }
}
```

## Powered by LNbits

[LNbits](https://lnbits.com) is a free and open-source lightning accounts system.

[![Visit LNbits Shop](https://img.shields.io/badge/Visit-LNbits%20Shop-7C3AED?logo=shopping-cart&logoColor=white&labelColor=5B21B6)](https://shop.lnbits.com/)
[![Try myLNbits SaaS](https://img.shields.io/badge/Try-myLNbits%20SaaS-2563EB?logo=lightning&logoColor=white&labelColor=1E40AF)](https://my.lnbits.com/login)
