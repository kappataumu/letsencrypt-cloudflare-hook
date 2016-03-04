# CloudFlare hook for letsencrypt.sh ACME client

This a hook for the [Let's Encrypt](https://letsencrypt.org/) ACME client [letsencrypt.sh](https://github.com/lukas2511/letsencrypt.sh), that enables using DNS records on [CloudFlare](https://www.cloudflare.com/) to respond to `dns-01` challenges. Requires Python 3 and your CloudFlare account e-mail and api key being in the environment.

## Setup

```
$ git clone https://github.com/lukas2511/letsencrypt.sh
$ cd letsencrypt.sh
$ mkdir hooks
$ git clone https://github.com/kappataumu/letsencrypt-cloudflare-hook hooks/cloudflare
$ pip install -r hooks/cloudflare/requirements.txt
$ export CF_EMAIL='user@example.com'
$ export CF_KEY='K9uX2HyUjeWg5AhAb'
```

### A note for Python 2

If using Python 2, you need to replace the requirements installation step with the one below. Check the [urllib3 documentation](http://urllib3.readthedocs.org/en/latest/security.html#installing-urllib3-with-sni-support-and-certificates) for other possible caveats.

```
$ pip install -r hooks/cloudflare/requirements-python-2.txt
```

## Usage

```
$ ./letsencrypt.sh -c -d example.com -t dns-01 -k 'hooks/cloudflare/hook.py'
#
# !! WARNING !! No main config file found, using default config!
#
Processing example.com
 + Signing domains...
 + Creating new directory /home/user/letsencrypt.sh/certs/example.com ...
 + Generating private key...
 + Generating signing request...
 + Requesting challenge for example.com...
 + CloudFlare hook executing: deploy_challenge
 + DNS not propagated, waiting 30s...
 + DNS not propagated, waiting 30s...
 + Responding to challenge for example.com...
 + CloudFlare hook executing: clean_challenge
 + Challenge is valid!
 + Requesting certificate...
 + Checking certificate...
 + Done!
 + Creating fullchain.pem...
 + CloudFlare hook executing: deploy_cert
 + ssl_certificate: /home/user/letsencrypt.sh/certs/example.com/fullchain.pem
 + ssl_certificate_key: /home/user/letsencrypt.sh/certs/example.com/privkey.pem
 + Done!
```

## Further reading
If you want some prose to go with the code, check out my relevant blog post here: [From StartSSL to Let's Encrypt, using CloudFlare DNS](http://kappataumu.com/articles/letsencrypt-cloudflare-dns-01-hook.html)
