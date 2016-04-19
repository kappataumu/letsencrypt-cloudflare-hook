# CloudFlare hook for letsencrypt.sh ACME client

This a hook for [letsencrypt.sh](https://github.com/lukas2511/letsencrypt.sh) (a [Let's Encrypt](https://letsencrypt.org/) ACME client) that allows you to use [CloudFlare](https://www.cloudflare.com/) DNS records to respond to `dns-01` challenges. Requires Python and your CloudFlare account e-mail and API key being in the environment.

## Installation

```
$ git clone https://github.com/lukas2511/letsencrypt.sh
$ cd letsencrypt.sh
$ mkdir hooks
$ git clone https://github.com/kappataumu/letsencrypt-cloudflare-hook hooks/cloudflare
$ pip install -r hooks/cloudflare/requirements.txt
```
If using Python 2, replace the last step with the one below and check the [urllib3 documentation](http://urllib3.readthedocs.org/en/latest/security.html#installing-urllib3-with-sni-support-and-certificates) for other possible caveats.

```
$ pip install -r hooks/cloudflare/requirements-python-2.txt
```


## Configuration

Your account's CloudFlare email and API key are expected to be in the environment, so make sure to:

```
$ export CF_EMAIL='user@example.com'
$ export CF_KEY='K9uX2HyUjeWg5AhAb'
```

Optionally, you can specify the DNS servers to be used for propagation checking via the `CF_DNS_SERVERS` environment variable (props [bennettp123](https://github.com/bennettp123)):

```
$ export CF_DNS_SERVERS='8.8.8.8 8.8.4.4'
```

Alternatively, these statements can be placed in `letsencrypt.sh\config.sh`, which is automatically sourced by `letsencrypt.sh` on startup:

```
echo "export CF_EMAIL='user@example.com'" >> config.sh
echo "export CF_KEY='K9uX2HyUjeWg5AhAb'" >> config.sh
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
If you want some prose to go with the code, check out my relevant blog post here: [From StartSSL to Let's Encrypt, using CloudFlare DNS](http://kappataumu.com/articles/letsencrypt-cloudflare-dns-01-hook.html).
