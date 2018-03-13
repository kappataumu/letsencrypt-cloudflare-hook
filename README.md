# CloudFlare hook for `dehydrated`

This is a hook for the [Let's Encrypt](https://letsencrypt.org/) ACME client [dehydrated](https://github.com/lukas2511/dehydrated) (previously known as `letsencrypt.sh`) that allows you to use [CloudFlare](https://www.cloudflare.com/) DNS records to respond to `dns-01` challenges. Requires Python and your CloudFlare account e-mail and API key being in the environment.

## Installation

```
$ cd ~
$ git clone https://github.com/lukas2511/dehydrated
$ cd dehydrated
$ mkdir hooks
$ git clone https://github.com/kappataumu/letsencrypt-cloudflare-hook hooks/cloudflare
```

If you are using Python 3:
```
$ pip install -r hooks/cloudflare/requirements.txt
```

Otherwise, if you are using Python 2 (make sure to also check the [urllib3 documentation](http://urllib3.readthedocs.org/en/latest/security.html#installing-urllib3-with-sni-support-and-certificates) for possible caveats):

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

If you want more information about what is going on while the hook is running:

```
$ export CF_DEBUG='true'
```

Alternatively, these statements can be placed in `dehydrated/config`, which is automatically sourced by `dehydrated` on startup:

```
echo "export CF_EMAIL=user@example.com" >> config
echo "export CF_KEY=K9uX2HyUjeWg5AhAb" >> config
echo "export CF_DEBUG=true" >> config
```

## Deploy hook

If you would like a program to be called when a certificate is deployed you can do so by doing:
```
export CF_DEPLOY_HOOK='program_to_execute'
```

Alternatively, it can be placed in `dehydrated/config`, which is automatically sourced by `dehydrated` on startup:

```
echo "export CF_DEPLOY_HOOK=program_to_execute" >> config
```

The `CF_DEPLOY_HOOK` script/program will be called with the following arguments:
    domain privkey_pem cert_pem fullchain_pem chain_pem timestamp

* **domain**: The domain name of the certificate. For example: foo.example.come
* **privkey_pem**: Location of the `privkey.pem` file.
* **cert_pem**: Location of the `cert.pem` file.
* **fullchain_pem**: Location of the `fullchain.pem` file.
* **chain_pem**: Location of the `chain.pem` file.
* **timestamp**: The timestamp of the certificate

It is up to your script/program to take this information to deploy the certificate as needed.

## Usage

```
$ ./dehydrated -c -d example.com -t dns-01 -k 'hooks/cloudflare/hook.py'
#
# !! WARNING !! No main config file found, using default config!
#
Processing example.com
 + Signing domains...
 + Creating new directory /home/user/dehydrated/certs/example.com ...
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
 + ssl_certificate: /home/user/dehydrated/certs/example.com/fullchain.pem
 + ssl_certificate_key: /home/user/dehydrated/certs/example.com/privkey.pem
 + Done!
```

## Further reading
If you want some prose to go with the code, check out the relevant blog post here: [From StartSSL to Let's Encrypt, using CloudFlare DNS](http://kappataumu.com/articles/letsencrypt-cloudflare-dns-01-hook.html).
