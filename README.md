# CloudFlare hook for `dehydrated`

This is a hook for the [Let's Encrypt](https://letsencrypt.org/) ACME client [dehydrated](https://github.com/lukas2511/dehydrated) (previously known as `letsencrypt.sh`) that allows you to use [CloudFlare](https://www.cloudflare.com/) DNS records to respond to `dns-01` challenges. Requires Python and your CloudFlare account e-mail and API key being in the environment.

## WSL, Ubuntu, and potentially Debian prerequisites
You may need to install the following two packages in addition to Python 3:

```
sudo apt install python3-pip python-is-python3
```


## Installation

```
$ cd ~
$ git clone https://github.com/lukas2511/dehydrated
$ cd dehydrated
$ mkdir hooks
$ git clone https://github.com/SeattleDevs/letsencrypt-cloudflare-hook hooks/cloudflare
```

Using Python 3:
```
$ pip3 install -r hooks/cloudflare/requirements.txt
```


## Configuration

Your account's CloudFlare email and API key are expected to be in the environment, so make sure to:

```
$ export CF_EMAIL='user@example.com'
$ export CF_KEY='K9uX2HyUjeWg5AhAb'
```

You can supply multiple account credentials by separating them with one or more spaces.  Accounts will be tried in the order given, until one is found that serves the relevant domain.
Leading, trailing, and extra spaces are ignored, so you can vertically align credential pairs for easy reading:

```
$ export CF_EMAIL='user1@example.com    user2@somewhere.com'
$ export CF_KEY='  K9uX2HyUjeWg5AhAtreb fdsfjhFdaKls45354kHJ9hsj'
```

Optionally, you can specify the DNS servers to be used for propagation checking via the `CF_DNS_SERVERS` environment variable (props [bennettp123](https://github.com/bennettp123)):

```
$ export CF_DNS_SERVERS='8.8.8.8 8.8.4.4'
```

If you experience problems with DNS propagation, increasing the time (in seconds) this hooks waits for things to settle down after setting the DNS records, may help. The default is 10.

```
$ export CF_SETTLE_TIME='30'
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
