#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import logging
import os
import subprocess
import sys
import time

import dns.exception
import dns.resolver
import requests
from tld import get_tld

# Enable verified HTTPS requests on older Pythons
# http://urllib3.readthedocs.org/en/latest/security.html
if sys.version_info[0] == 2:
    try:
        requests.packages.urllib3.contrib.pyopenssl.inject_into_urllib3()
    except AttributeError:
        # see https://github.com/certbot/certbot/issues/1883
        import urllib3.contrib.pyopenssl
        urllib3.contrib.pyopenssl.inject_into_urllib3()

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())

if os.environ.get('CF_DEBUG'):
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

CF_HEADERS = {}
CF_DEPLOY_HOOK = os.environ.get('CF_DEPLOY_HOOK', None)
DNS_SERVERS = False


def _has_dns_propagated(name, token):
    try:
        if DNS_SERVERS:
            custom_resolver = dns.resolver.Resolver()
            custom_resolver.nameservers = DNS_SERVERS
            dns_response = custom_resolver.query(name, 'TXT')
        else:
            dns_response = dns.resolver.query(name, 'TXT')

        for rdata in dns_response:
            if token in [b.decode('utf-8') for b in rdata.strings]:
                return True

    except dns.exception.DNSException as e:
        logger.debug(" + {0}. Retrying query...".format(e))

    return False


# https://api.cloudflare.com/#zone-list-zones
def _get_zone_id(domain):
    tld = get_tld('http://' + domain)
    url = "https://api.cloudflare.com/client/v4/zones?name={0}".format(tld)
    r = requests.get(url, headers=CF_HEADERS)
    r.raise_for_status()
    return r.json()['result'][0]['id']


# https://api.cloudflare.com/#dns-records-for-a-zone-dns-record-details
def _get_txt_record_id(zone_id, name, token):
    url = ("https://api.cloudflare.com/client/v4/zones/{0}/dns_records?"
           "type=TXT&name={1}&content={2}".format(zone_id, name, token))
    r = requests.get(url, headers=CF_HEADERS)
    r.raise_for_status()
    try:
        record_id = r.json()['result'][0]['id']
    except IndexError:
        logger.debug(" + Unable to locate record named {0}".format(name))
        return

    return record_id


# https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record
def create_txt_record(args):
    domain, challenge, token = args
    logger.debug(' + Creating TXT record: {0} => {1}'.format(domain, token))
    logger.debug(' + Challenge: {0}'.format(challenge))
    zone_id = _get_zone_id(domain)
    name = "{0}.{1}".format('_acme-challenge', domain)

    record_id = _get_txt_record_id(zone_id, name, token)
    if record_id:
        logger.debug(" + TXT record exists, skipping creation.")
        return

    url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records".format(
        zone_id)
    payload = {
        'type': 'TXT',
        'name': name,
        'content': token,
        'ttl': 120,
    }
    r = requests.post(url, headers=CF_HEADERS, json=payload)
    r.raise_for_status()
    record_id = r.json()['result']['id']
    logger.debug(" + TXT record created, CFID: {0}".format(record_id))


# https://api.cloudflare.com/#dns-records-for-a-zone-delete-dns-record
def delete_txt_record(args):
    domain, token = args[0], args[2]
    if not domain:
        logger.info(" + http_request() error in letsencrypt.sh?")
        return

    zone_id = _get_zone_id(domain)
    name = "{0}.{1}".format('_acme-challenge', domain)
    record_id = _get_txt_record_id(zone_id, name, token)

    if record_id:
        url = ("https://api.cloudflare.com/client/v4/zones/{0}/"
               "dns_records/{1}".format(zone_id, record_id))
        r = requests.delete(url, headers=CF_HEADERS)
        r.raise_for_status()
        logger.debug(" + Deleted TXT {0}, CFID {1}".format(name, record_id))
    else:
        logger.debug(" + No TXT {0} with token {1}".format(name, token))


def deploy_cert(args):
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem, timestamp = args
    # Convert all paths to absolute paths
    privkey_pem = os.path.abspath(privkey_pem)
    cert_pem = os.path.abspath(cert_pem)
    fullchain_pem = os.path.abspath(fullchain_pem)
    chain_pem = os.path.abspath(chain_pem)

    logger.debug(' + ssl_certificate: {0}'.format(fullchain_pem))
    logger.debug(' + ssl_certificate_key: {0}'.format(privkey_pem))

    # Run our deploy hook script/program if we have one
    if CF_DEPLOY_HOOK is not None:
        cmd_line = [CF_DEPLOY_HOOK, domain, privkey_pem, cert_pem,
                    fullchain_pem, chain_pem, timestamp]
        logger.debug(' + Executing CF_DEPLOY_HOOK command: {}'.format(
            ' '.join(cmd_line)))
        # NOTE: We don't care if it succeeds or fails
        subprocess.call(cmd_line)
    return


def unchanged_cert(args):
    return


def invalid_challenge(args):
    domain, result = args
    logger.debug(' + invalid_challenge for {0}'.format(domain))
    logger.debug(' + Full error: {0}'.format(result))
    return


def create_all_txt_records(args):
    X = 3
    for i in range(0, len(args), X):
        create_txt_record(args[i:i+X])
    # give it 10 seconds to settle down and avoid nxdomain caching
    logger.info(" + Settling down for 10s...")
    time.sleep(10)
    for i in range(0, len(args), X):
        domain, token = args[i], args[i+2]
        name = "{0}.{1}".format('_acme-challenge', domain)
        while(not _has_dns_propagated(name, token)):
            logger.info(" + DNS not propagated, waiting 30s...")
            time.sleep(30)


def delete_all_txt_records(args):
    X = 3
    for i in range(0, len(args), X):
        delete_txt_record(args[i:i+X])


def startup_hook(args):
    return


def exit_hook(args):
    return


def initialize_environment():
    """Validate and Initialize the environment"""
    missing_vars = {'CF_EMAIL', 'CF_KEY'} - set(os.environ)
    if missing_vars:
        logger.critical(" + Unable to locate Cloudflare credentials in the "
                        "environment!: {}".format(', '.join(missing_vars)))
        sys.exit(1)

    global CF_HEADERS
    CF_HEADERS = {
        'X-Auth-Email': os.environ['CF_EMAIL'],
        'X-Auth-Key': os.environ['CF_KEY'],
        'Content-Type': 'application/json',
    }

    if 'CF_DNS_SERVERS' in os.environ:
        global DNS_SERVERS
        DNS_SERVERS = os.environ['CF_DNS_SERVERS']
        # NOTE: Currently only supports whitespace separated values. Maybe it
        # should support comma separated values?
        DNS_SERVERS = DNS_SERVERS.split()


def main(argv):
    initialize_environment()

    ops = {
        'deploy_challenge': create_all_txt_records,
        'clean_challenge': delete_all_txt_records,
        'deploy_cert': deploy_cert,
        'unchanged_cert': unchanged_cert,
        'invalid_challenge': invalid_challenge,
        'startup_hook': startup_hook,
        'exit_hook': exit_hook
    }
    hook_name = argv[0]
    if hook_name not in ops:
        # Ignore unknown hook methods
        return

    hook_function = ops[hook_name]
    logger.info(" + CloudFlare hook executing: {0}".format(hook_name))
    hook_function(argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
