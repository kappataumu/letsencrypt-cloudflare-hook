#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from builtins import str

from future import standard_library
standard_library.install_aliases()

import dns.exception
import dns.resolver
import logging
import os
import requests
import sys
import time

from tld import get_tld

# Enable verified HTTPS requests on older Pythons
# http://urllib3.readthedocs.org/en/latest/security.html
if sys.version_info[0] == 2:
    requests.packages.urllib3.contrib.pyopenssl.inject_into_urllib3()

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

try:
    CF_HEADERS = {
        'X-Auth-Email': os.environ['CF_EMAIL'],
        'X-Auth-Key'  : os.environ['CF_KEY'],
        'Content-Type': 'application/json',
    }
except KeyError:
    logger.error(" + Unable to locate Cloudflare credentials in environment!")
    sys.exit(1)


def _has_dns_propagated(name, token):
    txt_records = []
    try:
        dns_response = dns.resolver.query(name, 'TXT')
        for rdata in dns_response:
            for txt_record in rdata.strings:
                txt_records.append(txt_record)
    except dns.exception.DNSException as error:
        return False

    for txt_record in txt_records:
        if txt_record == token:
            return True

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
    url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records?type=TXT&name={1}&content={2}".format(zone_id, name, token)
    r = requests.get(url, headers=CF_HEADERS)
    r.raise_for_status()
    try:
        record_id = r.json()['result'][0]['id']
    except IndexError:
        logger.info(" + Unable to locate record named {0}".format(name))
        return

    return record_id


# https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record
def create_txt_record(args):
    domain, token = args[0], args[2]
    zone_id = _get_zone_id(domain)
    name = "{0}.{1}".format('_acme-challenge', domain)
    url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records".format(zone_id)
    payload = {
        'type': 'TXT',
        'name': name,
        'content': token,
        'ttl': 1,
    }
    r = requests.post(url, headers=CF_HEADERS, json=payload)
    r.raise_for_status()
    record_id = r.json()['result']['id']
    logger.debug("+ TXT record created, ID: {0}".format(record_id))

    # give it 10 seconds to settle down and avoid nxdomain caching
    logger.info(" + Settling down for 10s...")
    time.sleep(10)

    while(_has_dns_propagated(name, token) == False):
        logger.info(" + DNS not propagated, waiting 30s...")
        time.sleep(30)


# https://api.cloudflare.com/#dns-records-for-a-zone-delete-dns-record
def delete_txt_record(args):
    domain, token = args[0], args[2]
    if not domain:
        logger.info(" + http_request() error in letsencrypt.sh?")
        return

    zone_id = _get_zone_id(domain)
    name = "{0}.{1}".format('_acme-challenge', domain)
    record_id = _get_txt_record_id(zone_id, name, token)

    logger.debug(" + Deleting TXT record name: {0}".format(name))
    url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records/{1}".format(zone_id, record_id)
    r = requests.delete(url, headers=CF_HEADERS)
    r.raise_for_status()


def deploy_cert(args):
    domain, privkey_pem, cert_pem, fullchain_pem = args
    logger.info(' + ssl_certificate: {0}'.format(fullchain_pem))
    logger.info(' + ssl_certificate_key: {0}'.format(privkey_pem))
    return


def main(argv):
    ops = {
        'deploy_challenge': create_txt_record,
        'clean_challenge' : delete_txt_record,
        'deploy_cert'     : deploy_cert,
    }
    logger.info(" + CloudFlare hook executing: {0}".format(argv[0]))
    ops[argv[0]](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
