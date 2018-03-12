from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import collections
import json
import os
import re

import mock
import requests_mock
from six.moves.urllib import parse as urlparse
import testtools

# Setup dummy environment variables so 'hook' can be imported
os.environ['CF_EMAIL'] = "email@example'com"
os.environ['CF_KEY'] = "a_cloudflare_example_key"

import hook  # noqa


CF_API_HOST = "api.cloudflare.com"
CF_API_PATH = "/client/v4"
CF_API_SCHEME = "https"


class TestBase(testtools.TestCase):

    def setUp(self):
        super(TestBase, self).setUp()
        self.expected_headers = {
            'Content-Type': 'application/json',
            'X-Auth-Email': "email@example'com",
            'X-Auth-Key': 'a_cloudflare_example_key',
        }


ExpectedRequestsData = collections.namedtuple(
    'ExpectedRequestsData', ['method', 'path', 'query', 'json_body'])


@requests_mock.Mocker()
class TestRequestCallers(TestBase):

    def setUp(self):
        super(TestRequestCallers, self).setUp()
        self.matcher = re.compile(r'^https://api.cloudflare.com/client/v4/')

    def _validate_requests_calls(self, mock_request, expected_data_list):
        """Helper function to check values of calls to requests"""
        # Make sure our call count matches up with what we expect
        self.assertEqual(len(expected_data_list), mock_request.call_count)
        for index, expected_data in enumerate(expected_data_list):
            # Provide a bit more info if a test fails
            expected_str = "Info: {}".format(expected_data)
            request_obj = mock_request.request_history[index]
            parsed_url = urlparse.urlparse(request_obj.url)
            self.assertEqual(expected_data.method.upper(),
                             request_obj.method)
            self.assertEqual(CF_API_SCHEME, parsed_url.scheme)
            self.assertEqual(CF_API_HOST, parsed_url.netloc)
            self.assertEqual(
                "{}/{}".format(CF_API_PATH, expected_data.path),
                parsed_url.path)
            self.assertEqual(expected_data.query, request_obj.qs,
                             expected_str)
            if expected_data.json_body is not None:
                self.assertEqual(expected_data.json_body,
                                 json.loads(request_obj._request.body),
                                 expected_str)

    def test__get_zone_id(self, mock_request):
        expected_list = [
            ExpectedRequestsData(
                method='get',
                path="zones",
                query={'name': ['example.com']},
                json_body=None,
            ),
        ]
        mock_request.get(self.matcher, text=ZONE_RESPONSE)

        result = hook._get_zone_id("example.com")

        expected_id = "023e105f4ecef8ad9ca31a8372d0c353"
        self.assertEqual(expected_id, result)

        self._validate_requests_calls(mock_request=mock_request,
                                      expected_data_list=expected_list)

    def test__get_txt_record_id_found(self, mock_request):
        expected_list = [
            ExpectedRequestsData(
                method='get',
                path='zones/ZONE_ID/dns_records',
                query={'content': ['token'], 'name': ['example.com'],
                       'type': ['txt']},
                json_body=None,
            ),
        ]
        mock_request.get(self.matcher, text=DNS_RECORDS_RESPONSE)

        result = hook._get_txt_record_id("ZONE_ID", "example.com", "TOKEN")

        expected_id = "372e67954025e0ba6aaa6d586b9e0b59"
        self.assertEqual(expected_id, result)

        self._validate_requests_calls(mock_request=mock_request,
                                      expected_data_list=expected_list)

    def test__get_txt_record_id_not_found(self, mock_request):
        expected_list = [
            ExpectedRequestsData(
                method='get',
                path="zones/ZONE_ID/dns_records",
                query={'content': ['token'], 'name': ['example.com'],
                       'type': ['txt']},
                json_body=None,
            ),
        ]
        mock_request.get(self.matcher, text=DNS_RECORDS_RESPONSE_NOT_FOUND)

        result = hook._get_txt_record_id("ZONE_ID", "example.com", "TOKEN")

        self.assertEqual(None, result)
        self._validate_requests_calls(mock_request=mock_request,
                                      expected_data_list=expected_list)

    @mock.patch.object(hook, '_get_txt_record_id',
                       lambda zone_id, name, token: None)
    @mock.patch.object(hook, '_get_txt_record_id',
                       lambda zone_id, name, token: None)
    def test_create_txt_record(self, mock_request):
        expected_list = [
            ExpectedRequestsData(
                method='get',
                path="zones",
                query={'name': ['example.com']},
                json_body=None,
            ),
            ExpectedRequestsData(
                method='post',
                path=("zones/023e105f4ecef8ad9ca31a8372d0c353/"
                      "dns_records"),
                query={},
                json_body={'content': 'TOKEN', 'type': 'TXT', 'ttl': 120,
                           'name': '_acme-challenge.example.com',
                           },
            )
        ]
        mock_request.get(self.matcher, text=ZONE_RESPONSE)
        mock_request.post(self.matcher, text=CREATE_DNS_RECORD_RESPONSE)

        args = ['example.com', 'CHALLENGE', 'TOKEN']
        result = hook.create_txt_record(args)

        self._validate_requests_calls(mock_request=mock_request,
                                      expected_data_list=expected_list)

        self.assertEqual(None, result)


# Sample responses

ZONE_RESPONSE = """
{
    "success": true,
    "errors": [
      {}
    ],
    "messages": [
      {}
    ],
    "result": [
      {
        "id": "023e105f4ecef8ad9ca31a8372d0c353",
        "name": "example.com",
        "development_mode": 7200,
        "original_name_servers": [
          "ns1.originaldnshost.com",
          "ns2.originaldnshost.com"
        ],
        "original_registrar": "GoDaddy",
        "original_dnshost": "NameCheap",
        "created_on": "2014-01-01T05:20:00.12345Z",
        "modified_on": "2014-01-01T05:20:00.12345Z",
        "owner": {
          "id": "7c5dae5552338874e5053f2534d2767a",
          "email": "user@example.com",
          "owner_type": "user"
        },
        "permissions": [
          "#zone:read",
          "#zone:edit"
        ],
        "plan": {
          "id": "e592fd9519420ba7405e1307bff33214",
          "name": "Pro Plan",
          "price": 20,
          "currency": "USD",
          "frequency": "monthly",
          "legacy_id": "pro",
          "is_subscribed": true,
          "can_subscribe": true
        },
        "plan_pending": {
          "id": "e592fd9519420ba7405e1307bff33214",
          "name": "Pro Plan",
          "price": 20,
          "currency": "USD",
          "frequency": "monthly",
          "legacy_id": "pro",
          "is_subscribed": true,
          "can_subscribe": true
        },
        "status": "active",
        "paused": false,
        "type": "full",
        "name_servers": [
          "tony.ns.cloudflare.com",
          "woz.ns.cloudflare.com"
        ]
      }
    ],
    "result_info": {
      "page": 1,
      "per_page": 20,
      "count": 1,
      "total_count": 2000
    }
}
"""

DNS_RECORDS_RESPONSE = """
{
    "success": true,
    "errors": [],
    "messages": [],
    "result": [
        {
            "id": "372e67954025e0ba6aaa6d586b9e0b59",
            "type": "TXT",
            "name": "_acme-challenge.test.example.com",
            "content": "WyIlYaKOp62zaDu_JDKwfXVCnr4q4ntYtmkZ3y5BF2w",
            "proxiable": false,
            "proxied": false,
            "ttl": 120,
            "locked": false,
            "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
            "zone_name": "example.com",
            "created_on": "2014-01-01T05:20:00.12345Z",
            "modified_on": "2014-01-01T05:20:00.12345Z",
            "data": {}
        }
    ],
    "result_info": {
      "page": 1,
      "per_page": 20,
      "count": 1,
      "total_count": 2000
    }
}
"""

DNS_RECORDS_RESPONSE_NOT_FOUND = """
{
    "success": true,
    "errors": [],
    "messages": [],
    "result": [],
    "result_info": {
      "page": 1,
      "per_page": 20,
      "count": 1,
      "total_count": 2000
    }
}
"""

CREATE_DNS_RECORD_RESPONSE = """
{
  "success": true,
  "errors": [
    {}
  ],
  "messages": [
    {}
  ],
  "result": {
    "id": "372e67954025e0ba6aaa6d586b9e0b59",
    "type": "A",
    "name": "example.com",
    "content": "1.2.3.4",
    "proxiable": true,
    "proxied": false,
    "ttl": 120,
    "locked": false,
    "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
    "zone_name": "example.com",
    "created_on": "2014-01-01T05:20:00.12345Z",
    "modified_on": "2014-01-01T05:20:00.12345Z",
    "data": {}
  }
}
"""
