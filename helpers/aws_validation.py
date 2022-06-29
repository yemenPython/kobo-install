# -*- coding: utf-8 -*-
import base64
import datetime
import hashlib
import hmac
import json
from datetime import timedelta
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import requests


class AWSValidation:
    """
    A class to validate AWS credentials without using boto3 as a dependency.

    The structure and methods have been adapted from the AWS documentation:
    http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
    """

    METHOD = 'POST'
    SERVICE = 'sts'
    # REGION = 'us-east-1'
    HOST = 'sts.amazonaws.com'
    ENDPOINT = 'https://sts.amazonaws.com'
    REQUEST_PARAMETERS = 'Action=GetCallerIdentity&Version=2011-06-15'
    CANONICAL_URI = '/'
    SIGNED_HEADERS = 'host;x-amz-date'
    PAYLOAD_HASH = hashlib.sha256(''.encode()).hexdigest()
    ALGORITHM = 'AWS4-HMAC-SHA256'

    def __init__(
        self,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        aws_bucket_name: str,
        aws_s3_region_name: str,
    ):
        self.access_key = aws_access_key_id
        self.secret_key = aws_secret_access_key
        self.bucket_name = aws_bucket_name
        self.region = aws_s3_region_name

    @staticmethod
    def _sign(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    @classmethod
    def _get_signature_key(cls, key, date_stamp, region_name, service_name):
        k_date = cls._sign(('AWS4' + key).encode(), date_stamp)
        k_region = cls._sign(k_date, region_name)
        k_service = cls._sign(k_region, service_name)
        return cls._sign(k_service, 'aws4_request')

    def _get_request_url_and_headers(self):
        t = datetime.datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')

        canonical_querystring = self.REQUEST_PARAMETERS

        canonical_headers = '\n'.join(
            [
                'host:{host}'.format(host=self.HOST),
                'x-amz-date:{amzdate}'.format(amzdate=amzdate),
                '',
            ]
        )

        canonical_request = '\n'.join(
            [
                self.METHOD,
                self.CANONICAL_URI,
                canonical_querystring,
                canonical_headers,
                self.SIGNED_HEADERS,
                self.PAYLOAD_HASH,
            ]
        )

        credential_scope = '/'.join(
            [datestamp, self.region, self.SERVICE, 'aws4_request']
        )

        string_to_sign = '\n'.join(
            [
                self.ALGORITHM,
                amzdate,
                credential_scope,
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            ]
        )

        signing_key = self._get_signature_key(
            self.secret_key, datestamp, self.region, self.SERVICE
        )

        signature = hmac.new(
            signing_key, string_to_sign.encode(), hashlib.sha256
        ).hexdigest()

        authorization_header = (
            '{} Credential={}/{}, SignedHeaders={}, Signature={}'.format(
                self.ALGORITHM,
                self.access_key,
                credential_scope,
                self.SIGNED_HEADERS,
                signature,
            )
        )

        headers = {'x-amz-date': amzdate, 'Authorization': authorization_header}
        request_url = '?'.join([self.ENDPOINT, canonical_querystring])

        return request_url, headers

    # def validate_credentials(self):
    #     request_url, headers = self._get_request_url_and_headers()
    #     req = Request(request_url, headers=headers, method=self.METHOD)
    #
    #     try:
    #         with urlopen(req) as res:
    #             if res.status == 200:
    #                 return True
    #             else:
    #                 return False
    #     except HTTPError as e:
    #         return False

    def validate_credentials(self):
        now = datetime.date.today()
        expiration = now + timedelta(hours=36)
        amzdate = now.strftime('%Y%m%dT%H%M%SZ')
        datestamp = now.strftime('%Y%m%d')
        # now_2_str = str(int(now.timestamp()))
        policy = json.dumps({
            'expiration': expiration.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'conditions': [
                {'bucket': self.bucket_name},
                ['starts-with', '$key', '/kobo-install/'],
                {'acl': 'private'},
                {
                 'success_action_redirect': f'https://{self.bucket_name}.s3.amazonaws.com/kobo-install/test-{datestamp}.html'},
                ['starts-with', '$Content-Type', 'text/'],
                {'x-amz-meta-uuid': '14365123651274'},
                {'x-amz-server-side-encryption': 'AES256'},
                ['starts-with', '$x-amz-meta-tag', ''],
                {'x-amz-credential': f'{self.access_key}/{datestamp}/{self.region}/s3/aws4_request'},
                {'x-amz-algorithm': 'AWS4-HMAC-SHA256'},
                {'x-amz-date': amzdate}
            ]
        })
        base64_policy = base64.b64encode(policy.encode())
        signature_key = self._get_signature_key(
            self.secret_key, datestamp, self.region, 's3'
        )

        signature = hmac.new(
            signature_key, base64_policy, hashlib.sha256
        ).hexdigest()

        data = {
            'key': f'/kobo-install/test-{datestamp}.html',
            'acl': 'public-read',
            'success_action_redirect': f'https://{self.bucket_name}.s3.amazonaws.com/kobo-install/test-{datestamp}.html',
            'Content-Type': 'text/html',
            'x-amz-meta-uuid': '14365123651274',
            'x-amz-server-side-encryption': 'AES256',
            'x-amz-credential': f'{self.access_key}/{datestamp}/{self.region}/s3/aws4_request',
            'x-amz-algorithm': 'AWS4-HMAC-SHA256',
            'x-amz-meta-tag': '',
            'x-amz-date': amzdate,
            'Policy': base64_policy.decode(),
            'x-amz-signature': signature,
        }

        url = f'https://{self.bucket_name}.s3.amazonaws.com/'
        with open(f'/tmp/test-{datestamp}.html', 'wb') as f:
            f.write(b'<html><body>Hello World!</body></html>')

        with open(f'/tmp/test-{datestamp}.html', 'rb') as f:
            resp = requests.post(url, data=data, files={'file': f})
            print('RESP', resp.content, flush=True)

        return resp

        # When it works with request, let's try to make it work directly with urllib.
        #headers = {
        #    'Content-Type': 'multipart/form-data'
        #}
        #    data['file'] = f
        #    req = Request(url, headers=headers, data=data, method='POST')  # this will make the method "POST"
        #    with urlopen(req) as resp:
        #        print('RESP', resp, flush=True)
