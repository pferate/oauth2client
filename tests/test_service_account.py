# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Oauth2client tests.

Unit tests for service account credentials implemented using RSA.
"""

import datetime
import json
import os
import tempfile

import httplib2
import mock
import pytest
import rsa
from six import BytesIO

from oauth2client import crypt
from oauth2client.service_account import _JWTAccessCredentials
from oauth2client.service_account import SERVICE_ACCOUNT
from oauth2client.service_account import ServiceAccountCredentials
from .http_mock import HttpMockSequence


def data_filename(filename):
    return os.path.join(os.path.dirname(__file__), 'data', filename)


def datafile(filename):
    with open(data_filename(filename), 'rb') as file_obj:
        return file_obj.read()


@pytest.fixture()
def setup_service_account(request):
    crypt.configure_module()
    request.cls.client_id = '123'
    request.cls.service_account_email = 'dummy@google.com'
    request.cls.private_key_id = 'ABCDEF'
    request.cls.private_key = datafile('pem_from_pkcs12.pem')
    request.cls.scopes = ['dummy_scope']
    request.cls.signer = crypt.Signer.from_string(request.cls.private_key)
    request.cls.credentials = ServiceAccountCredentials(
        request.cls.service_account_email,
        request.cls.signer,
        private_key_id=request.cls.private_key_id,
        client_id=request.cls.client_id,
    )


@pytest.fixture()
def setup_jwt_access(request):
    request.cls.client_id = '123'
    request.cls.service_account_email = 'dummy@google.com'
    request.cls.private_key_id = 'ABCDEF'
    request.cls.private_key = datafile('pem_from_pkcs12.pem')
    request.cls.signer = crypt.Signer.from_string(request.cls.private_key)
    request.cls.url = 'https://test.url.com'
    request.cls.jwt = _JWTAccessCredentials(
        request.cls.service_account_email,
        request.cls.signer,
        private_key_id=request.cls.private_key_id,
        client_id=request.cls.client_id,
        additional_claims={'aud': request.cls.url})


@pytest.mark.usefixtures('setup_service_account')
class TestServiceAccountCredentials:

    def test__to_json_override(self):
        signer = object()
        creds = ServiceAccountCredentials('name@email.com',
                                          signer)
        assert creds._signer == signer
        # Serialize over-ridden data (unrelated to ``creds``).
        to_serialize = {'unrelated': 'data'}
        serialized_str = creds._to_json([], to_serialize.copy())
        serialized_data = json.loads(serialized_str)
        expected_serialized = {
            '_class': 'ServiceAccountCredentials',
            '_module': 'oauth2client.service_account',
            'token_expiry': None,
        }
        expected_serialized.update(to_serialize)
        assert serialized_data == expected_serialized

    def test_sign_blob(self):
        private_key_id, signature = self.credentials.sign_blob('Google')
        assert self.private_key_id == private_key_id

        pub_key = rsa.PublicKey.load_pkcs1_openssl_pem(
            datafile('publickey_openssl.pem'))

        assert rsa.pkcs1.verify(b'Google', signature, pub_key) is True

        with pytest.raises(rsa.pkcs1.VerificationError):
            rsa.pkcs1.verify(b'Orest', signature, pub_key)
        with pytest.raises(rsa.pkcs1.VerificationError):
            rsa.pkcs1.verify(b'Google', b'bad signature', pub_key)

    def test_service_account_email(self):
        assert self.service_account_email == \
            self.credentials.service_account_email

    @staticmethod
    def _from_json_keyfile_name_helper(payload, scopes=None,
                                       token_uri=None, revoke_uri=None):
        filehandle, filename = tempfile.mkstemp()
        os.close(filehandle)
        try:
            with open(filename, 'w') as file_obj:
                json.dump(payload, file_obj)
            return ServiceAccountCredentials.from_json_keyfile_name(
                filename, scopes=scopes, token_uri=token_uri,
                revoke_uri=revoke_uri)
        finally:
            os.remove(filename)

    @mock.patch('oauth2client.crypt.Signer.from_string',
                return_value=object())
    def test_from_json_keyfile_name_factory(self, signer_factory):
        client_id = 'id123'
        client_email = 'foo@bar.com'
        private_key_id = 'pkid456'
        private_key = 's3kr3tz'
        payload = {
            'type': SERVICE_ACCOUNT,
            'client_id': client_id,
            'client_email': client_email,
            'private_key_id': private_key_id,
            'private_key': private_key,
        }
        scopes = ['foo', 'bar']
        token_uri = 'baz'
        revoke_uri = 'qux'
        base_creds = self._from_json_keyfile_name_helper(
            payload, scopes=scopes, token_uri=token_uri, revoke_uri=revoke_uri)
        assert base_creds._signer == signer_factory.return_value
        signer_factory.assert_called_once_with(private_key)

        payload['token_uri'] = token_uri
        payload['revoke_uri'] = revoke_uri
        creds_with_uris_from_file = self._from_json_keyfile_name_helper(
            payload, scopes=scopes)
        for creds in (base_creds, creds_with_uris_from_file):
            assert isinstance(creds, ServiceAccountCredentials)
            assert creds.client_id == client_id
            assert creds._service_account_email == client_email
            assert creds._private_key_id == private_key_id
            assert creds._private_key_pkcs8_pem == private_key
            assert creds._scopes == ' '.join(scopes)
            assert creds.token_uri == token_uri
            assert creds.revoke_uri == revoke_uri

    def test_from_json_keyfile_name_factory_bad_type(self):
        type_ = 'bad-type'
        assert type_ != SERVICE_ACCOUNT
        payload = {'type': type_}
        with pytest.raises(ValueError):
            self._from_json_keyfile_name_helper(payload)

    def test_from_json_keyfile_name_factory_missing_field(self):
        payload = {
            'type': SERVICE_ACCOUNT,
            'client_id': 'my-client',
        }
        with pytest.raises(KeyError):
            self._from_json_keyfile_name_helper(payload)

    def _from_p12_keyfile_helper(self, private_key_password=None, scopes='',
                                 token_uri=None, revoke_uri=None):
        service_account_email = 'name@email.com'
        filename = data_filename('privatekey.p12')
        with open(filename, 'rb') as file_obj:
            key_contents = file_obj.read()
        creds_from_filename = ServiceAccountCredentials.from_p12_keyfile(
            service_account_email, filename,
            private_key_password=private_key_password,
            scopes=scopes, token_uri=token_uri, revoke_uri=revoke_uri)
        creds_from_file_contents = (
            ServiceAccountCredentials.from_p12_keyfile_buffer(
                service_account_email, BytesIO(key_contents),
                private_key_password=private_key_password,
                scopes=scopes, token_uri=token_uri, revoke_uri=revoke_uri))
        for creds in (creds_from_filename, creds_from_file_contents):
            assert isinstance(creds, ServiceAccountCredentials)
            assert creds.client_id is None
            assert creds._service_account_email == service_account_email
            assert creds._private_key_id is None
            assert creds._private_key_pkcs8_pem is None
            assert creds._private_key_pkcs12 == key_contents
            if private_key_password is not None:
                assert creds._private_key_password == private_key_password
            assert creds._scopes == ' '.join(scopes)
            assert creds.token_uri == token_uri
            assert creds.revoke_uri == revoke_uri

    def _p12_not_implemented_helper(self):
        service_account_email = 'name@email.com'
        filename = data_filename('privatekey.p12')
        with pytest.raises(NotImplementedError):
            ServiceAccountCredentials.from_p12_keyfile(
                service_account_email, filename)

    @mock.patch('oauth2client.crypt.Signer', new=crypt.PyCryptoSigner)
    def test_from_p12_keyfile_with_pycrypto(self):
        self._p12_not_implemented_helper()

    @mock.patch('oauth2client.crypt.Signer', new=crypt.RsaSigner)
    def test_from_p12_keyfile_with_rsa(self):
        self._p12_not_implemented_helper()

    def test_from_p12_keyfile_defaults(self):
        self._from_p12_keyfile_helper()

    def test_from_p12_keyfile_explicit(self):
        password = 'notasecret'
        self._from_p12_keyfile_helper(private_key_password=password,
                                      scopes=['foo', 'bar'],
                                      token_uri='baz', revoke_uri='qux')

    def test_create_scoped_required_without_scopes(self):
        assert self.credentials.create_scoped_required() is True

    def test_create_scoped_required_with_scopes(self):
        signer = object()
        self.credentials = ServiceAccountCredentials(
            self.service_account_email,
            signer,
            scopes=self.scopes,
            private_key_id=self.private_key_id,
            client_id=self.client_id,
        )
        assert self.credentials.create_scoped_required() is False

    def test_create_scoped(self):
        new_credentials = self.credentials.create_scoped(self.scopes)
        assert self.credentials != new_credentials
        assert isinstance(new_credentials, ServiceAccountCredentials)
        assert 'dummy_scope' == new_credentials._scopes

    def test_create_delegated(self):
        signer = object()
        sub = 'foo@email.com'
        creds = ServiceAccountCredentials('name@email.com', signer)
        assert 'sub' not in creds._kwargs
        delegated_creds = creds.create_delegated(sub)
        assert delegated_creds._kwargs['sub'] == sub
        # Make sure the original is unchanged.
        assert 'sub' not in creds._kwargs

    def test_create_delegated_existing_sub(self):
        signer = object()
        sub1 = 'existing@email.com'
        sub2 = 'new@email.com'
        creds = ServiceAccountCredentials('name@email.com', signer, sub=sub1)
        assert creds._kwargs['sub'] == sub1
        delegated_creds = creds.create_delegated(sub2)
        assert delegated_creds._kwargs['sub'] == sub2
        # Make sure the original is unchanged.
        assert creds._kwargs['sub'] == sub1

    @mock.patch('oauth2client.client._UTCNOW')
    def test_access_token(self, utcnow):
        # Configure the patch.
        seconds = 11
        NOW = datetime.datetime(1992, 12, 31, second=seconds)
        utcnow.return_value = NOW

        # Create a custom credentials with a mock signer.
        signer = mock.MagicMock()
        signed_value = b'signed-content'
        signer.sign = mock.MagicMock(name='sign',
                                     return_value=signed_value)
        credentials = ServiceAccountCredentials(
            self.service_account_email,
            signer,
            private_key_id=self.private_key_id,
            client_id=self.client_id,
        )

        # Begin testing.
        lifetime = 2  # number of seconds in which the token expires
        EXPIRY_TIME = datetime.datetime(1992, 12, 31,
                                        second=seconds + lifetime)

        token1 = u'first_token'
        token_response_first = {
            'access_token': token1,
            'expires_in': lifetime,
        }
        token2 = u'second_token'
        token_response_second = {
            'access_token': token2,
            'expires_in': lifetime,
        }
        http = HttpMockSequence([
            ({'status': '200'},
             json.dumps(token_response_first).encode('utf-8')),
            ({'status': '200'},
             json.dumps(token_response_second).encode('utf-8')),
        ])

        # Get Access Token, First attempt.
        assert credentials.access_token is None
        assert credentials.access_token_expired is False
        assert credentials.token_expiry is None
        token = credentials.get_access_token(http=http)
        assert credentials.token_expiry == EXPIRY_TIME
        assert token1 == token.access_token
        assert lifetime == token.expires_in
        assert token_response_first == credentials.token_response
        # Two utcnow calls are expected:
        # - get_access_token() -> _do_refresh_request (setting expires in)
        # - get_access_token() -> _expires_in()
        expected_utcnow_calls = [mock.call()] * 2
        assert expected_utcnow_calls == utcnow.mock_calls
        # One call to sign() expected: Actual refresh was needed.
        assert len(signer.sign.mock_calls) == 1

        # Get Access Token, Second Attempt (not expired)
        assert credentials.access_token == token1
        assert credentials.access_token_expired is False
        token = credentials.get_access_token(http=http)
        # Make sure no refresh occurred since the token was not expired.
        assert token1 == token.access_token
        assert lifetime == token.expires_in
        assert token_response_first == credentials.token_response
        # Three more utcnow calls are expected:
        # - access_token_expired
        # - get_access_token() -> access_token_expired
        # - get_access_token -> _expires_in
        expected_utcnow_calls = [mock.call()] * (2 + 3)
        assert expected_utcnow_calls == utcnow.mock_calls
        # No call to sign() expected: the token was not expired.
        assert len(signer.sign.mock_calls) == 1 + 0

        # Get Access Token, Third Attempt (force expiration)
        assert credentials.access_token == token1
        credentials.token_expiry = NOW  # Manually force expiry.
        assert credentials.access_token_expired is True
        token = credentials.get_access_token(http=http)
        # Make sure refresh occurred since the token was not expired.
        assert token2 == token.access_token
        assert lifetime == token.expires_in
        assert credentials.access_token_expired is False
        assert token_response_second == credentials.token_response
        # Five more utcnow calls are expected:
        # - access_token_expired
        # - get_access_token -> access_token_expired
        # - get_access_token -> _do_refresh_request
        # - get_access_token -> _expires_in
        # - access_token_expired
        expected_utcnow_calls = [mock.call()] * (2 + 3 + 5)
        assert expected_utcnow_calls == utcnow.mock_calls
        # One more call to sign() expected: Actual refresh was needed.
        assert len(signer.sign.mock_calls) == 1 + 0 + 1

        assert credentials.access_token == token2

TOKEN_LIFE = _JWTAccessCredentials._MAX_TOKEN_LIFETIME_SECS
T1 = 42
T1_DATE = datetime.datetime(1970, 1, 1, second=T1)
T1_EXPIRY = T1 + TOKEN_LIFE
T1_EXPIRY_DATE = T1_DATE + datetime.timedelta(seconds=TOKEN_LIFE)

T2 = T1 + 100
T2_DATE = T1_DATE + datetime.timedelta(seconds=100)
T2_EXPIRY = T2 + TOKEN_LIFE
T2_EXPIRY_DATE = T2_DATE + datetime.timedelta(seconds=TOKEN_LIFE)

T3 = T1 + TOKEN_LIFE + 1
T3_DATE = T1_DATE + datetime.timedelta(seconds=TOKEN_LIFE + 1)
T3_EXPIRY = T3 + TOKEN_LIFE
T3_EXPIRY_DATE = T3_DATE + datetime.timedelta(seconds=TOKEN_LIFE)


@pytest.mark.usefixtures('setup_jwt_access')
class TestJWTAccessCredentials:

    @mock.patch('oauth2client.service_account._UTCNOW')
    @mock.patch('oauth2client.client._UTCNOW')
    @mock.patch('time.time')
    def test_get_access_token_no_claims(self, time, client_utcnow, utcnow):
        utcnow.return_value = T1_DATE
        client_utcnow.return_value = T1_DATE
        time.return_value = T1

        token_info = self.jwt.get_access_token()
        payload = crypt.verify_signed_jwt_with_certs(
            token_info.access_token,
            {'key': datafile('public_cert.pem')}, audience=self.url)
        assert payload['iss'] == self.service_account_email
        assert payload['sub'] == self.service_account_email
        assert payload['iat'] == T1
        assert payload['exp'] == T1_EXPIRY
        assert token_info.expires_in == T1_EXPIRY - T1

        # Verify that we vend the same token after 100 seconds
        utcnow.return_value = T2_DATE
        client_utcnow.return_value = T2_DATE
        token_info = self.jwt.get_access_token()
        payload = crypt.verify_signed_jwt_with_certs(
            token_info.access_token,
            {'key': datafile('public_cert.pem')}, audience=self.url)
        assert payload['iat'] == T1
        assert payload['exp'] == T1_EXPIRY
        assert token_info.expires_in == T1_EXPIRY - T2

        # Verify that we vend a new token after _MAX_TOKEN_LIFETIME_SECS
        utcnow.return_value = T3_DATE
        client_utcnow.return_value = T3_DATE
        time.return_value = T3
        token_info = self.jwt.get_access_token()
        payload = crypt.verify_signed_jwt_with_certs(
            token_info.access_token,
            {'key': datafile('public_cert.pem')}, audience=self.url)
        expires_in = token_info.expires_in
        assert payload['iat'] == T3
        assert payload['exp'] == T3_EXPIRY
        assert expires_in == T3_EXPIRY - T3

    @mock.patch('oauth2client.service_account._UTCNOW')
    @mock.patch('time.time')
    def test_get_access_token_additional_claims(self, time, utcnow):
        utcnow.return_value = T1_DATE
        time.return_value = T1

        token_info = self.jwt.get_access_token(
            additional_claims={'aud': 'https://test2.url.com',
                               'sub': 'dummy2@google.com'
                               })
        payload = crypt.verify_signed_jwt_with_certs(
            token_info.access_token,
            {'key': datafile('public_cert.pem')},
            audience='https://test2.url.com')
        expires_in = token_info.expires_in
        assert payload['iss'] == self.service_account_email
        assert payload['sub'] == 'dummy2@google.com'
        assert payload['iat'] == T1
        assert payload['exp'] == T1_EXPIRY
        assert expires_in == T1_EXPIRY - T1

    def test_revoke(self):
        self.jwt.revoke(None)

    def test_create_scoped_required(self):
        assert self.jwt.create_scoped_required() is True

    def test_create_scoped(self):
        self.jwt._private_key_pkcs12 = ''
        self.jwt._private_key_password = ''

        new_credentials = self.jwt.create_scoped('dummy_scope')
        assert self.jwt != new_credentials
        assert isinstance(new_credentials, ServiceAccountCredentials)
        assert 'dummy_scope' == new_credentials._scopes

    @mock.patch('oauth2client.service_account._UTCNOW')
    @mock.patch('oauth2client.client._UTCNOW')
    @mock.patch('time.time')
    def test_authorize_success(self, time, client_utcnow, utcnow):
        utcnow.return_value = T1_DATE
        client_utcnow.return_value = T1_DATE
        time.return_value = T1

        def mock_request(uri, method='GET', body=None, headers=None,
                         redirections=0, connection_type=None):
            assert uri == self.url
            bearer, token = headers[b'Authorization'].split()
            payload = crypt.verify_signed_jwt_with_certs(
                token,
                {'key': datafile('public_cert.pem')},
                audience=self.url)
            assert payload['iss'] == self.service_account_email
            assert payload['sub'] == self.service_account_email
            assert payload['iat'] == T1
            assert payload['exp'] == T1_EXPIRY
            assert uri == self.url
            assert bearer == b'Bearer'
            return (httplib2.Response({'status': '200'}), b'')

        h = httplib2.Http()
        h.request = mock_request
        self.jwt.authorize(h)
        h.request(self.url)

        # Ensure we use the cached token
        utcnow.return_value = T2_DATE
        client_utcnow.return_value = T2_DATE
        h.request(self.url)

    @mock.patch('oauth2client.service_account._UTCNOW')
    @mock.patch('oauth2client.client._UTCNOW')
    @mock.patch('time.time')
    def test_authorize_no_aud(self, time, client_utcnow, utcnow):
        utcnow.return_value = T1_DATE
        client_utcnow.return_value = T1_DATE
        time.return_value = T1

        jwt = _JWTAccessCredentials(self.service_account_email,
                                    self.signer,
                                    private_key_id=self.private_key_id,
                                    client_id=self.client_id)

        def mock_request(uri, method='GET', body=None, headers=None,
                         redirections=0, connection_type=None):
            assert uri == self.url
            bearer, token = headers[b'Authorization'].split()
            payload = crypt.verify_signed_jwt_with_certs(
                token,
                {'key': datafile('public_cert.pem')},
                audience=self.url)
            assert payload['iss'] == self.service_account_email
            assert payload['sub'] == self.service_account_email
            assert payload['iat'] == T1
            assert payload['exp'] == T1_EXPIRY
            assert uri == self.url
            assert bearer == b'Bearer'
            return (httplib2.Response({'status': '200'}), b'')

        h = httplib2.Http()
        h.request = mock_request
        jwt.authorize(h)
        h.request(self.url)

        # Ensure we do not cache the token
        assert jwt.access_token is None

    @mock.patch('oauth2client.service_account._UTCNOW')
    def test_authorize_stale_token(self, utcnow):
        utcnow.return_value = T1_DATE
        # Create an initial token
        h = HttpMockSequence([({'status': '200'}, b''),
                              ({'status': '200'}, b'')])
        self.jwt.authorize(h)
        h.request(self.url)
        token_1 = self.jwt.access_token

        # Expire the token
        utcnow.return_value = T3_DATE
        h.request(self.url)
        token_2 = self.jwt.access_token
        assert self.jwt.token_expiry == T3_EXPIRY_DATE
        assert token_1 != token_2

    @mock.patch('oauth2client.service_account._UTCNOW')
    def test_authorize_401(self, utcnow):
        utcnow.return_value = T1_DATE

        h = HttpMockSequence([
            ({'status': '200'}, b''),
            ({'status': '401'}, b''),
            ({'status': '200'}, b'')])
        self.jwt.authorize(h)
        h.request(self.url)
        token_1 = self.jwt.access_token

        utcnow.return_value = T2_DATE
        assert h.request(self.url)[0].status == 200
        token_2 = self.jwt.access_token
        # Check the 401 forced a new token
        assert token_1 != token_2

    @mock.patch('oauth2client.service_account._UTCNOW')
    def test_refresh(self, utcnow):
        utcnow.return_value = T1_DATE
        token_1 = self.jwt.access_token

        utcnow.return_value = T2_DATE
        self.jwt.refresh(None)
        token_2 = self.jwt.access_token
        assert self.jwt.token_expiry == T2_EXPIRY_DATE
        assert token_1 != token_2
