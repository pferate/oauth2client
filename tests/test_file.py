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

"""Oauth2client.file tests

Unit tests for oauth2client.file
"""

import copy
import datetime
import json
import os
import pickle
import stat
import tempfile

import pytest
import six
from six.moves import http_client

from oauth2client import file
from oauth2client.client import AccessTokenCredentials
from oauth2client.client import OAuth2Credentials
from .http_mock import HttpMockSequence

try:
    # Python2
    from future_builtins import oct
except:  # pragma: NO COVER
    pass

__author__ = 'jcgregorio@google.com (Joe Gregorio)'


@pytest.fixture(scope='function')
def temp_file(request):
    _filehandle, filename = tempfile.mkstemp('oauth2client_test.data')
    os.close(_filehandle)
    request.cls.temp_filename = filename

    def fin():
        try:
            os.unlink(request.cls.temp_filename)
        except OSError:
            pass
    request.addfinalizer(fin)


@pytest.mark.usefixtures('temp_file')
class TestOAuth2ClientFile:

    def _create_test_credentials(self, client_id='some_client_id',
                                 expiration=None):
        access_token = 'foo'
        client_secret = 'cOuDdkfjxxnv+'
        refresh_token = '1/0/a.df219fjls0'
        token_expiry = expiration or datetime.datetime.utcnow()
        token_uri = 'https://www.google.com/accounts/o8/oauth2/token'
        user_agent = 'refresh_checker/1.0'

        credentials = OAuth2Credentials(
            access_token, client_id, client_secret,
            refresh_token, token_expiry, token_uri,
            user_agent)
        return credentials

    def test_non_existent_file_storage(self):
        s = file.Storage(self.temp_filename)
        credentials = s.get()
        assert credentials is None

    @pytest.mark.skipif(not hasattr(os, 'symlink'),
                        reason='No symlink available')
    def test_no_sym_link_credentials(self):
        symfilename = self.temp_filename + '.sym'
        os.symlink(self.temp_filename, symfilename)
        s = file.Storage(symfilename)
        try:
            with pytest.raises(file.CredentialsFileSymbolicLinkError):
                s.get()
        finally:
            os.unlink(symfilename)

    def test_pickle_and_json_interop(self):
        # Write a file with a pickled OAuth2Credentials.
        credentials = self._create_test_credentials()

        f = open(self.temp_filename, 'wb')
        pickle.dump(credentials, f)
        f.close()

        # Storage should be not be able to read that object, as the capability
        # to read and write credentials as pickled objects has been removed.
        s = file.Storage(self.temp_filename)
        read_credentials = s.get()
        assert read_credentials is None

        # Now write it back out and confirm it has been rewritten as JSON
        s.put(credentials)
        with open(self.temp_filename) as f:
            data = json.load(f)

        assert data['access_token'] == 'foo'
        assert data['_class'] == 'OAuth2Credentials'
        assert data['_module'] == OAuth2Credentials.__module__

    def test_token_refresh_store_expired(self):
        expiration = (datetime.datetime.utcnow() -
                      datetime.timedelta(minutes=15))
        credentials = self._create_test_credentials(expiration=expiration)

        s = file.Storage(self.temp_filename)
        s.put(credentials)
        credentials = s.get()
        new_cred = copy.copy(credentials)
        new_cred.access_token = 'bar'
        s.put(new_cred)

        access_token = '1/3w'
        token_response = {'access_token': access_token, 'expires_in': 3600}
        http = HttpMockSequence([
            ({'status': '200'}, json.dumps(token_response).encode('utf-8')),
        ])

        credentials._refresh(http.request)
        assert credentials.access_token == access_token

    def test_token_refresh_store_expires_soon(self):
        # Tests the case where an access token that is valid when it is read
        # from the store expires before the original request succeeds.
        expiration = (datetime.datetime.utcnow() +
                      datetime.timedelta(minutes=15))
        credentials = self._create_test_credentials(expiration=expiration)

        s = file.Storage(self.temp_filename)
        s.put(credentials)
        credentials = s.get()
        new_cred = copy.copy(credentials)
        new_cred.access_token = 'bar'
        s.put(new_cred)

        access_token = '1/3w'
        token_response = {'access_token': access_token, 'expires_in': 3600}
        http = HttpMockSequence([
            ({'status': str(int(http_client.UNAUTHORIZED))},
             b'Initial token expired'),
            ({'status': str(int(http_client.UNAUTHORIZED))},
             b'Store token expired'),
            ({'status': str(int(http_client.OK))},
             json.dumps(token_response).encode('utf-8')),
            ({'status': str(int(http_client.OK))},
             b'Valid response to original request')
        ])

        credentials.authorize(http)
        http.request('https://example.com')
        assert credentials.access_token == access_token

    def test_token_refresh_good_store(self):
        expiration = (datetime.datetime.utcnow() +
                      datetime.timedelta(minutes=15))
        credentials = self._create_test_credentials(expiration=expiration)

        s = file.Storage(self.temp_filename)
        s.put(credentials)
        credentials = s.get()
        new_cred = copy.copy(credentials)
        new_cred.access_token = 'bar'
        s.put(new_cred)

        credentials._refresh(None)
        assert credentials.access_token == 'bar'

    def test_token_refresh_stream_body(self):
        expiration = (datetime.datetime.utcnow() +
                      datetime.timedelta(minutes=15))
        credentials = self._create_test_credentials(expiration=expiration)

        s = file.Storage(self.temp_filename)
        s.put(credentials)
        credentials = s.get()
        new_cred = copy.copy(credentials)
        new_cred.access_token = 'bar'
        s.put(new_cred)

        valid_access_token = '1/3w'
        token_response = {'access_token': valid_access_token,
                          'expires_in': 3600}
        http = HttpMockSequence([
            ({'status': str(int(http_client.UNAUTHORIZED))},
             b'Initial token expired'),
            ({'status': str(int(http_client.UNAUTHORIZED))},
             b'Store token expired'),
            ({'status': str(int(http_client.OK))},
             json.dumps(token_response).encode('utf-8')),
            ({'status': str(int(http_client.OK))}, 'echo_request_body')
        ])

        body = six.StringIO('streaming body')

        credentials.authorize(http)
        _, content = http.request('https://example.com', body=body)
        assert content == 'streaming body'
        assert credentials.access_token == valid_access_token

    def test_credentials_delete(self):
        credentials = self._create_test_credentials()

        s = file.Storage(self.temp_filename)
        s.put(credentials)
        credentials = s.get()
        assert credentials is not None
        s.delete()
        credentials = s.get()
        assert credentials is None

    def test_access_token_credentials(self):
        access_token = 'foo'
        user_agent = 'refresh_checker/1.0'

        credentials = AccessTokenCredentials(access_token, user_agent)

        s = file.Storage(self.temp_filename)
        credentials = s.put(credentials)
        credentials = s.get()

        assert credentials is not None
        assert 'foo' == credentials.access_token

        assert os.path.exists(self.temp_filename)

        if os.name == 'posix':  # pragma: NO COVER
            mode = os.stat(self.temp_filename).st_mode
            assert '0o600' == oct(stat.S_IMODE(mode))
            assert 0o600 == stat.S_IMODE(mode)
