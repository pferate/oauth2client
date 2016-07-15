# Copyright 2015 Google Inc. All rights reserved.
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

"""Unit tests for oauth2client.multistore_file."""

import datetime
import errno
import os
import stat
import tempfile

import mock
import pytest

from oauth2client import util
from oauth2client.client import OAuth2Credentials
from oauth2client.contrib import locked_file
from oauth2client.contrib import multistore_file


class _MockLockedFile(object):

    def __init__(self, filename_str, error_class, error_code):
        self.filename_str = filename_str
        self.error_class = error_class
        self.error_code = error_code
        self.open_and_lock_called = False

    def open_and_lock(self):
        self.open_and_lock_called = True
        raise self.error_class(self.error_code, '')

    def is_locked(self):
        return False

    def filename(self):
        return self.filename_str


class Test__dict_to_tuple_key:

    def test_key_conversions(self):
        key1, val1 = 'somekey', 'some value'
        key2, val2 = 'another', 'something else'
        key3, val3 = 'onemore', 'foo'
        test_dict = {
            key1: val1,
            key2: val2,
            key3: val3,
        }
        tuple_key = multistore_file._dict_to_tuple_key(test_dict)

        # the resulting key should be naturally sorted
        expected_output = (
            (key2, val2),
            (key3, val3),
            (key1, val1),
        )
        assert expected_output == tuple_key
        # check we get the original dictionary back
        assert test_dict == dict(tuple_key)


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
class TestMultistoreFile:

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

    def test_lock_file_raises_ioerror(self):
        filehandle, filename = tempfile.mkstemp()
        os.close(filehandle)

        try:
            for error_code in (errno.EDEADLK, errno.ENOSYS, errno.ENOLCK,
                               errno.EACCES):
                for error_class in (IOError, OSError):
                    multistore = multistore_file._MultiStore(filename)
                    multistore._file = _MockLockedFile(
                        filename, error_class, error_code)
                    # Should not raise though the underlying file class did.
                    multistore._lock()
                    assert multistore._file.open_and_lock_called is True
        finally:
            os.unlink(filename)

    def test_lock_file_raise_unexpected_error(self):
        filehandle, filename = tempfile.mkstemp()
        os.close(filehandle)

        try:
            multistore = multistore_file._MultiStore(filename)
            multistore._file = _MockLockedFile(filename, IOError, errno.EBUSY)
            with pytest.raises(IOError):
                multistore._lock()
            assert multistore._file.open_and_lock_called is True
        finally:
            os.unlink(filename)

    def test_read_only_file_fail_lock(self):
        credentials = self._create_test_credentials()

        open(self.temp_filename, 'a+b').close()
        os.chmod(self.temp_filename, 0o400)

        store = multistore_file.get_credential_storage(
            self.temp_filename,
            credentials.client_id,
            credentials.user_agent,
            ['some-scope', 'some-other-scope'])

        store.put(credentials)
        if os.name == 'posix':  # pragma: NO COVER
            assert store._multistore._read_only is True
        os.chmod(self.temp_filename, 0o600)

    def test_read_only_file_fail_lock_no_warning(self):
        open(self.temp_filename, 'a+b').close()
        os.chmod(self.temp_filename, 0o400)

        multistore = multistore_file._MultiStore(self.temp_filename)

        with mock.patch.object(multistore_file.logger, 'warn') as mock_warn:
            multistore._warn_on_readonly = False
            multistore._lock()
            assert mock_warn.called is False

    def test_lock_skip_refresh(self):
        with open(self.temp_filename, 'w') as f:
            f.write('123')
        os.chmod(self.temp_filename, 0o400)

        multistore = multistore_file._MultiStore(self.temp_filename)

        refresh_patch = mock.patch.object(
            multistore, '_refresh_data_cache')

        with refresh_patch as refresh_mock:
            multistore._data = {}
            multistore._lock()
            assert refresh_mock.called is False

    @pytest.mark.skipif(not hasattr(os, 'symlink'),
                        reason='No symlink available')
    def test_multistore_no_symbolic_link_files(self):
        symfilename = self.temp_filename + 'sym'
        os.symlink(self.temp_filename, symfilename)
        store = multistore_file.get_credential_storage(
            symfilename,
            'some_client_id',
            'user-agent/1.0',
            ['some-scope', 'some-other-scope'])
        try:
            with pytest.raises(
                    locked_file.CredentialsFileSymbolicLinkError):
                store.get()
        finally:
            os.unlink(symfilename)

    def test_multistore_non_existent_file(self):
        store = multistore_file.get_credential_storage(
            self.temp_filename,
            'some_client_id',
            'user-agent/1.0',
            ['some-scope', 'some-other-scope'])

        credentials = store.get()
        assert credentials is None

    def test_multistore_file(self):
        credentials = self._create_test_credentials()

        store = multistore_file.get_credential_storage(
            self.temp_filename,
            credentials.client_id,
            credentials.user_agent,
            ['some-scope', 'some-other-scope'])

        # Save credentials
        store.put(credentials)
        credentials = store.get()

        assert credentials is not None
        assert 'foo' == credentials.access_token

        # Delete credentials
        store.delete()
        credentials = store.get()

        assert credentials is None

        if os.name == 'posix':  # pragma: NO COVER
            assert 0o600 == stat.S_IMODE(os.stat(self.temp_filename).st_mode)

    def test_multistore_file_custom_key(self):
        credentials = self._create_test_credentials()

        custom_key = {'myapp': 'testing', 'clientid': 'some client'}
        store = multistore_file.get_credential_storage_custom_key(
            self.temp_filename, custom_key)

        store.put(credentials)
        stored_credentials = store.get()

        assert stored_credentials is not None
        assert credentials.access_token == stored_credentials.access_token

        store.delete()
        stored_credentials = store.get()

        assert stored_credentials is None

    def test_multistore_file_custom_string_key(self):
        credentials = self._create_test_credentials()

        # store with string key
        store = multistore_file.get_credential_storage_custom_string_key(
            self.temp_filename, 'mykey')

        store.put(credentials)
        stored_credentials = store.get()

        assert stored_credentials is not None
        assert credentials.access_token == stored_credentials.access_token

        # try retrieving with a dictionary
        multistore_file.get_credential_storage_custom_string_key(
            self.temp_filename, {'key': 'mykey'})
        stored_credentials = store.get()
        assert stored_credentials is not None
        assert credentials.access_token == stored_credentials.access_token

        store.delete()
        stored_credentials = store.get()

        assert stored_credentials is None

    def test_multistore_file_backwards_compatibility(self):
        credentials = self._create_test_credentials()
        scopes = ['scope1', 'scope2']

        # store the credentials using the legacy key method
        store = multistore_file.get_credential_storage(
            self.temp_filename, 'client_id', 'user_agent', scopes)
        store.put(credentials)

        # retrieve the credentials using a custom key that matches the
        # legacy key
        key = {'clientId': 'client_id', 'userAgent': 'user_agent',
               'scope': util.scopes_to_string(scopes)}
        store = multistore_file.get_credential_storage_custom_key(
            self.temp_filename, key)
        stored_credentials = store.get()

        assert credentials.access_token == stored_credentials.access_token

    def test_multistore_file_get_all_keys(self):
        # start with no keys
        keys = multistore_file.get_all_credential_keys(self.temp_filename)
        assert [] == keys

        # store credentials
        credentials = self._create_test_credentials(client_id='client1')
        custom_key = {'myapp': 'testing', 'clientid': 'client1'}
        store1 = multistore_file.get_credential_storage_custom_key(
            self.temp_filename, custom_key)
        store1.put(credentials)

        keys = multistore_file.get_all_credential_keys(self.temp_filename)
        assert [custom_key] == keys

        # store more credentials
        credentials = self._create_test_credentials(client_id='client2')
        string_key = 'string_key'
        store2 = multistore_file.get_credential_storage_custom_string_key(
            self.temp_filename, string_key)
        store2.put(credentials)

        keys = multistore_file.get_all_credential_keys(self.temp_filename)
        assert len(keys) == 2
        assert custom_key in keys
        assert {'key': string_key} in keys

        # back to no keys
        store1.delete()
        store2.delete()
        keys = multistore_file.get_all_credential_keys(self.temp_filename)
        assert [] == keys

    def _refresh_data_cache_helper(self):
        multistore = multistore_file._MultiStore(self.temp_filename)
        json_patch = mock.patch.object(multistore, '_locked_json_read')

        return multistore, json_patch

    def test__refresh_data_cache_bad_json(self):
        multistore, json_patch = self._refresh_data_cache_helper()

        with json_patch as json_mock:
            json_mock.side_effect = ValueError('')
            multistore._refresh_data_cache()
            assert json_mock.called is True
            assert multistore._data == {}

    def test__refresh_data_cache_bad_version(self):
        multistore, json_patch = self._refresh_data_cache_helper()

        with json_patch as json_mock:
            json_mock.return_value = {}
            multistore._refresh_data_cache()
            assert json_mock.called is True
            assert multistore._data == {}

    def test__refresh_data_cache_newer_version(self):
        multistore, json_patch = self._refresh_data_cache_helper()

        with json_patch as json_mock:
            json_mock.return_value = {'file_version': 5}
            with pytest.raises(multistore_file.NewerCredentialStoreError):
                multistore._refresh_data_cache()
            assert json_mock.called is True

    def test__refresh_data_cache_bad_credentials(self):
        multistore, json_patch = self._refresh_data_cache_helper()

        with json_patch as json_mock:
            json_mock.return_value = {
                'file_version': 1,
                'data': [
                    {'lol': 'this is a bad credential object.'}
                ]}
            multistore._refresh_data_cache()
            assert json_mock.called is True
            assert multistore._data == {}

    def test__delete_credential_nonexistent(self):
        multistore = multistore_file._MultiStore(self.temp_filename)

        with mock.patch.object(multistore, '_write') as write_mock:
            multistore._data = {}
            multistore._delete_credential('nonexistent_key')
            assert write_mock.called is True
