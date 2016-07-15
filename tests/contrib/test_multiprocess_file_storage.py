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

import contextlib
import datetime
import json
import multiprocessing
import os
import tempfile

import fasteners
import mock
import pytest
from six import StringIO

from oauth2client.client import OAuth2Credentials
from oauth2client.contrib import multiprocess_file_storage

from ..http_mock import HttpMockSequence


@contextlib.contextmanager
def scoped_child_process(target, **kwargs):
    die_event = multiprocessing.Event()
    ready_event = multiprocessing.Event()
    process = multiprocessing.Process(
        target=target, args=(die_event, ready_event), kwargs=kwargs)
    process.start()
    try:
        ready_event.wait()
        yield
    finally:
        die_event.set()
        process.join(5)


def _create_test_credentials(expiration=None):
    access_token = 'foo'
    client_secret = 'cOuDdkfjxxnv+'
    refresh_token = '1/0/a.df219fjls0'
    token_expiry = expiration or (
        datetime.datetime.utcnow() + datetime.timedelta(seconds=3600))
    token_uri = 'https://www.google.com/accounts/o8/oauth2/token'
    user_agent = 'refresh_checker/1.0'

    credentials = OAuth2Credentials(
        access_token, 'test-client-id', client_secret,
        refresh_token, token_expiry, token_uri,
        user_agent)
    return credentials


def _generate_token_response_http(new_token='new_token'):
    token_response = json.dumps({
        'access_token': new_token,
        'expires_in': '3600',
    })
    http = HttpMockSequence([
        ({'status': '200'}, token_response),
    ])

    return http


@pytest.fixture(scope='function')
def temp_file(request):
    _filehandle, filename = tempfile.mkstemp('oauth2client_test.data')
    os.close(_filehandle)
    request.cls.filename = filename

    def fin():
        try:
            os.unlink(request.cls.filename)
            os.unlink('{0}.lock'.format(request.cls.filename))
        except OSError:
            pass
    request.addfinalizer(fin)


@pytest.mark.usefixtures('temp_file')
class TestMultiprocessStorageBehavior:

    def test_basic_operations(self):
        credentials = _create_test_credentials()

        store = multiprocess_file_storage.MultiprocessFileStorage(
            self.filename, 'basic')

        # Save credentials
        store.put(credentials)
        credentials = store.get()

        assert credentials is not None
        assert 'foo' == credentials.access_token

        # Reset internal cache, ensure credentials were saved.
        store._backend._credentials = {}
        credentials = store.get()

        assert credentials is not None
        assert 'foo' == credentials.access_token

        # Delete credentials
        store.delete()
        credentials = store.get()

        assert credentials is None

    def test_single_process_refresh(self):
        store = multiprocess_file_storage.MultiprocessFileStorage(
            self.filename, 'single-process')
        credentials = _create_test_credentials()
        credentials.set_store(store)

        http = _generate_token_response_http()
        credentials.refresh(http)
        assert credentials.access_token == 'new_token'

        retrieved = store.get()
        assert retrieved.access_token == 'new_token'

    def test_multi_process_refresh(self):
        # This will test that two processes attempting to refresh credentials
        # will only refresh once.
        store = multiprocess_file_storage.MultiprocessFileStorage(
            self.filename, 'multi-process')
        credentials = _create_test_credentials()
        credentials.set_store(store)
        store.put(credentials)

        def child_process_func(
                die_event, ready_event, check_event):  # pragma: NO COVER
            store = multiprocess_file_storage.MultiprocessFileStorage(
                self.filename, 'multi-process')

            credentials = store.get()
            assert credentials is not None

            # Make sure this thread gets to refresh first.
            original_acquire_lock = store.acquire_lock

            def replacement_acquire_lock(*args, **kwargs):
                result = original_acquire_lock(*args, **kwargs)
                ready_event.set()
                check_event.wait()
                return result

            credentials.store.acquire_lock = replacement_acquire_lock

            http = _generate_token_response_http('b')
            credentials.refresh(http)

            assert credentials.access_token == 'b'

        check_event = multiprocessing.Event()
        with scoped_child_process(child_process_func, check_event=check_event):
            # The lock should be currently held by the child process.
            assert store._backend._process_lock.acquire(blocking=False) \
                is False
            check_event.set()

            # The child process will refresh first, so we should end up
            # with 'b' as the token.
            http = mock.Mock()
            credentials.refresh(http=http)
            assert credentials.access_token == 'b'
            assert http.request.called is False

        retrieved = store.get()
        assert retrieved.access_token == 'b'

    def test_read_only_file_fail_lock(self):
        credentials = _create_test_credentials()

        # Grab the lock in another process, preventing this process from
        # acquiring the lock.
        def child_process(die_event, ready_event):  # pragma: NO COVER
            lock = fasteners.InterProcessLock(
                '{0}.lock'.format(self.filename))
            with lock:
                ready_event.set()
                die_event.wait()

        with scoped_child_process(child_process):
            store = multiprocess_file_storage.MultiprocessFileStorage(
                self.filename, 'fail-lock')
            store.put(credentials)
            assert store._backend._read_only is True

        # These credentials should still be in the store's memory-only cache.
        assert store.get() is not None


@pytest.mark.usefixtures('temp_file')
class TestMultiprocessStorageUnit:

    def test__create_file_if_needed(self):
        assert multiprocess_file_storage._create_file_if_needed(
            self.filename) is False
        os.unlink(self.filename)
        assert multiprocess_file_storage._create_file_if_needed(
            self.filename) is True
        assert os.path.exists(self.filename) is True

    def test__get_backend(self):
        backend_one = multiprocess_file_storage._get_backend('file_a')
        backend_two = multiprocess_file_storage._get_backend('file_a')
        backend_three = multiprocess_file_storage._get_backend('file_b')

        assert backend_one is backend_two
        assert backend_one is not backend_three

    def test__read_write_credentials_file(self):
        credentials = _create_test_credentials()
        contents = StringIO()

        multiprocess_file_storage._write_credentials_file(
            contents, {'key': credentials})

        contents.seek(0)
        data = json.load(contents)
        assert data['file_version'] == 2
        assert bool(data['credentials']['key']) is True

        # Read it back.
        contents.seek(0)
        results = multiprocess_file_storage._load_credentials_file(contents)
        assert results['key'].access_token == credentials.access_token

        # Add an invalid credential and try reading it back. It should ignore
        # the invalid one but still load the valid one.
        data['credentials']['invalid'] = '123'
        results = multiprocess_file_storage._load_credentials_file(
            StringIO(json.dumps(data)))
        assert 'invalid' not in results
        assert results['key'].access_token == credentials.access_token

    def test__load_credentials_file_invalid_json(self):
        contents = StringIO('{[')
        assert multiprocess_file_storage._load_credentials_file(contents) == {}

    def test__load_credentials_file_no_file_version(self):
        contents = StringIO('{}')
        assert multiprocess_file_storage._load_credentials_file(contents) == {}

    def test__load_credentials_file_bad_file_version(self):
        contents = StringIO(json.dumps({'file_version': 1}))
        assert multiprocess_file_storage._load_credentials_file(contents) == {}

    def test__load_credentials_no_open_file(self):
        backend = multiprocess_file_storage._get_backend(self.filename)
        backend._credentials = mock.Mock()
        backend._credentials.update.side_effect = AssertionError()
        backend._load_credentials()

    def test_acquire_lock_nonexistent_file(self):
        backend = multiprocess_file_storage._get_backend(self.filename)
        os.unlink(self.filename)
        backend._process_lock = mock.Mock()
        backend._process_lock.acquire.return_value = False
        backend.acquire_lock()
        assert backend._file is None

    def test_release_lock_with_no_file(self):
        backend = multiprocess_file_storage._get_backend(self.filename)
        backend._file = None
        backend._read_only = True
        backend._thread_lock.acquire()
        backend.release_lock()

    def test__refresh_predicate(self):
        backend = multiprocess_file_storage._get_backend(self.filename)

        credentials = _create_test_credentials()
        assert backend._refresh_predicate(credentials) is False

        credentials.invalid = True
        assert backend._refresh_predicate(credentials) is True

        credentials = _create_test_credentials(
            expiration=(
                datetime.datetime.utcnow() - datetime.timedelta(seconds=3600)))
        assert backend._refresh_predicate(credentials) is True
