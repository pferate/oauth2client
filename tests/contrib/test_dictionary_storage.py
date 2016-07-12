# Copyright 2016 Google Inc. All rights reserved.
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

"""Unit tests for oauth2client.contrib.dictionary_storage"""

import unittest2

from oauth2client import GOOGLE_TOKEN_URI
from oauth2client.client import OAuth2Credentials
from oauth2client.contrib.dictionary_storage import DictionaryStorage


def _generate_credentials(scopes=None):
    return OAuth2Credentials(
        'access_tokenz',
        'client_idz',
        'client_secretz',
        'refresh_tokenz',
        '3600',
        GOOGLE_TOKEN_URI,
        'Test',
        id_token={
            'sub': '123',
            'email': 'user@example.com'
        },
        scopes=scopes)


class DictionaryStorageTests(unittest2.TestCase):

    def test_constructor_defaults(self):
        dictionary = {}
        key = 'test-key'
        storage = DictionaryStorage(dictionary, key)

        assert dictionary == storage._dictionary
        assert key == storage._key
        assert storage._lock is None

    def test_constructor_explicit(self):
        dictionary = {}
        key = 'test-key'
        storage = DictionaryStorage(dictionary, key)

        lock = object()
        storage = DictionaryStorage(dictionary, key, lock=lock)
        assert storage._lock == lock

    def test_get(self):
        credentials = _generate_credentials()
        dictionary = {}
        key = 'credentials'
        storage = DictionaryStorage(dictionary, key)

        assert storage.get() is None

        dictionary[key] = credentials.to_json()
        returned = storage.get()

        assert returned is not None
        assert returned.access_token == credentials.access_token
        assert returned.id_token == credentials.id_token
        assert returned.refresh_token == credentials.refresh_token
        assert returned.client_id == credentials.client_id

    def test_put(self):
        credentials = _generate_credentials()
        dictionary = {}
        key = 'credentials'
        storage = DictionaryStorage(dictionary, key)

        storage.put(credentials)
        returned = storage.get()

        assert key in dictionary
        assert returned is not None
        assert returned.access_token == credentials.access_token
        assert returned.id_token == credentials.id_token
        assert returned.refresh_token == credentials.refresh_token
        assert returned.client_id == credentials.client_id

    def test_delete(self):
        credentials = _generate_credentials()
        dictionary = {}
        key = 'credentials'
        storage = DictionaryStorage(dictionary, key)

        storage.put(credentials)

        assert key in dictionary

        storage.delete()

        assert key not in dictionary
        assert storage.get() is None
