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
"""Unit tests for oauth2client._helpers."""

import pytest

from oauth2client._helpers import _from_bytes
from oauth2client._helpers import _json_encode
from oauth2client._helpers import _parse_pem_key
from oauth2client._helpers import _to_bytes
from oauth2client._helpers import _urlsafe_b64decode
from oauth2client._helpers import _urlsafe_b64encode


class Test__parse_pem_key:

    def test_valid_input(self):
        test_string = b'1234-----BEGIN FOO BAR BAZ'
        result = _parse_pem_key(test_string)
        assert result == test_string[4:]

    def test_bad_input(self):
        test_string = b'DOES NOT HAVE DASHES'
        result = _parse_pem_key(test_string)
        assert result is None


class Test__json_encode:

    def test_dictionary_input(self):
        # Use only a single key since dictionary hash order
        # is non-deterministic.
        data = {u'foo': 10}
        result = _json_encode(data)
        assert result == '{"foo":10}'

    def test_list_input(self):
        data = [42, 1337]
        result = _json_encode(data)
        assert result == '[42,1337]'


class Test__to_bytes:

    def test_with_bytes(self):
        value = b'bytes-val'
        assert _to_bytes(value) == value

    def test_with_unicode(self):
        value = u'string-val'
        encoded_value = b'string-val'
        assert _to_bytes(value) == encoded_value

    def test_with_nonstring_type(self):
        value = object()
        with pytest.raises(ValueError):
            _to_bytes(value)


class Test__from_bytes:

    def test_with_unicode(self):
        value = u'bytes-val'
        assert _from_bytes(value) == value

    def test_with_bytes(self):
        value = b'string-val'
        decoded_value = u'string-val'
        assert _from_bytes(value) == decoded_value

    def test_with_nonstring_type(self):
        value = object()
        with pytest.raises(ValueError):
            _from_bytes(value)


class Test__urlsafe_b64encode:

    DEADBEEF_ENCODED = b'ZGVhZGJlZWY'

    def test_valid_input_bytes(self):
        test_string = b'deadbeef'
        result = _urlsafe_b64encode(test_string)
        assert result == self.DEADBEEF_ENCODED

    def test_valid_input_unicode(self):
        test_string = u'deadbeef'
        result = _urlsafe_b64encode(test_string)
        assert result == self.DEADBEEF_ENCODED


class Test__urlsafe_b64decode:

    def test_valid_input_bytes(self):
        test_string = b'ZGVhZGJlZWY'
        result = _urlsafe_b64decode(test_string)
        assert result == b'deadbeef'

    def test_valid_input_unicode(self):
        test_string = b'ZGVhZGJlZWY'
        result = _urlsafe_b64decode(test_string)
        assert result == b'deadbeef'

    def test_bad_input(self):
        import binascii
        bad_string = b'+'
        with pytest.raises((TypeError, binascii.Error)):
            _urlsafe_b64decode(bad_string)
