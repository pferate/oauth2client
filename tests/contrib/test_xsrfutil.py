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

"""Tests for oauth2client.contrib.xsrfutil."""

import base64

import mock
import pytest

from oauth2client._helpers import _to_bytes
from oauth2client.contrib import xsrfutil


__author__ = 'jcgregorio@google.com (Joe Gregorio)'


@pytest.fixture(scope='class')
def setup_token_info(request):
    # Jan 17 2008, 5:40PM
    request.cls.TEST_KEY = b'test key'
    # Jan. 17, 2008 22:40:32.081230 UTC
    request.cls.TEST_TIME = 1200609642081230
    request.cls.TEST_USER_ID_1 = 123832983
    request.cls.TEST_USER_ID_2 = 938297432
    request.cls.TEST_ACTION_ID_1 = b'some_action'
    request.cls.TEST_ACTION_ID_2 = b'some_other_action'
    request.cls.TEST_EXTRA_INFO_1 = b'extra_info_1'
    request.cls.TEST_EXTRA_INFO_2 = b'more_extra_info'


@pytest.mark.usefixtures('setup_token_info')
class Test_generate_token:

    def test_bad_positional(self):
        # Need 2 positional arguments.
        with pytest.raises(TypeError):
            xsrfutil.generate_token(None)
        # At most 2 positional arguments.
        with pytest.raises(TypeError):
            xsrfutil.generate_token(None, None, None)

    def test_it(self):
        digest = b'foobar'
        digester = mock.MagicMock()
        digester.digest = mock.MagicMock(name='digest', return_value=digest)
        with mock.patch('oauth2client.contrib.xsrfutil.hmac') as hmac:
            hmac.new = mock.MagicMock(name='new', return_value=digester)
            token = xsrfutil.generate_token(self.TEST_KEY,
                                            self.TEST_USER_ID_1,
                                            action_id=self.TEST_ACTION_ID_1,
                                            when=self.TEST_TIME)
            hmac.new.assert_called_once_with(self.TEST_KEY)
            digester.digest.assert_called_once_with()

            expected_digest_calls = [
                mock.call.update(_to_bytes(str(self.TEST_USER_ID_1))),
                mock.call.update(xsrfutil.DELIMITER),
                mock.call.update(self.TEST_ACTION_ID_1),
                mock.call.update(xsrfutil.DELIMITER),
                mock.call.update(_to_bytes(str(self.TEST_TIME))),
            ]
            assert digester.method_calls == expected_digest_calls

            expected_token_as_bytes = (digest + xsrfutil.DELIMITER +
                                       _to_bytes(str(self.TEST_TIME)))
            expected_token = base64.urlsafe_b64encode(
                expected_token_as_bytes)
            assert token == expected_token

    def test_with_system_time(self):
        digest = b'foobar'
        curr_time = 1440449755.74
        digester = mock.MagicMock()
        digester.digest = mock.MagicMock(name='digest', return_value=digest)
        with mock.patch('oauth2client.contrib.xsrfutil.hmac') as hmac:
            hmac.new = mock.MagicMock(name='new', return_value=digester)

            with mock.patch('oauth2client.contrib.xsrfutil.time') as time:
                time.time = mock.MagicMock(name='time', return_value=curr_time)
                # when= is omitted
                token = xsrfutil.generate_token(
                    self.TEST_KEY, self.TEST_USER_ID_1,
                    action_id=self.TEST_ACTION_ID_1)

                hmac.new.assert_called_once_with(self.TEST_KEY)
                time.time.assert_called_once_with()
                digester.digest.assert_called_once_with()

                expected_digest_calls = [
                    mock.call.update(_to_bytes(str(self.TEST_USER_ID_1))),
                    mock.call.update(xsrfutil.DELIMITER),
                    mock.call.update(self.TEST_ACTION_ID_1),
                    mock.call.update(xsrfutil.DELIMITER),
                    mock.call.update(_to_bytes(str(int(curr_time)))),
                ]
                assert digester.method_calls == expected_digest_calls

                expected_token_as_bytes = (digest + xsrfutil.DELIMITER +
                                           _to_bytes(str(int(curr_time))))
                expected_token = base64.urlsafe_b64encode(
                    expected_token_as_bytes)
                assert token == expected_token


@pytest.mark.usefixtures('setup_token_info')
class Test_validate_token:

    def test_bad_positional(self):
        # Need 3 positional arguments.
        with pytest.raises(TypeError):
            xsrfutil.validate_token(None, None)
        # At most 3 positional arguments.
        with pytest.raises(TypeError):
            xsrfutil.validate_token(None, None, None, None)

    def test_no_token(self):
        key = token = user_id = None
        assert xsrfutil.validate_token(key, token, user_id) is False

    def test_token_not_valid_base64(self):
        key = user_id = None
        token = b'a'  # Bad padding
        assert xsrfutil.validate_token(key, token, user_id) is False

    def test_token_non_integer(self):
        key = user_id = None
        token = base64.b64encode(b'abc' + xsrfutil.DELIMITER + b'xyz')
        assert xsrfutil.validate_token(key, token, user_id) is False

    def test_token_too_old_implicit_current_time(self):
        token_time = 123456789
        curr_time = token_time + xsrfutil.DEFAULT_TIMEOUT_SECS + 1

        key = user_id = None
        token = base64.b64encode(_to_bytes(str(token_time)))
        with mock.patch('oauth2client.contrib.xsrfutil.time') as time:
            time.time = mock.MagicMock(name='time', return_value=curr_time)
            assert xsrfutil.validate_token(key, token, user_id) is False
            time.time.assert_called_once_with()

    def test_token_too_old_explicit_current_time(self):
        token_time = 123456789
        curr_time = token_time + xsrfutil.DEFAULT_TIMEOUT_SECS + 1

        key = user_id = None
        token = base64.b64encode(_to_bytes(str(token_time)))
        assert xsrfutil.validate_token(key, token, user_id,
                                       current_time=curr_time) is False

    def test_token_length_differs_from_generated(self):
        token_time = 123456789
        # Make sure it isn't too old.
        curr_time = token_time + xsrfutil.DEFAULT_TIMEOUT_SECS - 1

        key = object()
        user_id = object()
        action_id = object()
        token = base64.b64encode(_to_bytes(str(token_time)))
        generated_token = b'a'
        # Make sure the token length comparison will fail.
        assert len(token) != len(generated_token)

        with mock.patch('oauth2client.contrib.xsrfutil.generate_token',
                        return_value=generated_token) as gen_tok:
            assert xsrfutil.validate_token(key, token, user_id,
                                           current_time=curr_time,
                                           action_id=action_id) is False
            gen_tok.assert_called_once_with(key, user_id, action_id=action_id,
                                            when=token_time)

    def test_token_differs_from_generated_but_same_length(self):
        token_time = 123456789
        # Make sure it isn't too old.
        curr_time = token_time + xsrfutil.DEFAULT_TIMEOUT_SECS - 1

        key = object()
        user_id = object()
        action_id = object()
        token = base64.b64encode(_to_bytes(str(token_time)))
        # It is encoded as b'MTIzNDU2Nzg5', which has length 12.
        generated_token = b'M' * 12
        # Make sure the token length comparison will succeed, but the token
        # comparison will fail.
        assert len(token) == len(generated_token)
        assert token != generated_token

        with mock.patch('oauth2client.contrib.xsrfutil.generate_token',
                        return_value=generated_token) as gen_tok:
            assert xsrfutil.validate_token(key, token, user_id,
                                           current_time=curr_time,
                                           action_id=action_id) is False
            gen_tok.assert_called_once_with(key, user_id, action_id=action_id,
                                            when=token_time)

    def test_success(self):
        token_time = 123456789
        # Make sure it isn't too old.
        curr_time = token_time + xsrfutil.DEFAULT_TIMEOUT_SECS - 1

        key = object()
        user_id = object()
        action_id = object()
        token = base64.b64encode(_to_bytes(str(token_time)))
        with mock.patch('oauth2client.contrib.xsrfutil.generate_token',
                        return_value=token) as gen_tok:
            assert xsrfutil.validate_token(key, token, user_id,
                                           current_time=curr_time,
                                           action_id=action_id) is True
            gen_tok.assert_called_once_with(key, user_id, action_id=action_id,
                                            when=token_time)


@pytest.mark.usefixtures('setup_token_info')
class TestXsrfUtil:
    """Test xsrfutil functions."""

    def testGenerateAndValidateToken(self):
        """Test generating and validating a token."""
        token = xsrfutil.generate_token(self.TEST_KEY,
                                        self.TEST_USER_ID_1,
                                        action_id=self.TEST_ACTION_ID_1,
                                        when=self.TEST_TIME)

        # Check that the token is considered valid when it should be.
        assert xsrfutil.validate_token(self.TEST_KEY,
                                       token,
                                       self.TEST_USER_ID_1,
                                       action_id=self.TEST_ACTION_ID_1,
                                       current_time=self.TEST_TIME) is True

        # Should still be valid 15 minutes later.
        later15mins = self.TEST_TIME + 15 * 60
        assert xsrfutil.validate_token(self.TEST_KEY,
                                       token,
                                       self.TEST_USER_ID_1,
                                       action_id=self.TEST_ACTION_ID_1,
                                       current_time=later15mins) is True

        # But not if beyond the timeout.
        later2hours = self.TEST_TIME + 2 * 60 * 60
        assert xsrfutil.validate_token(self.TEST_KEY,
                                       token,
                                       self.TEST_USER_ID_1,
                                       action_id=self.TEST_ACTION_ID_1,
                                       current_time=later2hours) is False

        # Or if the key is different.
        assert xsrfutil.validate_token('another key',
                                       token,
                                       self.TEST_USER_ID_1,
                                       action_id=self.TEST_ACTION_ID_1,
                                       current_time=later15mins) is False

        # Or the user ID....
        assert xsrfutil.validate_token(self.TEST_KEY,
                                       token,
                                       self.TEST_USER_ID_2,
                                       action_id=self.TEST_ACTION_ID_1,
                                       current_time=later15mins) is False

        # Or the action ID...
        assert xsrfutil.validate_token(self.TEST_KEY,
                                       token,
                                       self.TEST_USER_ID_1,
                                       action_id=self.TEST_ACTION_ID_2,
                                       current_time=later15mins) is False

        # Invalid when truncated
        assert xsrfutil.validate_token(self.TEST_KEY,
                                       token[:-1],
                                       self.TEST_USER_ID_1,
                                       action_id=self.TEST_ACTION_ID_1,
                                       current_time=later15mins) is False

        # Invalid with extra garbage
        assert xsrfutil.validate_token(self.TEST_KEY,
                                       token + b'x',
                                       self.TEST_USER_ID_1,
                                       action_id=self.TEST_ACTION_ID_1,
                                       current_time=later15mins) is False

        # Invalid with token of None
        assert xsrfutil.validate_token(self.TEST_KEY,
                                       None,
                                       self.TEST_USER_ID_1,
                                       action_id=self.TEST_ACTION_ID_1
                                       ) is False
