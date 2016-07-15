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

"""Unit tests for oauth2client.contrib.gce."""

import datetime
import json

import httplib2
import mock
import pytest
from six.moves import http_client
from tests.contrib.test_metadata import request_mock

from oauth2client.client import HttpAccessTokenRefreshError
from oauth2client.client import save_to_well_known_file
from oauth2client.contrib.gce import _SCOPES_WARNING
from oauth2client.contrib.gce import AppAssertionCredentials

__author__ = 'jcgregorio@google.com (Joe Gregorio)'

SERVICE_ACCOUNT_INFO = {
    'scopes': ['a', 'b'],
    'email': 'a@example.com',
    'aliases': ['default']
}


class TestAppAssertionCredentials:

    def test_constructor(self):
        credentials = AppAssertionCredentials()
        assert credentials.assertion_type is None
        assert credentials.service_account_email is None
        assert credentials.scopes is None
        assert credentials.invalid is True

    @mock.patch('warnings.warn')
    def test_constructor_with_scopes(self, warn_mock):
        scope = 'http://example.com/a http://example.com/b'
        scopes = scope.split()
        credentials = AppAssertionCredentials(scopes=scopes)
        assert credentials.scopes is None
        assert credentials.assertion_type is None
        warn_mock.assert_called_once_with(_SCOPES_WARNING)

    def test_to_json(self):
        credentials = AppAssertionCredentials()
        with pytest.raises(NotImplementedError):
            credentials.to_json()

    def test_from_json(self):
        with pytest.raises(NotImplementedError):
            AppAssertionCredentials.from_json({})

    @mock.patch('oauth2client.contrib._metadata.get_token',
                side_effect=[('A', datetime.datetime.min),
                             ('B', datetime.datetime.max)])
    @mock.patch('oauth2client.contrib._metadata.get_service_account_info',
                return_value=SERVICE_ACCOUNT_INFO)
    def test_refresh_token(self, get_info, get_token):
        http_request = mock.MagicMock()
        http_mock = mock.MagicMock(request=http_request)
        credentials = AppAssertionCredentials()
        credentials.invalid = False
        credentials.service_account_email = 'a@example.com'
        assert credentials.access_token is None
        credentials.get_access_token(http=http_mock)
        assert credentials.access_token == 'A'
        assert credentials.access_token_expired is True
        get_token.assert_called_with(http_request,
                                     service_account='a@example.com')
        credentials.get_access_token(http=http_mock)
        assert credentials.access_token == 'B'
        assert credentials.access_token_expired is False
        get_token.assert_called_with(http_request,
                                     service_account='a@example.com')
        get_info.assert_not_called()

    def test_refresh_token_failed_fetch(self):
        http_request = request_mock(
            http_client.NOT_FOUND,
            'application/json',
            json.dumps({'access_token': 'a', 'expires_in': 100})
        )
        credentials = AppAssertionCredentials()
        credentials.invalid = False
        credentials.service_account_email = 'a@example.com'
        with pytest.raises(HttpAccessTokenRefreshError):
            credentials._refresh(http_request)

    def test_serialization_data(self):
        credentials = AppAssertionCredentials()
        with pytest.raises(NotImplementedError):
            getattr(credentials, 'serialization_data')

    def test_create_scoped_required(self):
        credentials = AppAssertionCredentials()
        assert credentials.create_scoped_required() is False

    def test_sign_blob_not_implemented(self):
        credentials = AppAssertionCredentials([])
        with pytest.raises(NotImplementedError):
            credentials.sign_blob(b'blob')

    @mock.patch('oauth2client.contrib._metadata.get_service_account_info',
                return_value=SERVICE_ACCOUNT_INFO)
    def test_retrieve_scopes(self, metadata):
        http_request = mock.MagicMock()
        http_mock = mock.MagicMock(request=http_request)
        credentials = AppAssertionCredentials()
        assert credentials.invalid is True
        assert credentials.scopes is None
        scopes = credentials.retrieve_scopes(http_mock)
        assert scopes == SERVICE_ACCOUNT_INFO['scopes']
        assert credentials.invalid is False
        credentials.retrieve_scopes(http_mock)
        # Assert scopes weren't refetched
        metadata.assert_called_once_with(http_request,
                                         service_account='default')

    @mock.patch('oauth2client.contrib._metadata.get_service_account_info',
                side_effect=httplib2.HttpLib2Error('No Such Email'))
    def test_retrieve_scopes_bad_email(self, metadata):
        http_request = mock.MagicMock()
        http_mock = mock.MagicMock(request=http_request)
        credentials = AppAssertionCredentials(email='b@example.com')
        with pytest.raises(httplib2.HttpLib2Error):
            credentials.retrieve_scopes(http_mock)

        metadata.assert_called_once_with(http_request,
                                         service_account='b@example.com')

    def test_save_to_well_known_file(self):
        import os
        ORIGINAL_ISDIR = os.path.isdir
        try:
            os.path.isdir = lambda path: True
            credentials = AppAssertionCredentials()
            with pytest.raises(NotImplementedError):
                save_to_well_known_file(credentials)
        finally:
            os.path.isdir = ORIGINAL_ISDIR
