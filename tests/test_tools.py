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

import socket
import sys
import threading

import mock
import pytest
from six.moves.urllib import request

from oauth2client import tools
from oauth2client.client import FlowExchangeError
from oauth2client.client import OOB_CALLBACK_URN

try:
    import argparse
except ImportError:  # pragma: NO COVER
    pytest.skip('argparase unavailable.')


@pytest.fixture()
def setup_run_flow(request):
    request.cls.server = mock.Mock()
    request.cls.flow = mock.Mock()
    request.cls.storage = mock.Mock()
    request.cls.credentials = mock.Mock()

    request.cls.flow.step1_get_authorize_url.return_value = (
        'http://example.com/auth')
    request.cls.flow.step2_exchange.return_value = request.cls.credentials

    request.cls.flags = argparse.Namespace(
        noauth_local_webserver=True, logging_level='INFO')
    request.cls.server_flags = argparse.Namespace(
        noauth_local_webserver=False,
        logging_level='INFO',
        auth_host_port=[8080, ],
        auth_host_name='localhost')


class TestClientRedirectServer:
    """Test the ClientRedirectServer and ClientRedirectHandler classes."""

    def test_ClientRedirectServer(self):
        # create a ClientRedirectServer and run it in a thread to listen
        # for a mock GET request with the access token
        # the server should return a 200 message and store the token
        httpd = tools.ClientRedirectServer(('localhost', 0),
                                           tools.ClientRedirectHandler)
        code = 'foo'
        url = 'http://localhost:%i?code=%s' % (httpd.server_address[1], code)
        t = threading.Thread(target=httpd.handle_request)
        t.setDaemon(True)
        t.start()
        f = request.urlopen(url)
        assert f.read()
        t.join()
        httpd.server_close()
        assert httpd.query_params.get('code') == code


@pytest.mark.usefixtures('setup_run_flow')
class TestRunFlow:

    @mock.patch.object(sys, 'argv', ['ignored', '--noauth_local_webserver'])
    @mock.patch('oauth2client.tools.logging')
    @mock.patch('oauth2client.tools.input')
    def test_run_flow_no_webserver(self, input_mock, logging_mock):
        input_mock.return_value = 'auth_code'

        # Successful exchange.
        returned_credentials = tools.run_flow(self.flow, self.storage)

        assert self.credentials == returned_credentials
        assert self.flow.redirect_uri == OOB_CALLBACK_URN
        self.flow.step2_exchange.assert_called_once_with(
            'auth_code', http=None)
        self.storage.put.assert_called_once_with(self.credentials)
        self.credentials.set_store.assert_called_once_with(self.storage)

    @mock.patch('oauth2client.tools.logging')
    @mock.patch('oauth2client.tools.input')
    def test_run_flow_no_webserver_explicit_flags(
            self, input_mock, logging_mock):
        input_mock.return_value = 'auth_code'

        # Successful exchange.
        returned_credentials = tools.run_flow(
            self.flow, self.storage, flags=self.flags)

        assert self.credentials == returned_credentials
        assert self.flow.redirect_uri == OOB_CALLBACK_URN
        self.flow.step2_exchange.assert_called_once_with(
            'auth_code', http=None)

    @mock.patch('oauth2client.tools.logging')
    @mock.patch('oauth2client.tools.input')
    def test_run_flow_no_webserver_exchange_error(
            self, input_mock, logging_mock):
        input_mock.return_value = 'auth_code'
        self.flow.step2_exchange.side_effect = FlowExchangeError()

        # Error while exchanging.
        with pytest.raises(SystemExit):
            tools.run_flow(self.flow, self.storage, flags=self.flags)

        self.flow.step2_exchange.assert_called_once_with(
            'auth_code', http=None)

    @mock.patch('oauth2client.tools.logging')
    @mock.patch('oauth2client.tools.ClientRedirectServer')
    @mock.patch('webbrowser.open')
    def test_run_flow_webserver(
            self, webbrowser_open_mock, server_ctor_mock, logging_mock):
        server_ctor_mock.return_value = self.server
        self.server.query_params = {'code': 'auth_code'}

        # Successful exchange.
        returned_credentials = tools.run_flow(
            self.flow, self.storage, flags=self.server_flags)

        assert self.credentials == returned_credentials
        assert self.flow.redirect_uri == 'http://localhost:8080/'
        self.flow.step2_exchange.assert_called_once_with(
            'auth_code', http=None)
        self.storage.put.assert_called_once_with(self.credentials)
        self.credentials.set_store.assert_called_once_with(self.storage)
        assert self.server.handle_request.called is True
        webbrowser_open_mock.assert_called_once_with(
            'http://example.com/auth', autoraise=True, new=1)

    @mock.patch('oauth2client.tools.logging')
    @mock.patch('oauth2client.tools.ClientRedirectServer')
    @mock.patch('webbrowser.open')
    def test_run_flow_webserver_exchange_error(
            self, webbrowser_open_mock, server_ctor_mock, logging_mock):
        server_ctor_mock.return_value = self.server
        self.server.query_params = {'error': 'any error'}

        # Exchange returned an error code.
        with pytest.raises(SystemExit):
            tools.run_flow(self.flow, self.storage, flags=self.server_flags)

        assert self.server.handle_request.called is True

    @mock.patch('oauth2client.tools.logging')
    @mock.patch('oauth2client.tools.ClientRedirectServer')
    @mock.patch('webbrowser.open')
    def test_run_flow_webserver_no_code(
            self, webbrowser_open_mock, server_ctor_mock, logging_mock):
        server_ctor_mock.return_value = self.server
        self.server.query_params = {}

        # No code found in response
        with pytest.raises(SystemExit):
            tools.run_flow(self.flow, self.storage, flags=self.server_flags)

        assert self.server.handle_request.called is True

    @mock.patch('oauth2client.tools.logging')
    @mock.patch('oauth2client.tools.ClientRedirectServer')
    @mock.patch('oauth2client.tools.input')
    def test_run_flow_webserver_fallback(
            self, input_mock, server_ctor_mock, logging_mock):
        server_ctor_mock.side_effect = socket.error()
        input_mock.return_value = 'auth_code'

        # It should catch the socket error and proceed as if
        # noauth_local_webserver was specified.
        returned_credentials = tools.run_flow(
            self.flow, self.storage, flags=self.server_flags)

        assert self.credentials == returned_credentials
        assert self.flow.redirect_uri == OOB_CALLBACK_URN
        self.flow.step2_exchange.assert_called_once_with(
            'auth_code', http=None)
        assert server_ctor_mock.called is True
        assert self.server.handle_request.called is False


class TestMessageIfMissing:
    def test_message_if_missing(self):
        assert 'somefile.txt' in tools.message_if_missing('somefile.txt')
