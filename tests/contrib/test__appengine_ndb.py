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

import json
import os

from google.appengine.ext import ndb
from google.appengine.ext import testbed
import mock
import pytest

from oauth2client.client import Credentials
from oauth2client.client import flow_from_clientsecrets
from oauth2client.contrib.appengine import CredentialsNDBProperty
from oauth2client.contrib.appengine import FlowNDBProperty


DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')


def datafile(filename):
    return os.path.join(DATA_DIR, filename)


class TestNDBModel(ndb.Model):
    flow = FlowNDBProperty()
    creds = CredentialsNDBProperty()


@pytest.fixture()
def testbed_memcache(request):
    request.cls.testbed = testbed.Testbed()
    request.cls.testbed.activate()
    request.cls.testbed.init_datastore_v3_stub()
    request.cls.testbed.init_memcache_stub()

    def fin():
        request.cls.testbed.deactivate()
    request.addfinalizer(fin)


@pytest.mark.usefixtures('testbed_memcache')
class TestFlowNDBProperty:

    def test_flow_get_put(self):
        instance = TestNDBModel(
            flow=flow_from_clientsecrets(datafile('client_secrets.json'),
                                         'foo', redirect_uri='oob'),
            id='foo'
        )
        instance.put()
        retrieved = TestNDBModel.get_by_id('foo')

        assert 'foo_client_id' == retrieved.flow.client_id

    @mock.patch('oauth2client.contrib._appengine_ndb._LOGGER')
    def test_validate_success(self, mock_logger):
        flow_prop = TestNDBModel.flow
        flow_val = flow_from_clientsecrets(datafile('client_secrets.json'),
                                           'foo', redirect_uri='oob')
        flow_prop._validate(flow_val)
        mock_logger.info.assert_called_once_with('validate: Got type %s',
                                                 type(flow_val))

    @mock.patch('oauth2client.contrib._appengine_ndb._LOGGER')
    def test_validate_none(self, mock_logger):
        flow_prop = TestNDBModel.flow
        flow_val = None
        flow_prop._validate(flow_val)
        mock_logger.info.assert_called_once_with('validate: Got type %s',
                                                 type(flow_val))

    @mock.patch('oauth2client.contrib._appengine_ndb._LOGGER')
    def test_validate_bad_type(self, mock_logger):
        flow_prop = TestNDBModel.flow
        flow_val = object()
        with pytest.raises(TypeError):
            flow_prop._validate(flow_val)
        mock_logger.info.assert_called_once_with('validate: Got type %s',
                                                 type(flow_val))


@pytest.mark.usefixtures('testbed_memcache')
class TestCredentialsNDBProperty:

    def test_valid_creds_get_put(self):
        creds = Credentials()
        instance = TestNDBModel(creds=creds, id='bar')
        instance.put()
        retrieved = TestNDBModel.get_by_id('bar')
        assert isinstance(retrieved.creds, Credentials)

    @mock.patch('oauth2client.contrib._appengine_ndb._LOGGER')
    def test_validate_success(self, mock_logger):
        creds_prop = TestNDBModel.creds
        creds_val = Credentials()
        creds_prop._validate(creds_val)
        mock_logger.info.assert_called_once_with('validate: Got type %s',
                                                 type(creds_val))

    @mock.patch('oauth2client.contrib._appengine_ndb._LOGGER')
    def test_validate_none(self, mock_logger):
        creds_prop = TestNDBModel.creds
        creds_val = None
        creds_prop._validate(creds_val)
        mock_logger.info.assert_called_once_with('validate: Got type %s',
                                                 type(creds_val))

    @mock.patch('oauth2client.contrib._appengine_ndb._LOGGER')
    def test_validate_bad_type(self, mock_logger):
        creds_prop = TestNDBModel.creds
        creds_val = object()
        with pytest.raises(TypeError):
            creds_prop._validate(creds_val)
        mock_logger.info.assert_called_once_with('validate: Got type %s',
                                                 type(creds_val))

    def test__to_base_type_valid_creds(self):
        creds_prop = TestNDBModel.creds
        creds = Credentials()
        creds_json = json.loads(creds_prop._to_base_type(creds))
        assert creds_json == {
            '_class': 'Credentials',
            '_module': 'oauth2client.client',
            'token_expiry': None,
        }

    def test__to_base_type_null_creds(self):
        creds_prop = TestNDBModel.creds
        assert creds_prop._to_base_type(None) == ''

    def test__from_base_type_valid_creds(self):
        creds_prop = TestNDBModel.creds
        creds_json = json.dumps({
            '_class': 'Credentials',
            '_module': 'oauth2client.client',
            'token_expiry': None,
        })
        creds = creds_prop._from_base_type(creds_json)
        assert isinstance(creds, Credentials)

    def test__from_base_type_false_value(self):
        creds_prop = TestNDBModel.creds
        assert creds_prop._from_base_type('') is None
        assert creds_prop._from_base_type(False) is None
        assert creds_prop._from_base_type(None) is None
        assert creds_prop._from_base_type([]) is None
        assert creds_prop._from_base_type({}) is None

    def test__from_base_type_bad_json(self):
        creds_prop = TestNDBModel.creds
        creds_json = '{JK-I-AM-NOT-JSON'
        assert creds_prop._from_base_type(creds_json) is None
