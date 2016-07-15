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

import datetime

import pytest
import sqlalchemy
import sqlalchemy.ext.declarative
import sqlalchemy.orm

import oauth2client
import oauth2client.client
import oauth2client.contrib.sqlalchemy

Base = sqlalchemy.ext.declarative.declarative_base()


class DummyModel(Base):
    __tablename__ = 'dummy'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    # we will query against this, because of ROWID
    key = sqlalchemy.Column(sqlalchemy.Integer)
    credentials = sqlalchemy.Column(
        oauth2client.contrib.sqlalchemy.CredentialsType)


@pytest.fixture(scope='function')
def setup_session(request):
    engine = sqlalchemy.create_engine('sqlite://')
    Base.metadata.create_all(engine)

    request.cls.session = sqlalchemy.orm.sessionmaker(bind=engine)
    request.cls.credentials = oauth2client.client.OAuth2Credentials(
        access_token='token',
        client_id='client_id',
        client_secret='client_secret',
        refresh_token='refresh_token',
        token_expiry=datetime.datetime.utcnow(),
        token_uri=oauth2client.GOOGLE_TOKEN_URI,
        user_agent='DummyAgent',
    )

    def fin():
        session = request.cls.session()
        session.query(DummyModel).filter_by(key=1).delete()
        session.commit()
    request.addfinalizer(fin)


@pytest.mark.usefixtures('setup_session')
class TestSQLAlchemyStorage:

    def compare_credentials(self, result):
        assert result.access_token == self.credentials.access_token
        assert result.client_id == self.credentials.client_id
        assert result.client_secret == self.credentials.client_secret
        assert result.refresh_token == self.credentials.refresh_token
        assert result.token_expiry == self.credentials.token_expiry
        assert result.token_uri == self.credentials.token_uri
        assert result.user_agent == self.credentials.user_agent

    def test_get(self):
        session = self.session()
        session.add(DummyModel(
            key=1,
            credentials=self.credentials,
        ))
        session.commit()

        credentials = oauth2client.contrib.sqlalchemy.Storage(
            session=session,
            model_class=DummyModel,
            key_name='key',
            key_value=1,
            property_name='credentials',
        ).get()

        self.compare_credentials(credentials)

    def test_put(self):
        session = self.session()
        oauth2client.contrib.sqlalchemy.Storage(
            session=session,
            model_class=DummyModel,
            key_name='key',
            key_value=1,
            property_name='credentials',
        ).put(self.credentials)
        session.commit()

        entity = session.query(DummyModel).filter_by(key=1).first()
        self.compare_credentials(entity.credentials)

    def test_delete(self):
        session = self.session()
        session.add(DummyModel(
            key=1,
            credentials=self.credentials,
        ))
        session.commit()

        query = session.query(DummyModel).filter_by(key=1)
        assert query.first() is not None
        oauth2client.contrib.sqlalchemy.Storage(
            session=session,
            model_class=DummyModel,
            key_name='key',
            key_value=1,
            property_name='credentials',
        ).delete()
        session.commit()
        assert query.first() is None
