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
"""Unit tests for oauth2client._pycrypto_crypt."""

import os

import pytest
import unittest2

from oauth2client.crypt import PyCryptoSigner
from oauth2client.crypt import PyCryptoVerifier


class TestPyCryptoVerifier(unittest2.TestCase):

    PUBLIC_CERT_FILENAME = os.path.join(os.path.dirname(__file__),
                                        'data', 'public_cert.pem')
    PRIVATE_KEY_FILENAME = os.path.join(os.path.dirname(__file__),
                                        'data', 'privatekey.pem')

    def _load_public_cert_bytes(self):
        with open(self.PUBLIC_CERT_FILENAME, 'rb') as fh:
            return fh.read()

    def _load_private_key_bytes(self):
        with open(self.PRIVATE_KEY_FILENAME, 'rb') as fh:
            return fh.read()

    def test_verify_success(self):
        to_sign = b'foo'
        signer = PyCryptoSigner.from_string(self._load_private_key_bytes())
        actual_signature = signer.sign(to_sign)

        verifier = PyCryptoVerifier.from_string(self._load_public_cert_bytes(),
                                                is_x509_cert=True)
        assert verifier.verify(to_sign, actual_signature) is True

    def test_verify_failure(self):
        verifier = PyCryptoVerifier.from_string(self._load_public_cert_bytes(),
                                                is_x509_cert=True)
        bad_signature = b''
        assert bool(verifier.verify(b'foo', bad_signature)) is False

    def test_verify_bad_key(self):
        verifier = PyCryptoVerifier.from_string(self._load_public_cert_bytes(),
                                                is_x509_cert=True)
        bad_signature = b''
        print('bad_signature: ', bad_signature)
        assert bool(verifier.verify(b'foo', bad_signature)) is False

    def test_from_string_unicode_key(self):
        public_key = self._load_public_cert_bytes()
        public_key = public_key.decode('utf-8')
        verifier = PyCryptoVerifier.from_string(public_key, is_x509_cert=True)
        assert isinstance(verifier, PyCryptoVerifier)


class TestPyCryptoSigner(unittest2.TestCase):

    def test_from_string_bad_key(self):
        key_bytes = 'definitely-not-pem-format'
        with pytest.raises(NotImplementedError):
            PyCryptoSigner.from_string(key_bytes)
