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

import errno
import os
import sys
import tempfile

import mock
import pytest
import unittest2

from oauth2client.contrib import locked_file


class TestOpener(unittest2.TestCase):
    def _make_one(self):
        _filehandle, filename = tempfile.mkstemp()
        os.close(_filehandle)
        return locked_file._Opener(filename, 'r+', 'r'), filename

    def test_ctor(self):
        instance, filename = self._make_one()
        assert instance._locked is False
        assert instance._filename == filename
        assert instance._mode == 'r+'
        assert instance._fallback_mode == 'r'
        assert instance._fh is None
        assert instance._lock_fd is None

    def test_is_locked(self):
        instance, _ = self._make_one()
        assert instance.is_locked() is False
        instance._locked = True
        assert instance.is_locked() is True

    def test_file_handle(self):
        instance, _ = self._make_one()
        assert instance.file_handle() is None
        fh = mock.Mock()
        instance._fh = fh
        assert instance.file_handle() == fh

    def test_filename(self):
        instance, filename = self._make_one()
        assert instance.filename() == filename

    def test_open_and_lock(self):
        instance, _ = self._make_one()
        instance.open_and_lock(1, 1)

    def test_unlock_and_close(self):
        instance, _ = self._make_one()
        instance.unlock_and_close()


class TestPosixOpener(TestOpener):
    def _make_one(self):
        _filehandle, filename = tempfile.mkstemp()
        os.close(_filehandle)
        return locked_file._PosixOpener(filename, 'r+', 'r'), filename

    def test_relock_fail(self):
        instance, _ = self._make_one()
        instance.open_and_lock(1, 1)

        assert instance.is_locked() is True
        assert instance.file_handle() is not None
        with pytest.raises(locked_file.AlreadyLockedException):
            instance.open_and_lock(1, 1)

    @mock.patch('oauth2client.contrib.locked_file.open', create=True)
    def test_lock_access_error_fallback_mode(self, mock_open):
        # NOTE: This is a bad case. The behavior here should be that the
        # error gets re-raised, but the module lets the if statement fall
        # through.
        instance, _ = self._make_one()
        mock_open.side_effect = [IOError(errno.ENOENT, '')]
        instance.open_and_lock(1, 1)

        assert instance.file_handle() is None
        assert instance.is_locked() is True

    @mock.patch('oauth2client.contrib.locked_file.open', create=True)
    def test_lock_non_access_error(self, mock_open):
        instance, _ = self._make_one()
        fh_mock = mock.Mock()
        mock_open.side_effect = [IOError(errno.EACCES, ''), fh_mock]
        instance.open_and_lock(1, 1)

        assert instance.file_handle() == fh_mock
        assert instance.is_locked() is False

    @mock.patch('oauth2client.contrib.locked_file.open', create=True)
    def test_lock_unexpected_error(self, mock_open):
        instance, _ = self._make_one()

        with mock.patch('os.open') as mock_os_open:
            mock_os_open.side_effect = [OSError(errno.EPERM, '')]
            with pytest.raises(OSError):
                instance.open_and_lock(1, 1)

    @mock.patch('oauth2client.contrib.locked_file.open', create=True)
    @mock.patch('oauth2client.contrib.locked_file.logger')
    @mock.patch('time.time')
    def test_lock_timeout_error(self, mock_time, mock_logger, mock_open):
        instance, _ = self._make_one()
        # Make it seem like 10 seconds have passed between calls.
        mock_time.side_effect = [0, 10]

        with mock.patch('os.open') as mock_os_open:
            # Raising EEXIST should cause it to try to retry locking.
            mock_os_open.side_effect = [OSError(errno.EEXIST, '')]
            instance.open_and_lock(1, 1)
            assert instance.is_locked() is False
            assert mock_logger.warn.called is True

    @mock.patch('oauth2client.contrib.locked_file.open', create=True)
    @mock.patch('oauth2client.contrib.locked_file.logger')
    @mock.patch('time.time')
    def test_lock_timeout_error_no_fh(self, mock_time, mock_logger, mock_open):
        instance, _ = self._make_one()
        # Make it seem like 10 seconds have passed between calls.
        mock_time.side_effect = [0, 10]
        # This will cause the retry loop to enter without a file handle.
        fh_mock = mock.Mock()
        mock_open.side_effect = [IOError(errno.ENOENT, ''), fh_mock]

        with mock.patch('os.open') as mock_os_open:
            # Raising EEXIST should cause it to try to retry locking.
            mock_os_open.side_effect = [OSError(errno.EEXIST, '')]
            instance.open_and_lock(1, 1)
            assert instance.is_locked() is False
            assert mock_logger.warn.called is True
            assert instance.file_handle() == fh_mock

    @mock.patch('oauth2client.contrib.locked_file.open', create=True)
    @mock.patch('time.time')
    @mock.patch('time.sleep')
    def test_lock_retry_success(self, mock_sleep, mock_time, mock_open):
        instance, _ = self._make_one()
        # Make it seem like 1 second has passed between calls. Extra values
        # are needed by the logging module.
        mock_time.side_effect = [0, 1]

        with mock.patch('os.open') as mock_os_open:
            # Raising EEXIST should cause it to try to retry locking.
            mock_os_open.side_effect = [
                OSError(errno.EEXIST, ''), mock.Mock()]
            instance.open_and_lock(10, 1)
            print(mock_os_open.call_args_list)
            assert instance.is_locked() is True
            mock_sleep.assert_called_with(1)

    @mock.patch('oauth2client.contrib.locked_file.os')
    def test_unlock(self, os_mock):
        instance, _ = self._make_one()
        instance._locked = True
        lock_fd_mock = instance._lock_fd = mock.Mock()
        instance._fh = mock.Mock()

        instance.unlock_and_close()

        assert instance.is_locked() is False
        os_mock.close.assert_called_once_with(lock_fd_mock)
        assert os_mock.unlink.called is True
        assert instance._fh.close.called is True


class TestLockedFile(unittest2.TestCase):

    @mock.patch('oauth2client.contrib.locked_file._PosixOpener')
    def _make_one(self, opener_ctor_mock):
        opener_mock = mock.Mock()
        opener_ctor_mock.return_value = opener_mock
        return locked_file.LockedFile(
            'a_file', 'r+', 'r', use_native_locking=False), opener_mock

    @mock.patch('oauth2client.contrib.locked_file._PosixOpener')
    def test_ctor_minimal(self, opener_mock):
        locked_file.LockedFile(
            'a_file', 'r+', 'r', use_native_locking=False)
        opener_mock.assert_called_with('a_file', 'r+', 'r')

    @mock.patch.dict('sys.modules', {
        'oauth2client.contrib._win32_opener': mock.Mock()})
    def test_ctor_native_win32(self):
        _win32_opener_mock = sys.modules['oauth2client.contrib._win32_opener']
        locked_file.LockedFile(
            'a_file', 'r+', 'r', use_native_locking=True)
        _win32_opener_mock._Win32Opener.assert_called_with('a_file', 'r+', 'r')

    @mock.patch.dict('sys.modules', {
        'oauth2client.contrib._win32_opener': None,
        'oauth2client.contrib._fcntl_opener': mock.Mock()})
    def test_ctor_native_fcntl(self):
        _fnctl_opener_mock = sys.modules['oauth2client.contrib._fcntl_opener']
        locked_file.LockedFile(
            'a_file', 'r+', 'r', use_native_locking=True)
        _fnctl_opener_mock._FcntlOpener.assert_called_with('a_file', 'r+', 'r')

    @mock.patch('oauth2client.contrib.locked_file._PosixOpener')
    @mock.patch.dict('sys.modules', {
        'oauth2client.contrib._win32_opener': None,
        'oauth2client.contrib._fcntl_opener': None})
    def test_ctor_native_posix_fallback(self, opener_mock):
        locked_file.LockedFile(
            'a_file', 'r+', 'r', use_native_locking=True)
        opener_mock.assert_called_with('a_file', 'r+', 'r')

    def test_filename(self):
        instance, opener = self._make_one()
        opener._filename = 'some file'
        assert instance.filename() == 'some file'

    def test_file_handle(self):
        instance, opener = self._make_one()
        assert instance.file_handle() == opener.file_handle()
        assert opener.file_handle.called is True

    def test_is_locked(self):
        instance, opener = self._make_one()
        assert instance.is_locked() == opener.is_locked()
        assert opener.is_locked.called is True

    def test_open_and_lock(self):
        instance, opener = self._make_one()
        instance.open_and_lock()
        opener.open_and_lock.assert_called_with(0, 0.05)

    def test_unlock_and_close(self):
        instance, opener = self._make_one()
        instance.unlock_and_close()
        opener.unlock_and_close.assert_called_with()
