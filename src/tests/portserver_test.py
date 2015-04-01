#!/usr/bin/python3
#
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Tests for the example portserver."""

import asyncio
import os
import socket
import sys
import unittest
from unittest import mock

import portpicker
import portserver


def setUpModule():
    portserver._configure_logging(verbose=True)


class PortserverFunctionsTest(unittest.TestCase):

    @classmethod
    def setUp(cls):
        cls.port = portpicker.PickUnusedPort()

    def test_get_process_command_line(self):
        portserver._get_process_command_line(os.getpid())

    def test_get_process_start_time(self):
        self.assertGreater(portserver._get_process_start_time(os.getpid()), 0)

    def test_port_is_available_true(self):
        """This might be flaky unless this test is run with a portserver."""
        # Insert Inception "we must go deeper" meme here.
        self.assertTrue(portserver._port_is_available(self.port))

    def test_port_is_available_false(self):
        with mock.patch.object(socket, 'socket') as mock_sock:
            mock_sock.side_effect = socket.error('fake socket error', 0)
            self.assertFalse(portserver._port_is_available(self.port))

    def test_should_allocate_port(self):
        self.assertFalse(portserver._should_allocate_port(0))
        self.assertFalse(portserver._should_allocate_port(1))
        self.assertTrue(portserver._should_allocate_port, os.getpid())
        child_pid = os.fork()
        if child_pid == 0:
            os._exit(0)
        else:
            os.waitpid(child_pid, 0)
        # This test assumes that after waitpid returns the kernel has finished
        # cleaning the process.  We also assume that the kernel will not reuse
        # the former child's pid before our next call checks for its existence.
        # Likely assumptions, but not guaranteed.
        self.assertFalse(portserver._should_allocate_port(child_pid))

    def test_parse_command_line(self):
        with mock.patch.object(
            sys, 'argv', ['program_name', '--verbose',
                          '--portserver_static_pool=1-1,3-8',
                          '--portserver_unix_socket_address=@hello-test']):
            portserver._parse_command_line()

    def test_parse_port_ranges(self):
        self.assertFalse(portserver._parse_port_ranges(''))
        self.assertCountEqual(portserver._parse_port_ranges('1-1'), {1})
        self.assertCountEqual(portserver._parse_port_ranges('1-1,3-8,375-378'),
                              {1, 3, 4, 5, 6, 7, 8, 375, 376, 377, 378})
        # Unparsable parts are logged but ignored.
        self.assertEqual({1, 2},
                         portserver._parse_port_ranges('1-2,not,numbers'))
        self.assertEqual(set(), portserver._parse_port_ranges('8080-8081x'))
        # Port ranges that go out of bounds are logged but ignored.
        self.assertEqual(set(), portserver._parse_port_ranges('0-1138'))
        self.assertEqual(set(range(19, 84 + 1)),
                         portserver._parse_port_ranges('1138-65536,19-84'))

    def test_configure_logging(self):
        """Just code coverage really."""
        portserver._configure_logging(False)
        portserver._configure_logging(True)

    @mock.patch.object(
        sys, 'argv', ['PortserverFunctionsTest.test_main',
                      '--portserver_unix_socket_address=@TST-%d' % os.getpid()]
    )
    @mock.patch.object(portserver, '_parse_port_ranges')
    @mock.patch('asyncio.get_event_loop')
    @mock.patch('asyncio.start_unix_server')
    def test_main(self, *unused_mocks):
        portserver._parse_port_ranges.return_value = set()
        with self.assertRaises(SystemExit):
            portserver.main()

        # Give it at least one port and try again.
        portserver._parse_port_ranges.return_value = {self.port}

        mock_event_loop = mock.Mock(spec=asyncio.base_events.BaseEventLoop)
        asyncio.get_event_loop.return_value = mock_event_loop
        asyncio.start_unix_server.return_value = mock.Mock()
        mock_event_loop.run_forever.side_effect = KeyboardInterrupt

        portserver.main()

        mock_event_loop.run_until_complete.assert_any_call(
            asyncio.start_unix_server.return_value)
        mock_event_loop.close.assert_called_once_with()
        # NOTE: This could be improved.  Tests of main() are often gross.


class PortPoolTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.port = portpicker.PickUnusedPort()

    def setUp(self):
        self.pool = portserver._PortPool()

    def test_initialization(self):
        self.assertEqual(0, self.pool.num_ports())
        self.pool.add_port_to_free_pool(self.port)
        self.assertEqual(1, self.pool.num_ports())
        self.pool.add_port_to_free_pool(1138)
        self.assertEqual(2, self.pool.num_ports())
        self.assertRaises(ValueError, self.pool.add_port_to_free_pool, 0)
        self.assertRaises(ValueError, self.pool.add_port_to_free_pool, 65536)

    @mock.patch.object(portserver, '_port_is_available')
    def test_get_port_for_process_ok(self, mock_port_is_available):
        self.pool.add_port_to_free_pool(self.port)
        mock_port_is_available.return_value = True
        self.assertEqual(self.port, self.pool.get_port_for_process(os.getpid()))
        self.assertEqual(1, self.pool.ports_checked_for_last_request)

    @mock.patch.object(portserver, '_port_is_available')
    def test_get_port_for_process_none_left(self, mock_port_is_available):
        self.pool.add_port_to_free_pool(self.port)
        self.pool.add_port_to_free_pool(22)
        mock_port_is_available.return_value = False
        self.assertEqual(2, self.pool.num_ports())
        self.assertEqual(0, self.pool.get_port_for_process(os.getpid()))
        self.assertEqual(2, self.pool.num_ports())
        self.assertEqual(2, self.pool.ports_checked_for_last_request)


@mock.patch.object(portserver, '_get_process_command_line')
@mock.patch.object(portserver, '_should_allocate_port')
@mock.patch.object(portserver._PortPool, 'get_port_for_process')
class PortServerRequestHandlerTest(unittest.TestCase):
    def setUp(self):
        portserver._configure_logging(verbose=True)
        self.rh = portserver._PortServerRequestHandler([23, 42, 54])

    def test_stats_reporting(self, *unused_mocks):
        with mock.patch.object(portserver, 'log') as mock_logger:
            self.rh.dump_stats()
        mock_logger.info.assert_called_with('total-allocations 0')

    def test_handle_port_request_bad_data(self, *unused_mocks):
        self._test_bad_data_from_client(b'')
        self._test_bad_data_from_client(b'\n')
        self._test_bad_data_from_client(b'99Z\n')
        self._test_bad_data_from_client(b'99 8\n')
        self.assertEqual([], portserver._get_process_command_line.mock_calls)

    def _test_bad_data_from_client(self, data):
        mock_writer = mock.Mock(asyncio.StreamWriter)
        self.rh._handle_port_request(data, mock_writer)
        self.assertFalse(portserver._should_allocate_port.mock_calls)

    def test_handle_port_request_denied_allocation(self, *unused_mocks):
        portserver._should_allocate_port.return_value = False
        self.assertEqual(0, self.rh._denied_allocations)
        mock_writer = mock.Mock(asyncio.StreamWriter)
        self.rh._handle_port_request(b'5\n', mock_writer)
        self.assertEqual(1, self.rh._denied_allocations)

    def test_handle_port_request_bad_port_returned(self, *unused_mocks):
        portserver._should_allocate_port.return_value = True
        self.rh._port_pool.get_port_for_process.return_value = 0
        mock_writer = mock.Mock(asyncio.StreamWriter)
        self.rh._handle_port_request(b'6\n', mock_writer)
        self.rh._port_pool.get_port_for_process.assert_called_once_with(6)
        self.assertEqual(1, self.rh._denied_allocations)

    def test_handle_port_request_success(self, *unused_mocks):
        portserver._should_allocate_port.return_value = True
        self.rh._port_pool.get_port_for_process.return_value = 999
        mock_writer = mock.Mock(asyncio.StreamWriter)
        self.assertEqual(0, self.rh._total_allocations)
        self.rh._handle_port_request(b'8', mock_writer)
        portserver._should_allocate_port.assert_called_once_with(8)
        self.rh._port_pool.get_port_for_process.assert_called_once_with(8)
        self.assertEqual(1, self.rh._total_allocations)
        self.assertEqual(0, self.rh._denied_allocations)
        mock_writer.write.assert_called_once_with(b'999\n')


if __name__ == '__main__':
    unittest.main()
