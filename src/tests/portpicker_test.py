#!/usr/bin/python
#
# Copyright 2007 Google Inc. All Rights Reserved.
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
"""Unittests for the portpicker module."""

import os
import random
import socket
import unittest

try:
    # pylint: disable=no-name-in-module
    from unittest import mock  # Python >= 3.3.
except ImportError:
    import mock  # https://pypi.python.org/pypi/mock

import portpicker


class PickUnusedPortTest(unittest.TestCase):
    def IsUnusedTCPPort(self, port):
        return self._bind(port, socket.SOCK_STREAM, socket.IPPROTO_TCP)

    def IsUnusedUDPPort(self, port):
        return self._bind(port, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    def setUp(self):
        # So we can Bind even if portpicker.bind is stubbed out.
        self._bind = portpicker.bind

    def testPickUnusedPortActuallyWorks(self):
        """This test can be flaky."""
        for _ in range(10):
            port = portpicker.pick_unused_port()
            self.assertTrue(self.IsUnusedTCPPort(port))
            self.assertTrue(self.IsUnusedUDPPort(port))

    @unittest.skipIf('PORTSERVER_ADDRESS' not in os.environ,
                     'no port server to test against')
    def testPickUnusedCanSuccessfullyUsePortServer(self):

        with mock.patch.object(portpicker, '_pick_unused_port_without_server'):
            portpicker._pick_unused_port_without_server.side_effect = (
                Exception('eek!')
            )

            # Since _PickUnusedPortWithoutServer() raises an exception, if we
            # can successfully obtain a port, the portserver must be working.
            port = portpicker.pick_unused_port()
            self.assertTrue(self.IsUnusedTCPPort(port))
            self.assertTrue(self.IsUnusedUDPPort(port))

    @unittest.skipIf('PORTSERVER_ADDRESS' not in os.environ,
                     'no port server to test against')
    def testGetPortFromPortServer(self):
        """Exercise the get_port_from_port_server() helper function."""
        for _ in range(10):
            port = portpicker.get_port_from_port_server(
                os.environ['PORTSERVER_ADDRESS'])
            self.assertTrue(self.IsUnusedTCPPort(port))
            self.assertTrue(self.IsUnusedUDPPort(port))

    def testSendsPidToPortServer(self):
        server = mock.Mock()
        server.recv.return_value = b'42768\n'
        with mock.patch.object(socket, 'socket', return_value=server):
            port = portpicker.get_port_from_port_server('portserver', pid=1234)
            server.sendall.assert_called_once_with(b'1234\n')
        self.assertEqual(port, 42768)

    def testPidDefaultsToOwnPid(self):
        server = mock.Mock()
        server.recv.return_value = b'52768\n'
        with mock.patch.object(socket, 'socket', return_value=server):
            with mock.patch.object(os, 'getpid', return_value=9876):
                port = portpicker.get_port_from_port_server('portserver')
                server.sendall.assert_called_once_with(b'9876\n')
        self.assertEqual(port, 52768)

    def testRandomlyChosenPorts(self):
        # Unless this box is under an overwhelming socket load, this test
        # will heavily exercise the "pick a port randomly" part of the
        # port picking code, but may never hit the "OS assigns a port"
        # code.
        for _ in range(100):
            port = portpicker._pick_unused_port_without_server()
            self.assertTrue(self.IsUnusedTCPPort(port))
            self.assertTrue(self.IsUnusedUDPPort(port))

    def testOSAssignedPorts(self):
        self.last_assigned_port = None

        def error_for_explicit_ports(port, socket_type, socket_proto):
            # Only successfully return a port if an OS-assigned port is
            # requested, or if we're checking that the last OS-assigned port
            # is unused on the other protocol.
            if port == 0 or port == self.last_assigned_port:
                self.last_assigned_port = self._bind(port, socket_type,
                                                     socket_proto)
                return self.last_assigned_port
            else:
                return None

        with mock.patch.object(portpicker, 'bind', error_for_explicit_ports):
            for _ in range(100):
                port = portpicker._pick_unused_port_without_server()
                self.assertTrue(self.IsUnusedTCPPort(port))
                self.assertTrue(self.IsUnusedUDPPort(port))

    def testPickPortsWithError(self):
        r = random.Random()

        def bind_with_error(port, socket_type, socket_proto):
            # 95% failure rate means both port picking methods will be
            # exercised.
            if int(r.uniform(0, 20)) == 0:
                return self._bind(port, socket_type, socket_proto)
            else:
                return None

        with mock.patch.object(portpicker, 'bind', bind_with_error):
            for _ in range(100):
                port = portpicker._pick_unused_port_without_server()
                self.assertTrue(self.IsUnusedTCPPort(port))
                self.assertTrue(self.IsUnusedUDPPort(port))

    def testThatLegacyCapWordsAPIsExist(self):
        """The original APIs were CapWords style, 1.1 added PEP8 names."""
        self.assertEqual(portpicker.bind, portpicker.Bind)
        self.assertEqual(portpicker.is_port_free, portpicker.IsPortFree)
        self.assertEqual(portpicker.pick_unused_port, portpicker.PickUnusedPort)
        self.assertEqual(portpicker.get_port_from_port_server,
                         portpicker.GetPortFromPortServer)


if __name__ == '__main__':
    unittest.main()
