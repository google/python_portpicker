#!/usr/bin/python3
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
"""Unittests for portpicker."""

# pylint: disable=invalid-name,protected-access,missing-class-docstring,missing-function-docstring

from contextlib import ExitStack
import errno
import os
import socket
import subprocess
import sys
import time
import unittest
from unittest import mock

import portpicker
_winapi = portpicker._winapi

# pylint: disable=invalid-name,protected-access,missing-class-docstring,missing-function-docstring


class CommonTestMixin:
    def IsUnusedTCPPort(self, port):
        return self._bind(port, socket.SOCK_STREAM, socket.IPPROTO_TCP)

    def IsUnusedUDPPort(self, port):
        return self._bind(port, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    def setUp(self):
        super().setUp()
        # So we can Bind even if portpicker.bind is stubbed out.
        self._bind = portpicker.bind
        portpicker._owned_ports.clear()
        portpicker._free_ports.clear()
        portpicker._random_ports.clear()


@unittest.skipIf(
        ('PORTSERVER_ADDRESS' not in os.environ) and
        not hasattr(socket, 'AF_UNIX'),
        'no existing port server; test launching code requires AF_UNIX.')
class PickUnusedPortTestWithAPortServer(CommonTestMixin, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.portserver_process = None
        if 'PORTSERVER_ADDRESS' not in os.environ:
            # Launch a portserver child process for our tests to use if we are
            # able to. Obviously not host-exclusive, but good for integration
            # testing purposes on CI without a portserver of its own.
            cls.portserver_address = '@pid%d-test-ports' % os.getpid()
            try:
                cls.portserver_process = subprocess.Popen(
                        ['portserver.py',  # Installed in PATH within the venv.
                         '--portserver_address=%s' % cls.portserver_address])
            except EnvironmentError as err:
                raise unittest.SkipTest(
                        'Unable to launch portserver.py: %s' % err)
            linux_addr = '\0' + cls.portserver_address[1:]  # The @ means 0.
            # loop for a few seconds waiting for that socket to work.
            err = '???'
            for _ in range(123):
                time.sleep(0.05)
                try:
                    ps_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    ps_sock.connect(linux_addr)
                except socket.error as err:  # pylint: disable=unused-variable
                    continue
                ps_sock.close()
                break
            else:
                # The socket failed or never accepted connections, assume our
                # portserver setup attempt failed and bail out.
                if cls.portserver_process.poll() is not None:
                    cls.portserver_process.kill()
                    cls.portserver_process.wait()
                cls.portserver_process = None
                raise unittest.SkipTest(
                        'Unable to connect to our own portserver.py: %s' % err)
            # Point child processes at our shiny portserver process.
            os.environ['PORTSERVER_ADDRESS'] = cls.portserver_address

    @classmethod
    def tearDownClass(cls):
        if cls.portserver_process:
            if os.environ.get('PORTSERVER_ADDRESS') == cls.portserver_address:
                del os.environ['PORTSERVER_ADDRESS']
            if cls.portserver_process.poll() is None:
                cls.portserver_process.kill()
                cls.portserver_process.wait()
            cls.portserver_process = None

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

    def testPickUnusedCanSuccessfullyUsePortServerAddressKwarg(self):

        with mock.patch.object(portpicker, '_pick_unused_port_without_server'):
            portpicker._pick_unused_port_without_server.side_effect = (
                Exception('eek!')
            )

            # Since _PickUnusedPortWithoutServer() raises an exception, and
            # we've temporarily removed PORTSERVER_ADDRESS from os.environ, if
            # we can successfully obtain a port, the portserver must be working.
            addr = os.environ.pop('PORTSERVER_ADDRESS')
            try:
                port = portpicker.pick_unused_port(portserver_address=addr)
                self.assertTrue(self.IsUnusedTCPPort(port))
                self.assertTrue(self.IsUnusedUDPPort(port))
            finally:
                os.environ['PORTSERVER_ADDRESS'] = addr

    def testGetPortFromPortServer(self):
        """Exercise the get_port_from_port_server() helper function."""
        for _ in range(10):
            port = portpicker.get_port_from_port_server(
                os.environ['PORTSERVER_ADDRESS'])
            self.assertTrue(self.IsUnusedTCPPort(port))
            self.assertTrue(self.IsUnusedUDPPort(port))


class PickUnusedPortTest(CommonTestMixin, unittest.TestCase):

    def testPickUnusedPortActuallyWorks(self):
        """This test can be flaky."""
        for _ in range(10):
            port = portpicker.pick_unused_port()
            self.assertTrue(self.IsUnusedTCPPort(port))
            self.assertTrue(self.IsUnusedUDPPort(port))

    def testSendsPidToPortServer(self):
        with ExitStack() as stack:
            if _winapi:
                create_file_mock = mock.Mock()
                create_file_mock.return_value = 0
                read_file_mock = mock.Mock()
                write_file_mock = mock.Mock()
                read_file_mock.return_value = (b'42768\n', 0)
                stack.enter_context(
                    mock.patch('_winapi.CreateFile', new=create_file_mock))
                stack.enter_context(
                    mock.patch('_winapi.WriteFile', new=write_file_mock))
                stack.enter_context(
                    mock.patch('_winapi.ReadFile', new=read_file_mock))
                port = portpicker.get_port_from_port_server(
                    'portserver', pid=1234)
                write_file_mock.assert_called_once_with(0, b'1234\n')
            else:
                server = mock.Mock()
                server.recv.return_value = b'42768\n'
                stack.enter_context(
                    mock.patch.object(socket, 'socket', return_value=server))
                port = portpicker.get_port_from_port_server(
                    'portserver', pid=1234)
                server.sendall.assert_called_once_with(b'1234\n')

        self.assertEqual(port, 42768)

    def testPidDefaultsToOwnPid(self):
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(os, 'getpid', return_value=9876))

            if _winapi:
                create_file_mock = mock.Mock()
                create_file_mock.return_value = 0
                read_file_mock = mock.Mock()
                write_file_mock = mock.Mock()
                read_file_mock.return_value = (b'52768\n', 0)
                stack.enter_context(
                    mock.patch('_winapi.CreateFile', new=create_file_mock))
                stack.enter_context(
                    mock.patch('_winapi.WriteFile', new=write_file_mock))
                stack.enter_context(
                    mock.patch('_winapi.ReadFile', new=read_file_mock))
                port = portpicker.get_port_from_port_server('portserver')
                write_file_mock.assert_called_once_with(0, b'9876\n')
            else:
                server = mock.Mock()
                server.recv.return_value = b'52768\n'
                stack.enter_context(
                    mock.patch.object(socket, 'socket', return_value=server))
                port = portpicker.get_port_from_port_server('portserver')
                server.sendall.assert_called_once_with(b'9876\n')

        self.assertEqual(port, 52768)

    @mock.patch.dict(os.environ,{'PORTSERVER_ADDRESS': 'portserver'})
    def testReusesPortServerPorts(self):
        with ExitStack() as stack:
            if _winapi:
                read_file_mock = mock.Mock()
                read_file_mock.side_effect = [
                    (b'12345\n', 0),
                    (b'23456\n', 0),
                    (b'34567\n', 0),
                ]
                stack.enter_context(mock.patch('_winapi.CreateFile'))
                stack.enter_context(mock.patch('_winapi.WriteFile'))
                stack.enter_context(
                    mock.patch('_winapi.ReadFile', new=read_file_mock))
            else:
                server = mock.Mock()
                server.recv.side_effect = [b'12345\n', b'23456\n', b'34567\n']
                stack.enter_context(
                    mock.patch.object(socket, 'socket', return_value=server))

            self.assertEqual(portpicker.pick_unused_port(), 12345)
            self.assertEqual(portpicker.pick_unused_port(), 23456)
            portpicker.return_port(12345)
            self.assertEqual(portpicker.pick_unused_port(), 12345)

    @mock.patch.dict(os.environ,{'PORTSERVER_ADDRESS': ''})
    def testDoesntReuseRandomPorts(self):
        ports = set()
        for _ in range(10):
            try:
                port = portpicker.pick_unused_port()
            except portpicker.NoFreePortFoundError:
                # This sometimes happens when not using portserver. Just
                # skip to the next attempt.
                continue
            ports.add(port)
            portpicker.return_port(port)
        self.assertGreater(len(ports), 5)  # Allow some random reuse.

    def testReturnsReservedPorts(self):
        with mock.patch.object(portpicker, '_pick_unused_port_without_server'):
            portpicker._pick_unused_port_without_server.side_effect = (
                Exception('eek!'))
            # Arbitrary port. In practice you should get this from somewhere
            # that assigns ports.
            reserved_port = 28465
            portpicker.add_reserved_port(reserved_port)
            ports = set()
            for _ in range(10):
                port = portpicker.pick_unused_port()
                ports.add(port)
                portpicker.return_port(port)
            self.assertEqual(len(ports), 1)
            self.assertEqual(ports.pop(), reserved_port)

    @mock.patch.dict(os.environ,{'PORTSERVER_ADDRESS': ''})
    def testFallsBackToRandomAfterRunningOutOfReservedPorts(self):
        # Arbitrary port. In practice you should get this from somewhere
        # that assigns ports.
        reserved_port = 23456
        portpicker.add_reserved_port(reserved_port)
        self.assertEqual(portpicker.pick_unused_port(), reserved_port)
        self.assertNotEqual(portpicker.pick_unused_port(), reserved_port)

    def testRandomlyChosenPorts(self):
        # Unless this box is under an overwhelming socket load, this test
        # will heavily exercise the "pick a port randomly" part of the
        # port picking code, but may never hit the "OS assigns a port"
        # code.
        ports = 0
        for _ in range(100):
            try:
                port = portpicker._pick_unused_port_without_server()
            except portpicker.NoFreePortFoundError:
                # Without the portserver, pick_unused_port can sometimes fail
                # to find a free port. Check that it passes most of the time.
                continue
            self.assertTrue(self.IsUnusedTCPPort(port))
            self.assertTrue(self.IsUnusedUDPPort(port))
            ports += 1
        # Getting a port shouldn't have failed very often, even on machines
        # with a heavy socket load.
        self.assertGreater(ports, 95)

    def testOSAssignedPorts(self):
        self.last_assigned_port = None

        def error_for_explicit_ports(port, socket_type, socket_proto):
            # Only successfully return a port if an OS-assigned port is
            # requested, or if we're checking that the last OS-assigned port
            # is unused on the other protocol.
            if port in (0, self.last_assigned_port):
                self.last_assigned_port = self._bind(port, socket_type,
                                                     socket_proto)
                return self.last_assigned_port
            return None

        with mock.patch.object(portpicker, 'bind', error_for_explicit_ports):
            # Without server, this can be little flaky, so check that it
            # passes most of the time.
            ports = 0
            for _ in range(100):
                try:
                    port = portpicker._pick_unused_port_without_server()
                except portpicker.NoFreePortFoundError:
                    continue
                self.assertTrue(self.IsUnusedTCPPort(port))
                self.assertTrue(self.IsUnusedUDPPort(port))
                ports += 1
            self.assertGreater(ports, 70)

    def pickUnusedPortWithoutServer(self):
        # Try a few times to pick a port, to avoid flakiness and to make sure
        # the code path we want was exercised.
        for _ in range(5):
            try:
                port = portpicker._pick_unused_port_without_server()
            except portpicker.NoFreePortFoundError:
                continue
            else:
                self.assertTrue(self.IsUnusedTCPPort(port))
                self.assertTrue(self.IsUnusedUDPPort(port))
                return
        self.fail("Failed to find a free port")

    def testPickPortsWithoutServer(self):
        # Test the first part of _pick_unused_port_without_server, which
        # tries a few random ports and checks is_port_free.
        self.pickUnusedPortWithoutServer()

        # Now test the second part, the fallback from above, which asks the
        # OS for a port.
        def mock_port_free(unused_port):
            return False

        with mock.patch.object(portpicker, 'is_port_free', mock_port_free):
            self.pickUnusedPortWithoutServer()

    def checkIsPortFree(self):
        """This might be flaky unless this test is run with a portserver."""
        # The port should be free initially.
        port = portpicker.pick_unused_port()
        self.assertTrue(portpicker.is_port_free(port))

        cases = [
            (socket.AF_INET,  socket.SOCK_STREAM, None),
            (socket.AF_INET6, socket.SOCK_STREAM, 1),
            (socket.AF_INET,  socket.SOCK_DGRAM,  None),
            (socket.AF_INET6, socket.SOCK_DGRAM,  1),
        ]

        # Using v6only=0 on Windows doesn't result in collisions
        if not _winapi:
            cases.extend([
                (socket.AF_INET6, socket.SOCK_STREAM, 0),
                (socket.AF_INET6, socket.SOCK_DGRAM,  0),
            ])

        for (sock_family, sock_type, v6only) in cases:
            # Occupy the port on a subset of possible protocols.
            try:
                sock = socket.socket(sock_family, sock_type, 0)
            except socket.error:
                print('Kernel does not support sock_family=%d' % sock_family,
                      file=sys.stderr)
                # Skip this case, since we cannot occupy a port.
                continue

            if not hasattr(socket, 'IPPROTO_IPV6'):
                v6only = None

            if v6only is not None:
                try:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY,
                                    v6only)
                except socket.error:
                    print('Kernel does not support IPV6_V6ONLY=%d' % v6only,
                          file=sys.stderr)
                    # Don't care; just proceed with the default.

            # Socket may have been taken in the mean time, so catch the
            # socket.error with errno set to EADDRINUSE and skip this
            # attempt.
            try:
                sock.bind(('', port))
            except socket.error as e:
                if e.errno == errno.EADDRINUSE:
                    raise portpicker.NoFreePortFoundError
                raise

            # The port should be busy.
            self.assertFalse(portpicker.is_port_free(port))
            sock.close()

            # Now it's free again.
            self.assertTrue(portpicker.is_port_free(port))

    def testIsPortFree(self):
        # This can be quite flaky on a busy host, so try a few times.
        for _ in range(10):
            try:
                self.checkIsPortFree()
            except portpicker.NoFreePortFoundError:
                pass
            else:
                return
        self.fail("checkPortIsFree failed every time.")

    def testIsPortFreeException(self):
        port = portpicker.pick_unused_port()
        with mock.patch.object(socket, 'socket') as mock_sock:
            mock_sock.side_effect = socket.error('fake socket error', 0)
            self.assertFalse(portpicker.is_port_free(port))

    def testThatLegacyCapWordsAPIsExist(self):
        """The original APIs were CapWords style, 1.1 added PEP8 names."""
        self.assertEqual(portpicker.bind, portpicker.Bind)
        self.assertEqual(portpicker.is_port_free, portpicker.IsPortFree)
        self.assertEqual(portpicker.pick_unused_port, portpicker.PickUnusedPort)
        self.assertEqual(portpicker.get_port_from_port_server,
                         portpicker.GetPortFromPortServer)


def get_open_listen_tcp_ports():
    netstat = subprocess.run(['netstat', '-lnt'], capture_output=True,
                             encoding='utf-8')
    if netstat.returncode != 0:
        raise unittest.SkipTest('Unable to run netstat -lnt to list binds.')
    rows = (line.split() for line in netstat.stdout.splitlines())
    listen_addrs = (row[3] for row in rows if row[0].startswith('tcp'))
    listen_ports = [int(addr.split(':')[-1]) for addr in listen_addrs]
    return listen_ports


@unittest.skipUnless((sys.executable and os.access(sys.executable, os.X_OK))
                     or (os.environ.get('TEST_PORTPICKER_CLI') and
                         os.access(os.environ['TEST_PORTPICKER_CLI'], os.X_OK)),
                     'sys.executable portpicker.__file__ not launchable and '
                     ' no TEST_PORTPICKER_CLI supplied.')
class PortpickerCommandLineTests(unittest.TestCase):
    def setUp(self):
        self.main_py = portpicker.__file__

    def _run_portpicker(self, pp_args, env_override=None):
        env = dict(os.environ)
        if env_override:
            env.update(env_override)
        if os.environ.get('TEST_PORTPICKER_CLI'):
            pp_command = [os.environ['TEST_PORTPICKER_CLI']]
        else:
            pp_command = [sys.executable, '-m', 'portpicker']
        return subprocess.run(pp_command + pp_args,
                              capture_output=True,
                              env=env,
                              encoding='utf-8',
                              check=False)

    def test_command_line_help(self):
        cmd = self._run_portpicker(['-h'])
        self.assertNotEqual(0, cmd.returncode)
        self.assertIn('usage', cmd.stdout)
        self.assertIn('passed an arg', cmd.stdout)
        cmd = self._run_portpicker(['--help'])
        self.assertNotEqual(0, cmd.returncode)
        self.assertIn('usage', cmd.stdout)
        self.assertIn('passed an arg', cmd.stdout)

    def test_command_line_help_text_dedented(self):
        cmd = self._run_portpicker(['-h'])
        self.assertNotEqual(0, cmd.returncode)
        self.assertIn('\nIf passed an arg', cmd.stdout)
        self.assertIn('\n  #!/bin/bash', cmd.stdout)
        self.assertIn('\nOlder versions ', cmd.stdout)

    def test_command_line_interface(self):
        cmd = self._run_portpicker([str(os.getpid())])
        cmd.check_returncode()
        port = int(cmd.stdout)
        self.assertNotEqual(0, port, msg=cmd)
        listen_ports = sorted(get_open_listen_tcp_ports())
        self.assertNotIn(port, listen_ports, msg='expected nothing to be bound to port.')

    def test_command_line_interface_no_portserver(self):
        cmd = self._run_portpicker([str(os.getpid())],
                                   env_override={'PORTSERVER_ADDRESS': ''})
        cmd.check_returncode()
        port = int(cmd.stdout)
        self.assertNotEqual(0, port, msg=cmd)
        listen_ports = sorted(get_open_listen_tcp_ports())
        self.assertNotIn(port, listen_ports, msg='expected nothing to be bound to port.')

    def test_command_line_interface_no_portserver_bind_timeout(self):
        # This test is timing sensitive and leaves that bind process hanging
        # around consuming resources until it dies on its own unless the test
        # runner kills the process group upon exit.
        timeout = 9.5
        before = time.monotonic()
        cmd = self._run_portpicker([str(os.getpid()), str(timeout)],
                                   env_override={'PORTSERVER_ADDRESS': ''})
        self.assertEqual(0, cmd.returncode, msg=(cmd.stdout, cmd.stderr))
        port = int(cmd.stdout)
        self.assertNotEqual(0, port, msg=cmd)
        if 'WARNING' in cmd.stderr:
            raise unittest.SkipTest('bind timeout not supported on this platform.')
        listen_ports = sorted(get_open_listen_tcp_ports())
        self.assertIn(port, listen_ports, msg='expected port to be bound. '
                      '%f seconds elapsed of %f bind timeout.' %
                      (time.monotonic() - before, timeout))


if __name__ == '__main__':
    unittest.main()
