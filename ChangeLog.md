## 1.6.0

*   Resolve an internal source of potential flakiness on the bind/close port
    checks when used in active environments by calling `.shutdown()` before
    `.close()`.

## 1.6.0b1

*   Add `-h` and `--help` text to the command line tool.
*   The command line interface now defaults to associating the returned port
    with its parent process PID (usually the calling script) when no argument
    was given as that makes more sense.
*   When portpicker is used as a command line tool from a script, if a port is
    chosen without a portserver it can now be kept bound to a socket by a
    child process for a user specified timeout. When successful, this helps
    minimize race conditions as subsequent portpicker CLI invocations within
    the timeout window cannot choose the same port.
*   Some pylint based refactorings to portpicker and portpicker\_test.
*   Drop 3.6 from our CI test matrix and metadata. It probably still works
    there, but expect our unittests to include 3.7-ism's in the future. We'll
    *attempt* to avoid modern constructs in portpicker.py itself but zero
    guarantees. Using an old Python? Use an old portpicker.

## 1.5.2

*   Do not re-pick a known used (not-yet-returned) port when running stand alone
    without a portserver.

## 1.5.1

*   When not using a portserver *(you really should)*, try the `bind(0)`
    approach before hunting for random unused ports. More reliable per
    https://github.com/google/python_portpicker/issues/16.

## 1.5.0

*   Add portserver support to Windows using named pipes. To create or connect to
    a server, prefix the name of the server with `@` (e.g.
    `@unittest-portserver`).

## 1.4.0

*   Use `async def` instead of `@asyncio.coroutine` in order to support 3.10.
*   The portserver now checks for and rejects pid values that are out of range.
*   Declare a minimum Python version of 3.6 in the package config.
*   Rework `portserver_test.py` to launch an actual portserver process instead
    of mocks.

## 1.3.9

*   No portpicker or portserver code changes
*   Fixed the portserver test on recent Python 3.x versions.
*   Switched to setup.cfg based packaging.
*   We no longer declare ourselves Python 2.7 or 3.3-3.5 compatible.

## 1.3.1

*   Fix a race condition in `pick_unused_port()` involving the free ports set.

## 1.3.0

*   Adds an optional `portserver_address` parameter to `pick_unused_port()` so
    that callers can specify their own regardless of `os.environ`.
*   `pick_unused_port()` now raises `NoFreePortFoundError` when no available
    port could be found rather than spinning in a loop trying forever.
*   Fall back to `socket.AF_INET` when `socket.AF_UNIX` support is not available
    to communicate with a portserver.

## 1.2.0

*   Introduced `add_reserved_port()` and `return_port()` APIs to allow ports to
    be recycled and allow users to bring ports of their own.

## 1.1.1

*   Changed default port range to 15000-24999 to avoid ephemeral ports.
*   Portserver bugfix.

## 1.1.0

*   Renamed portpicker APIs to use PEP8 style function names in code and docs.
*   Legacy CapWords API name compatibility is maintained (and explicitly
    tested).

## 1.0.1

*   Code reindented to use 4 space indents and run through
    [YAPF](https://github.com/google/yapf) for consistent style.
*   Not packaged for release.

## 1.0.0

*   Original open source release.
