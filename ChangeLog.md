## 1.3.0

* Adds an optional `portserver_address` parameter to `pick_unused_port()` so
  that callers can specify their own regardless of `os.environ`.
* Fall back to `AF_INET` when `AF_UNIX` is not available to communicate with
  a portserver.

## 1.2.0

* Introduced `add_reserved_port()` and `return_port()` APIs to allow ports to
  be recycled and allow users to bring ports of their own.

## 1.1.1

* Changed default port range to 15000-24999 to avoid ephemeral ports.
* Portserver bugfix.

## 1.1.0

* Renamed portpicker APIs to use PEP8 style function names in code and docs.
* Legacy CapWords API name compatibility is maintained (and explicitly tested).

## 1.0.1

* Code reindented to use 4 space indents and run through
  [YAPF](https://github.com/google/yapf) for consistent style.
* Not packaged for release.

## 1.0.0

* Original open source release.
