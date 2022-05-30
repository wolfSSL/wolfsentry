# wolfSentry -- the wolfSSL IDPS

## Description

wolfSentry is the wolfSSL IDPS (Intrusion Detection and Prevention System).  It is mainly used as a library, but can also be used as part of a kernel module.

At a high level, wolfSentry is a dynamically configurable logic hub, arbitrarily associating user-defined events with user-defined actions, contextualized by connection attributes, tracking the evolution of the client-server relationship. At a low level, wolfSentry is an embedded firewall engine (both static and fully dynamic), with O(log n) lookup of known hosts/netblocks.

wolfSentry will be fully integrated into the wolfSSL library, wolfMQTT, and wolfSSH, with optional in-tree call-ins and callbacks that give application developers turnkey IDPS across all network-facing wolfSSL products, with a viable zero-configuration option. These integrations will be available via simple `--enable-wolfidps` configure options in wolfSSL sibling products.

The wolfSentry engine will be dynamically configurable programmatically through an API, or from a textual input file supplied to the engine. Callback and client-server implementations will also be supplied that deliver advanced capabilities including remote logging through MQTT or syslog, and remote configuration and status queries, all cryptographically secured.

Notably, wolfSentry is designed from the ground up to function well in resource-constrained, bare-metal, and realtime environments, with algorithms to stay within designated maximum memory footprints and maintain deterministic throughput. Opportunities include RTOS IDPS, and IDPS for ARM silicon and other common embedded CPUs and MCUs. wolfSentry with dynamic firewalling can add as little as 64k to the code footprint, and 32k to the volatile state footprint, and can fully leverage the existing logic and state of applications and sibling libraries.


## Dependencies

In its default build, wolfSentry depends on a POSIX runtime, specifically the
heap allocator, clock_gettime, stdio, semaphore, and string APIs.  However,
these dependencies can be avoided with various build-time options.  In
particular, the recipe

```
make STATIC=1 SINGLETHREADED=1 NO_STDIO=1 EXTRA_CFLAGS='-DWOLFSENTRY_NO_CLOCK_BUILTIN -DWOLFSENTRY_NO_MALLOC_BUILTIN'
```

generates a libwolfsentry.a that depends on only a handful of basic string
functions.  Allocator and time callbacks must then be set in a `struct
wolfsentry_host_platform_interface` supplied to `wolfsentry_init()`.


## Building and testing

Build and test libwolfsentry.a:

`make -j test`

Build verbosely:

`make V=1 -j test`

Build with artifacts in an alternate location (outside or in a subdirectory of the source tree):

`make BUILD_TOP=./build -j test`

Install from an alternate build location to a non-standard destination:

`make BUILD_TOP=./build INSTALL_DIR=/usr INSTALL_LIBDIR=/usr/lib64 install`

Build libwolfsentry.a and test it under various analyzers (memory and thread
testing under full battery of valgrind and sanitizer tests):

`make -j check`

Build and test libwolfsentry.a without support for multithreading:

`make -j SINGLETHREADED=1 test`

Other available make flags are `STATIC=1`, `STRIPPED=1`, `NO_JSON=1`, and
`NO_JSON_DOM=1`, and the defaults values for `DEBUG`, `OPTIM`, and `C_WARNFLAGS`
can also be usefully overridden.

Build with a user-supplied makefile preamble to override defaults:

`make -j USER_MAKE_CONF=Makefile.settings`

(`Makefile.settings` can contain simple settings like `OPTIM := -Os`, or
elaborate makefile code including additional rules and dependency mechanisms.)

Build the smallest simplest possible library:

`make -j SINGLETHREADED=1 NO_STDIO=1 DEBUG= OPTIM=-Os EXTRA_CFLAGS='-DWOLFSENTRY_NO_CLOCK_BUILTIN -DWOLFSENTRY_NO_MALLOC_BUILTIN -DWOLFSENTRY_NO_ERROR_STRINGS -Wno-error=inline -Wno-inline'`

Build and test with user settings:

`make -j USER_SETTINGS_FILE=user_settings.h test`


## Examples

In [the wolfSSL repository](https://github.com/wolfSSL/wolfssl), see code in
`wolfsentry/test.h` gated on `WOLFSSL_WOLFSENTRY_HOOKS`, including
`wolfsentry_store_endpoints()`, `wolfSentry_NetworkFilterCallback()`,
`wolfsentry_setup()`, and `tcp_connect_with_wolfSentry()`.  See also code in
`examples/server/server.c` and `examples/client/client.c` gated on
`WOLFSSL_WOLFSENTRY_HOOKS`.  Use `configure --enable-wolfsentry` to build with
wolfSentry integration, and use `--with-wolfsentry=/the/install/path` if
wolfSentry is installed in a nonstandard location.  The wolfSSL test
client/server can be loaded with user-supplied wolfSentry JSON configurations
from the command line, using `--wolfsentry-config <file>`.

More comprehensive examples of API usage are in the wolfSentry repo in
tests/unittests.c, particularly `test_static_routes()`, `test_dynamic_rules()`,
and `test_json()`.

Example JSON configuration files are at `tests/test-config.json` and
`tests/test-config-numeric.json`.  The latter differs only by the use of raw
numbers rather than names for address families and protocols.
