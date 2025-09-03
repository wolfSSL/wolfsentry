# wolfSentry -- The Wolfssl Embedded Firewall/IDPS

## Description

wolfSentry is the wolfSSL embedded IDPS (Intrusion Detection and Prevention
System).  In simple terms, wolfSentry is an embedded firewall engine (both
static and fully dynamic), with prefix-based and wildcard-capable lookup of
known hosts/netblocks qualified by interface, address family, protocol, port,
and other traffic parameters.  Additionally, wolfSentry can be used as a
dynamically configurable logic hub, arbitrarily associating user-defined events
with user-defined actions, contextualized by connection attributes.  The
evolution of client-server relationships can thus be tracked in detail, freely
passing traffic matching expected usage patterns, while efficiently rejecting
abusive traffic.

wolfSentry is fully integrated with the lwIP stack, through a patchset in the
`lwip/` subdirectory of the source tree, and has basic integration with the
wolfSSL library for application-level filtering of inbound and outbound
connections.

The wolfSentry engine is dynamically configurable programmatically through an
API, or from a textual input file in JSON supplied to the engine, or dynamically
and incrementally with JSON fragments, or any combination of these methods.
Reconfiguration is protected by transactional semantics, and advanced internal
locks on threaded targets assure seamless service availability with atomic
policy transition.  Callbacks allow for transport-agnostic remote logging,
e.g. through MQTT, syslog, or DDS message buses.

wolfSentry is designed from the ground up to function well in
resource-constrained, bare-metal, and realtime environments, with algorithms to
stay within designated maximum memory footprints and maintain deterministic
throughput.  This allows full firewall and IDPS functionality on embedded
targets such as FreeRTOS, Nucleus, NUTTX, Zephyr, VxWorks, and Green Hills
Integrity, and on ARM and other common embedded CPUs and MCUs.  wolfSentry with
dynamic firewalling can add as little as 64k to the code footprint, and 32k to
the volatile state footprint, and can fully leverage the existing logic and
state of applications and sibling libraries.


## Documentation

Basic application integration on FreeRTOS-lwIP is documented, with usable code fragments, in [doc/freertos-lwip-app.md](doc/freertos-lwip-app.md).

JSON configuration is documented in detail by [doc/json_configuration.md](doc/json_configuration.md).

With `doxygen` installed, the HTML version of the full API reference manual can
be generated from the top of the wolfSentry source tree with `make doc-html`.
This, and the source code itself, are the recommended API references.

The PDF version of the API reference manual is pregenerated and included with source
distributions in the `doc/` subdirectory at `doc/wolfSentry_refman.pdf`.  The latest version is always
available [on GitHub](https://raw.githubusercontent.com/wolfSSL/wolfsentry/master/doc/wolfSentry_refman.pdf).

The latest changes and additions are noted in the [ChangeLog.md](ChangeLog.md) at the top of the repository.


## Dependencies

In its default build, wolfSentry depends on a POSIX runtime, specifically the
heap allocator, clock_gettime, stdio, semaphore, pthreads, and string APIs.
However, these dependencies can be avoided with various build-time options.  The recipe

`make STATIC=1 SINGLETHREADED=1 NO_STDIO=1 EXTRA_CFLAGS="-DWOLFSENTRY_NO_CLOCK_BUILTIN -DWOLFSENTRY_NO_MALLOC_BUILTIN"`

builds a libwolfsentry.a that depends on only a handful of basic string
functions and the `inet_ntop()` library function (from POSIX.1-2001, and also
implemented by lwIP).  Allocator and time callbacks must then be set in a
`struct wolfsentry_host_platform_interface` supplied to `wolfsentry_init()`.

The wolfSentry `Makefile` depends on a modern (v4.0+) Gnu `make`.  The library
itself can be built outside `make`, within another project/framework, by
creating a user settings macro file and passing its path to the compiler with
the `WOLFSENTRY_USER_SETTINGS_FILE` macro.


## Building

wolfSentry was written with portability in mind, with provisions for non-POSIX
and C89 targets.  For example, all its dependencies can be met with the
FreeRTOS/newlib-nano/lwIP runtime.  If you have difficulty building wolfSentry,
please don’t hesitate to seek support through our [support
forums](<https://www.wolfssl.com/forums>) or contact us directly at
[support@wolfssl.com](mailto:support@wolfssl.com).

The current wolfSentry release can be downloaded from [the wolfSSL
website as a ZIP file](https://www.wolfssl.com/download), and developers can
[browse the release history](https://github.com/wolfSSL/wolfsentry/tags) and
clone [the wolfSentry Git repository](https://github.com/wolfSSL/wolfsentry) for
the latest pre-release updates.

There are several flags that can be passed to `make` to control the build
parameters.  `make` will store them at build time in
`wolfsentry/wolfsentry_options.h` in the build tree. If you are not
using `make`, then the C macro `WOLFSENTRY_USER_SETTINGS_FILE` should be
defined to the path to a file containing settings, both when building wolfSentry
and when building the application.

The following feature control variables are recognized.  True/false features
(`LWIP`, `NO_STDIO`, `NO_JSON`, etc.) are undefined by default, and activated
when defined.  Macros can be supplied using the `EXTRA_CFLAGS` option, or by
placing them in a `USER_SETTINGS_FILE`.  More detailed documentation for macros
is available in the reference manual "Startup/Configuration/Shutdown Subsystem"
topic.

| `make` Option | Macro Option | Description |
| -------------- | ------------ | ----------- |
| `SHELL` | | Supplies an explicit/alternative path to `bash`. |
| `AWK` | | Supplies an explicit/alternative path to Gnu `awk`. |
| `V` | | Verbose `make` output <br> e.g. `make V=1 -j test` |
| `USER_MAKE_CONF` | | User-defined make clauses to include at the top of the main Makefile <br> e.g. `make -j USER_MAKE_CONF=Makefile.settings` |
| `EXTRA_CFLAGS` | | Additional arguments to be passed verbatim to the compiler |
| `EXTRA_LDFLAGS` | | Additional arguments to be passed verbatim to the linker |
| `SRC_TOP` | | The source code top level directory (default `pwd -P`) |
| `BUILD_TOP` | | Build with artifacts in an alternate location (outside or in a subdirectory of the source tree) <br> e.g. `make BUILD_TOP=./build -j test`|
| `DEBUG` | | Compiler debugging flag to use (default `-ggdb`) |
| `OPTIM` | | The optimizer flag to use (default `-O3`) |
| `HOST` | | The target host tuple, for cross-compilation (default unset, i.e. native targeting) |
| `RUNTIME` | | The target runtime ecosystem -- default unset, `FreeRTOS-lwIP`, `Linux-lwIP` and `ThreadX-NetXDuo` are recognized |
| `C_WARNFLAGS` | | The warning flags to use (overriding the generally applicable defaults) |
| `STATIC` | | Build statically linked unit tests |
| `STRIPPED` | | Strip binaries of debugging symbols |
| `FUNCTION_SECTIONS` | | Cull any unused object code (with function granularity) to minimize total size. |
| `BUILD_DYNAMIC` | | Build dynamically linked library |
| `VERY_QUIET` | | Inhibit all non-error output during build |
| `TAR` | | Path to GNU tar binary for `make dist`, should be set to `gtar` for macOS |
| `VERSION` | | The version to package for `make dist` |
| `LWIP` | `WOLFSENTRY_LWIP` | True/false -- Activates appropriate build settings for lwIP |
| `NO_STDIO_STREAMS` | `WOLFSENTRY_NO_STDIO_STREAMS` | Define to omit functionality that depends on `stdio` stream I/O |
| | `WOLFSENTRY_NO_STDIO_H` | Define to inhibit inclusion of `stdio.h` |
| `NO_ADDR_BITMASK_MATCHING` | `WOLFSENTRY_NO_ADDR_BITMASK_MATCHING` | Define to omit support for bitmask matching of addresses, i.e. support only prefix matching. |
| `NO_IPV6` | `WOLFSENTRY_NO_IPV6` | Define to omit support for the IPv6 address family. |
| `NO_JSON` | `WOLFSENTRY_NO_JSON` | Define to omit JSON configuration support |
| `NO_JSON_DOM` | `WOLFSENTRY_NO_JSON_DOM` | Define to omit JSON DOM API |
| `CALL_TRACE` | `WOLFSENTRY_DEBUG_CALL_TRACE` | Define to activate runtime call stack logging (profusely verbose) |
| `USER_SETTINGS_FILE` | `WOLFSENTRY_USER_SETTINGS_FILE` | A substitute settings file, replacing autogenerated `wolfsentry_settings.h` |
| `SINGLETHREADED` | `WOLFSENTRY_SINGLETHREADED` | Define to omit thread safety logic, and replace thread safety functions and macros with no-op macros. |
| | `WOLFSENTRY_NO_PROTOCOL_NAMES` | If defined, omit APIs for rendering error codes and source code files in human readable form. They will be rendered numerically. |
| | `WOLFSENTRY_NO_GETPROTOBY` | Define to disable lookup and rendering of protocols and services by name. |
| | `WOLFSENTRY_NO_ERROR_STRINGS` | If defined, omit APIs for rendering error codes and source code files in human readable form. They will be rendered numerically. |
| | `WOLFSENTRY_NO_MALLOC_BUILTINS` | If defined, omit built-in heap allocator primitives; the `wolfsentry_host_platform_interface` supplied to wolfSentry APIs must include implementations of all functions in `struct wolfsentry_allocator`. |
| | `WOLFSENTRY_HAVE_NONGNU_ATOMICS` | Define if gnu-style atomic intrinsics are not available. `WOLFSENTRY_ATOMIC_*()` macro definitions for intrinsics will need to be supplied in `WOLFSENTRY_USER_SETTINGS_FILE` (see `wolfsentry_util.h`). |
| | `WOLFSENTRY_NO_CLOCK_BUILTIN` | If defined, omit built-in time primitives; the `wolfsentry_host_platform_interface` supplied to wolfSentry APIs must include implementations of all functions in `struct wolfsentry_timecbs`. |
| | `WOLFSENTRY_NO_SEM_BUILTIN` | If defined, omit built-in semaphore primitives; the `wolfsentry_host_platform_interface` supplied to wolfSentry APIs must include implementations of all functions in `struct wolfsentry_semcbs`. |
| | `WOLFSENTRY_USE_NONPOSIX_SEMAPHORES` | Define if POSIX semaphore API is not available. If no non-POSIX builtin implementation is present in `wolfsentry_util.c`, then #WOLFSENTRY_NO_SEM_BUILTIN must be set, and the `wolfsentry_host_platform_interface` supplied to wolfSentry APIs must include a full semaphore implementation (shim set) in its `wolfsentry_semcbs` slot. |
| | `WOLFSENTRY_SEMAPHORE_INCLUDE` | Define to the path of a header file declaring a semaphore API. |
| | `WOLFSENTRY_USE_NONPOSIX_THREADS` | Define if POSIX thread API is not available. `WOLFSENTRY_THREAD_INCLUDE`, `WOLFSENTRY_THREAD_ID_T`, and `WOLFSENTRY_THREAD_GET_ID_HANDLER` will need to be defined. |
| | `WOLFSENTRY_THREAD_INCLUDE` | Define to the path of a header file declaring a threading API. |
| | `WOLFSENTRY_THREAD_ID_T` | Define to the appropriate type analogous to POSIX `pthread_t`. |
| | `WOLFSENTRY_THREAD_GET_ID_HANDLER` | Define to the name of a void function analogous to POSIX `pthread_self`, returning a value of type `WOLFSENTRY_THREAD_ID_T`. |
| | `FREERTOS` | Build for FreeRTOS |

### Build and Self-Test Examples

Building and testing libwolfsentry.a on Linux:

`make -j test`

Build verbosely:

`make V=1 -j test`

Build with artifacts in an alternate location (outside or in a subdirectory of the source tree):

`make BUILD_TOP=./build -j test`

Install from an alternate build location to a non-standard destination:

`make BUILD_TOP=./build INSTALL_DIR=/usr INSTALL_LIBDIR=/usr/lib64 install`

Build libwolfsentry.a and test it in various configurations:

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

`make -j SINGLETHREADED=1 NO_STDIO=1 DEBUG= OPTIM=-Os EXTRA_CFLAGS="-DWOLFSENTRY_NO_CLOCK_BUILTIN -DWOLFSENTRY_NO_MALLOC_BUILTIN -DWOLFSENTRY_NO_ERROR_STRINGS -Wno-error=inline -Wno-inline"`

Build and test with user settings:

`make -j USER_SETTINGS_FILE=user_settings.h test`

Build for FreeRTOS on ARM32, assuming FreeRTOS and lwIP source trees are located as shown:

`make -j HOST=arm-none-eabi RUNTIME=FreeRTOS-lwIP FREERTOS_TOP=../third/FreeRTOSv202212.00 LWIP_TOP=../third/lwip EXTRA_CFLAGS=-mcpu=cortex-m7`


## Project Examples

In the `wolfsentry/examples/` subdirectory are a set of example ports and
applications, including a demo pop-up notification system implementing a toy
TLS-enabled embedded web server, integrating with the Linux D-Bus facility.

More comprehensive examples of API usage are in
`tests/unittests.c`, particularly `test_static_routes()`, `test_dynamic_rules()`,
and `test_json()`, and the JSON configuration files at `tests/test-config*.json`.

In [the wolfSSL repository](https://github.com/wolfSSL/wolfssl), see code in
`wolfssl/test.h` gated on `WOLFSSL_WOLFSENTRY_HOOKS`, including
`wolfsentry_store_endpoints()`, `wolfSentry_NetworkFilterCallback()`,
`wolfsentry_setup()`, and `tcp_connect_with_wolfSentry()`.  See also code in
`examples/server/server.c` and `examples/client/client.c` gated on
`WOLFSSL_WOLFSENTRY_HOOKS`.  Configure wolfssl with `--enable-wolfsentry` to
build with wolfSentry integration, and use `--with-wolfsentry=/the/install/path`
if wolfSentry is installed in a nonstandard location.  The wolfSSL test
client/server can be loaded with user-supplied wolfSentry JSON configurations
from the command line, using `--wolfsentry-config <file>`.
