# wolfSentry -- the wolfSSL IDPS

## Description

wolfSentry is the wolfSSL IDPS (Intrusion Detection and Prevention System).  It
is mainly used as a library, but can also be used as part of a kernel module.

At a high level, wolfSentry is a dynamically configurable logic hub, arbitrarily associating user-defined events with user-defined actions, contextualized by connection attributes, tracking the evolution of the client-server relationship. At a low level, wolfSentry is an embedded firewall engine (both static and fully dynamic), with O(log n) lookup of known hosts/netblocks.

wolfSentry will be fully integrated into the wolfSSL library, wolfMQTT, and wolfSSH, with optional in-tree call-ins and callbacks that give application developers turnkey IDPS across all network-facing wolfSSL products, with a viable zero-configuration option. These integrations will be available via simple --enable-wolfidps configure options in wolfSSL sibling products.

The wolfSentry engine will be dynamically configurable programmatically through an API, or from a textual input file supplied to the engine. Callback and client-server implementations will also be supplied that deliver advanced capabilities including remote logging through MQTT or syslog, and remote configuration and status queries, all cryptographically secured.

Notably, wolfSentry is designed from the ground up to function well in resource-constrained, bare-metal, and realtime environments, with algorithms to stay within designated maximum memory footprints and maintain deterministic throughput. Opportunities include RTOS IDPS, and IDPS for ARM silicon and other common embedded CPUs and MCUs. wolfSentry with dynamic firewalling can add as little as 64k to the code footprint, and 32k to the volatile state footprint, and can fully leverage the existing logic and state of applications and sibling libraries.


## Dependencies

In its default build, wolfSentry depends on a POSIX runtime, specifically the
heap allocator, clock_gettime, stdio, semaphore, and string APIs.  However,
these dependencies can be avoided with various build-time options.  In
particular, the recipe

```
make -f Makefile.minimal STATIC=1 SINGLETHREADED=1 EXTRA_CFLAGS='-DWOLFSENTRY_NO_STDIO -DWOLFSENTRY_NO_CLOCK_BUILTIN -DWOLFSENTRY_NO_MALLOC_BUILTIN'
```

generates a libwolfsentry.a that depends on only a handful of basic string
functions.  Allocator and time callbacks must then be set in a `struct
wolfsentry_host_platform_interface` supplied to `wolfsentry_init()`.


## Building and testing using Makefile.minimal

Build and test libwolfsentry.a:

`make -j -f Makefile.minimal test`

Build libwolfsentry.a and test it under valgrind:

`make -j -f Makefile.minimal valgrind`

Build and test libwolfsentry.a without support for multithreading:

`make -j -f Makefile.minimal WOLFSENTRY_SINGLETHREADED=1 test`

(Other available make flags are STATIC=1 and STRIPPED=1

Build and test libwolfsentry.a with extra C flags:

`make -j -f Makefile.minimal EXTRA_CFLAGS=-DWOLFSENTRY_NO_ERROR_STRINGS test`


## Building and testing using autotools

To Do


## Examples

See examples/server/server.c (sections gated on `WOLFSSL_WOLFSENTRY_HOOKS`) in
[wolfSSL PR#3889](https://github.com/wolfSSL/wolfssl/pull/3889).  Use `configure
--enable-wolfsentry` to build with wolfSentry integration.
