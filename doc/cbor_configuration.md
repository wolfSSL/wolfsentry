# CBOR configuration with wolfCOSE

wolfSentry can load its normal configuration schema from CBOR through the
wolfCOSE CBOR decoder. The policy loader is shared with the JSON path, so the
same configuration keys build the same events, routes, default policies, and
user values.

Build wolfCOSE first, then enable the integration when building wolfSentry:

```sh
make -C ../wolfCOSE
make WOLFCOSE=1 WOLFCOSE_TOP=../wolfCOSE NO_JSON=1
```

`WOLFCOSE_TOP` defaults to `../wolfCOSE`. `WOLFCOSE_LIB` defaults to
`$(WOLFCOSE_TOP)/libwolfcose.a` and is linked into wolfSentry test and shared
library targets. Set it to a position-independent archive or shared wolfCOSE
library when building `BUILD_DYNAMIC=1`. Applications using the static
libraries should link wolfSentry before wolfCOSE:

```sh
cc app.o libwolfsentry.a ../wolfCOSE/libwolfcose.a -o app
```

Use `wolfsentry_config_cbor_oneshot()` to load a complete CBOR document:

```c
#include <wolfsentry/wolfsentry_cbor.h>

ret = wolfsentry_config_cbor_oneshot(
    WOLFSENTRY_CONTEXT_ARGS_OUT,
    cbor,
    cbor_len,
    WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT,
    error_buffer,
    sizeof error_buffer);
```

Load flags have the same behavior as the JSON loader. The default
`WOLFSENTRY_CONFIG_LOAD_FLAG_NONE` flushes the active configuration before
parsing, so a failed load can leave it empty or partially updated. Use
`WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT`, as above, to preserve the
active configuration when parsing fails.

The CBOR document uses the schema documented in
[`json_configuration.md`](json_configuration.md). Map keys are CBOR text
strings. Maps and arrays must have definite lengths. Text strings, unsigned and
negative integers, booleans, null, and half, single, and double precision
floating point values are accepted. Configuration map order remains
significant because the existing policy schema requires the version and some
referenced objects to appear before their uses.

The wolfCOSE decoder requires RFC 8949 preferred serialization. Integer and
length arguments must use their shortest encoding. For example, encode version
`1` as `0x01`, not `0x18 0x01`.

CBOR byte strings are accepted for route `address` and `bitmask` values. They
contain the raw address bytes in network order and must have the full width of
the selected address family, such as 4 bytes for IPv4 or 16 bytes for IPv6.
Tags, indefinite length values, and unregistered simple values are rejected.
Byte-valued user settings continue to use the existing `base64` text field.
Nested `json` user values are available when the JSON DOM is also built; a
`NO_JSON=1` build omits that DOM storage type along with the JSON parser.

`WOLFSENTRY_MAX_CBOR_NESTING` defaults to 16 and
`WOLFSENTRY_MAX_CBOR_TOTAL_LEN` defaults to 10 MiB. Define either macro in the
application settings to lower the limits for an embedded target.

The configuration policy sections can be removed independently with
`WOLFSENTRY_CONFIG_NO_ROUTES`, `WOLFSENTRY_CONFIG_NO_EVENTS`,
`WOLFSENTRY_CONFIG_NO_USER_VALUES`, and
`WOLFSENTRY_CONFIG_NO_EVENTCONFIG`. `WOLFSENTRY_CONFIG_MINIMAL` enables all
four. Disabled sections are rejected as invalid keys. The corresponding make
options are `NO_CONFIG_ROUTES`, `NO_CONFIG_EVENTS`,
`NO_CONFIG_USER_VALUES`, `NO_CONFIG_EVENTCONFIG`, and `MINIMAL_CONFIG`.

`WOLFSENTRY_CONFIG_NO_TRANSACTIONS` removes clone, dry-run, and atomic commit
support. With this option, configuration changes apply directly to the active
context and a failed load can leave a partial update. The loader rejects
`WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN` and
`WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT`. The matching make option is
`NO_CONFIG_TRANSACTIONS`.

`WOLFSENTRY_CONFIG_NO_LEGACY_EVENT_SYNTAX` removes the pre-1.4 `actions`,
`insert-event`, `match-event`, `update-event`, `delete-event`, and
`decision-event` aliases. Current action-list keys such as `post-actions` and
`match-actions` remain available. The matching make option is
`NO_CONFIG_LEGACY_EVENT_SYNTAX`.

Routes can be retained while requiring numeric address-family identifiers with
`WOLFSENTRY_CONFIG_NO_ADDR_FAMILY_NAMES`, or while omitting remote and local
endpoint objects with `WOLFSENTRY_CONFIG_NO_ROUTE_ENDPOINTS`. The corresponding
make options are `NO_CONFIG_ADDR_FAMILY_NAMES` and
`NO_CONFIG_ROUTE_ENDPOINTS`.

`WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS` removes text-number conversion from a
CBOR-only build. Numeric fields must use native CBOR integers or floating-point
values. Durations must use integer seconds, so text forms such as `"5m"` are
rejected. Numeric CAN addresses must also use CBOR integers. This option
requires `WOLFSENTRY_WOLFCOSE` and `WOLFSENTRY_NO_JSON`. The matching make
option is `NO_CONFIG_TEXT_NUMBERS`.

`WOLFSENTRY_CONFIG_NO_TEXT_ADDRESSES` removes text-address conversion from a
CBOR-only build. Route `address` and `bitmask` values must use CBOR byte strings
containing the full-width address in network order. This option requires
`WOLFSENTRY_WOLFCOSE` and `WOLFSENTRY_NO_JSON`. The matching make option is
`NO_CONFIG_TEXT_ADDRESSES`.

`WOLFSENTRY_CONFIG_NO_ERROR_MESSAGES` omits human-readable parser diagnostics.
The loader still returns its normal encoded error value, but does not write to
the supplied error buffer. Combined with native CBOR numbers, this removes the
remaining `snprintf` dependency from the CBOR configuration loader. The
matching make option is `NO_CONFIG_ERROR_MESSAGES`.

## Measured footprint

The following linked sizes were measured on x86-64 macOS with Apple Clang
`-Os` and dead section removal. The baseline also used `SINGLETHREADED=1`,
`NO_STDIO_STREAMS=1`, `NO_ADDR_BITMASK_MATCHING=1`, `NO_IPV6=1`,
`WOLFSENTRY_NO_GETPROTOBY`, and `WOLFSENTRY_NO_ERROR_STRINGS`.

| Make option | Linked bytes | Bytes saved | Removed capability |
| --- | ---: | ---: | --- |
| Full CBOR configuration | 47,822 | 0 | None |
| `NO_CONFIG_TRANSACTIONS=1` | 41,926 | 5,896 | Dry run and atomic commit |
| `NO_CONFIG_ROUTES=1` | 39,020 | 8,802 | Static route loading |
| `NO_CONFIG_ADDR_FAMILY_NAMES=1` | 43,795 | 4,027 | Named route families |
| `NO_CONFIG_ROUTE_ENDPOINTS=1` | 44,676 | 3,146 | Remote and local endpoints |
| `NO_CONFIG_EVENTS=1` | 43,713 | 4,109 | Event loading |
| `NO_CONFIG_USER_VALUES=1` | 42,602 | 5,220 | User-value loading |
| `NO_CONFIG_EVENTCONFIG=1` | 43,611 | 4,211 | Global and per-event settings |
| `MINIMAL_CONFIG=1` | 25,336 | 22,486 | Routes, events, user values, and event settings |

Each row enables one option against the full baseline. Savings overlap and are
not additive. Results vary with the target, compiler, C library, and enabled
wolfSentry features.

The recommended profile below keeps routes, endpoints, events, actions,
default policies, and event configuration for an IDPS. Each row adds one
option to the preceding row:

| Added make option | Linked bytes | Incremental saving |
| --- | ---: | ---: |
| `NO_CONFIG_USER_VALUES=1 NO_CONFIG_ADDR_FAMILY_NAMES=1` | 38,575 | 9,247 |
| `NO_CONFIG_TRANSACTIONS=1` | 32,675 | 5,900 |
| `NO_CONFIG_LEGACY_EVENT_SYNTAX=1` | 32,061 | 614 |
| `NO_CONFIG_TEXT_NUMBERS=1` | 30,459 | 1,602 |
| `NO_CONFIG_ERROR_MESSAGES=1` | 30,017 | 442 |
| `NO_CONFIG_TEXT_ADDRESSES=1` | 29,131 | 886 |

This profile is 18,691 bytes smaller than the full CBOR configuration build:

```sh
make WOLFCOSE=1 NO_JSON=1 \
    NO_CONFIG_USER_VALUES=1 \
    NO_CONFIG_ADDR_FAMILY_NAMES=1 \
    NO_CONFIG_TRANSACTIONS=1 \
    NO_CONFIG_LEGACY_EVENT_SYNTAX=1 \
    NO_CONFIG_TEXT_NUMBERS=1 \
    NO_CONFIG_TEXT_ADDRESSES=1 \
    NO_CONFIG_ERROR_MESSAGES=1
```

## Measured loading speed

A one-route policy was loaded repeatedly into an existing single-threaded
context using the same `-Os` test host. The JSON policy was 261 bytes and the
equivalent CBOR policy was 195 bytes. Results are medians of seven runs with
20,000 complete policy loads per run:

| Input | Median time per load | Relative throughput |
| --- | ---: | ---: |
| JSON text | 3.07 microseconds | 1.00x |
| Native-number, binary-address CBOR | 1.64 microseconds | 1.88x |

For this policy, optimized CBOR reduced load time by 47 percent. The result
includes decoding, flushing the old policy, and constructing the new route.
Target-specific results will vary.

## Using an authenticated COSE payload

`wolfsentry_config_cbor_oneshot()` consumes plain CBOR and does not verify a
signature or MAC. Verify the COSE envelope first, then pass the authenticated
payload returned by wolfCOSE to wolfSentry. For a `COSE_Sign1` message:

```c
ret = wc_CoseSign1_Verify(
    &key, cose, cose_len,
    NULL, 0, NULL, 0,
    scratch, sizeof scratch,
    &headers, &payload, &payload_len);
if (ret == WOLFCOSE_SUCCESS) {
    ret = wolfsentry_config_cbor_oneshot(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        payload, payload_len,
        WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT,
        error_buffer, sizeof error_buffer);
}
```

The returned payload points into the COSE input buffer, so keep that buffer
valid until `wolfsentry_config_cbor_oneshot()` returns.

## Testing build options

`make wolfcose-test` builds and runs the unit tests once for each supported
wolfCOSE build option, using the wolfCOSE tree at `WOLFCOSE_TEST_TOP`
(default `../wolfCOSE`). Run a single option with its own target, such as
`make wolfcose-no-routes-test` or `make wolfcose-dynamic-test`. The targets
skip when wolfCOSE is absent unless `WOLFCOSE_REQUIRED=1` is set.
