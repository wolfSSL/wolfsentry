# wolfSentry Release 1.4.0 (July 17, 2023)

Release 1.4.0 of the wolfSentry embedded firewall/IDPS has bug fixes and improvements including:

## New Features

Routes can now be configured to match traffic with designated `action_results`
bit constraints, and can be configured to update `action_results` bits, by
inserting the route with a parent event that has the desired configuration.
Parent events can now also be configured to add or clear route flags for all
routes inserted with that parent event.

Added new `aux_event` mechanism to facilitate distinct configurations for a
static generator route and the narrower ephemeral routes dynamically created
when it is matched.

Added a new built-in action, `"%track-peer-v1"`, that can be used in combination
with the above new facilities to dynamically spawn ephemeral routes, allowing
for automatic pinhole routes, automatic adversary tracking, and easy
implementation of dynamic blocks for port scanning adversaries.

## Noteworthy Changes and Additions

Added new APIs `wolfsentry_event_set_aux_event()` and
`wolfsentry_event_get_aux_event()`.

Added flag filters and controls to `struct wolfsentry_eventconfig`, and
added corresponding clauses to JSON `"config"` sections:

* `.action_res_filter_bits_set`, "action-res-filter-bits-set"
* `.action_res_filter_bits_unset`, `"action-res-filter-bits-unset"`
* `.action_res_bits_to_add`, `"action-res-bits-to-add"`
* `.action_res_bits_to_clear`, `"action-res-bits-to-clear"`
* `.route_flags_to_add_on_insert`, `"route-flags-to-add-on-insert"`
* `.route_flags_to_clear_on_insert`, `"route-flags-to-clear-on-insert"`

Added new `WOLFSENTRY_ACTION_RES_*` (action result) flags to support filtering
matches by generic traffic type:

* `WOLFSENTRY_ACTION_RES_SENDING`
* `WOLFSENTRY_ACTION_RES_RECEIVED`
* `WOLFSENTRY_ACTION_RES_BINDING`
* `WOLFSENTRY_ACTION_RES_LISTENING`
* `WOLFSENTRY_ACTION_RES_STOPPED_LISTENING`
* `WOLFSENTRY_ACTION_RES_CONNECTING_OUT`
* `WOLFSENTRY_ACTION_RES_CLOSED`
* `WOLFSENTRY_ACTION_RES_UNREACHABLE`
* `WOLFSENTRY_ACTION_RES_SOCK_ERROR`

These flags are now passed by the lwIP
integration code in `src/lwip/packet_filter_glue.c`.  Detailed descriptions of
these and other `_ACTION_RES_` bits are in `wolfsentry/wolfsentry.h`.

Added `wolfsentry_addr_family_max_addr_bits()`, to allow programmatic
determination of whether a given address is a prefix or fully specified.

Added a family of functions to let routes be inserted directly from a prepared
`struct wolfsentry_route_exports`, and related helper functions to prepare it:

* `wolfsentry_route_insert_by_exports_into_table()`
* `wolfsentry_route_insert_by_exports()`
* `wolfsentry_route_insert_by_exports_into_table_and_check_out()`
* `wolfsentry_route_insert_by_exports_and_check_out()`
* `wolfsentry_route_reset_metadata_exports()`

Added convenience accessor/validator functions for routes:
* `wolfsentry_route_get_addrs()`
* `wolfsentry_route_check_flags_sensical()`

Refactored the event action list implementation so that the various action lists
(`WOLFSENTRY_ACTION_TYPE_POST`, `_INSERT`, `_MATCH`, `_UPDATE`, `_DELETE`, and
`_DECISION`) are represented directly in the `struct wolfsentry_event`, rather
than through a "subevent".  The related APIs
(`wolfsentry_event_action_prepend()`, `wolfsentry_event_action_append()`,
`wolfsentry_event_action_insert_after()`, `wolfsentry_event_action_delete()`,
`wolfsentry_event_action_list_start()`) each gain an additional argument,
`which_action_list`.  The old JSON grammar is still supported via internal
emulation (still tested by test-config.json).  The JSON configuration for the
new facility is `"post-actions"`, `"insert-actions"`, `"match-actions"`,
`"update-actions"`, `"delete-actions"`, and `"decision-actions"`, each optional,
and each expecting an array of zero or more actions.

Added a restriction that user-defined action and event labels can't start with
"%", and correspondingly, all built-in actions and events have labels that start
with "%".  This can be overridden by predefining
`WOLFSENTRY_BUILTIN_LABEL_PREFIX` in user settings.

Eliminated unused flag `WOLFSENTRY_ACTION_RES_CONTINUE`, as it was semantically
redundant relative to `WOLFSENTRY_ACTION_RES_STOP`.

Reduced number of available user-defined `_ACTION_RESULT_` bits from 16 to 8, to
accommodate new generic traffic bits (see above).

In `struct wolfsentry_route_metadata_exports`, changed `.connection_count`,
`.derogatory_count`, and `.commendable_count`, from `wolfsentry_hitcount_t` to
`uint16_t`, to match internal representations.  Similarly, in ` struct
wolfsentry_route_exports`, changed `.parent_event_label_len` from `size_t` to
`int` to match `label_len` arg type.

## Bug Fixes and Cleanups

Refactored internal code to avoid function pointer casts, previously used to
allow implementations with struct pointers where a handler pointer has a type
that expects `void *`.  The refactored code has shim implementations with fully
conformant signatures, that cast the arguments to pass them to the actual
implementations.  This works around over-eager analysis by the `clang` UB
sanitizer.


# wolfSentry Release 1.3.1 (July 5, 2023)

Release 1.3.1 of the wolfSentry embedded firewall/IDPS has bug fixes and improvements including:

## Bug Fixes and Cleanups

Updated lwIP patches to fix `packet_filter_event_t` checking on short-enum targets.

Fixed copying of route table header fields (table config) when cloning or rebuilding (preserve default policy etc when loading with `WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT | WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH` or `WOLFSENTRY_CONFIG_LOAD_FLAG_FLUSH_ONLY_ROUTES`).

Implemented proper locking in `wolfsentry_route_get_reference()`, and corresponding lock assertion in `wolfsentry_table_cursor_init()`.

Fixed logic in address matching to properly match zero-length addresses when peforming subnet matching, even if the corresponding `_ADDR_WILDCARD` flag bit is clear.

## Self-Test Enhancements

`Makefile.analyzers`: add `-fshort-enums` variants to `sanitize-all` and `sanitize-all-gcc` recipes, and add `short-enums-test` recipe.

Added `wolfsentry_route_event_dispatch()` cases to `test_json()`.

Added unit test coverage to confirm correct copying of route table header fields when cloning.


# wolfSentry Release 1.3 (May 19, 2023)

Release 1.3 of the wolfSentry embedded firewall/IDPS has bug fixes and improvements including:

## New Features

### Route dump to JSON

The route (rule) table can now be dumped in conformant JSON format to a byte stream, using wolfSentry intrinsics (no `stdio` dependencies), and subsequently reloaded.

  * `wolfsentry_route_table_dump_json_start()`, `_next()`, `_end()`

  * Byte streams using new `WOLFSENTRY_BYTE_STREAM_*()` macros, with stack and heap options.

  * Retryable rendering on `_BUFFER_TOO_SMALL` error, by flushing the byte stream, calling `WOLFSENTRY_BYTE_STREAM_RESET()`, and retrying the `wolfsentry_route_table_dump_json_*()` call.

  * New flag `WOLFSENTRY_CONFIG_LOAD_FLAG_FLUSH_ONLY_ROUTES`, to allow reloads that leave all event and key-value configuration intact, and only replace the routes.

## Bug Fixes and Cleanups

  * Non-threadsafe `get{proto,serv}by{name.number}()` calls (already configuration-gated) have been replaced by their `_r()` counterparts, and gated on compatible glibc.

  * Fixed an underread bug in `convert_hex_byte()` that affected parsing of MAC addresses.

## Self-Test Enhancements

  * Added `__wolfsentry_wur` to `WOLFSENTRY_LOCAL`.

  * Added new clauses in `test_json()` to verify bitwise idempotency of route table export-ingest cycles to/from JSON.

  * Added new target `notification-demo-build-test`.


# wolfSentry Release 1.2.2 (May 4, 2023)

Release 1.2.2 of the wolfSentry embedded firewall/IDPS has bug fixes and improvements including:

## Noteworthy Changes and Additions

Added C89 pedantic compatibility in core codebase, including unit tests, via `-DWOLFSENTRY_C89`.

Added error code `IO_FAILED`, returned for various stdio failures that previously returned `SYS_OP_FAILED` or went undetected.

Refined `wolfsentry_lock_unlock()` so that final unlock while holding a promotion reservation is not an error and implicitly drops the reservation.

## Bug Fixes and Cleanups

Cleanups guided by `clang-tidy` and `cppcheck`: fixed a misused retval from `posix_memalign()`, fixed overwritten retvals in `wolfsentry_lock_unlock()`, and effected myriad cleanups to improve clarity and portability.

Fixed missing assignment of `new->prev` in `wolfsentry_table_clone()`.

Fixed route metadata coherency in transactional configuration updates: add `wolfsentry_route_copy_metadata()`, and call it from `wolfsentry_context_exchange()`.

When `wolfsentry_route_event_dispatch*()` results in a default policy fallback, return `USED_FALLBACK` success code.

Properly release lock promotion reservation in `wolfsentry_config_json_init_ex()` if obtained.

Fixed several accounting bugs in the lock kernel related to promotion reservations.

Copy `fallthrough_route` pointer in `wolfsentry_route_table_clone_header()`, rather than improperly trying to clone the fallthrough route.

## Self-Test Enhancements

Added new global compiler warnings to `Makefile`:

  * `-Wmissing-prototypes`
  * `-Wdeclaration-after-statement`
  * `-Wnested-externs`
  * `-Wlogical-not-parentheses`
  * `-Wpacked-not-aligned`

Added new targets to `Makefile.analyzers`:

  * `clang-tidy-build-test`
  * `cppcheck-analyze`
  * `c89-test`
  * `m32-c89-test`
  * `freertos-arm32-c89-build-test`
  * `freertos-arm32-singlethreaded-build-test`
  * `sanitize-aarch64-be-test`
  * `sanitize-all-no-inline-gcc`
  * `no-inline-test`
  * `no-alloca-test`
  * `release-check`

Added `WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH` coverage and an array of should-fail JSON objects to `unittests.c`:`test_json()`.

Added more arg-not-null and thread-inited checks to thread/lock routines in `src/wolfsentry_util.c`, and corresponding unit test coverage for all null/uninited arg permutations.

Added assert in release recipe to assure that wolfsentry.h has a version that matches the tagged version.


# wolfSentry Release 1.2.1 (Apr 5, 2023)

Release 1.2.1 of the wolfSentry embedded firewall/IDPS has bug fixes and improvements including:

## Noteworthy Changes and Additions

Added API `wolfsentry_route_render_flags()`, now used in `wolfsentry_route_render()` and `wolfsentry_route_exports_render()`.

Refactored `wolfsentry_route_lookup_0()` to consistently return the highest-priority matching route, breaking ties using `compare_match_exactness()`.

Added `DEBUG_ROUTE_LOOKUP` code paths in `wolfsentry_route_lookup_0()`, for verbose troubleshooting of configurations and internal logic.

Added to `convert_hex_byte()` (and therefore to MAC address parsing) tolerance for single-hex-digit byte values, as in `a:b:c:1:2:3`.

## Bug Fixes

Removed several inappropriate wildcard flags on queries in lwIP event handlers, particularly `_SA_LOCAL_PORT_WILDCARD` for `FILT_PORT_UNREACHABLE` and `*_INTERFACE_WILDCARD` for `FILT_BINDING`/`FILT_LISTENING`/`FILT_STOP_LISTENING` and when `event->netif` is null.

Added nullness checks for `laddr` and `raddr` in lwIP event handlers, and if null, set all-zeros address.

Refactored wildcard handling in `wolfsentry_route_init()`, `wolfsentry_route_new()`, and `wolfsentry_route_insert_1()`, to zero out wildcard fields at insert time, rather than at init time, so that routes used as targets contain accurate information for `compare_match_exactness()`, regardless of wildcard bits.

Fixed `WOLFSENTRY_VERSION_*` values, which were inadvertently swapped in release 1.2.0.


# wolfSentry Release 1.2.0 (Mar 24, 2023)

Production Release 1.2.0 of the wolfSentry embedded firewall/IDPS has bug fixes and improvements including:

## New Features

### lwIP full firewall integration

When wolfSentry is built with make options `LWIP=1
LWIP_TOP=<path-to-lwIP-source>`, the library is built with new APIs
`wolfsentry_install_lwip_filter_ethernet_callback()`,
`wolfsentry_install_lwip_filter_ip_callbacks()`,
`wolfsentry_install_lwip_filter_icmp_callbacks()`,
`wolfsentry_install_lwip_filter_tcp_callback()`,
`wolfsentry_install_lwip_filter_udp_callback()`,
and the all-on-one `wolfsentry_install_lwip_filter_callbacks()`.  For each
layer/protocol, a simple bitmask, of type `packet_filter_event_mask_t`, allows
events to be selectively filtered, with other traffic passed with negligible overhead.
For example, TCP connection requests can be fully evaluated by wolfSentry, while
traffic within established TCP connections can pass freely.

`wolfSentry LWIP=1` relies on a patchset to lwIP, gated on the macro
`LWIP_PACKET_FILTER_API`, that adds generic filter callback APIs to each layer
and protocol.  See `lwip/README.md` for details.

In addition to `LWIP_DEBUG` instrumentation, the new integration supports
`WOLFSENTRY_DEBUG_PACKET_FILTER`, which renders the key attributes and outcome
for all callout events.

## Noteworthy Changes and Additions

Routes and default actions can now be annotated to return
`WOLFSENTRY_ACTION_RES_PORT_RESET` in their `action_results`.  This is used in
the new lwIP integration to control whether TCP reset and ICMP port-unreachable
packets are sent (versus dropping the rejected packet unacknowledged).

A new `ports/` tree is added, and the former FreeRTOS/ tree is moved to
`ports/FreeRTOS-lwIP`.

New helper macros are added for managing thread state:
`WOLFSENTRY_THREAD_HEADER_DECLS`, `WOLFSENTRY_THREAD_HEADER_INIT()`,
`WOLFSENTRY_THREAD_HEADER_INIT_CHECKED()`.

New flags `WOLFSENTRY_ROUTE_FLAG_PORT_RESET` and
`WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES` to support firewall
functionalities.

## Bug Fixes

Wildcard matching in the routes/rules table now works correctly even for
non-contiguous wildcard matching.

`struct wolfsentry_sockaddr` now aligns its `addr` member to a 4 byte boundary,
for safe casting to `(int *)`, using a new `attr_align_to()` macro.

The route lookup algorithm has been improved for correct results with
non-contiguous wildcards, to correctly break ties using the new
`compare_match_exactness()`, and to correctly give priority to routes with a
matching event.

When matching target routes (e.g. with `wolfsentry_route_event_dispatch()`),
ignore failure in `wolfsentry_event_get_reference()` if
`WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD` is set in the `flags`.


# wolfSentry Release 1.1.0 (Feb 23, 2023)

Production Release 1.1.0 of the wolfSentry embedded firewall/IDPS has bug fixes and improvements including:

## New Features

Internal settings, types, alignments, constants, a complete set of internal shims, and Makefile clauses, for portability to native FreeRTOS with threads on 32 bit gcc targets.

## Noteworthy Changes and Additions

rwlock control contexts can now be allocated inside interrupt handlers, and `WOLFSENTRY_LOCK_FLAG_RETAIN_SEMAPHORE` can be supplied to the new `wolfsentry_context_lock_mutex_timed_ex()`, allowing safe trylock followed by automatic lock recursion.

API routines are now marked warn-unused-return by default, subject to user-defined override.  This new default warns on untrapped errors, to aid preventing undefined behavior.

API arguments previously accepting "long" ints for counts of seconds now expect `time_t`, for portability to ARM32 and FreeRTOS.

New unit test: `test_json_corpus`, for highly configurable bulk trial runs of the JSON processing subsystem.

New tests in `Makefile.analyzers`: `no-getprotoby-test`, `freertos-arm32-build-test`.

A new guard macro, `WOLFSENTRY_NO_GETPROTOBY`, allows narrow elimination of dependencies on `getprotobyname()` and `getprotobynumber()`.

Recursive JSON DOM tree processing logic was refactored to greatly reduce stack burden.

Substantial enlargement of code coverage by unit tests, guided by `gcov`.

New convenience macros for typical threaded state tracking wrappers: `WOLFSENTRY_THREAD_HEADER_CHECKED()` and `WOLFSENTRY_THREAD_TAILER_CHECKED()`.

## Bug Fixes

Cloning of user-defined deep JSON objects is now implemented, as needed for configuration load dry runs and load-then-commit semantics.

JSON processing of UTF-8 surrogate pairs is now fixed.

Fixed retval testing in `wolfsentry_action_list_{append,prepend,insert}_1()`, and added missing `point_action` lookup in `wolfsentry_action_list_insert_after()`.

Fixed potential use-after-free defect in `wolfsentry_event_delete()`.


# wolfSentry Release 1.0.0 (Jan 18, 2023)

Production Release 1.0.0 of the wolfSentry embedded firewall/IDPS has bug fixes and improvements including:

## Noteworthy Changes and Additions

* Makefile improvements around `wolfsentry_options.h`, and a new com-bundle rule.

* A new macro `WOLFSENTRY_USE_NONPOSIX_THREADS`, separated from `WOLFSENTRY_USE_NONPOSIX_SEMAPHORES`, supporting mixed-model targets, e.g. Mac OS X.

## Bug Fixes

* In `examples/notification-demo/log_server/log_server.c`, in `main()`, properly reset `transaction_successful` at top of the accept loop.


# wolfSentry Release 0.8.0 (Jan 6, 2023)

Preview Release 0.8.0 of the wolfSentry embedded firewall/IDPS has bug fixes and new features including:

## New Features

### Multithreaded application support

* Automatic locking on API entry, using a high performance, highly portable
  semaphore-based readwrite lock facility, with error checking and opportunistic
  lock sharing.

* Thread-specific deadlines set by the caller, limiting waits for lock
  acquisition as needed for realtime applications.

* A mechanism for per-thread private data, accessible to user plugins.

* No dependencies on platform-supplied thread-local storage.

## Updated Examples

### examples/notification-demo

* Add interrupt handling for clean error-checked shutdown in `log_server`.

* Add `/kill-server` admin command to `log_server`.

* Reduce penalty-box-duration in `notify-config.{json,h}` to 10s for demo convenience.

## Noteworthy Changes and Additions

* A new first argument to `wolfsentry_init_ex()` and `wolfsentry_init()`,
  `caller_build_settings`, for runtime error-checking of application/library
  compatibility.  This mechanism will also allow future library changes to be
  conditionalized on caller version and/or configuration expectations as needed,
  often avoiding the need for application recompilation.

* `src/util.c` was renamed to `src/wolfsentry_util.c`.

* `wolfsentry/wolfsentry_settings.h` was added, containing setup code previously in `wolfsentry/wolfsentry.h`.

* Error IDs in `enum wolfsentry_error_id` are all now negative, and a new `WOLFSENTRY_SUCCESS_ID_*` namespace was added, with positive values and supporting macros.

### New public utility APIs, macros, types, etc.

* `WOLFSENTRY_VERSION_*` macros, for version testing

* `wolfsentry_init_thread_context()`, `wolfsentry_alloc_thread_context()`, `wolfsentry_get_thread_id()`, `wolfsentry_get_thread_user_context()`, `wolfsentry_get_thread_deadline()`, `wolfsentry_get_thread_flags()`, `wolfsentry_destroy_thread_context()`, `wolfsentry_free_thread_context()`, `wolfsentry_set_deadline_rel_usecs()`, `wolfsentry_set_deadline_abs()`, `wolfsentry_clear_deadline()`, `wolfsentry_set_thread_readonly()`, `wolfsentry_set_thread_readwrite()`

* `WOLFSENTRY_DEADLINE_NEVER` and `WOLFSENTRY_DEADLINE_NOW`, used internally and for testing values returned by `wolfsentry_get_thread_deadline()`

* Many new values in the `WOLFSENTRY_LOCK_FLAG_*` set.

* `wolfsentry_lock_*()` APIs now firmed, and new `wolfsentry_context_lock_shared_with_reservation_abstimed()`.

* `WOLFSENTRY_CONTEXT_*` helper macros.

* `WOLFSENTRY_UNLOCK_*()`, `WOLFSENTRY_SHARED_*()`, `WOLFSENTRY_MUTEX_*()`, and `WOLFSENTRY_PROMOTABLE_*()` helper macros

* `WOLFSENTRY_ERROR_UNLOCK_AND_RETURN()`, `WOLFSENTRY_SUCCESS_UNLOCK_AND_RETURN()`, and related helper macros.

## Bug Fixes

* Various fixes, and additional hardening and cleanup, in the readwrite lock kernel.

* Various fixes in `Makefile`, for proper handling and installation of `wolfsentry_options.h`.


# wolfSentry Release 0.7.0 (Nov 7, 2022)

Preview Release 0.7.0 of the wolfSentry embedded firewall/IDPS has bug fixes and new features including:

## New Features

### Support for freeform user-defined JSON objects in the "user-values" (key-value pair) section of the config package.

* Uses syntax `"key" : { "json" : x }` where `x` is any valid standalone JSON
  expression.

* Key length limited to `WOLFSENTRY_MAX_LABEL_BYTES` by default.

* String length limited to `WOLFSENTRY_KV_MAX_VALUE_BYTES` by default.

* JSON tree depth limited to `WOLFSENTRY_MAX_JSON_NESTING` by default.

* All default limits subject to caller runtime override using the `json_config`
  arg to the new APIs `wolfsentry_config_json_init_ex()` and
  `wolfsentry_config_json_oneshot_ex()`, accepting a `JSON_CONFIG *` (accepted as
  `const`).

#### New APIs for JSON KVs

* `wolfsentry_user_value_store_json()`
* `wolfsentry_user_value_get_json()`
* `WOLFSENTRY_KV_V_JSON()`
* `wolfsentry_config_json_init_ex()`
* `wolfsentry_config_json_oneshot_ex()`

#### New config load flags controlling JSON KV parsing

* `WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_ABORT`
* `WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_USEFIRST`
* `WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_USELAST`
* `WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_MAINTAINDICTORDER`

### Support for setting a user KV as read-only.

* Read-only KVs can't be deleted or overwritten without first setting them
  read-write.

* Mechanism can be used to protect user-configured data from dynamic changes by
  JSON configuration package -- JSON cannot change or override the read-only
  bit.

#### KV mutability APIs:

* `wolfsentry_user_value_set_mutability()`
* `wolfsentry_user_value_get_mutability()`


## Updated Examples

### examples/notification-demo

* Update and clean up `udp_to_dbus`, and add `--kv-string` and `--kv-int`
  command line args for runtime ad hoc config overrides.

* Rename config node controlling the `udp_to_dbus` listen address from
  "notification-dest-addr" to "notification-listen-addr".

#### Added examples/notification-demo/log_server

* Toy embedded web server demonstrating HTTPS with dynamic insertion of
  limited-lifespan wolfSentry rules blocking (penalty boxing) abusive peers.

* Demonstrates mutual authentication using TLS, and role-based authorizations
  pivoting on client certificate issuer (certificate authority).


## Noteworthy Changes and Additions

* JSON strings (natively UTF-8) are now consistently passed in and out with
  `unsigned char` pointers.

* `wolfsentry_kv_render_value()` now has a `struct wolfsentry_context *` as
  its first argument (necessitated by addition of freeform JSON rendering).

* Added new API routine `wolfsentry_centijson_errcode_translate()`, allowing
  conversion of all CentiJSON return codes (e.g. from `json_dom_parse()`,
  `json_value_path()`, and `json_value_build_path()`) from native CentiJSON to
  roughly-corresponding native wolfSentry codes.

### Cleanup of JSON DOM implementation

* Added `json_` prefix to all JSON functions and types.

* CentiJSON now uses wolfSentry configured allocator for all heap operations.

### New utility APIs

* `wolfsentry_get_allocator()`
* `wolfsentry_get_timecbs()`

## Bug Fixes

* Fix error-path memory leak in JSON KV handling.

* Fix "echo: write error: Broken pipe" condition in recipe for rule "force"

* Various minor portability fixes.

* Enlarged scope for build-time pedantic warnings -- now includes all of
  CentiJSON.


# wolfSentry Release 0.6.0 (Sep 30, 2022)

Preview Release 0.6.0 of the wolfSentry embedded firewall/IDPS has bug fixes and new features including:

## New Features

### Core support for automatic penalty boxing, with configurable threshold when derogatory count reaches threshold

#### New APIs for manipulating route derogatory/commendable counts from application/plugin code:

* `wolfsentry_route_increment_derogatory_count()`
* `wolfsentry_route_increment_commendable_count()`
* `wolfsentry_route_reset_derogatory_count()`
* `wolfsentry_route_reset_commendable_count()`

#### New JSON config nodes:

* `derog-thresh-for-penalty-boxing`
* `derog-thresh-ignore-commendable`
* `commendable-clears-derogatory`

####  Automatic purging of expired routes:

* constant time garbage collection
* `wolfsentry_route_table_max_purgeable_routes_get()`
* `wolfsentry_route_table_max_purgeable_routes_set()`
* `wolfsentry_route_stale_purge_one()`

## Noteworthy Changes and Additions

* New API `wolfsentry_route_insert_and_check_out()`, allowing efficient update of route state after insert; also related new API `wolfsentry_object_checkout()`.

* New APIs `wolfsentry_route_event_dispatch_by_route()` and `wolfsentry_route_event_dispatch_by_route_with_inited_result()`, analogous to the `_by_id()` variants, but accepting a struct wolfsentry_route pointer directly.

* `wolfsentry_route_init()` and `wolfsentry_route_new()` now allow (and ignore) nonzero supplied values in wildcarded wolfsentry_sockaddr members.

* New debugging aid, make CALL_TRACE=1, gives full call stack trace with codepoints and error codes, to aid debugging of library, plugins, and configurations.

## Bug Fixes

* src/internal.c: fix wrong constant of iteration in `wolfsentry_table_ent_get_by_id()`.


# wolfSentry Release 0.5.0 (Aug 1, 2022)

Preview Release 0.5.0 of the wolfSentry embedded firewall/IDPS has bug fixes and new features including:

## New Example

#### examples/notification-demo

Added examples/notification-demo, demonstrating plugin actions, JSON event representation, and pop-up messages using the D-Bus notification facility and a middleware translation daemon.

## Noteworthy Changes

* Added new API `wolfsentry_init_ex()` with `wolfsentry_init_flags_t` argument.

* Added runtime error-checking on lock facility.

## Bug Fixes

Fix missing assignment in `wolfsentry_list_ent_insert_after()`.


# wolfSentry Release 0.4.0 (May 27, 2022)

Preview Release 0.4.0 of the wolfSentry embedded firewall/IDPS has bug fixes and new features including:

## New Features

* User-defined key-value pairs in JSON configuration: allows user plugins to access custom config parameters in the wolfSentry config using the new `wolfsentry_user_value_*()` family of API functions.  Binary configuration data can be supplied in the configuration using base64 encoding, and are decoded at parse time and directly available to user plugins in the original raw binary form.  The key-value facility also supports a custom validator callback to enforce constraints on user-defined config params in the JSON.

* User-defined address families: allows user plugins for custom address families and formats, using new `wolfsentry_addr_family_*()` API routines.  This allows idiomatic formats for non-Internet addresses in the JSON config, useful for various buses and device namespaces.

* Formalization of the concepts of default events and fallthrough rules in the route tables.

* A new subevent action list facility to support logging and notifications around the final decisions of the rule engine, alongside the existing subevents for rule insertions, matches, and deletions.

* The main plugin interface (`wolfsentry_action_callback_t`) now passes two separate routes, a "`trigger_route`" with full attributes of the instant traffic, and a "`rule_route`" that matches that traffic.  In dynamic rule scenarios, plugins can manipulate the passed `rule_route` and set the `WOLFSENTRY_ACTION_RES_INSERT` bit in the to define a new rule that will match the traffic thereafter.  All actions in the chain retain readonly access to the unmodified trigger route for informational purposes.

* The JSON DOM facility from CentiJSON is now included in the library by default (disabled by make `NO_JSON_DOM=1`), layered on the SAX facility used directly by the wolfSentry core to process the JSON config package.  The DOM facility can be used as a helper in user plugins and applications, for convenient JSON parsing, random access, and production.


## Noteworthy Changes

* In the JSON config, non-event-specific members of top level node "config-update" node have been moved to the new top level node "default-policies", which must appear after "event-insert".  "default-policies" members are "default-policy-static", "default-policy-dynamic", "default-event-static", and "default-event-dynamic".


## Bug Fixes

* In `wolfsentry_config_json_init()`, properly copy the load_flags from the caller into the `_json_process_state`.

* The JSON SAX API routines (`wolfsentry/centijson_sax.h`) are now properly exported.


# wolfSentry Release 0.3.0 (Dec 30, 2021)

Preview Release 0.3.0 of the wolfSentry embedded firewall/IDPS has bug fixes and new features including:


## New Ports and Examples


#### examples/Linux-LWIP

This demo uses Linux-hosted LWIP in Docker containers to show packet-level and connection-level filtering using wolfSentry.  Filtering can be by MAC, IPv4, or IPv6 address.  Demos include pre-accept TCP filtering, and filtering of ICMP packets.

See examples/Linux-LWIP/README.md for the installation and usage guide, and examples/Linux-LWIP/echo-config.json for the associated wolfSentry configuration.


#### FreeRTOS with LWIP on STM32

This demo is similar to Linux-LWIP, but targets the STM32 ARM core and the STM32CubeMX or STM32CubeIDE toolchain, with a FreeRTOS+LWIP runtime.  It shows wolfSentry functionality in a fully embedded (bare metal) application.

See examples/STM32/README.md for the installation and usage guide, and examples/STM32/Src/sentry.c for the compiled-in wolfSentry configuration.


## New Features


* Autogeneration and inclusion of `wolfsentry_options.h`, synchronizing applications with wolfSentry library options as built.

* New APIs `wolfsentry_route_event_dispatch_[by_id]with_inited_result()`, for easy caller designation of known traffic attributes, e.g. `WOLFSENTRY_ACTION_RES_CONNECT` or `WOLFSENTRY_ACTION_RES_DISCONNECT`.

* Efficient support for aligned heap allocations on targets that don't have a native aligned allocation API: `wolfsentry_free_aligned_cb_t`, `wolfsentry_allocator.free_aligned`, `wolfsentry_builtin_free_aligned()`, `wolfsentry_free_aligned()`, and `WOLFSENTRY_FREE_ALIGNED()`.

* Semaphore wrappers for FreeRTOS, for use by the `wolfsentry_lock_*()` shareable-upgradeable lock facility.


## Bug Fixes


* `wolfsentry_route_event_dispatch_1()`: don't impose `config.penaltybox_duration` on routes with `route->meta.last_penaltybox_time == 0`.

* trivial fixes for backward compat with gcc-5.4.0, re `-Wconversion` and `-Winline`.


Please send questions or comments to douzzer@wolfssl.com
