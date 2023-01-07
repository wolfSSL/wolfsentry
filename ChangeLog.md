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
