# wolfSentry Release 0.4.0 (May 27, 2022)

Preview Release 0.4.0 of the wolfSentry embedded firewall/IDPS has bug fixes and new features including:

## New Features

* User-defined key-value pairs in JSON configuration: allows user plugins to access custom config parameters in the wolfSentry config using the new wolfsentry_user_value_*() family of API functions.  Binary configuration data can be supplied in the configuration using base64 encoding, and are decoded at parse time and directly available to user plugins in the original raw binary form.  The key-value facility also supports a custom validator callback to enforce constraints on user-defined config params in the JSON.

* User-defined address families: allows user plugins for custom address families and formats, using new wolfsentry_addr_family_*() API routines.  This allows idiomatic formats for non-Internet addresses in the JSON config, useful for various buses and device namespaces.

* Formalization of the concepts of default events and fallthrough rules in the route tables.

* A new subevent action list facility to support logging and notifications around the final decisions of the rule engine, alongside the existing subevents for rule insertions, matches, and deletions.

* The main plugin interface (wolfsentry_action_callback_t) now passes two separate routes, a "trigger_route" with full attributes of the instant traffic, and a "rule_route" that matches that traffic.  In dynamic rule scenarios, plugins can manipulate the passed rule_route and set the WOLFSENTRY_ACTION_RES_INSERT bit in the to define a new rule that will match the traffic thereafter.  All actions in the chain retain readonly access to the unmodified trigger route for informational purposes.

* The JSON DOM facility from CentiJSON is now included in the library by default (disabled by make NO_JSON_DOM=1), layered on the SAX facility used directly by the wolfSentry core to process the JSON config package.  The DOM facility can be used as a helper in user plugins and applications, for convenient JSON parsing, random access, and production.


## Noteworthy Changes

* In the JSON config, non-event-specific members of top level node "config-update" node have been moved to the new top level node "default-policies", which must appear after "event-insert".  "default-policies" members are "default-policy-static", "default-policy-dynamic", "default-event-static", and "default-event-dynamic".


## Bug Fixes

* In wolfsentry_config_json_init(), properly copy the load_flags from the caller into the _json_process_state.

* The JSON SAX API routines (wolfsentry/centijson_sax.h) are now properly exported.


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


* Autogeneration and inclusion of wolfsentry_options.h, synchronizing applications with wolfSentry library options as built.

* New APIs `wolfsentry_route_event_dispatch_[by_id]with_inited_result()`, for easy caller designation of known traffic attributes, e.g. `WOLFSENTRY_ACTION_RES_CONNECT` or `WOLFSENTRY_ACTION_RES_DISCONNECT`.

* Efficient support for aligned heap allocations on targets that don't have a native aligned allocation API: `wolfsentry_free_aligned_cb_t`, `wolfsentry_allocator.free_aligned`, `wolfsentry_builtin_free_aligned()`, `wolfsentry_free_aligned()`, and `WOLFSENTRY_FREE_ALIGNED()`.

* Semaphore wrappers for FreeRTOS, for use by the `wolfsentry_lock_*()` shareable-upgradeable lock facility.


## Bug Fixes


* `wolfsentry_route_event_dispatch_1()`: don't impose `config.penaltybox_duration` on routes with `route->meta.last_penaltybox_time == 0`.

* trivial fixes for backward compat with gcc-5.4.0, re `-Wconversion` and `-Winline`.


Please send questions or comments to douzzer@wolfssl.com
