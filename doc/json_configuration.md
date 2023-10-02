# Configuring wolfSentry using a JSON document


Most of the capabilities of wolfSentry can be configured, and dynamically
reconfigured, by supplying JSON documents to the library.  To use this
capability, add the following to wolfSentry initialization in the application:
<br>
```
#include <wolfsentry/wolfsentry_json.h>
```

After initialization and installation of application-supplied callbacks (if any), call one of the APIs to load the config:

* `wolfsentry_config_json_oneshot()`
* `wolfsentry_config_json_oneshot_ex()`, with an additional `json_config` arg
  for fine control of JSON parsing (see `struct JSON_CONFIG` in `wolfsentry/centijson_sax.h`)
* streaming API:
    * `wolfsentry_config_json_init()` or `wolfsentry_config_json_init_ex()`
    * `wolfsentry_config_json_feed()`
    * `wolfsentry_config_json_fini()`

See `wolfsentry/wolfsentry_json.h` for details on arguments.


## JSON Basics

wolfSentry configuration uses standard JSON syntax as defined in RFC 8259, as
restricted by RFC 7493, with certain additional requirements.  In particular,
certain sections in the JSON document are restricted in their sequence of
appearance.

* `"wolfsentry-config-version"` shall appear first, and each event definition shall
appear before any definitions for events, routes, or default policies that refer
to it through `"aux-parent-event"`, `"parent-event"`, or `"default-event"` clauses.

* Within event definitions, the `"label"`, `"priority"`, and `"config"`
elements shall appear before any other elements.

These sequence constraints are necessary to allow for high efficiency SAX-style
(sequential-incremental) loading of the configuration.

All wildcard flags are implicitly set on routes, and are cleared for fields with
explicit assignments in the configuration.  For example, if a route designates a
particular `"family"`, then `WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD` will be
implicitly cleared.  Thus, wildcard flags need not be explicitly set or
cleared in route definitions.

Note that certain element variants may be unavailable due to build settings:

* `address_family_name`: available if `defined(WOLFSENTRY_PROTOCOL_NAMES)`
* `route_protocol_name`: available if `!defined(WOLFSENTRY_NO_GETPROTOBY)`
* `address_port_name`: available if `!defined(WOLFSENTRY_NO_GETPROTOBY)`
* `json_value_clause`: available if `defined(WOLFSENTRY_HAVE_JSON_DOM)`

Caller-supplied event and action labels shall not begin with
`WOLFSENTRY_BUILTIN_LABEL_PREFIX` (by default `"%"`), as these are reserved for
built-ins.

`"config-update"` allows the default configuration to be updated.  It is termed an
“update” because wolfSentry is initially configured by the `config` argument to
`wolfsentry_init()` (which can be passed in `NULL`, signifying built-in
defaults).  Note that times (`config.penaltybox_duration` and
`config.route_idle_time_for_purge`) shall be passed to `wolfsentry_init()`
denominated in seconds, notwithstanding the `wolfsentry_time_t` type of the
members.

## JSON load flags

The `flags` argument to `wolfsentry_config_json_init()` and
`wolfsentry_config_json_oneshot()`, constructed by bitwise-or, changes the way
the JSON is processed, as follows:

* `WOLFSENTRY_CONFIG_LOAD_FLAG_NONE` -- Not a flag, but all-zeros, signifying default behavior:  The wolfSentry core is locked, the current configuration is flushed, and the new configuration is loaded incrementally.  Any error during load leaves wolfSentry in an undefined state that can be recovered with a subsequent flush and load that succeeds.

* `WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH` -- Inhibit initial flush of configuration, to allow incremental load.  Error during load leaves wolfSentry in an undefined state that can only be recovered with a subsequent flush and load that succeeds, unless `WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN` or `WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT` was also supplied.

* `WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN` -- Load into a temporary configuration, and deallocate before return.  Running configuration is unchanged.

* `WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT` -- Load into a newly allocated configuration, and install it only if load completes successfully.  On error, running configuration is unchanged.  On success, the old configuration is deallocated.

* `WOLFSENTRY_CONFIG_LOAD_FLAG_NO_ROUTES_OR_EVENTS` -- Inhibit loading of `"routes"` and `"events"` sections in the supplied JSON.

* `WOLFSENTRY_CONFIG_LOAD_FLAG_FLUSH_ONLY_ROUTES` -- At beginning of load process, retain all current configuration except for routes, which are flushed.  This is convenient in combination with `wolfsentry_route_table_dump_json_*()` for save/restore of dynamically added routes.

* `WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_ABORT` -- When processing user-defined JSON values, abort load on duplicate keys.
* `WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_USEFIRST` -- When processing user-defined JSON values, for any given key in an object use the first occurrence encountered.
* `WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_USELAST` -- When processing user-defined JSON values, for any given key in an object use the last occurrence encountered.
* `WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_MAINTAINDICTORDER` -- When processing user-defined JSON values, store sequence information so that subsequent calls to `wolfsentry_kv_render_value()` or `json_dom_dump(..., JSON_DOM_DUMP_PREFERDICTORDER)` render objects in their supplied sequence, rather than lexically sorted.

Note that `WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_*` flags are allowed only if `WOLFSENTRY_HAVE_JSON_DOM` is defined in the build, as it is with default settings.

## Overview of JSON syntax

Below is a JSON “lint” pseudodocument demonstrating all available configuration
nodes, with value specifiers that refer to the ABNF definitions below.  The
allowed values are as in the ABNF formal syntax later in this document.
<br>
```
{
    "wolfsentry-config-version" : 1,
    "config-update" : {
        "max-connection-count" : uint32,
        "penalty-box-duration" : duration,
        "route-idle-time-for-purge" : duration,
        "derog-thresh-for-penalty-boxing" : uint16,
        "derog-thresh-ignore-commendable" : boolean,
        "commendable-clears-derogatory" : boolean,
        "route-flags-to-add-on-insert" : route_flag_list,
        "route-flags-to-clear-on-insert" : route_flag_list,
        "action-res-filter-bits-set" : action_res_flag_list,
        "action-res-filter-bits-unset" : action_res_flag_list,
        "action-res-bits-to-add" : action_res_flag_list,
        "action-res-bits-to-clear" : action_res_flag_list,
        "max-purgeable-routes" : uint32
    },
    "events" : [
       { "label" : label,
         "priority" : uint16,
         "config" : {
            "max-connection-count" : uint32,
            "penalty-box-duration" : duration,
            "route-idle-time-for-purge" : duration,
            "derog-thresh-for-penalty-boxing" : uint16,
            "derog-thresh-ignore-commendable" : boolean,
            "commendable-clears-derogatory" : boolean,
            "route-flags-to-add-on-insert" : route_flag_list,
            "route-flags-to-clear-on-insert" : route_flag_list,
            "action-res-filter-bits-set" : action_res_flag_list,
            "action-res-filter-bits-unset" : action_res_flag_list,
            "action-res-bits-to-add" : action_res_flag_list,
            "action-res-bits-to-clear" : action_res_flag_list
         },
         "aux-parent-event"  : label,
         "post-actions" : action_list,
         "insert-actions" : action_list,
         "match-actions" : action_list,
         "update-actions" : action_list,
         "delete-actions" : action_list,
         "decision-actions" : action_list
      }
    ],
    "default-policies" : {
        "default-policy" : default_policy_value,
        "default-event" ":" label
    },
    "routes" : [
      {
        "parent-event" : label,
        "af-wild" : boolean,
        "raddr-wild" : boolean,
        "rport-wild" : boolean,
        "laddr-wild" : boolean,
        "lport-wild" : boolean,
        "riface-wild" : boolean,
        "liface-wild" : boolean,
        "tcplike-port-numbers" : boolean,
        "direction-in" : boolean,
        "direction-out" : boolean,
        "penalty-boxed" : boolean,
        "green-listed" : boolean,
        "dont-count-hits" : boolean,
        "dont-count-current-connections" : boolean,
        "port-reset" : boolean,

        "family" : address_family,
        "protocol" : route_protocol,
        "remote" : {
          "interface" : uint8,
          "address" : route_address,
          "prefix-bits" : uint16,
          "port" : endpoint_port
        },
        "local" : {
          "interface" : uint8,
          "address" : route_address,
          "prefix-bits" : uint16,
          "port" : endpoint_port
        }
      }
    ],
    "user-values" : {
      label : null,
      label : true,
      label : false,
      label : number_sint64,
      label : number_float,
      label : string,
      label : { "uint" : number_uint64 },
      label : { "sint" : number_sint64 },
      label : { "float" : number_float },
      label : { "string" : string_value },
      label : { "base64" : base64_value },
      label : { "json" : json_value }
    }
}
```

## Descriptions of elements

<b>`wolfsentry-config-version`</b> -- Shall appear first, with the value `1`.

<b>`config-update`</b> -- Sets default and global parameters.  The default parameters apply to routes that have no parent event, or a parent event with no config of its own.

* <b>`max-connection-count`</b> -- If nonzero, the concurrent connection limit, beyond which additional connection requests are rejected.

* <b>`penalty-box-duration`</b> -- If nonzero, the duration that a route stays in penalty box status before automatic release.

* <b>`derog-thresh-for-penalty-boxing`</b> -- If nonzero, the threshold at which accumulated derogatory counts (from `WOLFSENTRY_ACTION_RES_DEROGATORY` incidents) automatically penalty boxes a route.

* <b>`derog-thresh-ignore-commendable`</b> -- If true, then counts from `WOLFSENTRY_ACTION_RES_COMMENDABLE` are not subtracted from the derogatory count when checking for automatic penalty boxing.

* <b>`commendable-clears-derogatory`</b> -- If true, then each count from `WOLFSENTRY_ACTION_RES_COMMENDABLE` zeroes the derogatory count.

* <b>`max-purgeable-routes`</b> -- Global limit on the number of ephemeral routes to allow in the route table, beyond which the least recently matched ephemeral route is forced out early.  Not allowed in <b>`config`</b> clauses of events.

* <b>`route-idle-time-for-purge`</b> -- If nonzero, the time after the most recent dispatch match for a route to be garbage-collected.  Useful primarily in <b>`config`</b> clauses of events (see <b>`events`</b> below).

* <b>`route-flags-to-add-on-insert`</b> -- List of route flags to set on new routes upon insertion.  Useful primarily in <b>`config`</b> clauses of events (see <b>`events`</b> below).

* <b>`route-flags-to-clear-on-insert`</b> -- List of route flags to clear on new routes upon insertion.  Useful primarily in <b>`config`</b> clauses of events (see <b>`events`</b> below).

* <b>`action-res-filter-bits-set`</b> -- List of `action_res` flags that must be set at lookup time (dispatch) for referring routes to match.  Useful primarily in <b>`config`</b> clauses of events (see <b>`events`</b> below).

* <b>`action-res-filter-bits-unset`</b> -- List of `action_res` flags that must be clear at lookup time (dispatch) for referring routes to match.  Useful primarily in <b>`config`</b> clauses of events (see <b>`events`</b> below).

* <b>`action-res-bits-to-add`</b> -- List of `action_res` flags to be set upon match.

* <b>`action-res-bits-to-clear`</b> -- List of `action_res` flags to be cleared upon match.


<b>`events`</b> -- The list of events with their respective definitions.  This section can appear more than once, but any given event definition shall precede any definitions that refer to it.

Each event is composed of the following elements, all of which are optional except for <b>`label`</b>.  <b>`label`</b>, <b>`priority`</b>, and <b>`config`</b> shall appear before the other elements.

* <b>`label`</b> -- The name by which the event is identified.  See the definition of `label` in the ABNF grammar below for permissible values.

* <b>`priority`</b> -- The priority of routes that have this event as their <b>`parent-event`</b> (see <b>`routes`</b> below).  Lower number means higher priority.

* <b>`config`</b> -- The configuration to associate with routes with this <b>`parent-event`</b>, as above for <b>`config-update`</b>.

* <b>`aux-parent-event`</b> -- An event reference for use by action handlers, e.g. built-in `"%track-peer-v1"` creates routes with <b>`aux-parent-event`</b> as the new route's <b>`parent-event`</b>.

* <b>`post-actions`</b> -- List of actions to take when this event is passed via <b>`event_label`</b> to a dispatch routine such as `wolfsentry_route_event_dispatch()`.

* <b>`insert-actions`</b> -- List of actions to take when a route is inserted with this event as <b>`parent-event`</b>.

* <b>`match-actions`</b> -- List of actions to take when a route is matched by a dispatch routine, and the route has this event as its <b>`parent-event`</b>.

* <b>`update-actions`</b> -- List of actions to take when a route has a status update, such as a change of penalty box status, and has this event as its <b>`parent-event`</b>.

* <b>`delete-actions`</b> -- List of actions to take when a route is deleted, and has this event as its <b>`parent-event`</b>.

* <b>`decision-actions`</b> -- List of actions to take when dispatch final decision (final value of <b>`action_results`</b>) is determined, and the matched route has this event as its <b>`parent-event`</b>.

<b>`default-policies`</b> -- The global fallthrough default policies for dispatch routines such as `wolfsentry_route_event_dispatch()`.

* <b>`default-policy`</b> -- A simple <b>`action_result`</b> flag to set by default, either **accept**, **reject**, or **reset**, the latter of which causes generation of TCP reset and ICMP unreachable reply packets where relevant.

* <b>`default-event`</b> -- An event to use when a dispatch routine is called with a null <b>`event_label`</b>.

<b>`routes`</b> -- The list of routes with their respective definitions.  This section can appear more than once.

Each route is composed of the following elements, all of which are optional.

* <b>`parent-event`</b> -- The event whose attributes determine the dynamics of the route.

* <b>`family`</b> -- The address family to match.  See `address_family` definition in the ABNF grammar below for permissible values.

* <b>`protocol`</b> -- The protocol to match.  See `route_protocol` definition in the ABNF grammar below for permissible values.

* <b>`remote`</b> -- The attributes to match for the remote endpoint of the traffic.
    * <b>`interface`</b> -- Network interface ID, as an arbitrary integer chosen and used consistently by the caller or IP stack integration.
    * <b>`address`</b> -- The network address, in idiomatic form.  IPv4, IPv6, and MAC addresses shall enumerate all octets.  See `route_address` definition in the ABNF grammar below for permissible values.
    * <b>`prefix-bits`</b> -- The number of bits in the <b>`address`</b> that traffic must match.
    * <b>`port`</b> -- The port number that traffic must match.

* <b>`local`</b> -- The attributes to match for the local endpoint of the traffic.  The same nodes are available as for <b>`remote`</b>.
* <b>`direction-in`</b> -- If true, match inbound traffic.
* <b>`direction-out`</b> -- If true, match outbound traffic.
* <b>`penalty-boxed`</b> -- If true, traffic matching the route is penalty boxed (rejected or reset).
* <b>`green-listed`</b> -- If true, traffic matching the route is accepted.
* <b>`dont-count-hits`</b> -- If true, inhibit statistical bookkeeping (no effect on dynamics).
* <b>`dont-count-current-connections`</b> -- If true, inhibit tracking of concurrent connections, so that <b>`max-connection-count`</b> has no effect on traffic matching this route.
* <b>`port-reset`</b> -- If true, set the `WOLFSENTRY_ACTION_RES_PORT_RESET` flag in the <b>`action_results`</b> when this route is matched, causing TCP reset or ICMP unreachable reply packet to be generated if IP stack integration is activated (e.g. `wolfsentry_install_lwip_filter_callbacks()`).

<b>`user-values`</b> -- One or more sections of fully user-defined data available to application code for any use.  Each key is a label as defined in the ABNF grammar below.  The value can be any of:

* <b>`null`</b>
* <b>`true`</b>
* <b>`false`</b>
* an integral number, implicitly a signed 64 bit integer
* a floating point number, as defined in the ABNF grammar below for `number_float`
* a quoted string allowing standard JSON escapes
* any of several explicitly typed constructs, with values as defined in the ABNF grammar below.
    * `{ "uint" : number_uint64 }`
    * `{ "sint" : number_sint64 }`
    * `{ "float" : number_float }`
    * `{ "string" : string_value }`
    * `{ "base64" : base64_value }`
    * `{ "json" : json_value }`


## Formal ABNF grammar

Below is the formal ABNF definition of the configuration syntax and permitted values.

This definition uses ABNF syntax as prescribed in RFC 5234 and 7405, except:

* Whitespace is ignored, as provided in RFC 8259.

* a `-` operator is added, accepting a quoted literal string or a group of literal characters, to provide for omitted character(s) in the target text (here, trailing comma separators) by performing all notional matching operations of the containing group up to that point with the target text notionally extended with the argument to the operator.

The length limits used in the definition assume the default values in
wolfsentry_settings.h, 32 octets for labels (`WOLFSENTRY_MAX_LABEL_BYTES`), and
16384 octets for user-defined values (`WOLFSENTRY_KV_MAX_VALUE_BYTES`).  These
values can be overridden at build time with user-supplied values.
<br>
```
"{"
    DQUOTE %s"wolfsentry-config-version" DQUOTE ":" uint32
    [ "," DQUOTE %s"config-update" DQUOTE ":" top_config_list "," ]
    *("," DQUOTE %s"events" ":" "["
       event *("," event)
    "]")
    [ "," DQUOTE %s"default-policies" DQUOTE ":" "{"
        default_policy_item *("," default_policy_item)
    "}" ]
    *("," DQUOTE %s"routes" DQUOTE ":" "["
        route *("," route)
    "]")
    *("," DQUOTE %s"user-values" DQUOTE ":" "{"
        user_item *("," user_item)
    "}")
"}"

event = "{" label_clause
        [ "," priority_clause ]
        [ "," event_config_clause ]
        [ "," aux_parent_event_clause ]
        *("," action_list_clause) "}"

default_policy_item =
        (DQUOTE %s"default-policy" DQUOTE ":" default_policy_value) /
        (DQUOTE %s"default-event" DQUOTE ":" label)

default_policy_value = (%s"accept" / %s"reject" / %s"reset")

label_clause = DQUOTE %s"label" DQUOTE ":" label

priority_clause = DQUOTE %s"priority" DQUOTE ":" uint16

event_config_clause = DQUOTE %s"config" DQUOTE ":" event_config_list

aux_parent_event_clause = DQUOTE %s"aux-parent-event" DQUOTE ":" label

action_list_clause = DQUOTE (%s"post-actions" / %s"insert-actions" / %s"match-actions"
            / %s"update-actions" / %s"delete-actions" / %s"decision-actions") DQUOTE
            ":" action_list

action_list = "[" label *("," label) "]"

event_config_list = "{" event_config_item *("," event_config_item) "}"

top_config_list = "{" top_config_item *("," top_config_item) "}"

top_config_item = event_config_item / max_purgeable_routes_clause

event_config_item =
  (DQUOTE %s"max-connection-count" DQUOTE ":" uint32) /
  (DQUOTE %s"penalty-box-duration" DQUOTE ":" duration) /
  (DQUOTE %s"route-idle-time-for-purge" DQUOTE ":" duration) /
  (DQUOTE %s"derog-thresh-for-penalty-boxing" DQUOTE ":" uint16 /
  (DQUOTE %s"derog-thresh-ignore-commendable" DQUOTE ":" boolean /
  (DQUOTE %s"commendable-clears-derogatory" DQUOTE ":" boolean /
  (DQUOTE (%s"route-flags-to-add-on-insert" / %s"route-flags-to-clear-on-insert") DQUOTE ":" route_flag_list) /
  (DQUOTE (%s"action-res-filter-bits-set" / %s"action-res-filter-bits-unset" / %s"action-res-bits-to-add" / %s"action-res-bits-to-clear") DQUOTE ":" action_res_flag_list)

duration = number_sint64 / (DQUOTE number_sint64 [ %s"d" / %s"h" / %s"m" / %s"s" ] DQUOTE)

max_purgeable_routes_clause = DQUOTE %s"max-purgeable-routes" DQUOTE ":" uint32

route_flag_list = "[" route_flag *("," route_flag) "]"

action_res_flag_list = "[" action_res_flag *("," action_res_flag) "]"

route = "{"
    [ parent_event_clause "," ]
    *(route_flag_clause ",")
    [ family_clause ","
      [ route_protocol_clause "," ]
    ]
    [ route_remote_endpoint_clause "," ]
    [ route_local_endpoint_clause "," ]
    -","
"}"

parent_event_clause = DQUOTE %s"parent-event" DQUOTE ":" label
route_flag_clause = route_flag ":" boolean
family_clause = DQUOTE %s"family" DQUOTE ":" address_family
route_protocol_clause = DQUOTE %s"protocol" DQUOTE ":" route_protocol

route_remote_endpoint_clause = DQUOTE %s"remote" DQUOTE ":" route_endpoint
route_local_endpoint_clause = DQUOTE %s"local" DQUOTE ":" route_endpoint

route_endpoint = "{"
    [ route_interface_clause "," ]
    [ route_address_clause ","
      [ route_address_prefix_bits_clause "," ]
    ]
    [ route_port_clause "," ]
    -","
"}"

route_interface_clause = DQUOTE %s"interface" DQUOTE ":" uint8

route_address_clause = DQUOTE %s"address" DQUOTE ":" route_address

route_address = DQUOTE (route_address_ipv4 / route_address_ipv6 / route_address_mac / route_address_user) DQUOTE

route_address_ipv4 = uint8 3*3("." uint8)

route_address_ipv6 = < IPv6address from RFC 5954 section 4.1 >

route_address_mac = 1*2HEXDIG ( 5*5(":" 1*2HEXDIG) / 7*7(":" 1*2HEXDIG) )

route_address_user = < an address in a form recognized by a parser
                       installed with `wolfsentry_addr_family_handler_install()`
                     >

address_family = uint16 / address_family_name

address_family_name = DQUOTE ( "inet" / "inet6" / "link" / < a value recognized by wolfsentry_addr_family_pton() > ) DQUOTE

route_address_prefix_bits_clause = DQUOTE %s"prefix-bits" DQUOTE ":" uint16

route_protocol = uint16 / route_protocol_name

route_protocol_name = DQUOTE < a value recognized by getprotobyname_r(), requiring address family inet or inet6 >

route_port_clause = DQUOTE %s"port" DQUOTE ":" endpoint_port

endpoint_port = uint16 / endpoint_port_name

endpoint_port_name = DQUOTE < a value recognized by getservbyname_r() for the previously designated protocol > DQUOTE

route_flag = DQUOTE (
  %s"af-wild" /
  %s"raddr-wild" /
  %s"rport-wild" /
  %s"laddr-wild" /
  %s"lport-wild" /
  %s"riface-wild" /
  %s"liface-wild" /
  %s"tcplike-port-numbers" /
  %s"direction-in" /
  %s"direction-out" /
  %s"penalty-boxed" /
  %s"green-listed" /
  %s"dont-count-hits" /
  %s"dont-count-current-connections" /
  %s"port-reset"
) DQUOTE

action_res_flag = DQUOTE (
  %s"none" /
  %s"accept" /
  %s"reject" /
  %s"connect" /
  %s"disconnect" /
  %s"derogatory" /
  %s"commendable" /
  %s"stop" /
  %s"deallocated" /
  %s"inserted" /
  %s"error" /
  %s"fallthrough" /
  %s"update" /
  %s"port-reset" /
  %s"sending" /
  %s"received" /
  %s"binding" /
  %s"listening" /
  %s"stopped-listening" /
  %s"connecting-out" /
  %s"closed" /
  %s"unreachable" /
  %s"sock-error" /
  %s"user+0" /
  %s"user+1" /
  %s"user+2" /
  %s"user+3" /
  %s"user+4" /
  %s"user+5" /
  %s"user+6" /
  %s"user+7"
) DQUOTE

user_item = label ":" ( null / true / false / number_sint64_decimal / number_float / string / strongly_typed_user_item )

strongly_typed_user_item =
  ( "{" DQUOTE %s"uint" DQUOTE ":" number_uint64 "}" ) /
  ( "{" DQUOTE %s"sint" DQUOTE ":" number_sint64 "}" ) /
  ( "{" DQUOTE %s"float" DQUOTE ":" number_float "}" ) /
  ( "{" DQUOTE %s"string" DQUOTE ":" string_value "}" ) /
  ( "{" DQUOTE %s"base64" DQUOTE ":" base64_value "}" ) /
  json_value_clause

json_value_clause = "{" DQUOTE %s"json" DQUOTE ":" json_value "}"

null = %s"null"

true = %s"true"

false = %s"false"

boolean = true / false

number_uint64 = < decimal number in the range 0...18446744073709551615 > /
                ( DQUOTE < hexadecimal number in the range 0x0...0xffffffffffffffff > DQUOTE ) /
                ( DQUOTE < octal number in the range 00...01777777777777777777777 > DQUOTE )

number_sint64_decimal = < decimal number in the range -9223372036854775808...9223372036854775807 >

number_sint64 = number_sint64_decimal /
                ( DQUOTE < hexadecimal number in the range -0x8000000000000000...0x7fffffffffffffff > DQUOTE ) /
                ( DQUOTE < octal number in the range -01000000000000000000000...0777777777777777777777 > DQUOTE )

number_float = < floating point value in a form and range recognized by the linked strtod() implementation >

string_value = DQUOTE < any RFC 8259 JSON-valid string that decodes to at most 16384 octets > DQUOTE

base64_value = DQUOTE < any valid RFC 4648 base64 encoding that decodes to at most 16384 octets > DQUOTE

json_value = < any valid, complete and balanced RFC 8259 JSON expression, with
               keys limited to WOLFSENTRY_MAX_LABEL_BYTES (default 32 bytes),
               overall input length limited to WOLFSENTRY_JSON_VALUE_MAX_BYTES
               if set (default unset), and overall depth limited to
               WOLFSENTRY_MAX_JSON_NESTING (default 16) including the 4 parent
               levels
             >

label = DQUOTE < any RFC 8259 JSON-valid string that decodes to at at least 1 and at most 32 octets > DQUOTE

uint32 = < decimal integral number in the range 0...4294967295 >

uint16 = < decimal integral number in the range 0...65535 >

uint8 = < decimal integral number in the range 0...255 >
```
