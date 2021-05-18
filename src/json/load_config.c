/*
 * json/load_config.c
 *
 * Copyright (C) 2021 wolfSSL Inc.
 *
 * This file is part of wolfSentry.
 *
 * wolfSentry is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSentry is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include "wolfsentry/wolfsentry_json.h"
#include "wolfsentry/wolfsentry_util.h"

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_JSON_LOAD_CONFIG_C

#include <arpa/inet.h>
#include <sys/socket.h>

#define MAX_IPV4_ADDR_BITS (sizeof(struct in_addr) * BITS_PER_BYTE)
#define MAX_IPV6_ADDR_BITS (sizeof(struct in6_addr) * BITS_PER_BYTE)
#define MAX_MAC_ADDR_BITS 64
#define MAX_ADDR_BITS (MAX_IPV6_ADDR_BITS > MAX_IPV4_ADDR_BITS ?   \
                       ((MAX_MAC_ADDR_BITS > MAX_IPV6_ADDR_BITS) ? \
                        MAX_MAC_ADDR_BITS : MAX_IPV6_ADDR_BITS) :  \
                       ((MAX_MAC_ADDR_BITS > MAX_IPV4_ADDR_BITS) ? \
                        MAX_MAC_ADDR_BITS : MAX_IPV4_ADDR_BITS))

#ifdef WOLFSENTRY_PROTOCOL_NAMES
#include <netdb.h>
#endif

#ifndef __unused
#define __unused __attribute__((unused))
#endif

/*

{

"wolfsentry-config-version" : 1,

"config-update" : {
    "max-connection-count" : number,
    "penaltybox-duration" : number|string, // allow suffixes s,m,h,d
    "default-policy" : "accept" | "reject"
},

"events-insert" : [
{
    "label" : string,
    "config" : {
        "max_connection_count" : number
        "penaltybox-duration" : number|string // allow suffixes s,m,h,d

    }
    "actions" : [ string ... ],
    "insert-event" : string,
    "match-event" : string,
    "delete-event" : string,

    "priority" : number
}
],

"static-routes-insert" : [
{
    "parent-event" : string,
    "tcplike-port-numbers" : true|false,
    "direction-in" : true|false,
    "direction-out" : true|false,
    "penaltyboxed" : true|false,
    "greenlisted" : true|false,
    "dont-count-hits" : true|false,
    "dont-count-current-connections" : true|false
    "family" : string|number,
    "protocol" : string|number,
    "remote" : {
        "port" : number,
        "address" : string,
        "prefix-bits" : number,
        "interface" : number,
    },
    "local" : {
        "port" : number,
        "address" : string,
        "prefix-bits" : number,
        "interface" : number,
    }
}
],

"actions-update" : [
{
    "label" : string,
    "flags" : {
        "disabled" : true|false
    }
}
]

}

*/


struct string_list_ent {
    struct string_list_ent *next;
    size_t string_len;
    char string[];
};

struct json_process_state {
    uint32_t config_version;

    wolfsentry_config_load_flags_t load_flags;

    enum { T_U_C_NONE = 0, T_U_C_TOPCONFIG, T_U_C_STATIC_ROUTES, T_U_C_EVENTS, T_U_C_ACTIONS } table_under_construction;

    enum { O_U_C_NONE = 0, O_U_C_SKIPLEVEL, O_U_C_ROUTE, O_U_C_EVENT, O_U_C_ACTION } object_under_construction;

    enum { S_U_C_NONE = 0, S_U_C_EVENTCONFIG, S_U_C_FLAGS, S_U_C_ACTION_LIST, S_U_C_REMOTE_ENDPOINT, S_U_C_LOCAL_ENDPOINT, S_U_C_ROUTE_METADATA } section_under_construction;

    int cur_depth;
    char cur_keyname[WOLFSENTRY_MAX_LABEL_BYTES];
    int cur_keydepth;
    JSON_INPUT_POS key_pos;

    const struct wolfsentry_host_platform_interface *hpi;

    struct wolfsentry_eventconfig default_config;
    wolfsentry_action_res_t default_policy_static;
    wolfsentry_action_res_t default_policy_dynamic;

    JSON_PARSER parser;
    struct wolfsentry_context *wolfsentry;

    union {
        struct {
            char event_label[WOLFSENTRY_MAX_LABEL_BYTES];
            int event_label_len;
            void *caller_arg; /* xxx */
            WOLFSENTRY_SOCKADDR(MAX_ADDR_BITS) remote;
            WOLFSENTRY_SOCKADDR(MAX_ADDR_BITS) local;
            wolfsentry_route_flags_t flags;
        } route;
        struct {
            char label[WOLFSENTRY_MAX_LABEL_BYTES];
            int label_len;
            wolfsentry_priority_t priority;
            struct wolfsentry_eventconfig config;
            struct string_list_ent *actions;
            char *insert_event_label;
            int insert_event_label_len;
            char *match_event_label;
            int match_event_label_len;
            char *delete_event_label;
            int delete_event_label_len;
        } event;
        struct {
            char label[WOLFSENTRY_MAX_LABEL_BYTES];
            int label_len;
            wolfsentry_action_flags_t flags;
        } action;
    } o_u_c;
};

static void free_event_state(struct json_process_state *jps) {
    struct string_list_ent *i, *i_next;
    for (i = jps->o_u_c.event.actions;
         i;
         i = i_next) {
        i_next = i->next;
        wolfsentry_free(jps->wolfsentry, i);
    }
    if (jps->o_u_c.event.insert_event_label)
        wolfsentry_free(jps->wolfsentry, jps->o_u_c.event.insert_event_label);
    if (jps->o_u_c.event.match_event_label)
        wolfsentry_free(jps->wolfsentry, jps->o_u_c.event.match_event_label);
    if (jps->o_u_c.event.delete_event_label)
        wolfsentry_free(jps->wolfsentry, jps->o_u_c.event.delete_event_label);
}

static wolfsentry_errcode_t reset_o_u_c(struct json_process_state *jps) {
    switch (jps->object_under_construction) {
    case O_U_C_NONE:
    case O_U_C_SKIPLEVEL:
        return 0;
    case O_U_C_ROUTE:
    case O_U_C_ACTION:
        break;
    case O_U_C_EVENT:
        free_event_state(jps);
        break;
    default:
        WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
    }

    memset(&jps->o_u_c, 0, sizeof jps->o_u_c);
    jps->object_under_construction = O_U_C_NONE;

    return 0;
}

static wolfsentry_errcode_t convert_uint32(JSON_TYPE type, const char *data, size_t data_size, uint32_t *out) {
    char *endptr;
    unsigned long conv;

    if (type != JSON_NUMBER)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    conv = strtoul(data, &endptr, 0);

    if ((size_t)(endptr - data) != data_size)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    if (conv > MAX_UINT_OF(*out))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    *out = (uint32_t)conv;

    return 0;
}

static wolfsentry_errcode_t convert_uint16(JSON_TYPE type, const char *data, size_t data_size, uint16_t *out) {
    char *endptr;
    unsigned long conv;

    if (type != JSON_NUMBER)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    conv = strtoul(data, &endptr, 0);

    if ((size_t)(endptr - data) != data_size)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    if (conv > MAX_UINT_OF(*out))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    *out = (uint16_t)conv;

    return 0;
}

static wolfsentry_errcode_t convert_uint8(JSON_TYPE type, const char *data, size_t data_size, uint8_t *out) {
    char *endptr;
    unsigned long conv;

    if (type != JSON_NUMBER)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    conv = strtoul(data, &endptr, 0);

    if ((size_t)(endptr - data) != data_size)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    if (conv > MAX_UINT_OF(*out))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    *out = (uint8_t)conv;

    return 0;
}

static wolfsentry_errcode_t convert_wolfsentry_duration(struct wolfsentry_context *wolfsentry, JSON_TYPE type, const char *data, size_t data_size, wolfsentry_time_t *out) {
    wolfsentry_errcode_t ret;
    char *endptr;
    long conv;

    if ((type != JSON_STRING) && (type != JSON_NUMBER))
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    conv = strtol(data, &endptr, 0);

    switch (*endptr) {
    case 'd':
        conv *= 24;
        /* fallthrough */
    case 'h':
        conv *= 60;
        /* fallthrough */
    case 'm':
        conv *= 60;
        ++endptr;
    }
    if ((size_t)(endptr - data) != data_size)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    if ((ret = wolfsentry_interval_from_seconds(wolfsentry, conv, 0 /* howlong_nsecs */, out)) < 0)
        return ret;
    else
        return 0;
}

static wolfsentry_errcode_t convert_default_policy(JSON_TYPE type, const char *data, size_t data_size, wolfsentry_action_res_t *default_policy) {
    if (type != JSON_STRING)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    if (streq(data, "accept", data_size))
        *default_policy = WOLFSENTRY_ACTION_RES_ACCEPT|WOLFSENTRY_ACTION_RES_STOP;
    else if (streq(data, "reject", data_size))
        *default_policy = WOLFSENTRY_ACTION_RES_REJECT|WOLFSENTRY_ACTION_RES_STOP;
    else
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    return 0;
}

static wolfsentry_errcode_t handle_eventconfig_clause(struct json_process_state *jps, JSON_TYPE type, const char *data, size_t data_size, struct wolfsentry_eventconfig *eventconfig) {
    if (jps->cur_depth != 2)
        WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
    if (! strcmp(jps->cur_keyname, "max-connection-count"))
        return convert_uint32(type, data, data_size, &eventconfig->max_connection_count);
    if (! strcmp(jps->cur_keyname, "penaltybox-duration"))
        return convert_wolfsentry_duration(jps->wolfsentry, type, data, data_size, &eventconfig->penaltybox_duration);
    if (jps->table_under_construction != T_U_C_TOPCONFIG)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
    if (! strcmp(jps->cur_keyname, "default-policy-static"))
        return convert_default_policy(type, data, data_size, &jps->default_policy_static);
    if (! strcmp(jps->cur_keyname, "default-policy-dynamic"))
        return convert_default_policy(type, data, data_size, &jps->default_policy_dynamic);
    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
}

static wolfsentry_errcode_t convert_sockaddr_address(JSON_TYPE type, const char *data, size_t data_size, struct wolfsentry_sockaddr *sa) {
    char d_buf[64];

    if (type != JSON_STRING)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    if (data_size >= sizeof d_buf)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);

    memcpy(d_buf, data, data_size);
    d_buf[data_size] = 0;

    if (sa->sa_family == WOLFSENTRY_AF_LINK) {
        int n = 0;
        if ((sscanf(d_buf,
                    "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%n",
                    sa->addr + 0,
                    sa->addr + 1,
                    sa->addr + 2,
                    sa->addr + 3,
                    sa->addr + 4,
                    sa->addr + 5,
                    &n) >= 6) && ((size_t)n == data_size)) {
            if (sa->addr_len == 0)
                sa->addr_len = 48;
            return 0;
        }
        if ((sscanf(d_buf,
                    "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%n",
                    sa->addr + 0,
                    sa->addr + 1,
                    sa->addr + 2,
                    sa->addr + 3,
                    sa->addr + 4,
                    sa->addr + 5,
                    sa->addr + 6,
                    sa->addr + 7,
                    &n) >= 8) && ((size_t)n == data_size)) {
            if (sa->addr_len == 0)
                sa->addr_len = 64;
            return 0;
        }
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    }
    else if (sa->sa_family == WOLFSENTRY_AF_INET) {
        switch (inet_pton(AF_INET, d_buf, sa->addr)) {
        case 1:
            if (sa->addr_len == 0)
                sa->addr_len = 32;
            return 0;
        case 0:
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        case -1:
        default:
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        }
    }
    else if (sa->sa_family == WOLFSENTRY_AF_INET6) {
        switch (inet_pton(AF_INET6, d_buf, sa->addr)) {
        case 1:
            if (sa->addr_len == 0)
                sa->addr_len = 128;
            return 0;
        case 0:
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        case -1:
        default:
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        }
    }
    else
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
}

#ifdef WOLFSENTRY_PROTOCOL_NAMES

static wolfsentry_errcode_t convert_sockaddr_port_name(struct json_process_state *jps, const char *data, size_t data_size, struct wolfsentry_sockaddr *sa) {
    char d_buf[64];
    struct servent *s;
    struct protoent *p;

    if (! WOLFSENTRY_CHECK_BITS(jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS))
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    if (data_size >= sizeof d_buf)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);

    memcpy(d_buf, data, data_size);
    d_buf[data_size] = 0;

    if (sa->sa_proto != 0)
        p = getprotobynumber(sa->sa_proto);
    else
        p = NULL;

    s = getservbyname(d_buf, p ? p->p_name : NULL);
    if (s == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    else {
        sa->sa_port = (wolfsentry_port_t)ntohs((uint16_t)s->s_port);
        return 0;
    }
}

#endif

static wolfsentry_errcode_t handle_route_endpoint_clause(struct json_process_state *jps, JSON_TYPE type, const char *data, size_t data_size, struct wolfsentry_sockaddr *sa) {
    if (! strcmp(jps->cur_keyname, "port")) {
        WOLFSENTRY_CLEAR_BITS(jps->o_u_c.route.flags,
                              sa == (struct wolfsentry_sockaddr *)&jps->o_u_c.route.remote ?
                              WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD :
                              WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD);
        if (type == JSON_NUMBER)
            return convert_uint16(type, data, data_size, &sa->sa_port);
#ifdef WOLFSENTRY_PROTOCOL_NAMES
        else if (type == JSON_STRING)
            return convert_sockaddr_port_name(jps, data, data_size, sa);
#endif
        else
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    } else if (! strcmp(jps->cur_keyname, "address")) {
        WOLFSENTRY_CLEAR_BITS(jps->o_u_c.route.flags,
                              sa == (struct wolfsentry_sockaddr *)&jps->o_u_c.route.remote ?
                              WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD :
                              WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD);
        return convert_sockaddr_address(type, data, data_size, sa);
    } else if (! strcmp(jps->cur_keyname, "prefix-bits"))
        return convert_uint16(type, data, data_size, &sa->addr_len);
    else if (! strcmp(jps->cur_keyname, "interface")) {
        WOLFSENTRY_CLEAR_BITS(jps->o_u_c.route.flags,
                              sa == (struct wolfsentry_sockaddr *)&jps->o_u_c.route.remote ?
                              WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD :
                              WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD);
        return convert_uint8(type, data, data_size, &sa->interface);
    } else
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
}

static wolfsentry_errcode_t handle_route_boolean_clause(JSON_TYPE type, wolfsentry_route_flags_t *flags, wolfsentry_route_flags_t bit) {
    if (type == JSON_TRUE) {
        WOLFSENTRY_SET_BITS(*flags, bit);
        return 0;
    } else if (type == JSON_FALSE) {
        WOLFSENTRY_CLEAR_BITS(*flags, bit);
        return 0;
    } else
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
}

static wolfsentry_errcode_t handle_route_family_clause(struct json_process_state *jps, JSON_TYPE type, const char *data, size_t data_size) {
    WOLFSENTRY_CLEAR_BITS(jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD);

    if (type == JSON_NUMBER) {
        wolfsentry_errcode_t ret = convert_uint16(type, data, data_size, &jps->o_u_c.route.remote.sa_family);
        if (ret < 0)
            return ret;
        jps->o_u_c.route.local.sa_family = jps->o_u_c.route.remote.sa_family;
        return 0;
    }
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    else if (type == JSON_STRING) {
        jps->o_u_c.route.remote.sa_family = jps->o_u_c.route.local.sa_family = wolfsentry_family_pton(data, data_size);
        if (jps->o_u_c.route.remote.sa_family == WOLFSENTRY_AF_UNSPEC)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        else
            return 0;
    }
#endif
    else
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
}

static wolfsentry_errcode_t handle_route_protocol_clause(struct json_process_state *jps, JSON_TYPE type, const char *data, size_t data_size) {
    WOLFSENTRY_CLEAR_BITS(jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD);

    if (type == JSON_NUMBER) {
        wolfsentry_errcode_t ret = convert_uint16(type, data, data_size, &jps->o_u_c.route.remote.sa_proto);
        if (ret < 0)
            return ret;
        jps->o_u_c.route.local.sa_proto = jps->o_u_c.route.remote.sa_proto;
    }
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    else if (type == JSON_STRING) {
        char d_buf[64];
        struct protoent *p;

        if ((jps->o_u_c.route.remote.sa_family != WOLFSENTRY_AF_INET) &&
            (jps->o_u_c.route.remote.sa_family != WOLFSENTRY_AF_INET6))
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

        if (data_size >= sizeof d_buf)
            WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);

        memcpy(d_buf, data, data_size);
        d_buf[data_size] = 0;

        p = getprotobyname(d_buf);
        if (p == NULL)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        else {
            jps->o_u_c.route.remote.sa_proto = (wolfsentry_proto_t)p->p_proto;
            jps->o_u_c.route.local.sa_proto = (wolfsentry_proto_t)p->p_proto;
        }
    }
#endif
    else
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    if (((jps->o_u_c.route.remote.sa_family == WOLFSENTRY_AF_INET) || (jps->o_u_c.route.remote.sa_family == WOLFSENTRY_AF_INET6)) &&
        ((jps->o_u_c.route.remote.sa_proto == IPPROTO_TCP) || (jps->o_u_c.route.remote.sa_proto == IPPROTO_UDP)))
        WOLFSENTRY_SET_BITS(jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS);

    return 0;
}

static wolfsentry_errcode_t handle_route_clause(struct json_process_state *jps, JSON_TYPE type, const char *data, size_t data_size) {
    wolfsentry_errcode_t ret;
    if ((jps->cur_depth == 2) && (type == JSON_OBJECT_END)) {
        wolfsentry_ent_id_t id;
        wolfsentry_action_res_t action_results;
        ret = wolfsentry_route_insert_static(
            jps->wolfsentry,
            jps->o_u_c.route.caller_arg,
            (const struct wolfsentry_sockaddr *)&jps->o_u_c.route.remote,
            (const struct wolfsentry_sockaddr *)&jps->o_u_c.route.local,
            jps->o_u_c.route.flags,
            (jps->o_u_c.route.event_label_len > 0) ? jps->o_u_c.route.event_label : NULL,
            jps->o_u_c.route.event_label_len,
            &id,
            &action_results);
        reset_o_u_c(jps);
        if (ret < 0)
            return ret;
        else
            return 0;
    }
    if ((jps->cur_depth == 3) && (type == JSON_OBJECT_BEG)) {
        reset_o_u_c(jps);
        jps->object_under_construction = O_U_C_ROUTE;
        /* speculatively set all the wildcard fields, then clear them piecemeal as directives provide. */
        WOLFSENTRY_SET_BITS(jps->o_u_c.route.flags,
                            WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD|
                            WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD|
                            WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD|
                            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD|
                            WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD|
                            WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD|
                            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD|
                            WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD);
        return 0;
    }
    if (jps->cur_depth == 4) {
        if (type == JSON_OBJECT_BEG) {
            if (! strcmp(jps->cur_keyname, "remote")) {
                jps->section_under_construction = S_U_C_REMOTE_ENDPOINT;
                return 0;
            } else if (! strcmp(jps->cur_keyname, "local")) {
                jps->section_under_construction = S_U_C_LOCAL_ENDPOINT;
                return 0;
            } else
                WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
        } else if (jps->section_under_construction == S_U_C_REMOTE_ENDPOINT)
            return handle_route_endpoint_clause(jps, type, data, data_size, (struct wolfsentry_sockaddr *)&jps->o_u_c.route.remote);
        else if (jps->section_under_construction == S_U_C_LOCAL_ENDPOINT)            
            return handle_route_endpoint_clause(jps, type, data, data_size, (struct wolfsentry_sockaddr *)&jps->o_u_c.route.local);
        else
            WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED); /* can't happen. */
    }
    if ((jps->cur_depth == 3) && (type == JSON_OBJECT_END)) {
        jps->section_under_construction = S_U_C_NONE;
        return 0;
    }

    if (jps->cur_depth != 3)
        WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);

    if (! strcmp(jps->cur_keyname, "parent-event")) {
        if (data_size > sizeof jps->o_u_c.route.event_label)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        jps->o_u_c.route.event_label_len = (int)data_size;
        memcpy(jps->o_u_c.route.event_label, data, data_size);
        WOLFSENTRY_CLEAR_BITS(jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD);
    }
    else if (! strcmp(jps->cur_keyname, "family"))
        return handle_route_family_clause(jps, type, data, data_size);
    else if (! strcmp(jps->cur_keyname, "protocol"))
        return handle_route_protocol_clause(jps, type, data, data_size);
    else if (! strcmp(jps->cur_keyname, "tcplike-port-numbers"))
        return handle_route_boolean_clause(type, &jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS);
    else if (! strcmp(jps->cur_keyname, "direction-in"))
        return handle_route_boolean_clause(type, &jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    else if (! strcmp(jps->cur_keyname, "direction-out"))
        return handle_route_boolean_clause(type, &jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);
    else if (! strcmp(jps->cur_keyname, "penalty-boxed"))
        return handle_route_boolean_clause(type, &jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED);
    else if (! strcmp(jps->cur_keyname, "green-listed"))
        return handle_route_boolean_clause(type, &jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_GREENLISTED);
    else if (! strcmp(jps->cur_keyname, "dont-count-hits"))
        return handle_route_boolean_clause(type, &jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_HITS);
    else if (! strcmp(jps->cur_keyname, "dont-count-current-connections"))
        return handle_route_boolean_clause(type, &jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_CURRENT_CONNECTIONS);
    else
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);

    return 0;
}

#define WOLFSENTRY_ERROR_OUT(x) { ret = WOLFSENTRY_ERROR_ENCODE(x); goto out; }

static wolfsentry_errcode_t json_process(
    JSON_TYPE type,
    const char *data,
    size_t data_size,
    struct json_process_state *jps)
{
    wolfsentry_errcode_t ret;

#ifdef DEBUG_JSON
    if (data)
        printf("depth=%d t=%d d=\"%.*s\"\n", jps->cur_depth, type, (int)data_size, data);
    else
        printf("depth=%d t=%d\n", jps->cur_depth, type);
#endif

    if (type == JSON_KEY) {
        memcpy(&jps->key_pos, &jps->parser.pos, sizeof jps->key_pos);
        jps->key_pos.column_number -= (unsigned)(data_size + 2U); /* kludge to move the pointer back to the start of the key */
        if (data_size >= sizeof jps->cur_keyname)
            WOLFSENTRY_ERROR_OUT(CONFIG_INVALID_KEY);
        memcpy(jps->cur_keyname, data, data_size);
        jps->cur_keyname[data_size] = 0;
        jps->cur_keydepth = jps->cur_depth;
        return 0;
    }

    if ((type == JSON_OBJECT_BEG) || (type == JSON_ARRAY_BEG))
        ++jps->cur_depth;
    else if ((type == JSON_OBJECT_END) || (type == JSON_ARRAY_END))
        --jps->cur_depth;

    if ((type == JSON_OBJECT_BEG) && (jps->cur_depth == 1))
        return 0;

    if ((type == JSON_OBJECT_END) && (jps->cur_depth == 0)) {
        reset_o_u_c(jps);
        return 0;
    }

    if (jps->table_under_construction == T_U_C_NONE) {
        if ((jps->cur_keydepth == 1) && (jps->cur_depth <= 2))  {
            switch (type) {
            case JSON_FALSE:
            case JSON_TRUE:
            case JSON_NUMBER:
            case JSON_STRING:
                if (jps->cur_depth != 1)
                    WOLFSENTRY_ERROR_OUT(CONFIG_UNEXPECTED);
                if (! strcmp(jps->cur_keyname, "wolfsentry-config-version")) {
                    ret = convert_uint32(type, data, data_size, &jps->config_version);
                    if (ret < 0)
                        goto out;
                    if (jps->config_version != 1)
                        WOLFSENTRY_ERROR_OUT(CONFIG_INVALID_VALUE);
                    return 0;
                }
                WOLFSENTRY_ERROR_OUT(CONFIG_INVALID_KEY);
            case JSON_OBJECT_BEG:
                if (jps->config_version == 0)
                    WOLFSENTRY_ERROR_OUT(CONFIG_UNEXPECTED);
                if (jps->cur_depth != 2)
                    WOLFSENTRY_ERROR_OUT(CONFIG_UNEXPECTED);
                if (! strcmp(jps->cur_keyname, "config-update")) {
                    jps->table_under_construction = T_U_C_TOPCONFIG;
                    return 0;
                }
                WOLFSENTRY_ERROR_OUT(CONFIG_INVALID_KEY);
            case JSON_ARRAY_BEG:
                if (jps->config_version == 0)
                    WOLFSENTRY_ERROR_OUT(CONFIG_UNEXPECTED);
                if (jps->cur_depth != 2)
                    WOLFSENTRY_ERROR_OUT(CONFIG_UNEXPECTED);
                if (! strcmp(jps->cur_keyname, "events-insert")) {
                    jps->table_under_construction = T_U_C_EVENTS;
                    return 0;
                }
                if (! strcmp(jps->cur_keyname, "static-routes-insert")) {
                    jps->table_under_construction = T_U_C_STATIC_ROUTES;
                    return 0;
                }
                if (! strcmp(jps->cur_keyname, "actions-update")) {
                    jps->table_under_construction = T_U_C_ACTIONS;
                    return 0;
                }
                WOLFSENTRY_ERROR_OUT(CONFIG_INVALID_KEY);
            case JSON_NULL:
            case JSON_KEY:
            case JSON_OBJECT_END:
            case JSON_ARRAY_END:
            WOLFSENTRY_ERROR_OUT(CONFIG_UNEXPECTED);
            }
        }
        WOLFSENTRY_ERROR_OUT(CONFIG_UNEXPECTED);
    }

    if (jps->table_under_construction == T_U_C_TOPCONFIG) {
        if ((jps->cur_depth == 1) && (type == JSON_OBJECT_END)) {
            jps->table_under_construction = T_U_C_NONE;
            ret = wolfsentry_defaultconfig_update(jps->wolfsentry, &jps->default_config);
            if (ret < 0)
                goto out;
            if (jps->default_policy_static) {
                struct wolfsentry_route_table *static_routes;
                ret = wolfsentry_route_get_table_static(jps->wolfsentry, &static_routes);
                if (ret < 0)
                    return ret;
                ret = wolfsentry_route_table_default_policy_set(jps->wolfsentry, static_routes, jps->default_policy_static);
                if (ret < 0)
                    return ret;
            }
            if (jps->default_policy_dynamic) {
                struct wolfsentry_route_table *dynamic_routes;
                ret = wolfsentry_route_get_table_dynamic(jps->wolfsentry, &dynamic_routes);
                if (ret < 0)
                    return ret;
                ret = wolfsentry_route_table_default_policy_set(jps->wolfsentry, dynamic_routes, jps->default_policy_dynamic);
                if (ret < 0)
                    return ret;
            }
            return 0;
        }
        ret = handle_eventconfig_clause(jps, type, data, data_size, &jps->default_config);
        goto out;
    }

    if (jps->table_under_construction == T_U_C_STATIC_ROUTES) {
        if ((jps->cur_depth == 1) && (type == JSON_ARRAY_END)) {
            jps->table_under_construction = T_U_C_NONE;
            return 0;
        }
        ret = handle_route_clause(jps, type, data, data_size);
        goto out;
    }

    WOLFSENTRY_ERROR_OUT(CONFIG_UNEXPECTED);

  out:

    if (ret < 0) {
        reset_o_u_c(jps);
        if (WOLFSENTRY_ERROR_CODE_IS(ret, CONFIG_INVALID_KEY))
            memcpy(&jps->parser.err_pos, &jps->key_pos, sizeof(JSON_INPUT_POS));
        else if (WOLFSENTRY_ERROR_CODE_IS(ret, CONFIG_INVALID_VALUE))
            memcpy(&jps->parser.err_pos, &jps->parser.value_pos, sizeof(JSON_INPUT_POS));
        else
            memcpy(&jps->parser.err_pos, &jps->parser.pos, sizeof(JSON_INPUT_POS));
        return ret;
    } else
        return 0;
}

wolfsentry_errcode_t wolfsentry_config_json_init(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_config_load_flags_t load_flags,
    struct json_process_state **jps)
{
    int ret;
    static const JSON_CALLBACKS json_callbacks = {
        .process = (int (*)(JSON_TYPE,  const char *, size_t,  void *))json_process
    };

    const JSON_CONFIG json_config = {
        .max_total_len = 0,
        .max_total_values = 0,
        .max_number_len = 20,
        .max_string_len = WOLFSENTRY_MAX_LABEL_BYTES,
        .max_key_len = WOLFSENTRY_MAX_LABEL_BYTES,
        .max_nesting_level = 10,
        .flags = JSON_NOSCALARROOT,
        .wolfsentry_context = wolfsentry
    };

    (void)load_flags;

    if (wolfsentry == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if ((*jps = (struct json_process_state *)wolfsentry_malloc(wolfsentry, sizeof **jps)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    memset(*jps, 0, sizeof **jps);
    (*jps)->wolfsentry = wolfsentry;

    ret = json_init(&(*jps)->parser,
                    &json_callbacks,
                    &json_config,
                    *jps);
    if (ret != JSON_ERR_SUCCESS) {
        wolfsentry_free(wolfsentry, *jps);
        *jps = NULL;
        if (ret == JSON_ERR_OUTOFMEMORY)
            WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
        else
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    }

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_config_json_feed(
    struct json_process_state *jps,
    const char *json_in,
    size_t json_in_len,
    char *err_buf,
    size_t err_buf_size)
{
    JSON_INPUT_POS json_pos;
    int ret = json_feed(&jps->parser, json_in, json_in_len);
    if (ret != JSON_ERR_SUCCESS) {
        ret = json_fini(&jps->parser, &json_pos);
        if (err_buf) {
            if (WOLFSENTRY_ERROR_DECODE_SOURCE_ID(ret) == WOLFSENTRY_SOURCE_ID_UNSET)
                snprintf(err_buf, err_buf_size, "json_feed failed at offset %zu, L%u, col %u, with centijson code %d: %s", json_pos.offset,json_pos.line_number, json_pos.column_number, ret, json_error_str(ret));
            else
                snprintf(err_buf, err_buf_size, "json_feed failed at offset %zu, L%u, col %u, with " WOLFSENTRY_ERROR_FMT, json_pos.offset,json_pos.line_number, json_pos.column_number, WOLFSENTRY_ERROR_FMT_ARGS(ret));
        }
        if (WOLFSENTRY_ERROR_DECODE_SOURCE_ID(ret) == WOLFSENTRY_SOURCE_ID_UNSET)
            WOLFSENTRY_ERROR_RETURN(CONFIG_PARSER);
        else
            return ret;
    }
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_config_centijson_errcode(struct json_process_state *jps, int *json_errcode, const char **json_errmsg)
{
    if ((jps == NULL) || (jps->parser.user_data == NULL))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (json_errcode)
        *json_errcode = jps->parser.errcode;
    if (json_errmsg)
        *json_errmsg = json_error_str(jps->parser.errcode);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_config_json_fini(
    struct json_process_state *jps,
    char *err_buf,
    size_t err_buf_size)
{
    JSON_INPUT_POS json_pos;
    int ret = json_fini(&jps->parser, &json_pos);
    wolfsentry_free(jps->wolfsentry, jps);
    if (ret != JSON_ERR_SUCCESS) {
        if (err_buf != NULL)
            snprintf(err_buf, err_buf_size, "json_fini failed at offset %zu, L%u, col %u, with code %d: %s.",
                     json_pos.offset,json_pos.line_number, json_pos.column_number, ret, json_error_str(ret));
        WOLFSENTRY_ERROR_RETURN(CONFIG_PARSER);
    }

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_config_json_oneshot(
    struct wolfsentry_context *wolfsentry,
    const char *json_in,
    size_t json_in_len,
    wolfsentry_config_load_flags_t load_flags,
    char *err_buf,
    size_t err_buf_size)
{
    wolfsentry_errcode_t ret;
    struct json_process_state *jps;
    if ((ret = wolfsentry_config_json_init(wolfsentry, load_flags, &jps)) < 0)
        return ret;
    if ((ret = wolfsentry_config_json_feed(jps, json_in, json_in_len, err_buf, err_buf_size)) < 0) {
        (void)wolfsentry_config_json_fini(jps, NULL, 0);
        return ret;
    }
    return wolfsentry_config_json_fini(jps, err_buf, err_buf_size);
}
