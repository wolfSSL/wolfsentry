/*
 * json/load_config.c
 *
 * Copyright (C) 2021-2025 wolfSSL Inc.
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

#ifdef WOLFSENTRY_WOLFCOSE
#include "wolfsentry/wolfsentry_cbor.h"
/* Prevent wolfSSL from redeclaring wolfSentry's byte typedef under C99. */
#define byte byte
#include <wolfcose/wolfcose.h>
#undef byte
#endif

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_JSON_LOAD_CONFIG_C

#include <stdlib.h>
#include <limits.h>

#define MAX_IPV4_ADDR_BITS (sizeof(struct in_addr) * BITS_PER_BYTE)
#define MAX_IPV6_ADDR_BITS (sizeof(struct in6_addr) * BITS_PER_BYTE)
#define MAX_MAC_ADDR_BITS 64

#ifdef WOLFSENTRY_LWIP
#include "lwip/sockets.h"
#elif defined(WOLFSENTRY_NETXDUO)
#include "wolfsentry/wolfsentry_netxduo.h"
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#ifndef WOLFSENTRY_NO_GETPROTOBY
#include <netdb.h>
#endif

#ifndef WOLFSENTRY_NO_ERRNO_H
#include <errno.h>
#endif

/* note that the order of objects in the JSON is semantically significant.
 * Thus, any application-level JSON preprocessing must be ES5-compliant
 * (preserve the order of pairs exactly).
 *
 * see doc/json_configuration.md
 */

enum config_input_format {
    CONFIG_INPUT_JSON = 0,
    CONFIG_INPUT_CBOR
};

#if defined(WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS) && \
    !defined(WOLFSENTRY_WOLFCOSE)
    #error WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS requires WOLFSENTRY_WOLFCOSE.
#endif
#if defined(WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS) && \
    !defined(WOLFSENTRY_NO_JSON)
    #error WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS requires WOLFSENTRY_NO_JSON.
#endif
#if defined(WOLFSENTRY_CONFIG_NO_TEXT_ADDRESSES) && \
    !defined(WOLFSENTRY_WOLFCOSE)
    #error WOLFSENTRY_CONFIG_NO_TEXT_ADDRESSES requires WOLFSENTRY_WOLFCOSE.
#endif
#if defined(WOLFSENTRY_CONFIG_NO_TEXT_ADDRESSES) && \
    !defined(WOLFSENTRY_NO_JSON)
    #error WOLFSENTRY_CONFIG_NO_TEXT_ADDRESSES requires WOLFSENTRY_NO_JSON.
#endif

#ifdef WOLFSENTRY_WOLFCOSE
    #define CONFIG_VALUE_BYTE_STRING ((JSON_TYPE)(JSON_OBJECT_END + 1))
    #define CONFIG_VALUE_NUMBER ((JSON_TYPE)(JSON_OBJECT_END + 2))
    #define CONFIG_TYPE_IS_NUMBER(type) \
        (((type) == JSON_NUMBER) || ((type) == CONFIG_VALUE_NUMBER))
#else
    #define CONFIG_TYPE_IS_NUMBER(type) ((type) == JSON_NUMBER)
#endif

#ifdef WOLFSENTRY_WOLFCOSE
enum config_number_type {
    CONFIG_NUMBER_NONE = 0,
    CONFIG_NUMBER_UINT,
    CONFIG_NUMBER_SINT,
    CONFIG_NUMBER_FLOAT
};

struct config_number {
    enum config_number_type type;
    union {
        uint64_t uint_value;
        int64_t sint_value;
        double float_value;
    } value;
};
#endif

#if defined(WOLFSENTRY_HAVE_JSON_DOM) && \
    !defined(WOLFSENTRY_CONFIG_NO_USER_VALUES)
    #define WOLFSENTRY_CONFIG_HAVE_JSON_DOM
#endif

struct wolfsentry_json_process_state {
    enum config_input_format input_format;

    uint32_t config_version;

    wolfsentry_config_load_flags_t load_flags;

    enum { T_U_C_NONE = 0, T_U_C_TOPCONFIG, T_U_C_EVENTS, T_U_C_DEFAULTPOLICIES, T_U_C_STATIC_ROUTES, T_U_C_ACTIONS, T_U_C_USER_VALUES } table_under_construction;

    enum { O_U_C_NONE = 0, O_U_C_SKIPLEVEL, O_U_C_ROUTE, O_U_C_EVENT, O_U_C_ACTION, O_U_C_USER_VALUE } object_under_construction;

    enum { S_U_C_NONE = 0, S_U_C_EVENTCONFIG, S_U_C_FLAGS, S_U_C_ACTION_LIST, S_U_C_REMOTE_ENDPOINT, S_U_C_LOCAL_ENDPOINT, S_U_C_ROUTE_METADATA, S_U_C_USER_VALUE_JSON } section_under_construction;

    int cur_depth;
    char cur_keyname[WOLFSENTRY_MAX_LABEL_BYTES];
    int cur_keydepth;
#ifndef WOLFSENTRY_NO_JSON
    JSON_INPUT_POS key_pos;
#if defined(WOLFSENTRY_CONFIG_HAVE_JSON_DOM) && defined(WOLFSENTRY_JSON_VALUE_MAX_BYTES)
    JSON_INPUT_POS json_value_start_pos;
#endif

    wolfsentry_errcode_t fini_ret;
#endif

#ifndef WOLFSENTRY_CONFIG_NO_EVENTCONFIG
    struct wolfsentry_eventconfig default_config;
#endif
    wolfsentry_action_res_t default_policy;

#ifndef WOLFSENTRY_NO_JSON
    JSON_PARSER parser;
#endif
    struct wolfsentry_context *wolfsentry;
#ifndef WOLFSENTRY_CONFIG_NO_TRANSACTIONS
    struct wolfsentry_context *wolfsentry_actual;
#endif
#ifdef WOLFSENTRY_CONFIG_HAVE_JSON_DOM
    unsigned int dom_parser_flags;
    JSON_DOM_PARSER dom_parser; /* has a duplicate JSON_PARSER in it that is not used, except for its .wolfsentry_context member. */
#if defined(WOLFSENTRY_WOLFCOSE) && defined(WOLFSENTRY_JSON_VALUE_MAX_BYTES)
    size_t cbor_offset;
    size_t cbor_value_start_offset;
    size_t cbor_json_value_start_offset;
#endif
#endif
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread;
#ifndef WOLFSENTRY_CONFIG_NO_TRANSACTIONS
    int got_reservation;
#endif
#define JPS_WOLFSENTRY_CONTEXT_ARGS_OUT jps->wolfsentry, jps->thread
#define JPSP_WOLFSENTRY_CONTEXT_ARGS_OUT (*jps)->wolfsentry, (*jps)->thread
#define JPSP_P_WOLFSENTRY_CONTEXT_ARGS_OUT &(*jps)->wolfsentry, (*jps)->thread
#ifdef WOLFSENTRY_CONFIG_NO_TRANSACTIONS
#define JPSP_WOLFSENTRY_ACTUAL_CONTEXT_ARGS_OUT (*jps)->wolfsentry, (*jps)->thread
#else
#define JPSP_WOLFSENTRY_ACTUAL_CONTEXT_ARGS_OUT (*jps)->wolfsentry_actual, (*jps)->thread
#endif
#else
#define JPS_WOLFSENTRY_CONTEXT_ARGS_OUT jps->wolfsentry
#define JPSP_WOLFSENTRY_CONTEXT_ARGS_OUT (*jps)->wolfsentry
#define JPSP_P_WOLFSENTRY_CONTEXT_ARGS_OUT &(*jps)->wolfsentry
#ifdef WOLFSENTRY_CONFIG_NO_TRANSACTIONS
#define JPSP_WOLFSENTRY_ACTUAL_CONTEXT_ARGS_OUT (*jps)->wolfsentry
#else
#define JPSP_WOLFSENTRY_ACTUAL_CONTEXT_ARGS_OUT (*jps)->wolfsentry_actual
#endif
#endif

    union {
        unsigned char unused;
#ifndef WOLFSENTRY_CONFIG_NO_ROUTES
        struct {
            char event_label[WOLFSENTRY_MAX_LABEL_BYTES];
            int event_label_len;
            void *caller_arg; /* xxx */
            WOLFSENTRY_SOCKADDR(WOLFSENTRY_MAX_ADDR_BITS) remote;
            WOLFSENTRY_SOCKADDR(WOLFSENTRY_MAX_ADDR_BITS) local;
            wolfsentry_route_flags_t flags;
        } route;
#endif
#ifndef WOLFSENTRY_CONFIG_NO_EVENTS
        struct {
            char label[WOLFSENTRY_MAX_LABEL_BYTES];
            int label_len;
            wolfsentry_priority_t priority;
#ifndef WOLFSENTRY_CONFIG_NO_EVENTCONFIG
            struct wolfsentry_eventconfig config;
            int configed;
#endif
            int inserted;
            wolfsentry_action_type_t cur_action_list_under_construction;
        } event;
#endif
#ifndef WOLFSENTRY_CONFIG_NO_USER_VALUES
        struct {
            char label[WOLFSENTRY_MAX_LABEL_BYTES];
            int label_len;
        } user_value;
#endif
    } o_u_c;
};

#ifdef WOLFSENTRY_WOLFCOSE
static const struct config_number *get_config_number(
    JSON_TYPE type,
    const unsigned char *data,
    size_t data_size)
{
    if ((type != CONFIG_VALUE_NUMBER) || (data == NULL) ||
        (data_size != sizeof(struct config_number)))
    {
        return NULL;
    }
    return (const struct config_number *)(const void *)data;
}
#endif

static wolfsentry_errcode_t reset_o_u_c(struct wolfsentry_json_process_state *jps) {
    switch (jps->object_under_construction) {
    case O_U_C_NONE:
    case O_U_C_SKIPLEVEL:
        WOLFSENTRY_RETURN_OK;
    case O_U_C_ROUTE:
    case O_U_C_ACTION:
    case O_U_C_EVENT:
    case O_U_C_USER_VALUE:
        break;
    default:
        WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
    }

    memset(&jps->o_u_c, 0, sizeof jps->o_u_c);
    jps->object_under_construction = O_U_C_NONE;
    jps->section_under_construction = S_U_C_NONE;

    WOLFSENTRY_RETURN_OK;
}

#ifndef WOLFSENTRY_CONFIG_NO_USER_VALUES

static wolfsentry_errcode_t convert_uint64(
    JSON_TYPE type,
    const unsigned char *data,
    size_t data_size,
    uint64_t *out)
{
#ifndef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    char buf[24];
    char *endptr;
#ifdef WOLFSENTRY_HAVE_LONG_LONG
    unsigned long long conv;
#else
    unsigned long conv;
#endif
#endif
#ifdef WOLFSENTRY_WOLFCOSE
    const struct config_number *number =
        get_config_number(type, data, data_size);

    if (type == CONFIG_VALUE_NUMBER) {
        if ((number == NULL) || (number->type != CONFIG_NUMBER_UINT))
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        *out = number->value.uint_value;
        WOLFSENTRY_RETURN_OK;
    }
#endif
#ifdef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#else
    /* allow JSON_STRING to accommodate hex and octal values. */
    if ((type != JSON_NUMBER) && (type != JSON_STRING))
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    if (data_size >= sizeof buf)
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    memcpy(buf, data, data_size);
    buf[data_size] = 0;

#ifndef WOLFSENTRY_NO_ERRNO_H
    errno = 0;
#endif
#ifdef WOLFSENTRY_HAVE_LONG_LONG
    conv = strtoull(buf, &endptr, 0);
#else
    conv = strtoul(buf, &endptr, 0);
#endif
#ifndef WOLFSENTRY_NO_ERRNO_H
    if (errno != 0)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#endif

    if ((size_t)(endptr - buf) != data_size)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    *out = (uint64_t)conv;
#endif

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t convert_sint64(
    JSON_TYPE type,
    const unsigned char *data,
    size_t data_size,
    int64_t *out)
{
#ifndef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    char buf[24];
    char *endptr;
#ifdef WOLFSENTRY_HAVE_LONG_LONG
    long long conv;
#else
    long conv;
#endif
#endif
#ifdef WOLFSENTRY_WOLFCOSE
    const struct config_number *number =
        get_config_number(type, data, data_size);

    if (type == CONFIG_VALUE_NUMBER) {
        if (number == NULL)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        if (number->type == CONFIG_NUMBER_SINT)
            *out = number->value.sint_value;
        else if ((number->type == CONFIG_NUMBER_UINT) &&
                 (number->value.uint_value <= (uint64_t)INT64_MAX))
        {
            *out = (int64_t)number->value.uint_value;
        }
        else
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        WOLFSENTRY_RETURN_OK;
    }
#endif
#ifdef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#else
    /* allow JSON_STRING to accommodate hex and octal values. */
    if ((type != JSON_NUMBER) && (type != JSON_STRING))
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    if (data_size >= sizeof buf)
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    memcpy(buf, data, data_size);
    buf[data_size] = 0;

#ifndef WOLFSENTRY_NO_ERRNO_H
    errno = 0;
#endif
#ifdef WOLFSENTRY_HAVE_LONG_LONG
    conv = strtoll(buf, &endptr, 0);
#else
    conv = strtol(buf, &endptr, 0);
#endif
#ifndef WOLFSENTRY_NO_ERRNO_H
    if (errno != 0)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#endif

    if ((size_t)(endptr - buf) != data_size)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    *out = (int64_t)conv;
#endif

    WOLFSENTRY_RETURN_OK;
}

#endif /* !WOLFSENTRY_CONFIG_NO_USER_VALUES */

static wolfsentry_errcode_t convert_uint32(
    JSON_TYPE type,
    const unsigned char *data,
    size_t data_size,
    uint32_t *out)
{
#ifndef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    char buf[16];
    char *endptr;
    unsigned long conv;
#endif
#ifdef WOLFSENTRY_WOLFCOSE
    const struct config_number *number =
        get_config_number(type, data, data_size);

    if (type == CONFIG_VALUE_NUMBER) {
        if ((number == NULL) || (number->type != CONFIG_NUMBER_UINT))
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        if (number->value.uint_value > MAX_UINT_OF(*out))
            WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
        *out = (uint32_t)number->value.uint_value;
        WOLFSENTRY_RETURN_OK;
    }
#endif
#ifdef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#else
    /* allow JSON_STRING to accommodate hex and octal values. */
    if ((type != JSON_NUMBER) && (type != JSON_STRING))
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    if (data_size >= sizeof buf)
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    memcpy(buf, data, data_size);
    buf[data_size] = 0;

#ifndef WOLFSENTRY_NO_ERRNO_H
    errno = 0;
#endif
    conv = strtoul(buf, &endptr, 0);
#ifndef WOLFSENTRY_NO_ERRNO_H
    if (errno != 0)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#endif

    if ((size_t)(endptr - buf) != data_size)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    if (conv > MAX_UINT_OF(*out))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    *out = (uint32_t)conv;
#endif

    WOLFSENTRY_RETURN_OK;
}

#if !defined(WOLFSENTRY_CONFIG_NO_ROUTES) || \
    !defined(WOLFSENTRY_CONFIG_NO_EVENTS)

static wolfsentry_errcode_t convert_uint16(
    JSON_TYPE type,
    const unsigned char *data,
    size_t data_size,
    uint16_t *out)
{
#ifndef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    char buf[8];
    char *endptr;
    unsigned long conv;
#endif
#ifdef WOLFSENTRY_WOLFCOSE
    const struct config_number *number =
        get_config_number(type, data, data_size);

    if (type == CONFIG_VALUE_NUMBER) {
        if ((number == NULL) || (number->type != CONFIG_NUMBER_UINT))
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        if (number->value.uint_value > MAX_UINT_OF(*out))
            WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
        *out = (uint16_t)number->value.uint_value;
        WOLFSENTRY_RETURN_OK;
    }
#endif
#ifdef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#else
    /* allow JSON_STRING to accommodate hex and octal values. */
    if ((type != JSON_NUMBER) && (type != JSON_STRING))
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    if (data_size >= sizeof buf)
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    memcpy(buf, data, data_size);
    buf[data_size] = 0;

#ifndef WOLFSENTRY_NO_ERRNO_H
    errno = 0;
#endif
    conv = strtoul(buf, &endptr, 0);
#ifndef WOLFSENTRY_NO_ERRNO_H
    if (errno != 0)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#endif

    if ((size_t)(endptr - buf) != data_size)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    if (conv > MAX_UINT_OF(*out))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    *out = (uint16_t)conv;
#endif

    WOLFSENTRY_RETURN_OK;
}

#endif /* routes or events */

#if !defined(WOLFSENTRY_CONFIG_NO_ROUTES) && \
    !defined(WOLFSENTRY_CONFIG_NO_ROUTE_ENDPOINTS)
static wolfsentry_errcode_t convert_uint8(
    JSON_TYPE type,
    const unsigned char *data,
    size_t data_size,
    uint8_t *out)
{
#ifndef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    char buf[4];
    char *endptr;
    unsigned long conv;
#endif
#ifdef WOLFSENTRY_WOLFCOSE
    const struct config_number *number =
        get_config_number(type, data, data_size);

    if (type == CONFIG_VALUE_NUMBER) {
        if ((number == NULL) || (number->type != CONFIG_NUMBER_UINT))
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        if (number->value.uint_value > MAX_UINT_OF(*out))
            WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
        *out = (uint8_t)number->value.uint_value;
        WOLFSENTRY_RETURN_OK;
    }
#endif
#ifdef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#else
    /* allow JSON_STRING to accommodate hex and octal values. */
    if ((type != JSON_NUMBER) && (type != JSON_STRING))
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    if (data_size >= sizeof buf)
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    memcpy(buf, data, data_size);
    buf[data_size] = 0;

#ifndef WOLFSENTRY_NO_ERRNO_H
    errno = 0;
#endif
    conv = strtoul(buf, &endptr, 0);
#ifndef WOLFSENTRY_NO_ERRNO_H
    if (errno != 0)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#endif

    if ((size_t)(endptr - buf) != data_size)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    if (conv > MAX_UINT_OF(*out))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    *out = (uint8_t)conv;
#endif

    WOLFSENTRY_RETURN_OK;
}
#endif

#ifndef WOLFSENTRY_CONFIG_NO_USER_VALUES
static wolfsentry_errcode_t convert_double(
    JSON_TYPE type,
    const unsigned char *data,
    size_t data_size,
    double *out)
{
#ifndef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    char buf[32];
    char *endptr;
    double conv;
#endif
#ifdef WOLFSENTRY_WOLFCOSE
    const struct config_number *number =
        get_config_number(type, data, data_size);

    if (type == CONFIG_VALUE_NUMBER) {
        if (number == NULL)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        if (number->type == CONFIG_NUMBER_FLOAT)
            *out = number->value.float_value;
        else if (number->type == CONFIG_NUMBER_SINT)
            *out = (double)number->value.sint_value;
        else if (number->type == CONFIG_NUMBER_UINT)
            *out = (double)number->value.uint_value;
        else
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        WOLFSENTRY_RETURN_OK;
    }
#endif
#ifdef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#else
    /* allow JSON_STRING to accommodate hex, octal, Inf, NaN, etc. */
    if ((type != JSON_NUMBER) && (type != JSON_STRING))
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    if (data_size >= sizeof buf)
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    memcpy(buf, data, data_size);
    buf[data_size] = 0;

#ifndef WOLFSENTRY_NO_ERRNO_H
    errno = 0;
#endif
    conv = strtod(buf, &endptr);
#ifndef WOLFSENTRY_NO_ERRNO_H
    if (errno != 0)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#endif

    if ((size_t)(endptr - buf) != data_size)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    *out = conv;
#endif

    WOLFSENTRY_RETURN_OK;
}
#endif

#ifndef WOLFSENTRY_CONFIG_NO_EVENTCONFIG
static wolfsentry_errcode_t convert_eventconfig_flag(JSON_TYPE type, wolfsentry_eventconfig_flags_t *flags, wolfsentry_eventconfig_flags_t flag) {
    if (type == JSON_FALSE)
        *flags &= ~flag;
    else if (type == JSON_TRUE)
        *flags |= flag;
    else
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t convert_wolfsentry_duration(
    struct wolfsentry_context *wolfsentry,
    JSON_TYPE type,
    const unsigned char *data,
    size_t data_size,
    wolfsentry_time_t *out)
{
    wolfsentry_errcode_t ret;
    long conv;
#ifndef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    char buf[24];
    char *endptr;
#endif
#ifdef WOLFSENTRY_WOLFCOSE
    const struct config_number *number =
        get_config_number(type, data, data_size);

    if (type == CONFIG_VALUE_NUMBER) {
        if (number == NULL)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        if (number->type == CONFIG_NUMBER_SINT) {
            if ((number->value.sint_value < (int64_t)LONG_MIN) ||
                (number->value.sint_value > (int64_t)LONG_MAX))
            {
                WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
            }
            conv = (long)number->value.sint_value;
        }
        else if ((number->type == CONFIG_NUMBER_UINT) &&
                 (number->value.uint_value <= (uint64_t)LONG_MAX))
        {
            conv = (long)number->value.uint_value;
        }
        else
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        WOLFSENTRY_ERROR_RERETURN(
            wolfsentry_interval_from_seconds(
                wolfsentry, conv, 0 /* howlong_nsecs */, out));
    }
#endif
#ifdef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#else
    if ((type != JSON_STRING) && (type != JSON_NUMBER))
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    if (data_size >= sizeof buf)
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    memcpy(buf, data, data_size);
    buf[data_size] = 0;

#ifndef WOLFSENTRY_NO_ERRNO_H
    errno = 0;
#endif
    conv = strtol(buf, &endptr, 0);
#ifndef WOLFSENTRY_NO_ERRNO_H
    if (errno != 0)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#endif

    switch (*endptr) {
    case 'd':
        if (conv > LONG_MAX / 24 || conv < LONG_MIN / 24)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        conv *= 24;
        /* fallthrough */
    case 'h':
        if (conv > LONG_MAX / 60 || conv < LONG_MIN / 60)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        conv *= 60;
        /* fallthrough */
    case 'm':
        if (conv > LONG_MAX / 60 || conv < LONG_MIN / 60)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        conv *= 60;
        /* fallthrough */
    case 's':
        ++endptr;
        break;
    default:
        break;
    }
    if ((size_t)(endptr - buf) != data_size)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#endif
    if ((ret = wolfsentry_interval_from_seconds(
            wolfsentry, conv, 0 /* howlong_nsecs */, out)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    else
        WOLFSENTRY_RETURN_OK;
}

#endif /* !WOLFSENTRY_CONFIG_NO_EVENTCONFIG */

static wolfsentry_errcode_t convert_default_policy(JSON_TYPE type, const unsigned char *data, size_t data_size, wolfsentry_action_res_t *default_policy) {
    if (type != JSON_STRING)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    if (streq(data, "accept", data_size))
        *default_policy = WOLFSENTRY_ACTION_RES_ACCEPT;
    else if (streq(data, "reject", data_size))
        *default_policy = WOLFSENTRY_ACTION_RES_REJECT;
    else if (streq(data, "reset", data_size))
        *default_policy = WOLFSENTRY_ACTION_RES_REJECT|WOLFSENTRY_ACTION_RES_PORT_RESET;
    else
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    WOLFSENTRY_RETURN_OK;
}

#ifndef WOLFSENTRY_CONFIG_NO_EVENTCONFIG

static wolfsentry_errcode_t handle_eventconfig_clause(struct wolfsentry_json_process_state *jps, JSON_TYPE type, const unsigned char *data, size_t data_size, struct wolfsentry_eventconfig *eventconfig) {
    if (jps->cur_depth == 5) {
        if ((! strcmp(jps->cur_keyname, "route-flags-to-add-on-insert")) ||
            (! strcmp(jps->cur_keyname, "route-flags-to-clear-on-insert")))
        {
            wolfsentry_route_flags_t flag;
            wolfsentry_errcode_t ret;

            if (type == JSON_ARRAY_BEG)
                WOLFSENTRY_RETURN_OK;

            if (type != JSON_STRING)
                WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

            ret = wolfsentry_route_flag_assoc_by_name((const char *)data, (int)data_size, &flag);
            WOLFSENTRY_RERETURN_IF_ERROR(ret);
            if (! strcmp(jps->cur_keyname, "route-flags-to-add-on-insert"))
                eventconfig->route_flags_to_add_on_insert |= flag;
            else
                eventconfig->route_flags_to_clear_on_insert |= flag;
            WOLFSENTRY_RETURN_OK;

        } else if ((! strcmp(jps->cur_keyname, "action-res-filter-bits-set")) ||
                   (! strcmp(jps->cur_keyname, "action-res-filter-bits-unset")) ||
                   (! strcmp(jps->cur_keyname, "action-res-bits-to-add")) ||
                   (! strcmp(jps->cur_keyname, "action-res-bits-to-clear")))
        {
            wolfsentry_action_res_t flag;
            wolfsentry_errcode_t ret;

            if (type == JSON_ARRAY_BEG)
                WOLFSENTRY_RETURN_OK;

            if (type != JSON_STRING)
                WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

            ret = wolfsentry_action_res_assoc_by_name((const char *)data, (int)data_size, &flag);
            WOLFSENTRY_RERETURN_IF_ERROR(ret);

            if (! strcmp(jps->cur_keyname, "action-res-filter-bits-set"))
                eventconfig->action_res_filter_bits_set |= flag;
            else if (! strcmp(jps->cur_keyname, "action-res-filter-bits-unset"))
                eventconfig->action_res_filter_bits_unset |= flag;
            else if (! strcmp(jps->cur_keyname, "action-res-bits-to-add"))
                eventconfig->action_res_bits_to_add |= flag;
            else
                eventconfig->action_res_bits_to_clear |= flag;
            WOLFSENTRY_RETURN_OK;
        } else
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
    }

    if (type == JSON_ARRAY_END)
        WOLFSENTRY_RETURN_OK;

    if (type == JSON_OBJECT_END) {
        /* only here if in T_U_C_TOPCONFIG -- handle_event_clause() handles the JSON_OBJECT_END itself. */
        wolfsentry_errcode_t ret;
        if (jps->table_under_construction != T_U_C_TOPCONFIG)
            WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
        ret = wolfsentry_defaultconfig_update(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, &jps->default_config);
        jps->table_under_construction = T_U_C_NONE;
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        if (jps->default_policy) {
            struct wolfsentry_route_table *routes;
            ret = wolfsentry_route_get_main_table(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, &routes);
            WOLFSENTRY_RERETURN_IF_ERROR(ret);
            ret = wolfsentry_route_table_default_policy_set(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, routes, jps->default_policy);
            WOLFSENTRY_RERETURN_IF_ERROR(ret);
        }
        WOLFSENTRY_RETURN_OK;
    }
    if (! strcmp(jps->cur_keyname, "max-connection-count"))
        WOLFSENTRY_ERROR_RERETURN(convert_uint32(type, data, data_size, &eventconfig->max_connection_count));
    if (! strcmp(jps->cur_keyname, "penalty-box-duration"))
        WOLFSENTRY_ERROR_RERETURN(convert_wolfsentry_duration(jps->wolfsentry, type, data, data_size, &eventconfig->penaltybox_duration));
    if (! strcmp(jps->cur_keyname, "route-idle-time-for-purge"))
        WOLFSENTRY_ERROR_RERETURN(convert_wolfsentry_duration(jps->wolfsentry, type, data, data_size, &eventconfig->route_idle_time_for_purge));
    if (! strcmp(jps->cur_keyname, "derog-thresh-for-penalty-boxing"))
        WOLFSENTRY_ERROR_RERETURN(convert_uint32(type, data, data_size, &eventconfig->derogatory_threshold_for_penaltybox));
    if (! strcmp(jps->cur_keyname, "derog-thresh-ignore-commendable"))
        WOLFSENTRY_ERROR_RERETURN(convert_eventconfig_flag(type, &eventconfig->flags, WOLFSENTRY_EVENTCONFIG_FLAG_DEROGATORY_THRESHOLD_IGNORE_COMMENDABLE));
    if (! strcmp(jps->cur_keyname, "commendable-clears-derogatory"))
        WOLFSENTRY_ERROR_RERETURN(convert_eventconfig_flag(type, &eventconfig->flags, WOLFSENTRY_EVENTCONFIG_FLAG_COMMENDABLE_CLEARS_DEROGATORY));

    if (! strcmp(jps->cur_keyname, "max-purgeable-routes")) {
        struct wolfsentry_route_table *route_table;
        wolfsentry_hitcount_t max_purgeable_routes;
        wolfsentry_errcode_t ret;

        if (jps->table_under_construction != T_U_C_TOPCONFIG)
            WOLFSENTRY_ERROR_RETURN(CONFIG_MISPLACED_KEY);

        ret = convert_uint32(type, data, data_size, &max_purgeable_routes);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        ret = wolfsentry_route_get_main_table(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, &route_table);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        ret = wolfsentry_route_table_max_purgeable_routes_set(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, route_table, max_purgeable_routes);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);

        WOLFSENTRY_RETURN_OK;
    }

    if (! strcmp(jps->cur_keyname, "max-purgeable-idle-time")) {
        struct wolfsentry_route_table *route_table;
        wolfsentry_time_t max_purgeable_idle_time;
        wolfsentry_errcode_t ret;

        if (jps->table_under_construction != T_U_C_TOPCONFIG)
            WOLFSENTRY_ERROR_RETURN(CONFIG_MISPLACED_KEY);

        ret = convert_wolfsentry_duration(jps->wolfsentry, type, data, data_size, &max_purgeable_idle_time);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        ret = wolfsentry_route_get_main_table(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, &route_table);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        ret = wolfsentry_route_table_max_purgeable_idle_time_set(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, route_table, max_purgeable_idle_time);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);

        WOLFSENTRY_RETURN_OK;
    }

    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
}

#endif /* !WOLFSENTRY_CONFIG_NO_EVENTCONFIG */

static wolfsentry_errcode_t handle_defaultpolicy_clause(struct wolfsentry_json_process_state *jps, JSON_TYPE type, const unsigned char *data, size_t data_size) {
    if (jps->table_under_construction != T_U_C_DEFAULTPOLICIES)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
    if (type == JSON_OBJECT_END) {
        jps->table_under_construction = T_U_C_NONE;
        if (jps->default_policy) {
            wolfsentry_errcode_t ret;
            struct wolfsentry_route_table *routes;
            ret = wolfsentry_route_get_main_table(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, &routes);
            WOLFSENTRY_RERETURN_IF_ERROR(ret);
            ret = wolfsentry_route_table_default_policy_set(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, routes, jps->default_policy);
            WOLFSENTRY_RERETURN_IF_ERROR(ret);
        }
        WOLFSENTRY_RETURN_OK;
    }
    if (! strcmp(jps->cur_keyname, "default-policy"))
        WOLFSENTRY_ERROR_RERETURN(convert_default_policy(type, data, data_size, &jps->default_policy));
    if (! strcmp(jps->cur_keyname, "default-event")) {
        struct wolfsentry_route_table *routes;
        wolfsentry_errcode_t ret;
        if (type != JSON_STRING)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        if (WOLFSENTRY_CHECK_BITS(jps->load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_NO_ROUTES_OR_EVENTS))
            WOLFSENTRY_RETURN_OK;
        ret = wolfsentry_route_get_main_table(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, &routes);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_table_set_default_event(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, routes, (const char *)data, (int)data_size));
    }
    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
}

#ifndef WOLFSENTRY_CONFIG_NO_ROUTES

#ifndef WOLFSENTRY_CONFIG_NO_ROUTE_ENDPOINTS

#ifndef WOLFSENTRY_CONFIG_NO_TEXT_ADDRESSES
static inline int convert_hex_digit(unsigned char digit) {
    if ((digit >= '0') && (digit <= '9'))
        return digit - '0';
    else if ((digit >= 'A') && (digit <= 'F'))
        return digit - 'A' + 10;
    else if ((digit >= 'a') && (digit <= 'f'))
        return digit - 'a' + 10;
    else
        return -1;
}

static inline int convert_hex_byte(const unsigned char **in, size_t *in_len, byte *out) {
    int d1, d2;
    if (*in_len < 1)
        return -1;
    d1 = convert_hex_digit(**in);
    if (d1 < 0)
        return d1;
    ++(*in);
    --(*in_len);
    if (*in_len < 1) {
        *out = (byte)d1;
        return 0;
    }
    d2 = convert_hex_digit(**in);
    if (d2 < 0) {
        *out = (byte)d1;
        return 0;
    }
    ++(*in);
    --(*in_len);
    *out = (byte)((d1 << 4) | d2);
    return 0;
}
#endif

static wolfsentry_errcode_t convert_sockaddr_address(
    struct wolfsentry_json_process_state *jps,
    JSON_TYPE type,
    const unsigned char *data,
    size_t data_size,
    struct wolfsentry_sockaddr *sa,
    byte *sa_addr)
{
#ifdef WOLFSENTRY_WOLFCOSE
    if (type == CONFIG_VALUE_BYTE_STRING) {
        wolfsentry_addr_bits_t max_addr_bits;
        wolfsentry_addr_bits_t max_stored_bits;
        wolfsentry_errcode_t ret;

        if (sa->sa_family == WOLFSENTRY_AF_UNSPEC)
            WOLFSENTRY_ERROR_RETURN(CONFIG_OUT_OF_SEQUENCE);

        ret = wolfsentry_addr_family_max_addr_bits(
            JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
            sa->sa_family,
            &max_addr_bits);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        if ((max_addr_bits == 0U) ||
            (max_addr_bits > WOLFSENTRY_MAX_ADDR_BITS))
        {
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        }
        if (data_size != WOLFSENTRY_BITS_TO_BYTES(max_addr_bits))
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

        max_stored_bits = max_addr_bits;
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
        if ((jps->section_under_construction == S_U_C_REMOTE_ENDPOINT) ?
            WOLFSENTRY_CHECK_BITS(
                jps->o_u_c.route.flags,
                WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK) :
            WOLFSENTRY_CHECK_BITS(
                jps->o_u_c.route.flags,
                WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK))
        {
            if (max_addr_bits > (WOLFSENTRY_MAX_ADDR_BITS >> 1U))
                WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
            max_stored_bits = (wolfsentry_addr_bits_t)(max_addr_bits << 1U);
        }
#endif
        if (sa->addr_len > max_stored_bits)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

        memcpy(sa_addr, data, data_size);
        if (sa->addr_len == 0U)
            sa->addr_len = max_addr_bits;
        WOLFSENTRY_RETURN_OK;
    }
    if ((sa->sa_family == WOLFSENTRY_AF_CAN) &&
        (type == CONFIG_VALUE_NUMBER))
    {
        uint32_t addr;
        wolfsentry_errcode_t ret;

        ret = convert_uint32(type, data, data_size, &addr);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        sa_addr[0] = (byte)(addr >> 24U);
        sa_addr[1] = (byte)(addr >> 16U);
        sa_addr[2] = (byte)(addr >> 8U);
        sa_addr[3] = (byte)addr;
        if (sa->addr_len == 0U)
            sa->addr_len = 32U;
        WOLFSENTRY_RETURN_OK;
    }
#endif

#ifdef WOLFSENTRY_CONFIG_NO_TEXT_ADDRESSES
    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#else
    if ((sa->sa_family == WOLFSENTRY_AF_LINK48) || (sa->sa_family == WOLFSENTRY_AF_LINK64)) {
        int n;
        if (type != JSON_STRING)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        for (n=0; ;) {
            if (n == 8)
                WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
            if (convert_hex_byte(&data, &data_size, sa_addr + n) < 0)
                WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
            ++n;
            if (data_size == 0) {
                if (n == 6)
                    sa->sa_family = WOLFSENTRY_AF_LINK48;
                else if (n == 8)
                    sa->sa_family = WOLFSENTRY_AF_LINK64;
                else
                    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
                if (sa->addr_len == 0)
                    sa->addr_len = (wolfsentry_addr_bits_t)(n * 8);
                WOLFSENTRY_RETURN_OK;
            }
            if (*data++ != ':')
                WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
            --data_size;
        }

        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    }
    else if (sa->sa_family == WOLFSENTRY_AF_INET) {
        char d_buf[16];
        if (type != JSON_STRING)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        if (data_size >= sizeof d_buf)
            WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
        memcpy(d_buf, data, data_size);
        d_buf[data_size] = 0;
        switch (inet_pton(AF_INET, d_buf, sa_addr)) {
        case 1:
            if (sa->addr_len == 0)
                sa->addr_len = 32;
            WOLFSENTRY_RETURN_OK;
        case 0:
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        case -1:
        default:
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        }
    }
#ifdef WOLFSENTRY_IPV6
    else if (sa->sa_family == WOLFSENTRY_AF_INET6) {
        char d_buf[64];
        if (type != JSON_STRING)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        if (data_size >= sizeof d_buf)
            WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
        memcpy(d_buf, data, data_size);
        d_buf[data_size] = 0;
        switch (inet_pton(AF_INET6, d_buf, sa_addr)) {
        case 1:
            if (sa->addr_len == 0)
                sa->addr_len = 128;
            WOLFSENTRY_RETURN_OK;
        case 0:
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        case -1:
        default:
            WOLFSENTRY_ERROR_RETURN(CONFIG_MISSING_HANDLER);
        }
    }
#endif
    else if (sa->sa_family == WOLFSENTRY_AF_CAN) {
        /* accept CAN addrs as either strings consisting of hex or octal numbers, or as a JSON-native decimal integer. */
#ifdef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
        uint32_t addr;
        wolfsentry_errcode_t ret;

        if (! CONFIG_TYPE_IS_NUMBER(type))
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        ret = convert_uint32(type, data, data_size, &addr);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
#else
        char d_buf[13], *endptr;
        unsigned long addr;
        if ((type != JSON_STRING) && (type != JSON_NUMBER))
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        if (data_size >= sizeof d_buf)
            WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
        if (sa->addr_len > 32) {
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
            if ((jps->section_under_construction == S_U_C_REMOTE_ENDPOINT) ?
                (jps->o_u_c.route.flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK) :
                (jps->o_u_c.route.flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK))
            {
                if (sa->addr_len > 64)
                    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
            } else
#endif
            {
                WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
            }
        }
        memcpy(d_buf, data, data_size);
        d_buf[data_size] = 0;
#ifndef WOLFSENTRY_NO_ERRNO_H
        errno = 0;
#endif
        addr = strtoul(d_buf, &endptr, 0);
#ifndef WOLFSENTRY_NO_ERRNO_H
        if (errno != 0)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#endif
        if ((size_t)(endptr - d_buf) != data_size)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        if (addr > MAX_UINT_OF(uint32_t))
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
#endif
        sa_addr[0] = (byte)(addr >> 24U);
        sa_addr[1] = (byte)(addr >> 16U);
        sa_addr[2] = (byte)(addr >> 8U);
        sa_addr[3] = (byte)addr;
        if (sa->addr_len == 0)
            sa->addr_len = 32;
        WOLFSENTRY_RETURN_OK;
    }
    else if (sa->sa_family == WOLFSENTRY_AF_UNSPEC) {
        WOLFSENTRY_ERROR_RETURN(CONFIG_OUT_OF_SEQUENCE);
    }
    else {
        wolfsentry_addr_family_parser_t parser;
        wolfsentry_errcode_t ret;
        wolfsentry_addr_bits_t sa_addr_len;

#ifdef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
        if (type != JSON_STRING)
#else
        if ((type != JSON_STRING) && (type != JSON_NUMBER))
#endif
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

        if (wolfsentry_addr_family_get_parser(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, sa->sa_family, &parser) < 0)
            WOLFSENTRY_ERROR_RETURN(CONFIG_MISSING_HANDLER);
        if (sa->addr_len == 0)
            sa_addr_len = WOLFSENTRY_MAX_ADDR_BITS;
        else
            sa_addr_len = sa->addr_len;
        ret = parser(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, (const char *)data, (int)data_size, sa_addr, &sa_addr_len);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        if (sa->addr_len == 0)
            sa->addr_len = sa_addr_len;
        WOLFSENTRY_ERROR_RERETURN(ret);
    }
#endif
}

#ifndef WOLFSENTRY_NO_GETPROTOBY

static wolfsentry_errcode_t convert_sockaddr_port_name(struct wolfsentry_json_process_state *jps, const unsigned char *data, size_t data_size, struct wolfsentry_sockaddr *sa) {
    char d_buf[64];
    char get_buf[256];
    char p_name_buf[16];
    const char *p_name;
    struct protoent protoent, *p;
    struct servent servent, *s;

    if (! WOLFSENTRY_CHECK_BITS(jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS))
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    if (data_size >= sizeof d_buf)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);

    memcpy(d_buf, data, data_size);
    d_buf[data_size] = 0;

    if (sa->sa_proto != 0) {
        if (getprotobynumber_r(
                sa->sa_proto,
                &protoent,
                get_buf, sizeof get_buf,
                &p) != 0) {
            if (errno == ERANGE)
                WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
            else
                WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
        }
    } else
        p = NULL;

    if (p) {
        size_t p_name_len = strlen(p->p_name) + 1;
        if (p_name_len <= sizeof p_name_buf) {
            memcpy(p_name_buf, p->p_name, p_name_len);
            p_name = p_name_buf;
        } else
            WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    } else
        p_name = NULL;

    if (getservbyname_r(d_buf, p_name, &servent, get_buf, sizeof get_buf, &s) != 0) {
        if (errno == ERANGE)
            WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
        else
            WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    }

    sa->sa_port = (wolfsentry_port_t)ntohs((uint16_t)s->s_port);
    WOLFSENTRY_RETURN_OK;
}

#endif /* !WOLFSENTRY_NO_GETPROTOBY */

static wolfsentry_errcode_t handle_route_endpoint_clause(struct wolfsentry_json_process_state *jps, JSON_TYPE type, const unsigned char *data, size_t data_size, struct wolfsentry_sockaddr *sa) {
    if (! strcmp(jps->cur_keyname, "port")) {
        if (sa->sa_family == WOLFSENTRY_AF_UNSPEC)
            WOLFSENTRY_ERROR_RETURN(CONFIG_OUT_OF_SEQUENCE);
        WOLFSENTRY_CLEAR_BITS(jps->o_u_c.route.flags,
                              sa == (struct wolfsentry_sockaddr *)&jps->o_u_c.route.remote ?
                              WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD :
                              WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD);
        if (CONFIG_TYPE_IS_NUMBER(type))
            WOLFSENTRY_ERROR_RERETURN(convert_uint16(type, data, data_size, &sa->sa_port));
#ifndef WOLFSENTRY_NO_GETPROTOBY
        else if (type == JSON_STRING)
            WOLFSENTRY_ERROR_RERETURN(convert_sockaddr_port_name(jps, data, data_size, sa));
#endif
        else
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    } else if (! strcmp(jps->cur_keyname, "address")) {
        if (sa->sa_family == WOLFSENTRY_AF_UNSPEC)
            WOLFSENTRY_ERROR_RETURN(CONFIG_OUT_OF_SEQUENCE);
        WOLFSENTRY_CLEAR_BITS(jps->o_u_c.route.flags,
                              sa == (struct wolfsentry_sockaddr *)&jps->o_u_c.route.remote ?
                              WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD :
                              WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD);
        WOLFSENTRY_ERROR_RERETURN(convert_sockaddr_address(jps, type, data, data_size, sa, sa->addr));
    }
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    else if (! strcmp(jps->cur_keyname, "bitmask")) {
        wolfsentry_addr_bits_t addr_size;
        wolfsentry_errcode_t ret;

        if (sa->sa_family == WOLFSENTRY_AF_UNSPEC)
            WOLFSENTRY_ERROR_RETURN(CONFIG_OUT_OF_SEQUENCE);

        ret = wolfsentry_addr_family_max_addr_bits(
            JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
            sa->sa_family,
            &addr_size);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);

        if (addr_size & 0x7)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

        if ((addr_size << 1) > WOLFSENTRY_MAX_ADDR_BITS)
            WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);

        /* if the address was already supplied and is shorter than the bitmask,
         * move it to right-justified position.
         */
        if ((sa->addr_len != 0) && (sa->addr_len != addr_size)) {
            size_t pad_bytes = WOLFSENTRY_BITS_TO_BYTES((size_t)addr_size - (size_t)sa->addr_len);
            memmove(sa->addr + pad_bytes, sa->addr, sa->addr_len);
            memset(sa->addr, 0, pad_bytes);
        }

        if (jps->section_under_construction == S_U_C_REMOTE_ENDPOINT)
            WOLFSENTRY_SET_BITS(jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK);
        else
            WOLFSENTRY_SET_BITS(jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK);

        ret = convert_sockaddr_address(jps, type, data, data_size, sa, sa->addr + WOLFSENTRY_BITS_TO_BYTES(addr_size));
        WOLFSENTRY_RERETURN_IF_ERROR(ret);

        sa->addr_len = (wolfsentry_addr_bits_t)(addr_size << 1);
        WOLFSENTRY_ERROR_RERETURN(ret);
    }
#endif
    else if (! strcmp(jps->cur_keyname, "prefix-bits")) {
        if (sa->sa_family == WOLFSENTRY_AF_UNSPEC)
            WOLFSENTRY_ERROR_RETURN(CONFIG_OUT_OF_SEQUENCE);
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
        if (((jps->section_under_construction == S_U_C_REMOTE_ENDPOINT) &&
             (jps->o_u_c.route.flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK))
            ||
            ((jps->section_under_construction == S_U_C_LOCAL_ENDPOINT) &&
             (jps->o_u_c.route.flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK)))
        {
            WOLFSENTRY_ERROR_RETURN(CONFIG_MISPLACED_KEY);
        }
#endif
        WOLFSENTRY_ERROR_RERETURN(convert_uint16(type, data, data_size, &sa->addr_len));
    }
    else if (! strcmp(jps->cur_keyname, "interface")) {
        WOLFSENTRY_CLEAR_BITS(jps->o_u_c.route.flags,
                              sa == (struct wolfsentry_sockaddr *)&jps->o_u_c.route.remote ?
                              WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD :
                              WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD);
        WOLFSENTRY_ERROR_RERETURN(convert_uint8(type, data, data_size, &sa->interface));
    } else
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
}

#endif /* !WOLFSENTRY_CONFIG_NO_ROUTE_ENDPOINTS */

static wolfsentry_errcode_t handle_route_boolean_clause(JSON_TYPE type, wolfsentry_route_flags_t *flags, wolfsentry_route_flags_t bit) {
    if (type == JSON_TRUE) {
        WOLFSENTRY_SET_BITS(*flags, bit);
        WOLFSENTRY_RETURN_OK;
    } else if (type == JSON_FALSE) {
        WOLFSENTRY_CLEAR_BITS(*flags, bit);
        WOLFSENTRY_RETURN_OK;
    } else
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
}

static wolfsentry_errcode_t handle_route_family_clause(struct wolfsentry_json_process_state *jps, JSON_TYPE type, const unsigned char *data, size_t data_size) {
    WOLFSENTRY_CLEAR_BITS(jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD);

    if (CONFIG_TYPE_IS_NUMBER(type)) {
        wolfsentry_errcode_t ret = convert_uint16(type, data, data_size, &jps->o_u_c.route.remote.sa_family);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        jps->o_u_c.route.local.sa_family = jps->o_u_c.route.remote.sa_family;
        WOLFSENTRY_RETURN_OK;
    }
#if defined(WOLFSENTRY_PROTOCOL_NAMES) && \
    !defined(WOLFSENTRY_CONFIG_NO_ADDR_FAMILY_NAMES)
    else if (type == JSON_STRING) {
        wolfsentry_errcode_t ret;
        ret = wolfsentry_addr_family_pton(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, (const char *)data, (int)data_size, &jps->o_u_c.route.local.sa_family);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        jps->o_u_c.route.remote.sa_family = jps->o_u_c.route.local.sa_family;
        WOLFSENTRY_ERROR_RERETURN(ret);
    }
#endif
    else
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
}

static wolfsentry_errcode_t handle_route_protocol_clause(struct wolfsentry_json_process_state *jps, JSON_TYPE type, const unsigned char *data, size_t data_size) {
    WOLFSENTRY_CLEAR_BITS(jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD);

    if (CONFIG_TYPE_IS_NUMBER(type)) {
        wolfsentry_errcode_t ret = convert_uint16(type, data, data_size, &jps->o_u_c.route.remote.sa_proto);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        jps->o_u_c.route.local.sa_proto = jps->o_u_c.route.remote.sa_proto;
    }
#ifndef WOLFSENTRY_NO_GETPROTOBY
    else if (type == JSON_STRING) {
        char d_buf[64];
        char get_buf[256];
        struct protoent protoent, *p;

        if (jps->o_u_c.route.remote.sa_family == WOLFSENTRY_AF_UNSPEC)
            WOLFSENTRY_ERROR_RETURN(CONFIG_OUT_OF_SEQUENCE);

        if ((jps->o_u_c.route.remote.sa_family != WOLFSENTRY_AF_INET) &&
            (jps->o_u_c.route.remote.sa_family != WOLFSENTRY_AF_INET6))
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

        if (data_size >= sizeof d_buf)
            WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);

        memcpy(d_buf, data, data_size);
        d_buf[data_size] = 0;

        if (getprotobyname_r(
                d_buf,
                &protoent,
                get_buf, sizeof get_buf,
                &p) != 0) {
            if (errno == ERANGE)
                WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
            else
                WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
        }

        jps->o_u_c.route.remote.sa_proto = (wolfsentry_proto_t)p->p_proto;
        jps->o_u_c.route.local.sa_proto = (wolfsentry_proto_t)p->p_proto;
    }
#endif /* !WOLFSENTRY_NO_GETPROTOBY */
    else
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    if (((jps->o_u_c.route.remote.sa_family == WOLFSENTRY_AF_INET) || (jps->o_u_c.route.remote.sa_family == WOLFSENTRY_AF_INET6)) &&
        ((jps->o_u_c.route.remote.sa_proto == IPPROTO_TCP) || (jps->o_u_c.route.remote.sa_proto == IPPROTO_UDP)))
        WOLFSENTRY_SET_BITS(jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS);

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t handle_route_clause(struct wolfsentry_json_process_state *jps, JSON_TYPE type, const unsigned char *data, size_t data_size) {
    wolfsentry_errcode_t ret;
    if ((jps->cur_depth == 2) && (type == JSON_OBJECT_END)) {
        wolfsentry_ent_id_t id;
        wolfsentry_action_res_t action_results;
        if (WOLFSENTRY_CHECK_BITS(jps->load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_NO_ROUTES_OR_EVENTS))
            ret = WOLFSENTRY_ERROR_ENCODE(OK);
        else
            ret = wolfsentry_route_insert(
                JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                jps->o_u_c.route.caller_arg,
                (const struct wolfsentry_sockaddr *)&jps->o_u_c.route.remote,
                (const struct wolfsentry_sockaddr *)&jps->o_u_c.route.local,
                jps->o_u_c.route.flags,
                (jps->o_u_c.route.event_label_len > 0) ? jps->o_u_c.route.event_label : NULL,
                jps->o_u_c.route.event_label_len,
                &id,
                &action_results);
        reset_o_u_c(jps);
        WOLFSENTRY_ERROR_RERETURN(ret);
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
        WOLFSENTRY_RETURN_OK;
    }
#ifndef WOLFSENTRY_CONFIG_NO_ROUTE_ENDPOINTS
    if (jps->cur_depth == 4) {
        if (type == JSON_OBJECT_BEG) {
            if (! strcmp(jps->cur_keyname, "remote")) {
                jps->section_under_construction = S_U_C_REMOTE_ENDPOINT;
                WOLFSENTRY_RETURN_OK;
            } else if (! strcmp(jps->cur_keyname, "local")) {
                jps->section_under_construction = S_U_C_LOCAL_ENDPOINT;
                WOLFSENTRY_RETURN_OK;
            } else
                WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
        } else if (jps->section_under_construction == S_U_C_REMOTE_ENDPOINT)
            WOLFSENTRY_ERROR_RERETURN(handle_route_endpoint_clause(jps, type, data, data_size, (struct wolfsentry_sockaddr *)&jps->o_u_c.route.remote));
        else if (jps->section_under_construction == S_U_C_LOCAL_ENDPOINT)
            WOLFSENTRY_ERROR_RERETURN(handle_route_endpoint_clause(jps, type, data, data_size, (struct wolfsentry_sockaddr *)&jps->o_u_c.route.local));
        else
            WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED); /* can't happen. */
    }
#endif
    if ((jps->cur_depth == 3) && (type == JSON_OBJECT_END)) {
        jps->section_under_construction = S_U_C_NONE;
        WOLFSENTRY_RETURN_OK;
    }

    if (jps->cur_depth != 3)
        WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);

    if (! strcmp(jps->cur_keyname, "parent-event")) {
        if (type != JSON_STRING)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        if (data_size > sizeof jps->o_u_c.route.event_label)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        jps->o_u_c.route.event_label_len = (int)data_size;
        memcpy(jps->o_u_c.route.event_label, data, data_size);
        WOLFSENTRY_CLEAR_BITS(jps->o_u_c.route.flags, WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD);
        WOLFSENTRY_RETURN_OK;
    }
    else if (! strcmp(jps->cur_keyname, "family"))
        WOLFSENTRY_ERROR_RERETURN(handle_route_family_clause(jps, type, data, data_size));
    else if (! strcmp(jps->cur_keyname, "protocol"))
        WOLFSENTRY_ERROR_RERETURN(handle_route_protocol_clause(jps, type, data, data_size));
    else {
        wolfsentry_route_flags_t flag;
        ret = wolfsentry_route_flag_assoc_by_name(jps->cur_keyname, WOLFSENTRY_LENGTH_NULL_TERMINATED, &flag);
        if (ret >= 0)
            WOLFSENTRY_ERROR_RERETURN(handle_route_boolean_clause(type, &jps->o_u_c.route.flags, flag));
        else {
            if (WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND))
                WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
            else
                WOLFSENTRY_ERROR_RERETURN(ret);
        }
    }
}

#endif /* !WOLFSENTRY_CONFIG_NO_ROUTES */

#ifndef WOLFSENTRY_CONFIG_NO_EVENTS

static wolfsentry_errcode_t handle_event_clause(struct wolfsentry_json_process_state *jps, JSON_TYPE type, const unsigned char *data, size_t data_size) {
    if (jps->table_under_construction != T_U_C_EVENTS)
        WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);

    if ((jps->cur_depth == 1) && (type == JSON_ARRAY_END)) {
        jps->table_under_construction = T_U_C_NONE;
        WOLFSENTRY_RETURN_OK;
    }

    if (jps->object_under_construction != O_U_C_EVENT) {
        if ((jps->cur_depth == 3) && (type == JSON_OBJECT_BEG) && (jps->object_under_construction == O_U_C_NONE)) {
            jps->object_under_construction = O_U_C_EVENT;
            WOLFSENTRY_RETURN_OK;
        } else
            WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
    }

    if ((jps->cur_depth == 3) && (type == JSON_STRING) && (! strcmp(jps->cur_keyname, "label"))) {
        if (data_size >= sizeof jps->o_u_c.event.label)
            WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
        memcpy(jps->o_u_c.event.label, data, data_size);
        jps->o_u_c.event.label_len = (int)data_size;
        WOLFSENTRY_RETURN_OK;
    }

    if ((jps->cur_depth == 3) && CONFIG_TYPE_IS_NUMBER(type)) {
        if (! strcmp(jps->cur_keyname, "priority")) {
            if (jps->o_u_c.event.inserted)
                WOLFSENTRY_ERROR_RETURN(CONFIG_OUT_OF_SEQUENCE);
            WOLFSENTRY_ERROR_RERETURN(convert_uint16(type, data, data_size, &jps->o_u_c.event.priority));
        }
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
    }

#ifndef WOLFSENTRY_CONFIG_NO_EVENTCONFIG
    if ((jps->cur_depth == 4) && (type == JSON_OBJECT_BEG) && (! strcmp(jps->cur_keyname, "config")) && (jps->section_under_construction == S_U_C_NONE)) {
        if (jps->o_u_c.event.inserted)
            WOLFSENTRY_ERROR_RETURN(CONFIG_OUT_OF_SEQUENCE);
        jps->section_under_construction = S_U_C_EVENTCONFIG;
        jps->o_u_c.event.config = jps->default_config; /* initialize with global defaults, particularly to pick up route_private_data* fields */
        jps->o_u_c.event.configed = 1;
        WOLFSENTRY_RETURN_OK;
    }

    if (((jps->cur_depth == 4) || (jps->cur_depth == 5)) && (jps->section_under_construction == S_U_C_EVENTCONFIG))
        WOLFSENTRY_ERROR_RERETURN(handle_eventconfig_clause(jps, type, data, data_size, &jps->o_u_c.event.config));

    if ((jps->cur_depth == 3) && (type == JSON_OBJECT_END) && (jps->section_under_construction == S_U_C_EVENTCONFIG)) {
        jps->section_under_construction = S_U_C_NONE;
        if (WOLFSENTRY_CHECK_BITS(jps->load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_NO_ROUTES_OR_EVENTS))
            WOLFSENTRY_RETURN_OK;
        else if (jps->o_u_c.event.inserted)
            WOLFSENTRY_ERROR_RERETURN(wolfsentry_event_update_config(JPS_WOLFSENTRY_CONTEXT_ARGS_OUT, jps->o_u_c.event.label, jps->o_u_c.event.label_len, &jps->o_u_c.event.config));
        else
            WOLFSENTRY_RETURN_OK;
    }
#endif /* !WOLFSENTRY_CONFIG_NO_EVENTCONFIG */

    if (! jps->o_u_c.event.inserted) {
        wolfsentry_ent_id_t id;
        wolfsentry_errcode_t ret;
        if (WOLFSENTRY_CHECK_BITS(jps->load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_NO_ROUTES_OR_EVENTS))
            ret = WOLFSENTRY_ERROR_ENCODE(OK);
        else
            ret = wolfsentry_event_insert(
                JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                jps->o_u_c.event.label,
                jps->o_u_c.event.label_len,
                jps->o_u_c.event.priority,
#ifndef WOLFSENTRY_CONFIG_NO_EVENTCONFIG
                jps->o_u_c.event.configed ? &jps->o_u_c.event.config : NULL,
#else
                NULL,
#endif
                WOLFSENTRY_EVENT_FLAG_NONE,
                &id);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        jps->o_u_c.event.inserted = 1;
    }

    if ((jps->cur_depth == 2) && (type == JSON_OBJECT_END))
        WOLFSENTRY_ERROR_RERETURN(reset_o_u_c(jps));

    if ((jps->cur_depth == 3) && (type == JSON_STRING)) {
        if (! strcmp(jps->cur_keyname, "aux-parent-event")) {
            if (WOLFSENTRY_CHECK_BITS(jps->load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_NO_ROUTES_OR_EVENTS))
                WOLFSENTRY_RETURN_OK;
            WOLFSENTRY_ERROR_RERETURN(wolfsentry_event_set_aux_event(
                JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                jps->o_u_c.event.label,
                jps->o_u_c.event.label_len,
                (const char *)data,
                (int)data_size));
        }

#ifndef WOLFSENTRY_CONFIG_NO_LEGACY_EVENT_SYNTAX
        {
            wolfsentry_errcode_t ret;
            wolfsentry_action_type_t subevent_type = WOLFSENTRY_ACTION_TYPE_NONE;

            /* In early versions (pre-1.4.0), there was only one action list in
             * each event, and "subevents" held the lists for each action type.
             */
            if (! strcmp(jps->cur_keyname, "insert-event"))
                subevent_type = WOLFSENTRY_ACTION_TYPE_INSERT;
            else if (! strcmp(jps->cur_keyname, "match-event"))
                subevent_type = WOLFSENTRY_ACTION_TYPE_MATCH;
            else if (! strcmp(jps->cur_keyname, "update-event"))
                subevent_type = WOLFSENTRY_ACTION_TYPE_UPDATE;
            else if (! strcmp(jps->cur_keyname, "delete-event"))
                subevent_type = WOLFSENTRY_ACTION_TYPE_DELETE;
            else if (! strcmp(jps->cur_keyname, "decision-event"))
                subevent_type = WOLFSENTRY_ACTION_TYPE_DECISION;

            if (subevent_type != WOLFSENTRY_ACTION_TYPE_NONE) {
                struct wolfsentry_action_list_ent *subevent_action_cursor;
                const char *action_label;
                int action_label_len;

                if (data_size > WOLFSENTRY_MAX_LABEL_BYTES)
                    WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
                if (WOLFSENTRY_CHECK_BITS(jps->load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_NO_ROUTES_OR_EVENTS))
                    WOLFSENTRY_RETURN_OK;

                ret = wolfsentry_event_action_list_start(
                    JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                    (const char *)data,
                    (int)data_size,
                    WOLFSENTRY_ACTION_TYPE_POST,
                    &subevent_action_cursor);
                WOLFSENTRY_RERETURN_IF_ERROR(ret);

                while (wolfsentry_event_action_list_next(
                           JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                           &subevent_action_cursor,
                           &action_label,
                           &action_label_len) >= 0)
                {
                    ret = wolfsentry_event_action_append(
                        JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                        jps->o_u_c.event.label,
                        jps->o_u_c.event.label_len,
                        subevent_type,
                        action_label,
                        action_label_len);
                    WOLFSENTRY_RERETURN_IF_ERROR(ret);
                }

                ret = wolfsentry_event_action_list_done(
                    JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                    &subevent_action_cursor);

                WOLFSENTRY_ERROR_RERETURN(ret);
            }
        }
#endif

        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
    }

    if ((jps->cur_depth == 4) && (type == JSON_ARRAY_BEG) && (jps->section_under_construction == S_U_C_NONE)) {
        if (! strcmp(jps->cur_keyname, "post-actions"))
        {
            jps->o_u_c.event.cur_action_list_under_construction = WOLFSENTRY_ACTION_TYPE_POST;
        }
#ifndef WOLFSENTRY_CONFIG_NO_LEGACY_EVENT_SYNTAX
        else if (! strcmp(jps->cur_keyname, "actions"))
            jps->o_u_c.event.cur_action_list_under_construction = WOLFSENTRY_ACTION_TYPE_POST;
#endif
        else if (! strcmp(jps->cur_keyname, "insert-actions"))
            jps->o_u_c.event.cur_action_list_under_construction = WOLFSENTRY_ACTION_TYPE_INSERT;
        else if (! strcmp(jps->cur_keyname, "match-actions"))
            jps->o_u_c.event.cur_action_list_under_construction = WOLFSENTRY_ACTION_TYPE_MATCH;
        else if (! strcmp(jps->cur_keyname, "update-actions"))
            jps->o_u_c.event.cur_action_list_under_construction = WOLFSENTRY_ACTION_TYPE_UPDATE;
        else if (! strcmp(jps->cur_keyname, "delete-actions"))
            jps->o_u_c.event.cur_action_list_under_construction = WOLFSENTRY_ACTION_TYPE_DELETE;
        else if (! strcmp(jps->cur_keyname, "decision-actions"))
            jps->o_u_c.event.cur_action_list_under_construction = WOLFSENTRY_ACTION_TYPE_DECISION;
        else
            jps->o_u_c.event.cur_action_list_under_construction = WOLFSENTRY_ACTION_TYPE_NONE;

        if (jps->o_u_c.event.cur_action_list_under_construction == WOLFSENTRY_ACTION_TYPE_NONE)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);

        jps->section_under_construction = S_U_C_ACTION_LIST;
        WOLFSENTRY_RETURN_OK;
    }

    if ((jps->cur_depth == 4) && (jps->section_under_construction == S_U_C_ACTION_LIST) && (type == JSON_STRING)) {
        if (data_size > WOLFSENTRY_MAX_LABEL_BYTES)
            WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
        if (WOLFSENTRY_CHECK_BITS(jps->load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_NO_ROUTES_OR_EVENTS))
            WOLFSENTRY_RETURN_OK;
        WOLFSENTRY_ERROR_RERETURN(wolfsentry_event_action_append(
                    JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                    jps->o_u_c.event.label,
                    jps->o_u_c.event.label_len,
                    jps->o_u_c.event.cur_action_list_under_construction,
                    (const char *)data,
                    (int)data_size));
    }

    if ((jps->cur_depth == 3) && (type == JSON_ARRAY_END) && (jps->section_under_construction == S_U_C_ACTION_LIST)) {
        jps->section_under_construction = S_U_C_NONE;
        WOLFSENTRY_RETURN_OK;
    }

    WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
}

#endif /* !WOLFSENTRY_CONFIG_NO_EVENTS */

#ifndef WOLFSENTRY_CONFIG_NO_USER_VALUES

static wolfsentry_errcode_t handle_user_value_clause(struct wolfsentry_json_process_state *jps, JSON_TYPE json_type, const unsigned char *data, size_t data_size) {
    wolfsentry_errcode_t ret;

    if (jps->table_under_construction != T_U_C_USER_VALUES)
        WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);

    if ((jps->cur_depth == 1) && (json_type == JSON_OBJECT_END)) {
        jps->table_under_construction = T_U_C_NONE;
        WOLFSENTRY_RETURN_OK;
    }

    if ((jps->cur_depth == 2) && (jps->object_under_construction == O_U_C_USER_VALUE) && (json_type == JSON_OBJECT_END))
        WOLFSENTRY_ERROR_RERETURN(reset_o_u_c(jps));

    if ((jps->cur_depth == 3) && (jps->cur_keydepth == 2) && (jps->object_under_construction == O_U_C_NONE)) {
        jps->o_u_c.user_value.label_len = (int)strlen(jps->cur_keyname);
        memcpy(jps->o_u_c.user_value.label, jps->cur_keyname, (size_t)jps->o_u_c.user_value.label_len);
        jps->object_under_construction = O_U_C_USER_VALUE;
        WOLFSENTRY_RETURN_OK;
    }

    if ((jps->cur_depth == 2) && (jps->cur_keydepth == 2) && (jps->object_under_construction == O_U_C_NONE)) {
        switch ((int)json_type) {
        case JSON_NULL:
            ret = wolfsentry_user_value_store_null(
                JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                jps->cur_keyname,
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                0);
            jps->object_under_construction = O_U_C_NONE;
            WOLFSENTRY_ERROR_RERETURN(ret);
        case JSON_FALSE:
            ret = wolfsentry_user_value_store_bool(
                JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                jps->cur_keyname,
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                WOLFSENTRY_KV_FALSE,
                0);
            jps->object_under_construction = O_U_C_NONE;
            WOLFSENTRY_ERROR_RERETURN(ret);
        case JSON_TRUE:
            ret = wolfsentry_user_value_store_bool(
                JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                jps->cur_keyname,
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                WOLFSENTRY_KV_TRUE,
                0);
            jps->object_under_construction = O_U_C_NONE;
            WOLFSENTRY_ERROR_RERETURN(ret);
        case JSON_NUMBER:
            do {
                int64_t i;
                if ((ret = convert_sint64(json_type, data, data_size, &i)) < 0)
                    break;
                ret = wolfsentry_user_value_store_sint(
                    JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                    jps->cur_keyname,
                    WOLFSENTRY_LENGTH_NULL_TERMINATED,
                    i,
                    0);
            } while(0);
            if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
                double d;
                if ((ret = convert_double(json_type, data, data_size, &d)) < 0)
                    WOLFSENTRY_ERROR_RERETURN(ret);
                ret = wolfsentry_user_value_store_double(
                    JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                    jps->cur_keyname,
                    WOLFSENTRY_LENGTH_NULL_TERMINATED,
                    d,
                    0);
            }
            jps->object_under_construction = O_U_C_NONE;
            WOLFSENTRY_ERROR_RERETURN(ret);
#ifdef WOLFSENTRY_WOLFCOSE
        case CONFIG_VALUE_NUMBER:
            {
                const struct config_number *number =
                    get_config_number(json_type, data, data_size);

                if (number == NULL)
                    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
                if (number->type == CONFIG_NUMBER_FLOAT) {
                    ret = wolfsentry_user_value_store_double(
                        JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                        jps->cur_keyname,
                        WOLFSENTRY_LENGTH_NULL_TERMINATED,
                        number->value.float_value,
                        0);
                } else {
                    int64_t value;

                    if (number->type == CONFIG_NUMBER_SINT)
                        value = number->value.sint_value;
                    else if ((number->type == CONFIG_NUMBER_UINT) &&
                             (number->value.uint_value <= (uint64_t)INT64_MAX))
                    {
                        value = (int64_t)number->value.uint_value;
                    } else
                        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
                    ret = wolfsentry_user_value_store_sint(
                        JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                        jps->cur_keyname,
                        WOLFSENTRY_LENGTH_NULL_TERMINATED,
                        value,
                        0);
                }
                jps->object_under_construction = O_U_C_NONE;
                WOLFSENTRY_ERROR_RERETURN(ret);
            }
#endif
        case JSON_STRING:
            if (data_size >= WOLFSENTRY_KV_MAX_VALUE_BYTES)
                WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
            ret = wolfsentry_user_value_store_string(
                JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                jps->cur_keyname,
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (const char *)data,
                (int)data_size,
                0);
            jps->object_under_construction = O_U_C_NONE;
            WOLFSENTRY_ERROR_RERETURN(ret);
        case JSON_OBJECT_BEG:
            jps->o_u_c.user_value.label_len = (int)strlen(jps->cur_keyname);
            memcpy(jps->o_u_c.user_value.label, jps->cur_keyname, (size_t)jps->o_u_c.user_value.label_len);
            WOLFSENTRY_RETURN_OK;
        case JSON_OBJECT_END:
            jps->object_under_construction = O_U_C_NONE;
            WOLFSENTRY_RETURN_OK;
        default:
            WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
        }
    }

#ifdef WOLFSENTRY_CONFIG_HAVE_JSON_DOM
    if ((jps->object_under_construction == O_U_C_USER_VALUE) && (jps->section_under_construction != S_U_C_USER_VALUE_JSON) && (! strcmp(jps->cur_keyname, "json"))) {
#ifdef WOLFSENTRY_JSON_VALUE_MAX_BYTES
        if (jps->input_format == CONFIG_INPUT_JSON)
            jps->json_value_start_pos = jps->parser.pos;
#ifdef WOLFSENTRY_WOLFCOSE
        else {
            jps->cbor_json_value_start_offset =
                jps->cbor_value_start_offset;
            if (jps->cbor_offset - jps->cbor_json_value_start_offset >
                WOLFSENTRY_JSON_VALUE_MAX_BYTES)
            {
                WOLFSENTRY_ERROR_RETURN(CONFIG_JSON_VALUE_SIZE);
            }
        }
#endif
#endif
        jps->section_under_construction = S_U_C_USER_VALUE_JSON;
        ret = json_dom_init_1(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(wolfsentry_get_allocator(jps->wolfsentry), jps->thread), &jps->dom_parser, jps->dom_parser_flags);
        if (ret < 0)
            WOLFSENTRY_ERROR_RERETURN(wolfsentry_centijson_errcode_translate(ret));
    }

    if ((jps->cur_depth >= 3) && (jps->object_under_construction == O_U_C_USER_VALUE) && (jps->section_under_construction == S_U_C_USER_VALUE_JSON)) {

#ifdef WOLFSENTRY_JSON_VALUE_MAX_BYTES
        if ((jps->input_format == CONFIG_INPUT_JSON) &&
            (jps->parser.pos.offset - jps->json_value_start_pos.offset > WOLFSENTRY_JSON_VALUE_MAX_BYTES))
        {
            memcpy(&jps->parser.err_pos, &jps->parser.pos, sizeof jps->parser.err_pos);
            WOLFSENTRY_ERROR_RETURN(CONFIG_JSON_VALUE_SIZE);
        }
#ifdef WOLFSENTRY_WOLFCOSE
        if ((jps->input_format == CONFIG_INPUT_CBOR) &&
            (jps->cbor_offset - jps->cbor_json_value_start_offset >
             WOLFSENTRY_JSON_VALUE_MAX_BYTES))
        {
            WOLFSENTRY_ERROR_RETURN(CONFIG_JSON_VALUE_SIZE);
        }
#endif
#endif

        ret = json_dom_process(json_type, data, data_size, (void *)&jps->dom_parser);

        if ((ret < 0) && (jps->input_format == CONFIG_INPUT_JSON)) {
            memcpy(&jps->parser.err_pos, &jps->parser.value_pos, sizeof jps->parser.err_pos);
        }
        if (ret < 0) {
            WOLFSENTRY_ERROR_RERETURN(wolfsentry_centijson_errcode_translate(ret));
        }

        if (jps->cur_depth == 3) {
            JSON_VALUE jv;

            ret = json_dom_fini_aux(&jps->dom_parser, &jv);
            if (ret != 0)
                WOLFSENTRY_ERROR_RERETURN(wolfsentry_centijson_errcode_translate(ret));

            ret = wolfsentry_user_value_store_json(
                JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                jps->o_u_c.user_value.label,
                jps->o_u_c.user_value.label_len,
                &jv,
                0 /* overwrite_p */);

            if (ret < 0) {
                wolfsentry_errcode_t ret2 = json_value_fini(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(wolfsentry_get_allocator(jps->wolfsentry), jps->thread), &jv);
                if (ret2 < 0)
                    WOLFSENTRY_ERROR_RERETURN(wolfsentry_centijson_errcode_translate(ret2));
                else
                    WOLFSENTRY_ERROR_RERETURN(ret);
            }

            jps->section_under_construction = S_U_C_NONE;
        }
        WOLFSENTRY_RETURN_OK;
    }
#endif /* WOLFSENTRY_CONFIG_HAVE_JSON_DOM */

    if ((jps->cur_depth == 3) && (jps->object_under_construction == O_U_C_USER_VALUE)) {
        wolfsentry_kv_type_t ws_type;

        if (jps->cur_keydepth != 3)
            WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);

        if (! (CONFIG_TYPE_IS_NUMBER(json_type) ||
               (json_type == JSON_STRING)))
            WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);

        if (! strcmp(jps->cur_keyname, "uint"))
            ws_type = WOLFSENTRY_KV_UINT;
        else if (! strcmp(jps->cur_keyname, "sint"))
            ws_type = WOLFSENTRY_KV_SINT;
        else if (! strcmp(jps->cur_keyname, "float"))
            ws_type = WOLFSENTRY_KV_FLOAT;
        else if (! strcmp(jps->cur_keyname, "string"))
            ws_type = WOLFSENTRY_KV_STRING;
        else if (! strcmp(jps->cur_keyname, "base64"))
            ws_type = WOLFSENTRY_KV_BYTES;
        else
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

        if (((ws_type == WOLFSENTRY_KV_STRING) ||
             (ws_type == WOLFSENTRY_KV_BYTES)) &&
            (json_type != JSON_STRING))
        {
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        }

        switch (ws_type) {
        case WOLFSENTRY_KV_UINT: {
            uint64_t i;
            if ((ret = convert_uint64(json_type, data, data_size, &i)) < 0)
                WOLFSENTRY_ERROR_RERETURN(ret);
            WOLFSENTRY_ERROR_RERETURN(wolfsentry_user_value_store_uint(
                JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                jps->o_u_c.user_value.label,
                jps->o_u_c.user_value.label_len,
                i,
                0));
        }
        case WOLFSENTRY_KV_SINT: {
            int64_t i;
            if ((ret = convert_sint64(json_type, data, data_size, &i)) < 0)
                WOLFSENTRY_ERROR_RERETURN(ret);
            WOLFSENTRY_ERROR_RERETURN(wolfsentry_user_value_store_sint(
                JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                jps->o_u_c.user_value.label,
                jps->o_u_c.user_value.label_len,
                i,
                0));
        }
        case WOLFSENTRY_KV_FLOAT: {
            double d;
            if ((ret = convert_double(json_type, data, data_size, &d)) < 0)
                WOLFSENTRY_ERROR_RERETURN(ret);
            WOLFSENTRY_ERROR_RERETURN(wolfsentry_user_value_store_double(
                JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                jps->o_u_c.user_value.label,
                jps->o_u_c.user_value.label_len,
                d,
                0));
        }
        case WOLFSENTRY_KV_STRING:
            if (data_size >= WOLFSENTRY_KV_MAX_VALUE_BYTES)
                WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
            WOLFSENTRY_ERROR_RERETURN(wolfsentry_user_value_store_string(
                JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                jps->o_u_c.user_value.label,
                jps->o_u_c.user_value.label_len,
                (const char *)data,
                (int)data_size,
                0));

        case WOLFSENTRY_KV_BYTES:
            if (data_size >= WOLFSENTRY_KV_MAX_VALUE_BYTES)
                WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
            WOLFSENTRY_ERROR_RERETURN(wolfsentry_user_value_store_bytes_base64(
                JPS_WOLFSENTRY_CONTEXT_ARGS_OUT,
                jps->o_u_c.user_value.label,
                jps->o_u_c.user_value.label_len,
                (const char *)data,
                (int)data_size,
                0));

        case WOLFSENTRY_KV_JSON:
        case WOLFSENTRY_KV_NONE:
        case WOLFSENTRY_KV_NULL:
        case WOLFSENTRY_KV_TRUE:
        case WOLFSENTRY_KV_FALSE:
        case WOLFSENTRY_KV_FLAG_READONLY:
            WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
        }

        WOLFSENTRY_RETURN_OK;

    }

    WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
}

#endif /* !WOLFSENTRY_CONFIG_NO_USER_VALUES */

#define WOLFSENTRY_ERROR_OUT(x) { ret = WOLFSENTRY_ERROR_ENCODE(x); goto out; }

static wolfsentry_errcode_t json_process(
    JSON_TYPE type,
    const unsigned char *data,
    size_t data_size,
    void *pre_jps)
{
    struct wolfsentry_json_process_state *jps = (struct wolfsentry_json_process_state *)pre_jps;
    wolfsentry_errcode_t ret;

#ifdef DEBUG_JSON
    if (data)
        printf("depth=%d t=%d d=\"%.*s\"\n", jps->cur_depth, type, (int)data_size, data);
    else
        printf("depth=%d t=%d\n", jps->cur_depth, type);
#endif

    if (type == JSON_KEY) {

#ifdef WOLFSENTRY_CONFIG_HAVE_JSON_DOM
        if (jps->section_under_construction == S_U_C_USER_VALUE_JSON) {
            ret = handle_user_value_clause(jps, type, data, data_size);
            goto out;
        }
#endif

#ifndef WOLFSENTRY_NO_JSON
        if (jps->input_format == CONFIG_INPUT_JSON) {
            memcpy(&jps->key_pos, &jps->parser.pos, sizeof jps->key_pos);
            jps->key_pos.column_number -= (unsigned)(data_size + 2U); /* kludge to move the pointer back to the start of the key */
        }
#endif
        if (data_size >= sizeof jps->cur_keyname)
            WOLFSENTRY_ERROR_OUT(CONFIG_INVALID_KEY);
        memcpy(jps->cur_keyname, data, data_size);
        jps->cur_keyname[data_size] = 0;
        jps->cur_keydepth = jps->cur_depth;
        WOLFSENTRY_RETURN_OK;
    }

    if ((type == JSON_OBJECT_BEG) || (type == JSON_ARRAY_BEG))
        ++jps->cur_depth;
    else if ((type == JSON_OBJECT_END) || (type == JSON_ARRAY_END))
        --jps->cur_depth;

    if ((type == JSON_OBJECT_BEG) && (jps->cur_depth == 1))
        WOLFSENTRY_RETURN_OK;

    if ((type == JSON_OBJECT_END) && (jps->cur_depth == 0)) {
        reset_o_u_c(jps);
        WOLFSENTRY_RETURN_OK;
    }

    if (jps->table_under_construction == T_U_C_NONE) {
        if ((jps->cur_keydepth == 1) && (jps->cur_depth <= 2))  {
            switch ((int)type) {
            case JSON_FALSE:
            case JSON_TRUE:
            case JSON_NUMBER:
#ifdef WOLFSENTRY_WOLFCOSE
            case CONFIG_VALUE_NUMBER:
#endif
            case JSON_STRING:
                if (jps->cur_depth != 1)
                    WOLFSENTRY_ERROR_OUT(CONFIG_UNEXPECTED);
                if (! strcmp(jps->cur_keyname, "wolfsentry-config-version")) {
                    ret = convert_uint32(type, data, data_size, &jps->config_version);
                    if (ret < 0)
                        goto out;
                    if (jps->config_version != 1)
                        WOLFSENTRY_ERROR_OUT(CONFIG_INVALID_VALUE);
                    WOLFSENTRY_RETURN_OK;
                }
                WOLFSENTRY_ERROR_OUT(CONFIG_INVALID_KEY);
            case JSON_OBJECT_BEG:
                if (jps->config_version == 0)
                    WOLFSENTRY_ERROR_OUT(CONFIG_UNEXPECTED);
                if (jps->cur_depth != 2)
                    WOLFSENTRY_ERROR_OUT(CONFIG_UNEXPECTED);
#ifndef WOLFSENTRY_CONFIG_NO_EVENTCONFIG
                if (! strcmp(jps->cur_keyname, "config-update")) {
                    jps->table_under_construction = T_U_C_TOPCONFIG;
                    WOLFSENTRY_RETURN_OK;
                }
#endif
                if (! strcmp(jps->cur_keyname, "default-policies")) {
                    jps->table_under_construction = T_U_C_DEFAULTPOLICIES;
                    WOLFSENTRY_RETURN_OK;
                }
#ifndef WOLFSENTRY_CONFIG_NO_USER_VALUES
                if (! strcmp(jps->cur_keyname, "user-values")) {
                    jps->table_under_construction = T_U_C_USER_VALUES;
                    WOLFSENTRY_RETURN_OK;
                }
#endif
                WOLFSENTRY_ERROR_OUT(CONFIG_INVALID_KEY);
            case JSON_ARRAY_BEG:
                if (jps->config_version == 0)
                    WOLFSENTRY_ERROR_OUT(CONFIG_UNEXPECTED);
                if (jps->cur_depth != 2)
                    WOLFSENTRY_ERROR_OUT(CONFIG_UNEXPECTED);
#ifndef WOLFSENTRY_CONFIG_NO_EVENTS
                if ((! strcmp(jps->cur_keyname, "events-insert")) ||
                    (! strcmp(jps->cur_keyname, "events")))
                {
                    jps->table_under_construction = T_U_C_EVENTS;
                    WOLFSENTRY_RETURN_OK;
                }
#endif
#ifndef WOLFSENTRY_CONFIG_NO_ROUTES
                if ((! strcmp(jps->cur_keyname, "static-routes-insert")) ||
                    (! strcmp(jps->cur_keyname, "routes")))
                {
                    jps->table_under_construction = T_U_C_STATIC_ROUTES;
                    WOLFSENTRY_RETURN_OK;
                }
#endif
                if (! strcmp(jps->cur_keyname, "actions-update")) {
                    WOLFSENTRY_ERROR_RETURN(CONFIG_MISSING_HANDLER);
                    /*
                    jps->table_under_construction = T_U_C_ACTIONS;
                    WOLFSENTRY_RETURN_OK;
                    */
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

#ifndef WOLFSENTRY_CONFIG_NO_EVENTCONFIG
    if (jps->table_under_construction == T_U_C_TOPCONFIG) {
        ret = handle_eventconfig_clause(jps, type, data, data_size, &jps->default_config);
        goto out;
    }
#endif

    if (jps->table_under_construction == T_U_C_DEFAULTPOLICIES) {
        ret = handle_defaultpolicy_clause(jps, type, data, data_size);
        goto out;
    }

#ifndef WOLFSENTRY_CONFIG_NO_ROUTES
    if (jps->table_under_construction == T_U_C_STATIC_ROUTES) {
        if ((jps->cur_depth == 1) && (type == JSON_ARRAY_END)) {
            jps->table_under_construction = T_U_C_NONE;
            WOLFSENTRY_RETURN_OK;
        }
        ret = handle_route_clause(jps, type, data, data_size);
        goto out;
    }
#endif

#ifndef WOLFSENTRY_CONFIG_NO_EVENTS
    if (jps->table_under_construction == T_U_C_EVENTS) {
        if ((jps->cur_depth == 1) && (type == JSON_ARRAY_END)) {
            jps->table_under_construction = T_U_C_NONE;
            WOLFSENTRY_RETURN_OK;
        }
        ret = handle_event_clause(jps, type, data, data_size);
        goto out;
    }
#endif

#if 0
    if (jps->table_under_construction == T_U_C_ACTIONS) {
        if ((jps->cur_depth == 1) && (type == JSON_ARRAY_END)) {
            jps->table_under_construction = T_U_C_NONE;
            WOLFSENTRY_RETURN_OK;
        }
        ret = handle_action_clause(jps, type, data, data_size);
        goto out;
    }
#endif

#ifndef WOLFSENTRY_CONFIG_NO_USER_VALUES
    if (jps->table_under_construction == T_U_C_USER_VALUES) {
        if ((jps->cur_depth == 1) && (type == JSON_ARRAY_END)) {
            jps->table_under_construction = T_U_C_NONE;
            WOLFSENTRY_RETURN_OK;
        }
        ret = handle_user_value_clause(jps, type, data, data_size);
        goto out;
    }
#endif

    WOLFSENTRY_ERROR_OUT(CONFIG_UNEXPECTED);

  out:

    if (ret < 0) {
        reset_o_u_c(jps);
#ifndef WOLFSENTRY_NO_JSON
        if (jps->input_format == CONFIG_INPUT_JSON) {
            if (WOLFSENTRY_ERROR_CODE_IS(ret, CONFIG_INVALID_KEY))
                memcpy(&jps->parser.err_pos, &jps->key_pos, sizeof(JSON_INPUT_POS));
            else if (WOLFSENTRY_ERROR_CODE_IS(ret, CONFIG_INVALID_VALUE))
                memcpy(&jps->parser.err_pos, &jps->parser.value_pos, sizeof(JSON_INPUT_POS));
            else
                memcpy(&jps->parser.err_pos, &jps->parser.pos, sizeof(JSON_INPUT_POS));
        }
#endif
        WOLFSENTRY_ERROR_RERETURN(ret);
    } else
        WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t config_state_fini(
    struct wolfsentry_json_process_state **jps,
    wolfsentry_errcode_t ret);

static wolfsentry_errcode_t config_state_init(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_config_load_flags_t load_flags,
    enum config_input_format input_format,
    struct wolfsentry_json_process_state **jps)
{
    wolfsentry_errcode_t ret = WOLFSENTRY_ERROR_ENCODE(OK);
#ifdef WOLFSENTRY_THREADSAFE
    int locked = 0;
#endif
    if (wolfsentry == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (WOLFSENTRY_MASKIN_BITS(load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_FINI))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
#ifndef WOLFSENTRY_CONFIG_NO_TRANSACTIONS
    if (WOLFSENTRY_MASKIN_BITS(
            load_flags,
            WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN) &&
        WOLFSENTRY_MASKIN_BITS(
            load_flags,
            WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT))
    {
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }
#else
    if (WOLFSENTRY_MASKIN_BITS(
            load_flags,
            WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN |
                WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT))
    {
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    }
#endif

    if ((*jps = (struct wolfsentry_json_process_state *)wolfsentry_malloc(WOLFSENTRY_CONTEXT_ARGS_OUT, sizeof **jps)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    memset(*jps, 0, sizeof **jps);
    (*jps)->load_flags = load_flags;
    (*jps)->input_format = input_format;

    if (WOLFSENTRY_MASKIN_BITS(load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_ABORT)) {
#ifdef WOLFSENTRY_CONFIG_HAVE_JSON_DOM
        (*jps)->dom_parser_flags |= JSON_DOM_DUPKEY_ABORT;
#else
        { ret = WOLFSENTRY_ERROR_ENCODE(IMPLEMENTATION_MISSING); goto out; }
#endif
    }
    if (WOLFSENTRY_MASKIN_BITS(load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_USEFIRST)) {
#ifdef WOLFSENTRY_CONFIG_HAVE_JSON_DOM
        (*jps)->dom_parser_flags |= JSON_DOM_DUPKEY_USEFIRST;
#else
        { ret = WOLFSENTRY_ERROR_ENCODE(IMPLEMENTATION_MISSING); goto out; }
#endif
    }
    if (WOLFSENTRY_MASKIN_BITS(load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_USELAST)) {
#ifdef WOLFSENTRY_CONFIG_HAVE_JSON_DOM
        (*jps)->dom_parser_flags |= JSON_DOM_DUPKEY_USELAST;
#else
        { ret = WOLFSENTRY_ERROR_ENCODE(IMPLEMENTATION_MISSING); goto out; }
#endif
    }
    if (WOLFSENTRY_MASKIN_BITS(load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_MAINTAINDICTORDER)) {
#ifdef WOLFSENTRY_CONFIG_HAVE_JSON_DOM
        (*jps)->dom_parser_flags |= JSON_DOM_MAINTAINDICTORDER;
#else
        { ret = WOLFSENTRY_ERROR_ENCODE(IMPLEMENTATION_MISSING); goto out; }
#endif
    }

#ifdef WOLFSENTRY_THREADSAFE
#ifdef WOLFSENTRY_CONFIG_NO_TRANSACTIONS
    if ((ret = WOLFSENTRY_MUTEX_EX(wolfsentry)) < 0)
        goto out;
#else
    if ((! WOLFSENTRY_MASKIN_BITS(load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN|WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT)) ||
        (thread == NULL))
    {
        if ((ret = WOLFSENTRY_MUTEX_EX(wolfsentry)) < 0)
            goto out;
    } else if (WOLFSENTRY_MASKIN_BITS(load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN)) {
        /* thread == NULL is already routed to the mutex path above. */
        if ((ret = WOLFSENTRY_SHARED_EX(wolfsentry)) < 0)
            goto out;
    } else {
        ret = WOLFSENTRY_PROMOTABLE_EX(wolfsentry);
        if (ret < 0)
            goto out;
        if (WOLFSENTRY_SUCCESS_CODE_IS(ret, LOCK_OK_AND_GOT_RESV))
            (*jps)->got_reservation = 1;
    }
#endif
    locked = 1;
#endif

#ifndef WOLFSENTRY_CONFIG_NO_TRANSACTIONS
    (*jps)->wolfsentry_actual = wolfsentry;
#endif
#ifdef WOLFSENTRY_THREADSAFE
    (*jps)->thread = thread;
#endif
#ifdef WOLFSENTRY_CONFIG_NO_TRANSACTIONS
    (*jps)->wolfsentry = wolfsentry;
#else
    if (WOLFSENTRY_MASKIN_BITS(load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN|WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT)) {
        ret = wolfsentry_context_clone(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            &(*jps)->wolfsentry,
            WOLFSENTRY_CHECK_BITS(load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH)
            ? WOLFSENTRY_CLONE_FLAG_NONE :
            WOLFSENTRY_CHECK_BITS(load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_FLUSH_ONLY_ROUTES)
            ? WOLFSENTRY_CLONE_FLAG_NO_ROUTES
            : WOLFSENTRY_CLONE_FLAG_AS_AT_CREATION);
        if (ret < 0)
            goto out;
        ret = wolfsentry_context_inhibit_actions(JPSP_WOLFSENTRY_CONTEXT_ARGS_OUT);
        if (ret < 0)
            goto out;
    } else {
        (*jps)->wolfsentry = wolfsentry;
    }
#endif

  out:

    if (ret < 0) {
#ifdef WOLFSENTRY_THREADSAFE
        if (locked) {
            wolfsentry_errcode_t _lock_ret;
#ifdef WOLFSENTRY_CONFIG_NO_TRANSACTIONS
            _lock_ret = wolfsentry_context_unlock(wolfsentry, thread);
#else
            if ((*jps)->got_reservation)
                _lock_ret = wolfsentry_context_unlock_and_abandon_reservation(wolfsentry, thread);
            else
                _lock_ret = wolfsentry_context_unlock(wolfsentry, thread);
#endif
            if (_lock_ret < 0)
                ret = _lock_ret;
        }
#endif
#ifndef WOLFSENTRY_CONFIG_NO_TRANSACTIONS
        if (WOLFSENTRY_MASKIN_BITS(load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN|WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT) &&
            ((*jps)->wolfsentry != NULL))
        {
            int ret2 = wolfsentry_context_free(JPSP_P_WOLFSENTRY_CONTEXT_ARGS_OUT);
            if (ret2 < 0)
                ret = ret2;
        }
#endif
        wolfsentry_free(WOLFSENTRY_CONTEXT_ARGS_OUT, *jps);
        *jps = NULL;
        WOLFSENTRY_ERROR_RERETURN(ret);
    } else
        WOLFSENTRY_RETURN_OK; /* keeping lock! */
}

static wolfsentry_errcode_t config_state_prepare(
    struct wolfsentry_json_process_state **jps)
{
    wolfsentry_errcode_t ret;

#ifndef WOLFSENTRY_CONFIG_NO_EVENTCONFIG
    /* Preserve context-specific defaults such as route private data fields. */
    ret = wolfsentry_defaultconfig_get(
        JPSP_WOLFSENTRY_CONTEXT_ARGS_OUT,
        &(*jps)->default_config);
    if (ret < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
#endif

#ifdef WOLFSENTRY_CONFIG_NO_TRANSACTIONS
    if (! WOLFSENTRY_MASKIN_BITS(
            (*jps)->load_flags,
            WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH))
#else
    if (! WOLFSENTRY_MASKIN_BITS(
            (*jps)->load_flags,
            WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN |
                WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH |
                WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT))
#endif
    {
        if (WOLFSENTRY_CHECK_BITS(
                (*jps)->load_flags,
                WOLFSENTRY_CONFIG_LOAD_FLAG_FLUSH_ONLY_ROUTES))
        {
            struct wolfsentry_route_table *main_table;
            wolfsentry_action_res_t action_results;

            WOLFSENTRY_CLEAR_ALL_BITS(action_results);
            ret = wolfsentry_route_get_main_table(
                JPSP_WOLFSENTRY_CONTEXT_ARGS_OUT,
                &main_table);
            if (ret < 0)
                WOLFSENTRY_ERROR_RERETURN(ret);
            ret = wolfsentry_route_flush_table(
                JPSP_WOLFSENTRY_CONTEXT_ARGS_OUT,
                main_table,
                &action_results);
        } else {
            ret = wolfsentry_context_flush(
                JPSP_WOLFSENTRY_CONTEXT_ARGS_OUT);
        }
        if (ret < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
    }

    WOLFSENTRY_RETURN_OK;
}

#ifndef WOLFSENTRY_NO_JSON

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_init_ex(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_config_load_flags_t load_flags,
    const JSON_CONFIG *json_config,
    struct wolfsentry_json_process_state **jps)
{
    wolfsentry_errcode_t ret;
    static const JSON_CALLBACKS json_callbacks = {
#ifdef WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
        .process =
#endif
        (int (*)(JSON_TYPE, const unsigned char *, size_t, void *))json_process
    };
    static const JSON_CONFIG default_json_config = {
#ifdef WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
        .max_total_len = WOLFSENTRY_MAX_JSON_TOTAL_LEN,
        .max_total_values = 0,
        .max_number_len = 20,
        .max_string_len = WOLFSENTRY_KV_MAX_VALUE_BYTES,
        .max_key_len = WOLFSENTRY_MAX_LABEL_BYTES,
        .max_nesting_level = WOLFSENTRY_MAX_JSON_NESTING,
        .flags = JSON_NOSCALARROOT
#else
        WOLFSENTRY_MAX_JSON_TOTAL_LEN,
        0,
        20,
        WOLFSENTRY_KV_MAX_VALUE_BYTES,
        WOLFSENTRY_MAX_LABEL_BYTES,
        WOLFSENTRY_MAX_JSON_NESTING,
        JSON_NOSCALARROOT
#endif
    };

    if (json_config == NULL)
        json_config = &default_json_config;

    /* Key safety depends on CentiJSON enforcing this configured limit. */
    if (json_config->max_key_len > WOLFSENTRY_MAX_LABEL_BYTES)
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);

    ret = config_state_init(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        load_flags,
        CONFIG_INPUT_JSON,
        jps);
    if (ret < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    ret = json_init(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator((*jps)->wolfsentry)),
        &(*jps)->parser,
        &json_callbacks,
        json_config,
        *jps);
    if (ret < 0) {
        ret = wolfsentry_centijson_errcode_translate(ret);
        WOLFSENTRY_ERROR_RERETURN(config_state_fini(jps, ret));
    }

    ret = config_state_prepare(jps);
    if (ret < 0)
        WOLFSENTRY_ERROR_RERETURN(config_state_fini(jps, ret));

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_init(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_config_load_flags_t load_flags,
    struct wolfsentry_json_process_state **jps)
{
    WOLFSENTRY_ERROR_RERETURN(
        wolfsentry_config_json_init_ex(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            load_flags,
            NULL,
            jps));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_feed(
    struct wolfsentry_json_process_state *jps,
    const unsigned char *json_in,
    size_t json_in_len,
    char *err_buf,
    size_t err_buf_size)
{
    JSON_INPUT_POS json_pos;
    int ret;

#ifdef WOLFSENTRY_CONFIG_NO_ERROR_MESSAGES
    (void)err_buf;
    (void)err_buf_size;
#endif

    if (jps == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (WOLFSENTRY_CHECK_BITS(jps->load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_FINI))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    ret = json_feed(&jps->parser, json_in, json_in_len);
    if (ret < 0) {
        jps->fini_ret = json_fini(&jps->parser, &json_pos);
        WOLFSENTRY_SET_BITS(jps->load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_FINI);
#ifndef WOLFSENTRY_CONFIG_NO_ERROR_MESSAGES
        if ((err_buf != NULL) && (err_buf_size > 0U)) {
            if (WOLFSENTRY_ERROR_DECODE_SOURCE_ID(jps->fini_ret) == WOLFSENTRY_SOURCE_ID_UNSET)
                ret = snprintf(err_buf, err_buf_size, "json_feed failed at offset %d, line %u, col %u, with centijson code " WOLFSENTRY_ERRCODE_FMT ": %s", (int)json_pos.offset, json_pos.line_number, json_pos.column_number, (int)jps->fini_ret, json_error_str(jps->fini_ret));
            else
                ret = snprintf(err_buf, err_buf_size, "json_feed failed at offset %d, line %u, col %u, with " WOLFSENTRY_ERROR_FMT, (int)json_pos.offset, json_pos.line_number, json_pos.column_number, WOLFSENTRY_ERROR_FMT_ARGS(jps->fini_ret));
            if (ret >= (int)err_buf_size)
                err_buf[err_buf_size - 1] = 0;
        }
#endif
        WOLFSENTRY_ERROR_RERETURN(wolfsentry_centijson_errcode_translate(jps->fini_ret));
    }
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_centijson_errcode(struct wolfsentry_json_process_state *jps, int *json_errcode, const char **json_errmsg)
{
    if ((jps == NULL) || (jps->parser.user_data == NULL))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (json_errcode)
        *json_errcode = jps->parser.errcode;
    if (json_errmsg)
        *json_errmsg = json_error_str(jps->parser.errcode);
    WOLFSENTRY_RETURN_OK;
}

#endif /* !WOLFSENTRY_NO_JSON */

#ifdef WOLFSENTRY_WOLFCOSE

struct cbor_container_state {
    size_t remaining;
    unsigned char major_type;
    unsigned char expecting_key;
};

static float cbor_half_to_float(uint16_t half)
{
    uint32_t sign = ((uint32_t)half & 0x8000U) << 16U;
    uint32_t exponent = ((uint32_t)half >> 10U) & 0x1fU;
    uint32_t fraction = (uint32_t)half & 0x3ffU;
    uint32_t bits;
    float value;

    if (exponent == 0U) {
        if (fraction == 0U) {
            bits = sign;
        } else {
            exponent = 113U;
            while ((fraction & 0x400U) == 0U) {
                fraction <<= 1U;
                --exponent;
            }
            fraction &= 0x3ffU;
            bits = sign | (exponent << 23U) | (fraction << 13U);
        }
    } else if (exponent == 31U) {
        bits = sign | 0x7f800000U | (fraction << 13U);
    } else {
        bits = sign | ((exponent + 112U) << 23U) | (fraction << 13U);
    }

    memcpy(&value, &bits, sizeof value);
    return value;
}

static wolfsentry_errcode_t cbor_decode_number(
    const WOLFCOSE_CBOR_ITEM *item,
    unsigned char additional_info,
    struct config_number *number)
{
    if (item->majorType == WOLFCOSE_CBOR_UINT) {
        number->type = CONFIG_NUMBER_UINT;
        number->value.uint_value = item->val;
    } else if (item->majorType == WOLFCOSE_CBOR_NEGINT) {
        if (item->val > (uint64_t)INT64_MAX)
            WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_SMALL);
        number->type = CONFIG_NUMBER_SINT;
        number->value.sint_value = -1 - (int64_t)item->val;
    } else if (additional_info == WOLFCOSE_CBOR_AI_FLOAT16) {
        number->type = CONFIG_NUMBER_FLOAT;
        number->value.float_value =
            (double)cbor_half_to_float((uint16_t)item->val);
    } else if (additional_info == WOLFCOSE_CBOR_AI_FLOAT32) {
        uint32_t bits = (uint32_t)item->val;
        float value;

        memcpy(&value, &bits, sizeof value);
        number->type = CONFIG_NUMBER_FLOAT;
        number->value.float_value = (double)value;
    } else if (additional_info == WOLFCOSE_CBOR_AI_FLOAT64) {
        uint64_t bits = item->val;

        number->type = CONFIG_NUMBER_FLOAT;
        memcpy(&number->value.float_value, &bits, sizeof bits);
    } else {
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    }

    WOLFSENTRY_RETURN_OK;
}

#ifndef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
static int cbor_text_number_is_json(const char *text, size_t text_len)
{
    size_t i = 0U;

    if ((i < text_len) && (text[i] == '-'))
        ++i;
    if (i >= text_len)
        return 0;
    if (text[i] == '0')
        ++i;
    else if ((text[i] >= '1') && (text[i] <= '9')) {
        do {
            ++i;
        } while ((i < text_len) && (text[i] >= '0') && (text[i] <= '9'));
    } else
        return 0;
    if ((i < text_len) && (text[i] == '.')) {
        ++i;
        if ((i >= text_len) || (text[i] < '0') || (text[i] > '9'))
            return 0;
        do {
            ++i;
        } while ((i < text_len) && (text[i] >= '0') && (text[i] <= '9'));
    }
    if ((i < text_len) && ((text[i] == 'e') || (text[i] == 'E'))) {
        ++i;
        if ((i < text_len) && ((text[i] == '+') || (text[i] == '-')))
            ++i;
        if ((i >= text_len) || (text[i] < '0') || (text[i] > '9'))
            return 0;
        do {
            ++i;
        } while ((i < text_len) && (text[i] >= '0') && (text[i] <= '9'));
    }

    return i == text_len;
}

static wolfsentry_errcode_t cbor_emit_text_number(
    struct wolfsentry_json_process_state *jps,
    const struct config_number *number)
{
    char text[32];
    int number_len;

    if (number->type == CONFIG_NUMBER_UINT) {
        number_len = snprintf(
            text,
            sizeof text,
            "%llu",
            (unsigned long long)number->value.uint_value);
    } else if (number->type == CONFIG_NUMBER_SINT) {
        number_len = snprintf(
            text,
            sizeof text,
            "%lld",
            (long long)number->value.sint_value);
    } else if (number->type == CONFIG_NUMBER_FLOAT) {
        char *decimal_point;

        number_len = snprintf(
            text,
            sizeof text,
            "%.17g",
            number->value.float_value);
        decimal_point = strchr(text, ',');
        if (decimal_point != NULL)
            *decimal_point = '.';
        if ((number_len > 0) && ((size_t)(number_len + 2) < sizeof text) &&
            (strspn(text, "-0123456789") == (size_t)number_len))
        {
            text[number_len++] = '.';
            text[number_len++] = '0';
            text[number_len] = 0;
        }
    } else {
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    }

    if ((number_len < 0) || ((size_t)number_len >= sizeof text))
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    if (! cbor_text_number_is_json(text, (size_t)number_len))
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);

    WOLFSENTRY_ERROR_RERETURN(json_process(
        JSON_NUMBER,
        (const unsigned char *)text,
        (size_t)number_len,
        jps));
}
#endif

static wolfsentry_errcode_t cbor_emit_number(
    struct wolfsentry_json_process_state *jps,
    const WOLFCOSE_CBOR_ITEM *item,
    unsigned char additional_info)
{
    struct config_number number;

    WOLFSENTRY_RERETURN_IF_ERROR(
        cbor_decode_number(item, additional_info, &number));

#ifndef WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS
    {
        int emit_text = 0;

#if !defined(WOLFSENTRY_CONFIG_NO_ROUTES) && \
    !defined(WOLFSENTRY_CONFIG_NO_ROUTE_ENDPOINTS)
        if (((((jps->section_under_construction == S_U_C_REMOTE_ENDPOINT) &&
               (jps->o_u_c.route.remote.sa_family != WOLFSENTRY_AF_CAN)) ||
              ((jps->section_under_construction == S_U_C_LOCAL_ENDPOINT) &&
               (jps->o_u_c.route.local.sa_family != WOLFSENTRY_AF_CAN))) &&
             ((! strcmp(jps->cur_keyname, "address")) ||
              (! strcmp(jps->cur_keyname, "bitmask")))))
        {
            emit_text = 1;
        }
#endif
#ifdef WOLFSENTRY_CONFIG_HAVE_JSON_DOM
        if ((jps->section_under_construction == S_U_C_USER_VALUE_JSON) ||
            ((jps->object_under_construction == O_U_C_USER_VALUE) &&
             (! strcmp(jps->cur_keyname, "json"))))
        {
            emit_text = 1;
        }
#endif
        if (emit_text != 0)
            return cbor_emit_text_number(jps, &number);
    }
#endif

    WOLFSENTRY_ERROR_RERETURN(json_process(
        CONFIG_VALUE_NUMBER,
        (const unsigned char *)(const void *)&number,
        sizeof number,
        jps));
}

static wolfsentry_errcode_t cbor_emit_scalar(
    struct wolfsentry_json_process_state *jps,
    const WOLFCOSE_CBOR_ITEM *item,
    unsigned char additional_info)
{
    switch (item->majorType) {
    case WOLFCOSE_CBOR_UINT:
    case WOLFCOSE_CBOR_NEGINT:
        WOLFSENTRY_ERROR_RERETURN(cbor_emit_number(jps, item, additional_info));

    case WOLFCOSE_CBOR_TSTR:
        WOLFSENTRY_ERROR_RERETURN(json_process(
            JSON_STRING,
            item->data,
            item->dataLen,
            jps));

    case WOLFCOSE_CBOR_SIMPLE:
        switch (additional_info) {
        case 20U:
            WOLFSENTRY_ERROR_RERETURN(json_process(JSON_FALSE, NULL, 0U, jps));
        case 21U:
            WOLFSENTRY_ERROR_RERETURN(json_process(JSON_TRUE, NULL, 0U, jps));
        case 22U:
            WOLFSENTRY_ERROR_RERETURN(json_process(JSON_NULL, NULL, 0U, jps));
        case WOLFCOSE_CBOR_AI_FLOAT16:
        case WOLFCOSE_CBOR_AI_FLOAT32:
        case WOLFCOSE_CBOR_AI_FLOAT64:
            WOLFSENTRY_ERROR_RERETURN(cbor_emit_number(jps, item, additional_info));
        default:
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        }

    case WOLFCOSE_CBOR_BSTR:
        if (((jps->section_under_construction != S_U_C_REMOTE_ENDPOINT) &&
             (jps->section_under_construction != S_U_C_LOCAL_ENDPOINT)) ||
            ((strcmp(jps->cur_keyname, "address") != 0) &&
             (strcmp(jps->cur_keyname, "bitmask") != 0)))
        {
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        }
        WOLFSENTRY_ERROR_RERETURN(json_process(
            CONFIG_VALUE_BYTE_STRING,
            item->data,
            item->dataLen,
            jps));

    case WOLFCOSE_CBOR_TAG:
    default:
        WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
    }
}

static wolfsentry_errcode_t cbor_process(
    struct wolfsentry_json_process_state *jps,
    WOLFCOSE_CBOR_CTX *decoder,
    int *decoder_ret)
{
    struct cbor_container_state stack[WOLFSENTRY_MAX_CBOR_NESTING];
    size_t depth = 0U;
    int root_seen = 0;

    *decoder_ret = WOLFCOSE_SUCCESS;

    for (;;) {
        WOLFCOSE_CBOR_ITEM item;
        size_t item_offset;
        unsigned char additional_info;
        wolfsentry_errcode_t ret;

        if ((depth > 0U) && (stack[depth - 1U].remaining == 0U)) {
            JSON_TYPE end_type;

            if ((stack[depth - 1U].major_type == WOLFCOSE_CBOR_MAP) &&
                (stack[depth - 1U].expecting_key == 0U))
            {
                WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
            }

            end_type = stack[depth - 1U].major_type == WOLFCOSE_CBOR_MAP
                ? JSON_OBJECT_END
                : JSON_ARRAY_END;
#if defined(WOLFSENTRY_CONFIG_HAVE_JSON_DOM) && \
    defined(WOLFSENTRY_JSON_VALUE_MAX_BYTES)
            jps->cbor_offset = decoder->idx;
#endif
            ret = json_process(end_type, NULL, 0U, jps);
            if (ret < 0)
                WOLFSENTRY_ERROR_RERETURN(ret);
            --depth;
            if (depth == 0U)
                break;
            continue;
        }

        if ((depth > 0U) &&
            (stack[depth - 1U].major_type == WOLFCOSE_CBOR_MAP) &&
            (stack[depth - 1U].expecting_key != 0U))
        {
            item_offset = decoder->idx;
            *decoder_ret = wc_CBOR_DecodeHead(decoder, &item);
            if (*decoder_ret < 0)
                WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
            --stack[depth - 1U].remaining;
            if (item.majorType != WOLFCOSE_CBOR_TSTR)
                WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
#ifdef WOLFSENTRY_CONFIG_HAVE_JSON_DOM
            if ((jps->section_under_construction ==
                 S_U_C_USER_VALUE_JSON) &&
                (item.dataLen > WOLFSENTRY_MAX_LABEL_BYTES))
            {
                WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
            }
#endif
#if defined(WOLFSENTRY_CONFIG_HAVE_JSON_DOM) && \
    defined(WOLFSENTRY_JSON_VALUE_MAX_BYTES)
            jps->cbor_offset = decoder->idx;
#endif
            ret = json_process(JSON_KEY, item.data, item.dataLen, jps);
            if (ret < 0)
                WOLFSENTRY_ERROR_RERETURN(ret);
            stack[depth - 1U].expecting_key = 0U;
            continue;
        }

        if ((depth == 0U) && (root_seen != 0))
            break;

        item_offset = decoder->idx;
        *decoder_ret = wc_CBOR_DecodeHead(decoder, &item);
        if (*decoder_ret < 0)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        additional_info = decoder->cbuf[item_offset] & 0x1fU;

        if (depth == 0U) {
            root_seen = 1;
            if (item.majorType != WOLFCOSE_CBOR_MAP)
                WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
        } else {
            --stack[depth - 1U].remaining;
            if (stack[depth - 1U].major_type == WOLFCOSE_CBOR_MAP)
                stack[depth - 1U].expecting_key = 1U;
        }

        if ((item.majorType == WOLFCOSE_CBOR_MAP) ||
            (item.majorType == WOLFCOSE_CBOR_ARRAY))
        {
            JSON_TYPE begin_type;

            if (depth >= WOLFSENTRY_MAX_CBOR_NESTING)
                WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);

            begin_type = item.majorType == WOLFCOSE_CBOR_MAP
                ? JSON_OBJECT_BEG
                : JSON_ARRAY_BEG;
#if defined(WOLFSENTRY_CONFIG_HAVE_JSON_DOM) && \
    defined(WOLFSENTRY_JSON_VALUE_MAX_BYTES)
            jps->cbor_value_start_offset = item_offset;
            jps->cbor_offset = decoder->idx;
#endif
            ret = json_process(begin_type, NULL, 0U, jps);
            if (ret < 0)
                WOLFSENTRY_ERROR_RERETURN(ret);

            stack[depth].major_type = item.majorType;
            stack[depth].expecting_key = item.majorType == WOLFCOSE_CBOR_MAP
                ? 1U
                : 0U;
            if (item.val > (uint64_t)SIZE_MAX)
                WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
            stack[depth].remaining = (size_t)item.val;
            if (item.majorType == WOLFCOSE_CBOR_MAP) {
                if (stack[depth].remaining > (SIZE_MAX / 2U))
                    WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
                stack[depth].remaining *= 2U;
            }
            ++depth;
        } else {
#if defined(WOLFSENTRY_CONFIG_HAVE_JSON_DOM) && \
    defined(WOLFSENTRY_JSON_VALUE_MAX_BYTES)
            jps->cbor_value_start_offset = item_offset;
            jps->cbor_offset = decoder->idx;
#endif
            ret = cbor_emit_scalar(jps, &item, additional_info);
            if (ret < 0)
                WOLFSENTRY_ERROR_RERETURN(ret);
        }
    }

    if ((root_seen == 0) || (decoder->idx != decoder->bufSz) ||
        (jps->config_version != 1U))
        WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_cbor_oneshot(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const unsigned char *cbor_in,
    size_t cbor_in_len,
    wolfsentry_config_load_flags_t load_flags,
    char *err_buf,
    size_t err_buf_size)
{
    struct wolfsentry_json_process_state *jps = NULL;
    WOLFCOSE_CBOR_CTX decoder;
    wolfsentry_errcode_t ret;
    int decoder_ret;

#ifdef WOLFSENTRY_CONFIG_NO_ERROR_MESSAGES
    (void)err_buf;
    (void)err_buf_size;
#endif

    if ((cbor_in == NULL) || (cbor_in_len == 0U))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if ((WOLFSENTRY_MAX_CBOR_TOTAL_LEN > 0U) &&
        (cbor_in_len > WOLFSENTRY_MAX_CBOR_TOTAL_LEN))
    {
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    }
    decoder_ret = wc_CBOR_DecoderInit(&decoder, cbor_in, cbor_in_len);
    if (decoder_ret < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    ret = config_state_init(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        load_flags,
        CONFIG_INPUT_CBOR,
        &jps);
    if (ret < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    ret = config_state_prepare(&jps);
    if (ret < 0)
        WOLFSENTRY_ERROR_RERETURN(config_state_fini(&jps, ret));

    ret = cbor_process(jps, &decoder, &decoder_ret);
#ifndef WOLFSENTRY_CONFIG_NO_ERROR_MESSAGES
    if ((ret < 0) && (err_buf != NULL) && (err_buf_size > 0U)) {
        int print_ret;

        if (decoder_ret < 0) {
            print_ret = snprintf(
                err_buf,
                err_buf_size,
                "CBOR decoding failed at offset " SIZET_FMT
                    ", decoder code %d",
                decoder.idx,
                decoder_ret);
        } else {
            print_ret = snprintf(
                err_buf,
                err_buf_size,
                "CBOR configuration failed at offset " SIZET_FMT
                    ", wolfSentry code " WOLFSENTRY_ERRCODE_FMT,
                decoder.idx,
                (int)ret);
        }
        if (print_ret >= (int)err_buf_size)
            err_buf[err_buf_size - 1U] = 0;
    }
#endif

    WOLFSENTRY_ERROR_RERETURN(config_state_fini(&jps, ret));
}

#endif /* WOLFSENTRY_WOLFCOSE */

static wolfsentry_errcode_t config_state_fini(
    struct wolfsentry_json_process_state **jps,
    wolfsentry_errcode_t ret)
{
    if ((jps == NULL) || (*jps == NULL))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (ret < 0)
        goto out;

#ifndef WOLFSENTRY_CONFIG_NO_TRANSACTIONS
    if (WOLFSENTRY_CHECK_BITS((*jps)->load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN)) {
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        goto out;
    }

    if (WOLFSENTRY_CHECK_BITS((*jps)->load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT)) {
        int full_cycle_of_insert_actions_p = ! WOLFSENTRY_MASKIN_BITS((*jps)->load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH);
        struct wolfsentry_route_table *old_route_table, *new_route_table;
        if ((ret = wolfsentry_route_get_main_table(JPSP_WOLFSENTRY_ACTUAL_CONTEXT_ARGS_OUT, &old_route_table)) < 0)
            goto out;
        if ((ret = wolfsentry_route_get_main_table(JPSP_WOLFSENTRY_CONTEXT_ARGS_OUT, &new_route_table)) < 0)
            goto out;
        if (wolfsentry_table_n_deletes((struct wolfsentry_table_header *)new_route_table)
            != wolfsentry_table_n_deletes((struct wolfsentry_table_header *)old_route_table))
        {
            full_cycle_of_insert_actions_p = 1;
        }

        ret = wolfsentry_context_exchange(JPSP_WOLFSENTRY_ACTUAL_CONTEXT_ARGS_OUT, (*jps)->wolfsentry);
        if (ret < 0)
            goto out;

        if (full_cycle_of_insert_actions_p) {
            wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
            if ((ret = wolfsentry_route_bulk_clear_insert_action_status(JPSP_WOLFSENTRY_ACTUAL_CONTEXT_ARGS_OUT, &action_results)) < 0)
                goto out;
            if ((ret = wolfsentry_context_flush(JPSP_WOLFSENTRY_CONTEXT_ARGS_OUT)) < 0)
                goto out;
        }

        if ((ret = wolfsentry_context_enable_actions(JPSP_WOLFSENTRY_ACTUAL_CONTEXT_ARGS_OUT)) < 0)
            goto out;

        {
            wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
            if ((ret = wolfsentry_route_bulk_insert_actions(JPSP_WOLFSENTRY_ACTUAL_CONTEXT_ARGS_OUT, &action_results)) < 0)
                goto out;
        }

        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_context_free(JPSP_P_WOLFSENTRY_CONTEXT_ARGS_OUT));
    } else
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
#else
    ret = WOLFSENTRY_ERROR_ENCODE(OK);
#endif

  out:

#ifdef WOLFSENTRY_CONFIG_HAVE_JSON_DOM
    (void)json_dom_clean(&(*jps)->dom_parser);
#endif

#ifndef WOLFSENTRY_CONFIG_NO_TRANSACTIONS
    if ((*jps)->wolfsentry && ((*jps)->wolfsentry != (*jps)->wolfsentry_actual))
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_context_free(JPSP_P_WOLFSENTRY_CONTEXT_ARGS_OUT));
#endif

#ifdef WOLFSENTRY_THREADSAFE
    {
        wolfsentry_errcode_t _lock_ret;
#ifdef WOLFSENTRY_CONFIG_NO_TRANSACTIONS
        _lock_ret = wolfsentry_context_unlock((*jps)->wolfsentry, (*jps)->thread);
#else
        if ((*jps)->got_reservation)
            _lock_ret = wolfsentry_context_unlock_and_abandon_reservation((*jps)->wolfsentry_actual, (*jps)->thread);
        else
            _lock_ret = wolfsentry_context_unlock((*jps)->wolfsentry_actual, (*jps)->thread);
#endif
        if (_lock_ret < 0)
            ret = _lock_ret;
    }
#endif

    wolfsentry_free(JPSP_WOLFSENTRY_ACTUAL_CONTEXT_ARGS_OUT, *jps);

    *jps = NULL;

    if (ret < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    else
        WOLFSENTRY_RETURN_OK;
}

#ifndef WOLFSENTRY_NO_JSON

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_fini(
    struct wolfsentry_json_process_state **jps,
    char *err_buf,
    size_t err_buf_size)
{
    wolfsentry_errcode_t ret = WOLFSENTRY_ERROR_ENCODE(OK);
    JSON_INPUT_POS json_pos;

#ifdef WOLFSENTRY_CONFIG_NO_ERROR_MESSAGES
    (void)err_buf;
    (void)err_buf_size;
#endif

    if ((jps == NULL) || (*jps == NULL))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (WOLFSENTRY_CHECK_BITS((*jps)->load_flags, WOLFSENTRY_CONFIG_LOAD_FLAG_FINI)) {
        if ((*jps)->fini_ret < 0)
            ret = wolfsentry_centijson_errcode_translate((*jps)->fini_ret);
    } else {
        (*jps)->fini_ret = json_fini(&(*jps)->parser, &json_pos);
        if ((*jps)->fini_ret < 0) {
#ifndef WOLFSENTRY_CONFIG_NO_ERROR_MESSAGES
            if ((err_buf != NULL) && (err_buf_size > 0U)) {
                int print_ret = snprintf(
                    err_buf,
                    err_buf_size,
                    "json_fini failed at offset %d, line %u, col %u, with code " WOLFSENTRY_ERRCODE_FMT ": %s.",
                    (int)json_pos.offset,
                    json_pos.line_number,
                    json_pos.column_number,
                    (int)(*jps)->fini_ret,
                    json_error_str((*jps)->fini_ret));
                if (print_ret >= (int)err_buf_size)
                    err_buf[err_buf_size - 1U] = 0;
            }
#endif
            ret = wolfsentry_centijson_errcode_translate((*jps)->fini_ret);
        }
    }

    WOLFSENTRY_ERROR_RERETURN(config_state_fini(jps, ret));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_oneshot_ex(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const unsigned char *json_in,
    size_t json_in_len,
    wolfsentry_config_load_flags_t load_flags,
    const JSON_CONFIG *json_config,
    char *err_buf,
    size_t err_buf_size)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_json_process_state *jps;
    if ((ret = wolfsentry_config_json_init_ex(WOLFSENTRY_CONTEXT_ARGS_OUT, load_flags, json_config, &jps)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    if (wolfsentry_config_json_feed(jps, json_in, json_in_len, err_buf, err_buf_size) < 0) {
        ret = wolfsentry_config_json_fini(&jps, NULL, 0);
        WOLFSENTRY_ERROR_RERETURN(ret);
    }
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_config_json_fini(&jps, err_buf, err_buf_size));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_oneshot(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const unsigned char *json_in,
    size_t json_in_len,
    wolfsentry_config_load_flags_t load_flags,
    char *err_buf,
    size_t err_buf_size)
{
    WOLFSENTRY_ERROR_RERETURN(
        wolfsentry_config_json_oneshot_ex(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            json_in,
            json_in_len,
            load_flags,
            NULL,
            err_buf,
            err_buf_size));
}

#endif /* !WOLFSENTRY_NO_JSON */
