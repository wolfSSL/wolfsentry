/*
 * wolfsentry_errcodes.h
 *
 * Copyright (C) 2021-2022 wolfSSL Inc.
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

#ifndef WOLFSENTRY_ERRCODES_H
#define WOLFSENTRY_ERRCODES_H

typedef int32_t wolfsentry_errcode_t;
#ifdef PRId32
#define WOLFSENTRY_ERRCODE_FMT "%" PRId32
#else
#define WOLFSENTRY_ERRCODE_FMT "%d"
#endif

/* these must be all-1s */
#define WOLFSENTRY_SOURCE_ID_MAX 127
#define WOLFSENTRY_ERROR_ID_MAX 255
#define WOLFSENTRY_LINE_NUMBER_MAX 65535

#define WOLFSENTRY_ERROR_ENCODE_0(x) (((x) == 0) ?                           \
        (((__LINE__ & WOLFSENTRY_LINE_NUMBER_MAX) << 8)                      \
           | ((WOLFSENTRY_SOURCE_ID & WOLFSENTRY_SOURCE_ID_MAX) << 24))      \
    :                                                                        \
        (-(((x) & WOLFSENTRY_ERROR_ID_MAX)                                   \
           | ((__LINE__ & WOLFSENTRY_LINE_NUMBER_MAX) << 8)                  \
           | ((WOLFSENTRY_SOURCE_ID & WOLFSENTRY_SOURCE_ID_MAX) << 24))))

#if defined(__GNUC__) && defined(static_assert)
#define WOLFSENTRY_ERROR_ENCODE_1(x) ({                                      \
    static_assert(((x) >= 0) && ((x) <= WOLFSENTRY_ERROR_ID_MAX),            \
                  "error code must be 0-" _q(WOLFSENTRY_ERROR_ID_MAX) );     \
    static_assert(__LINE__ <= WOLFSENTRY_LINE_NUMBER_MAX,                    \
                  "line number must be 1-" _q(WOLFSENTRY_LINE_NUMBER_MAX) ); \
    static_assert((WOLFSENTRY_SOURCE_ID >= 0)                                \
                  && (WOLFSENTRY_SOURCE_ID <= 0x7f),                         \
                  "source file ID must be 0-" _q(WOLFSENTRY_SOURCE_ID_MAX) );\
    WOLFSENTRY_ERROR_ENCODE_0(x);                                            \
})
#else
#define WOLFSENTRY_ERROR_ENCODE_1(x) WOLFSENTRY_ERROR_ENCODE_0(x)
#endif

#define WOLFSENTRY_ERROR_RERETURN(x) return WOLFSENTRY_ERROR_ENCODE_0(WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x))
#define WOLFSENTRY_ERROR_RECODE(x) WOLFSENTRY_ERROR_ENCODE_0(WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x))
#define WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x) (((x) < 0) ? (-(x) & WOLFSENTRY_ERROR_ID_MAX) : ((x) & WOLFSENTRY_ERROR_ID_MAX))
#define WOLFSENTRY_ERROR_CODE_IS(x, y) (WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x) == WOLFSENTRY_ERROR_ID_ ## y)
#define WOLFSENTRY_ERROR_DECODE_SOURCE_ID(x) (((x) < 0) ? ((-(x)) >> 24) : ((x) >> 24))
#define WOLFSENTRY_ERROR_DECODE_LINE_NUMBER(x) (((x) < 0) ? (((-(x)) >> 8) & WOLFSENTRY_LINE_NUMBER_MAX) : (((x) >> 8) & WOLFSENTRY_LINE_NUMBER_MAX))

#ifdef WOLFSENTRY_ERROR_STRINGS
#define WOLFSENTRY_ERROR_FMT "code " WOLFSENTRY_ERRCODE_FMT " (%s), src " WOLFSENTRY_ERRCODE_FMT " (%s), line " WOLFSENTRY_ERRCODE_FMT
#define WOLFSENTRY_ERROR_FMT_ARGS(x) WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x), wolfsentry_errcode_error_string(x), WOLFSENTRY_ERROR_DECODE_SOURCE_ID(x), wolfsentry_errcode_source_string(x), WOLFSENTRY_ERROR_DECODE_LINE_NUMBER(x)
#else
#define WOLFSENTRY_ERROR_FMT "code " WOLFSENTRY_ERRCODE_FMT ", src " WOLFSENTRY_ERRCODE_FMT ", line " WOLFSENTRY_ERRCODE_FMT
#define WOLFSENTRY_ERROR_FMT_ARGS(x) WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x), WOLFSENTRY_ERROR_DECODE_SOURCE_ID(x), WOLFSENTRY_ERROR_DECODE_LINE_NUMBER(x)
#endif /* WOLFSENTRY_ERROR_STRINGS */

#define WOLFSENTRY_ERROR_ENCODE(x) WOLFSENTRY_ERROR_ENCODE_1(WOLFSENTRY_ERROR_ID_ ## x)
#define WOLFSENTRY_ERROR_RETURN(x) return WOLFSENTRY_ERROR_ENCODE(x)
#define WOLFSENTRY_RETURN_OK WOLFSENTRY_ERROR_RETURN(OK)

#ifdef WOLFSENTRY_ERROR_STRINGS
WOLFSENTRY_API const char *wolfsentry_errcode_source_string(wolfsentry_errcode_t e);
WOLFSENTRY_API const char *wolfsentry_errcode_error_string(wolfsentry_errcode_t e);
#endif

#if !defined(WOLFSENTRY_NO_STDIO) && !defined(WOLFSENTRY_NO_DIAG_MSGS)

#include <errno.h>

#ifdef __STRICT_ANSI__
#define WOLFSENTRY_WARN(fmt,...) fprintf(stderr, "%s@L%d " fmt, __FILE__, __LINE__, __VA_ARGS__)
#else
#define WOLFSENTRY_WARN(fmt,...) fprintf(stderr, "%s@L%d " fmt, __FILE__, __LINE__, ## __VA_ARGS__)
#endif

#define WOLFSENTRY_WARN_ON_FAILURE(...) do { wolfsentry_errcode_t _ret = (__VA_ARGS__); if (_ret < 0) { WOLFSENTRY_WARN(#__VA_ARGS__ ": " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(_ret)); }} while(0)
#define WOLFSENTRY_WARN_ON_FAILURE_LIBC(...) do { if ((__VA_ARGS__) < 0) { WOLFSENTRY_WARN(#__VA_ARGS__ ": %s\n", strerror(errno)); }} while(0)

#else

#define WOLFSENTRY_WARN(fmt,...) do {} while (0)
#define WOLFSENTRY_WARN_ON_FAILURE(...) (__VA_ARGS__)
#define WOLFSENTRY_WARN_ON_FAILURE_LIBC(...) (__VA_ARGS__)

#endif /* !WOLFSENTRY_NO_STDIO && !WOLFSENTRY_NO_DIAG_MSGS */

enum wolfsentry_source_id {
    WOLFSENTRY_SOURCE_ID_UNSET      =  0,
    WOLFSENTRY_SOURCE_ID_ACTIONS_C  =  1,
    WOLFSENTRY_SOURCE_ID_EVENTS_C   =  2,
    WOLFSENTRY_SOURCE_ID_INTERNAL_C =  3,
    WOLFSENTRY_SOURCE_ID_ROUTES_C   =  4,
    WOLFSENTRY_SOURCE_ID_UTIL_C     =  5,
    WOLFSENTRY_SOURCE_ID_KV_C       =  6,
    WOLFSENTRY_SOURCE_ID_ADDR_FAMILIES_C = 7,
    WOLFSENTRY_SOURCE_ID_JSON_LOAD_CONFIG_C = 8,

    WOLFSENTRY_SOURCE_ID_USER_BASE  =  112
};

#ifdef WOLFSENTRY_ERROR_STRINGS
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_source_string_set(enum wolfsentry_source_id wolfsentry_source_id, const char *source_string);
#define WOLFSENTRY_REGISTER_SOURCE() wolfsentry_user_source_string_set(WOLFSENTRY_SOURCE_ID,__FILE__)
#endif

enum wolfsentry_error_id {
    WOLFSENTRY_ERROR_ID_OK                     =   0,
    WOLFSENTRY_ERROR_ID_NOT_OK                 =   1,
    WOLFSENTRY_ERROR_ID_INTERNAL_CHECK_FATAL   =   2,
    WOLFSENTRY_ERROR_ID_SYS_OP_FATAL           =   3,
    WOLFSENTRY_ERROR_ID_SYS_OP_FAILED          =   4,
    WOLFSENTRY_ERROR_ID_SYS_RESOURCE_FAILED    =   5,
    WOLFSENTRY_ERROR_ID_INCOMPATIBLE_STATE     =   6,
    WOLFSENTRY_ERROR_ID_TIMED_OUT              =   7,
    WOLFSENTRY_ERROR_ID_INVALID_ARG            =   8,
    WOLFSENTRY_ERROR_ID_BUSY                   =   9,
    WOLFSENTRY_ERROR_ID_INTERRUPTED            =  10,
    WOLFSENTRY_ERROR_ID_NUMERIC_ARG_TOO_BIG    =  11,
    WOLFSENTRY_ERROR_ID_NUMERIC_ARG_TOO_SMALL  =  12,
    WOLFSENTRY_ERROR_ID_STRING_ARG_TOO_LONG    =  13,
    WOLFSENTRY_ERROR_ID_BUFFER_TOO_SMALL       =  14,
    WOLFSENTRY_ERROR_ID_IMPLEMENTATION_MISSING =  15,
    WOLFSENTRY_ERROR_ID_ITEM_NOT_FOUND         =  16,
    WOLFSENTRY_ERROR_ID_ITEM_ALREADY_PRESENT   =  17,
    WOLFSENTRY_ERROR_ID_ALREADY_STOPPED        =  18,
    WOLFSENTRY_ERROR_ID_WRONG_OBJECT           =  19,
    WOLFSENTRY_ERROR_ID_DATA_MISSING           =  20,
    WOLFSENTRY_ERROR_ID_NOT_PERMITTED          =  21,
    WOLFSENTRY_ERROR_ID_ALREADY                =  22,
    WOLFSENTRY_ERROR_ID_CONFIG_INVALID_KEY     =  23,
    WOLFSENTRY_ERROR_ID_CONFIG_INVALID_VALUE   =  24,
    WOLFSENTRY_ERROR_ID_CONFIG_OUT_OF_SEQUENCE =  25,
    WOLFSENTRY_ERROR_ID_CONFIG_UNEXPECTED      =  26,
    WOLFSENTRY_ERROR_ID_CONFIG_PARSER          =  27,
    WOLFSENTRY_ERROR_ID_CONFIG_MISSING_HANDLER =  28,
    WOLFSENTRY_ERROR_ID_OP_NOT_SUPP_FOR_PROTO  =  29,
    WOLFSENTRY_ERROR_ID_WRONG_TYPE             =  30,
    WOLFSENTRY_ERROR_ID_BAD_VALUE              =  31,

    WOLFSENTRY_ERROR_ID_USER_BASE              = 224
};

#ifdef WOLFSENTRY_ERROR_STRINGS
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_error_string_set(enum wolfsentry_error_id, const char *error_string);
#define WOLFSENTRY_REGISTER_ERROR(err, msg) wolfsentry_user_error_string_set(WOLFSENTRY_ERROR_ID_ ## err, msg)
#endif

#endif /* WOLFSENTRY_ERRCODES_H */
