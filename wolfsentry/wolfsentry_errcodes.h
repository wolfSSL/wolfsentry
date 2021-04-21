/*
 * wolfsentry_errcodes.h
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

#ifndef WOLFSENTRY_ERRCODES_H
#define WOLFSENTRY_ERRCODES_H

typedef int32_t wolfsentry_errcode_t;
#ifdef PRId32
#define WOLFSENTRY_ERRCODE_FMT "%" PRId32
#else
#define WOLFSENTRY_ERRCODE_FMT "%d"
#endif

#define WOLFSENTRY_ERROR_ENCODE_0(x) (((x) == 0) ?                                \
        (((__LINE__ & 0xffff) << 8) | ((WOLFSENTRY_SOURCE_ID & 0x7f) << 24))      \
    :                                                                             \
        (-(((x) & 0xff) | ((__LINE__ & 0xffff) << 8) | ((WOLFSENTRY_SOURCE_ID & 0x7f) << 24))))

#if defined(__GNUC__) && defined(static_assert)
#define WOLFSENTRY_ERROR_ENCODE_1(x) ({                                           \
    static_assert(((x) >= 0) && ((x) <= 0xff), "error code must be 0-255");       \
    static_assert(__LINE__ <= 0xffff, "line number must be 1-65535");             \
    static_assert((WOLFSENTRY_SOURCE_ID >= 0) && (WOLFSENTRY_SOURCE_ID <= 0x7f), "source file ID must be 0-127"); \
    WOLFSENTRY_ERROR_ENCODE_0(x);                                                 \
})
#else
#define WOLFSENTRY_ERROR_ENCODE_1(x) WOLFSENTRY_ERROR_ENCODE_0(x)
#endif

#define WOLFSENTRY_ERROR_RERETURN(x) return WOLFSENTRY_ERROR_ENCODE_0(WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x))
#define WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x) (((x) < 0) ? (-(x) & 0xff) : ((x) & 0xff))
#define WOLFSENTRY_ERROR_CODE_IS(x, y) (WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x) == WOLFSENTRY_ERROR_ID_ ## y)
#define WOLFSENTRY_ERROR_DECODE_SOURCE_ID(x) (((x) < 0) ? ((-(x)) >> 24) : ((x) >> 24))
#define WOLFSENTRY_ERROR_DECODE_LINE_NUMBER(x) (((x) < 0) ? (((-(x)) >> 8) & 0xffff) : (((x) >> 8) & 0xffff))

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
const char *wolfsentry_errcode_source_string(wolfsentry_errcode_t e);
const char *wolfsentry_errcode_error_string(wolfsentry_errcode_t e);
#endif

#if !defined(WOLFSENTRY_NO_STDIO) && !defined(WOLFSENTRY_NO_DIAG_MSGS)

#include <errno.h>

#define WOLFSENTRY_WARN(fmt,...) fprintf(stderr, "%s@L%d " fmt, __FILE__, __LINE__, ## __VA_ARGS__)
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
    WOLFSENTRY_SOURCE_ID_USER_BASE  =  112
};

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
    WOLFSENTRY_ERROR_ID_NUMERIC_ARG_TOO_BIG    =  10,
    WOLFSENTRY_ERROR_ID_NUMERIC_ARG_TOO_SMALL  =  11,
    WOLFSENTRY_ERROR_ID_STRING_ARG_TOO_LONG    =  12,
    WOLFSENTRY_ERROR_ID_BUFFER_TOO_SMALL       =  13,
    WOLFSENTRY_ERROR_ID_IMPLEMENTATION_MISSING =  14,
    WOLFSENTRY_ERROR_ID_ITEM_NOT_FOUND         =  15,
    WOLFSENTRY_ERROR_ID_ITEM_ALREADY_PRESENT   =  16,
    WOLFSENTRY_ERROR_ID_ALREADY_STOPPED        =  17,
    WOLFSENTRY_ERROR_ID_WRONG_OBJECT           =  18,
    WOLFSENTRY_ERROR_ID_NOT_INSERTED           =  19,
    WOLFSENTRY_ERROR_ID_DATA_MISSING           =  20,
    WOLFSENTRY_ERROR_ID_NOT_PERMITTED          =  21,
    WOLFSENTRY_ERROR_ID_USER_BASE              = 224
};

#endif /* WOLFSENTRY_ERRCODES_H */
