/*
 * wolfsentry_errcodes.h
 *
 * Copyright (C) 2021-2023 wolfSSL Inc.
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
#ifdef FREERTOS
#define WOLFSENTRY_ERRCODE_FMT "%d"
#elif defined(PRId32)
#define WOLFSENTRY_ERRCODE_FMT "%" PRId32
#else
#define WOLFSENTRY_ERRCODE_FMT "%d"
#endif

/* these must be all-1s */
#define WOLFSENTRY_SOURCE_ID_MAX 127
#define WOLFSENTRY_ERROR_ID_MAX 255
#define WOLFSENTRY_LINE_NUMBER_MAX 65535

#define WOLFSENTRY_ERROR_ENCODE_0(x) (((x) < 0) ?                            \
        -(((-(x)) & WOLFSENTRY_ERROR_ID_MAX)                                 \
           | ((__LINE__ & WOLFSENTRY_LINE_NUMBER_MAX) << 8)                  \
           | ((WOLFSENTRY_SOURCE_ID & WOLFSENTRY_SOURCE_ID_MAX) << 24))      \
    :                                                                        \
        (((x) & WOLFSENTRY_ERROR_ID_MAX)                                     \
           | ((__LINE__ & WOLFSENTRY_LINE_NUMBER_MAX) << 8)                  \
           | ((WOLFSENTRY_SOURCE_ID & WOLFSENTRY_SOURCE_ID_MAX) << 24)))

#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
#define WOLFSENTRY_ERROR_ENCODE_1(x) ({                                      \
    wolfsentry_static_assert(((x) >= -WOLFSENTRY_ERROR_ID_MAX)               \
                   && ((x) <= WOLFSENTRY_ERROR_ID_MAX),                      \
                  "error code must be -"                                     \
                  _q(WOLFSENTRY_ERROR_ID_MAX)                                \
                  " <= e <= "                                                \
                  _q(WOLFSENTRY_ERROR_ID_MAX) );                             \
    wolfsentry_static_assert(__LINE__ <= WOLFSENTRY_LINE_NUMBER_MAX,         \
                  "line number must be 1-" _q(WOLFSENTRY_LINE_NUMBER_MAX) ); \
    wolfsentry_static_assert((WOLFSENTRY_SOURCE_ID >= 0)                     \
                  && (WOLFSENTRY_SOURCE_ID <= 0x7f),                         \
                  "source file ID must be 0-" _q(WOLFSENTRY_SOURCE_ID_MAX) );\
    WOLFSENTRY_ERROR_ENCODE_0(x);                                            \
})
#else
#define WOLFSENTRY_ERROR_ENCODE_1(x) WOLFSENTRY_ERROR_ENCODE_0(x)
#endif

#define WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x) ((int)((((x) < 0) ? -(-(x) & WOLFSENTRY_ERROR_ID_MAX) : ((x) & WOLFSENTRY_ERROR_ID_MAX))))
#define WOLFSENTRY_ERROR_RECODE(x) WOLFSENTRY_ERROR_ENCODE_0(WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x))
#define WOLFSENTRY_ERROR_CODE_IS(x, y) (WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x) == WOLFSENTRY_ERROR_ID_ ## y)
#define WOLFSENTRY_SUCCESS_CODE_IS(x, y) (WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x) == WOLFSENTRY_SUCCESS_ID_ ## y)
#define WOLFSENTRY_ERROR_DECODE_SOURCE_ID(x) ((int)((((x) < 0) ? ((-(x)) >> 24) : ((x) >> 24))))
#define WOLFSENTRY_ERROR_DECODE_LINE_NUMBER(x) ((int)((((x) < 0) ? (((-(x)) >> 8) & WOLFSENTRY_LINE_NUMBER_MAX) : (((x) >> 8) & WOLFSENTRY_LINE_NUMBER_MAX))))

#ifdef WOLFSENTRY_ERROR_STRINGS
#define WOLFSENTRY_ERROR_FMT "code " WOLFSENTRY_ERRCODE_FMT " (%s), src " WOLFSENTRY_ERRCODE_FMT " (%s), line " WOLFSENTRY_ERRCODE_FMT
#define WOLFSENTRY_ERROR_FMT_ARGS(x) WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x), wolfsentry_errcode_error_string(x), WOLFSENTRY_ERROR_DECODE_SOURCE_ID(x), wolfsentry_errcode_source_string(x), WOLFSENTRY_ERROR_DECODE_LINE_NUMBER(x)
#else
#define WOLFSENTRY_ERROR_FMT "code " WOLFSENTRY_ERRCODE_FMT ", src " WOLFSENTRY_ERRCODE_FMT ", line " WOLFSENTRY_ERRCODE_FMT
#define WOLFSENTRY_ERROR_FMT_ARGS(x) WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x), WOLFSENTRY_ERROR_DECODE_SOURCE_ID(x), WOLFSENTRY_ERROR_DECODE_LINE_NUMBER(x)
#endif /* WOLFSENTRY_ERROR_STRINGS */

#define WOLFSENTRY_ERROR_ENCODE(x) WOLFSENTRY_ERROR_ENCODE_1(WOLFSENTRY_ERROR_ID_ ## x)
#define WOLFSENTRY_SUCCESS_ENCODE(x) WOLFSENTRY_ERROR_ENCODE_1(WOLFSENTRY_SUCCESS_ID_ ## x)

#if defined(WOLFSENTRY_DEBUG_CALL_TRACE) && !defined(WOLFSENTRY_NO_STDIO)
    #define WOLFSENTRY_ERROR_RETURN(x) WOLFSENTRY_ERROR_RETURN_1(WOLFSENTRY_ERROR_ID_ ## x)
    #define WOLFSENTRY_SUCCESS_RETURN(x) WOLFSENTRY_ERROR_RETURN_1(WOLFSENTRY_SUCCESS_ID_ ## x)
    #if defined(WOLFSENTRY_ERROR_STRINGS) && defined(__GNUC__) && !defined(__STRICT_ANSI__)
        #ifdef WOLFSENTRY_CALL_DEPTH_RETURNS_STRING
        extern const char *_wolfsentry_call_depth(void);
        #define _INDENT_FMT "%s"
        #define _INDENT_ARGS _wolfsentry_call_depth()
        #else
        extern unsigned int _wolfsentry_call_depth(void);
        #define _INDENT_FMT "%*s"
        #define _INDENT_ARGS _wolfsentry_call_depth(), ""
        #endif
        #define WOLFSENTRY_ERROR_RETURN_1(x) do { const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR(_INDENT_FMT "%s L%d %s(): return %d (%s)\n", _INDENT_ARGS, _fn, __LINE__, __FUNCTION__, x, wolfsentry_errcode_error_name(x)); return WOLFSENTRY_ERROR_ENCODE_1(x); } while (0)
        #define WOLFSENTRY_ERROR_RETURN_RECODED(x) do { wolfsentry_errcode_t _xret = (x); const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR(_INDENT_FMT "%s L%d %s(): return-recoded %d (%s)\n", _INDENT_ARGS, _fn, __LINE__, __FUNCTION__, WOLFSENTRY_ERROR_DECODE_ERROR_CODE(_xret), wolfsentry_errcode_error_name(_xret)); return WOLFSENTRY_ERROR_ENCODE_0(WOLFSENTRY_ERROR_DECODE_ERROR_CODE(_xret)); } while (0)
        #define WOLFSENTRY_ERROR_RERETURN(x) do { wolfsentry_errcode_t _xret = (x); const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR(_INDENT_FMT "%s L%d %s(): rereturn %d (%s)\n", _INDENT_ARGS, _fn, __LINE__, __FUNCTION__, WOLFSENTRY_ERROR_DECODE_ERROR_CODE(_xret), wolfsentry_errcode_error_name(_xret)); return (_xret); } while (0)
        #define WOLFSENTRY_RETURN_VALUE(x) do { const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR(_INDENT_FMT "%s L%d %s(): return value\n", _INDENT_ARGS, _fn, __LINE__, __FUNCTION__); return (x); } while (0)
        #define WOLFSENTRY_RETURN_VOID do { const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR(_INDENT_FMT "%s L%d %s(): return void\n", _INDENT_ARGS, _fn, __LINE__, __FUNCTION__); return; } while (0)
    #elif defined(WOLFSENTRY_ERROR_STRINGS)
        #define WOLFSENTRY_ERROR_RETURN_1(x) do { const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR("%s L%d: return %d (%s)\n", _fn, __LINE__, x, wolfsentry_errcode_error_name(x)); return WOLFSENTRY_ERROR_ENCODE_1(x); } while (0)
        #define WOLFSENTRY_ERROR_RETURN_RECODED(x) do { wolfsentry_errcode_t _xret = (x); const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR("%s L%d: return-recoded %d (%s)\n", _fn, __LINE__, WOLFSENTRY_ERROR_DECODE_ERROR_CODE(_xret), wolfsentry_errcode_error_name(_xret)); return WOLFSENTRY_ERROR_ENCODE_0(WOLFSENTRY_ERROR_DECODE_ERROR_CODE(_xret)); } while (0)
        #define WOLFSENTRY_ERROR_RERETURN(x) do { wolfsentry_errcode_t _xret = (x); const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR("%s L%d: rereturn %d (%s)\n", _fn, __LINE__, WOLFSENTRY_ERROR_DECODE_ERROR_CODE(_xret), wolfsentry_errcode_error_name(_xret)); return (_xret); } while (0)
        #define WOLFSENTRY_RETURN_VALUE(x) do { const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR("%s L%d: return value\n", _fn, __LINE__); return (x); } while (0)
        #define WOLFSENTRY_RETURN_VOID do { const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR("%s L%d: return void\n", _fn, __LINE__); return; } while (0)
    #else
        #define WOLFSENTRY_ERROR_RETURN_1(x) do { const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR("%s L%d: return %d\n", _fn, __LINE__, x); return WOLFSENTRY_ERROR_ENCODE_1(x); } while (0)
        #define WOLFSENTRY_ERROR_RETURN_RECODED(x) do { wolfsentry_errcode_t _xret = (x); const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR("%s L%d: return-recoded %d\n", _fn, __LINE__, WOLFSENTRY_ERROR_DECODE_ERROR_CODE(_xret)); return WOLFSENTRY_ERROR_ENCODE_0(WOLFSENTRY_ERROR_DECODE_ERROR_CODE(_xret)); } while (0)
        #define WOLFSENTRY_ERROR_RERETURN(x) do { wolfsentry_errcode_t _xret = (x); const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR("%s L%d: rereturn %d\n", _fn, __LINE__, WOLFSENTRY_ERROR_DECODE_ERROR_CODE(_xret)); return (_xret); } while (0)
        #define WOLFSENTRY_RETURN_VALUE(x) do { const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR("%s L%d: return value\n", _fn, __LINE__); return (x); } while (0)
        #define WOLFSENTRY_RETURN_VOID do { const char *_fn = strrchr(__FILE__, '/'); if (_fn) { ++_fn; } else { _fn = __FILE__; } WOLFSENTRY_PRINTF_ERR("%s L%d: return void\n", _fn, __LINE__); return; } while (0)
    #endif
#else
    #define WOLFSENTRY_ERROR_RETURN(x) return WOLFSENTRY_ERROR_ENCODE(x)
    #define WOLFSENTRY_SUCCESS_RETURN(x) return WOLFSENTRY_SUCCESS_ENCODE(x)
    #define WOLFSENTRY_ERROR_RETURN_RECODED(x) return WOLFSENTRY_ERROR_ENCODE_0(WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x))
    #define WOLFSENTRY_ERROR_RERETURN(x) return (x)
    #define WOLFSENTRY_RETURN_VALUE(x) return (x)
    #define WOLFSENTRY_RETURN_VOID return
#endif

#define WOLFSENTRY_SUCCESS_RETURN_RECODED(x) WOLFSENTRY_ERROR_RETURN_RECODED(x)
#define WOLFSENTRY_SUCCESS_RERETURN(x) WOLFSENTRY_ERROR_RERETURN(x)

#ifdef WOLFSENTRY_THREADSAFE

    #define WOLFSENTRY_UNLOCK_FOR_RETURN_EX(ctx) do {           \
        wolfsentry_errcode_t _lock_ret;                         \
        if ((_lock_ret = wolfsentry_context_unlock(ctx, thread)) < 0) { \
            WOLFSENTRY_ERROR_RERETURN(_lock_ret);               \
        }                                                       \
    } while (0)

    #define WOLFSENTRY_UNLOCK_FOR_RETURN() WOLFSENTRY_UNLOCK_FOR_RETURN_EX(wolfsentry)

    #define WOLFSENTRY_UNLOCK_AND_UNRESERVE_FOR_RETURN_EX(ctx) do { \
        wolfsentry_errcode_t _lock_ret;                             \
        if ((_lock_ret = wolfsentry_context_unlock_and_abandon_reservation(ctx, thread)) < 0) { \
            WOLFSENTRY_ERROR_RERETURN(_lock_ret);                   \
        }                                                           \
    } while (0)

    #define WOLFSENTRY_UNLOCK_AND_UNRESERVE_FOR_RETURN() WOLFSENTRY_UNLOCK_AND_UNRESERVE_FOR_RETURN_EX(wolfsentry)

    #define WOLFSENTRY_MUTEX_EX(ctx) wolfsentry_context_lock_mutex_abstimed(ctx, thread, NULL)

    #define WOLFSENTRY_MUTEX_OR_RETURN() do {                   \
        wolfsentry_errcode_t _lock_ret;                         \
        if ((_lock_ret = WOLFSENTRY_MUTEX_EX(wolfsentry)) < 0)  \
            WOLFSENTRY_ERROR_RERETURN(_lock_ret);               \
    } while (0)

    #define WOLFSENTRY_SHARED_EX(ctx) wolfsentry_context_lock_shared_abstimed(ctx, thread, NULL)

    #define WOLFSENTRY_SHARED_OR_RETURN() do {                  \
        wolfsentry_errcode_t _lock_ret;                         \
        if (thread == NULL)                                     \
            _lock_ret = WOLFSENTRY_MUTEX_EX(wolfsentry);        \
        else                                                    \
            _lock_ret = WOLFSENTRY_SHARED_EX(wolfsentry);       \
        WOLFSENTRY_RERETURN_IF_ERROR(_lock_ret);                \
    } while (0)

    #define WOLFSENTRY_PROMOTABLE_EX(ctx) wolfsentry_context_lock_shared_with_reservation_abstimed(ctx, thread, NULL)

    #define WOLFSENTRY_PROMOTABLE_OR_RETURN() do {              \
        wolfsentry_errcode_t _lock_ret;                         \
        if (thread == NULL)                                     \
            _lock_ret = WOLFSENTRY_MUTEX_EX(wolfsentry);        \
        else                                                    \
            _lock_ret = WOLFSENTRY_PROMOTABLE_EX(wolfsentry);   \
        WOLFSENTRY_RERETURN_IF_ERROR(_lock_ret);                \
    } while (0)

    #define WOLFSENTRY_UNLOCK_AND_RETURN(ret) do {              \
        WOLFSENTRY_UNLOCK_FOR_RETURN();                         \
        WOLFSENTRY_ERROR_RERETURN(ret);                         \
    } while (0)

#else
    #define WOLFSENTRY_UNLOCK_FOR_RETURN() do {} while (0)
    #define WOLFSENTRY_UNLOCK_FOR_RETURN_EX(ctx) do {} while (0)
    #define WOLFSENTRY_MUTEX_EX(ctx) ((void)(ctx), WOLFSENTRY_ERROR_ENCODE(OK))
    #define WOLFSENTRY_MUTEX_OR_RETURN() (void)wolfsentry
    #define WOLFSENTRY_SHARED_EX(ctx) (void)(ctx)
    #define WOLFSENTRY_SHARED_OR_RETURN() (void)wolfsentry
    #define WOLFSENTRY_PROMOTABLE_EX(ctx) (void)(ctx)
    #define WOLFSENTRY_PROMOTABLE_OR_RETURN() (void)wolfsentry
    #define WOLFSENTRY_UNLOCK_AND_RETURN(lock, ret) WOLFSENTRY_ERROR_RERETURN(ret)
#endif

#define WOLFSENTRY_ERROR_UNLOCK_AND_RETURN(x) do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_ERROR_RETURN(x); } while (0)
#define WOLFSENTRY_ERROR_UNLOCK_AND_RETURN_RECODED(x) do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_ERROR_RETURN_RECODED(x); } while (0)
#define WOLFSENTRY_ERROR_UNLOCK_AND_RETURN_EX(ctx, x) do { WOLFSENTRY_UNLOCK_FOR_RETURN_EX(ctx); WOLFSENTRY_ERROR_RETURN(x); } while (0)
#define WOLFSENTRY_ERROR_UNLOCK_AND_RETURN_RECODED_EX(ctx, x) do { WOLFSENTRY_UNLOCK_FOR_RETURN_EX(ctx); WOLFSENTRY_ERROR_RETURN_RECODED(x); } while (0)
#define WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(x) do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_ERROR_RERETURN(x); } while (0)
#define WOLFSENTRY_ERROR_RERETURN_AND_UNLOCK(y) do { wolfsentry_errcode_t _yret = (y); WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_ERROR_RERETURN(_yret); } while (0)

#define WOLFSENTRY_SUCCESS_UNLOCK_AND_RETURN(x) do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_SUCCESS_RETURN(x); } while (0)
#define WOLFSENTRY_SUCCESS_UNLOCK_AND_RETURN_RECODED(x) do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_SUCCESS_RETURN_RECODED(x); } while (0)
#define WOLFSENTRY_SUCCESS_UNLOCK_AND_RERETURN(x) do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_SUCCESS_RERETURN(x); } while (0)
#define WOLFSENTRY_SUCCESS_RERETURN_AND_UNLOCK(y) do { wolfsentry_errcode_t _yret = (y); WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_SUCCESS_RERETURN(_yret); } while (0)

#define WOLFSENTRY_UNLOCK_AND_RETURN_VALUE(x) do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_RETURN_VALUE(x); } while (0)
#define WOLFSENTRY_UNLOCK_AND_RETURN_VOID do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_RETURN_VOID; } while (0)

#define WOLFSENTRY_RETURN_OK WOLFSENTRY_SUCCESS_RETURN(OK)
#define WOLFSENTRY_UNLOCK_AND_RETURN_OK do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_SUCCESS_RETURN(OK); } while (0)
#define WOLFSENTRY_RERETURN_IF_ERROR(y) do { wolfsentry_errcode_t _yret = (y); if (_yret < 0) WOLFSENTRY_ERROR_RERETURN(_yret); } while (0)
#define WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(y) do { wolfsentry_errcode_t _yret = (y); if (_yret < 0) { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_ERROR_RERETURN(_yret); } } while (0)

#ifdef WOLFSENTRY_ERROR_STRINGS
WOLFSENTRY_API const char *wolfsentry_errcode_source_string(wolfsentry_errcode_t e);
WOLFSENTRY_API const char *wolfsentry_errcode_error_string(wolfsentry_errcode_t e);
WOLFSENTRY_API const char *wolfsentry_errcode_error_name(wolfsentry_errcode_t e);
#endif

#if !defined(WOLFSENTRY_NO_STDIO) && !defined(WOLFSENTRY_NO_DIAG_MSGS)

#include <errno.h>

#ifdef __STRICT_ANSI__
#define WOLFSENTRY_WARN(fmt,...) WOLFSENTRY_PRINTF_ERR("%s@L%d " fmt, __FILE__, __LINE__, __VA_ARGS__)
#else
#define WOLFSENTRY_WARN(fmt,...) WOLFSENTRY_PRINTF_ERR("%s@L%d " fmt, __FILE__, __LINE__, ## __VA_ARGS__)
#endif

#define WOLFSENTRY_WARN_ON_FAILURE(...) do { wolfsentry_errcode_t _ret = (__VA_ARGS__); if (_ret < 0) { WOLFSENTRY_WARN(#__VA_ARGS__ ": " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(_ret)); }} while(0)
#define WOLFSENTRY_WARN_ON_FAILURE_LIBC(...) do { if ((__VA_ARGS__) < 0) { WOLFSENTRY_WARN(#__VA_ARGS__ ": %s\n", strerror(errno)); }} while(0)

#else

#define WOLFSENTRY_WARN(fmt,...) do {} while (0)
#define WOLFSENTRY_WARN_ON_FAILURE(...) do { if ((__VA_ARGS__) < 0) {} } while (0)
#define WOLFSENTRY_WARN_ON_FAILURE_LIBC(...) do { if ((__VA_ARGS__) < 0) {}} while (0)

#endif /* !WOLFSENTRY_NO_STDIO && !WOLFSENTRY_NO_DIAG_MSGS */

enum wolfsentry_source_id {
    WOLFSENTRY_SOURCE_ID_UNSET      =  0,
    WOLFSENTRY_SOURCE_ID_ACTIONS_C  =  1,
    WOLFSENTRY_SOURCE_ID_EVENTS_C   =  2,
    WOLFSENTRY_SOURCE_ID_WOLFSENTRY_INTERNAL_C =  3,
    WOLFSENTRY_SOURCE_ID_ROUTES_C   =  4,
    WOLFSENTRY_SOURCE_ID_WOLFSENTRY_UTIL_C     =  5,
    WOLFSENTRY_SOURCE_ID_KV_C       =  6,
    WOLFSENTRY_SOURCE_ID_ADDR_FAMILIES_C = 7,
    WOLFSENTRY_SOURCE_ID_JSON_LOAD_CONFIG_C = 8,
    WOLFSENTRY_SOURCE_ID_JSON_JSON_UTIL_C = 9,
    WOLFSENTRY_SOURCE_ID_LWIP_PACKET_FILTER_GLUE_C = 10,

    WOLFSENTRY_SOURCE_ID_USER_BASE  =  112
};

#ifdef WOLFSENTRY_ERROR_STRINGS
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_source_string_set(enum wolfsentry_source_id wolfsentry_source_id, const char *source_string);
#define WOLFSENTRY_REGISTER_SOURCE() wolfsentry_user_source_string_set(WOLFSENTRY_SOURCE_ID,__FILE__)
#endif

enum wolfsentry_error_id {
    WOLFSENTRY_ERROR_ID_OK                     =    0,
    WOLFSENTRY_ERROR_ID_NOT_OK                 =   -1,
    WOLFSENTRY_ERROR_ID_INTERNAL_CHECK_FATAL   =   -2,
    WOLFSENTRY_ERROR_ID_SYS_OP_FATAL           =   -3,
    WOLFSENTRY_ERROR_ID_SYS_OP_FAILED          =   -4,
    WOLFSENTRY_ERROR_ID_SYS_RESOURCE_FAILED    =   -5,
    WOLFSENTRY_ERROR_ID_INCOMPATIBLE_STATE     =   -6,
    WOLFSENTRY_ERROR_ID_TIMED_OUT              =   -7,
    WOLFSENTRY_ERROR_ID_INVALID_ARG            =   -8,
    WOLFSENTRY_ERROR_ID_BUSY                   =   -9,
    WOLFSENTRY_ERROR_ID_INTERRUPTED            =  -10,
    WOLFSENTRY_ERROR_ID_NUMERIC_ARG_TOO_BIG    =  -11,
    WOLFSENTRY_ERROR_ID_NUMERIC_ARG_TOO_SMALL  =  -12,
    WOLFSENTRY_ERROR_ID_STRING_ARG_TOO_LONG    =  -13,
    WOLFSENTRY_ERROR_ID_BUFFER_TOO_SMALL       =  -14,
    WOLFSENTRY_ERROR_ID_IMPLEMENTATION_MISSING =  -15,
    WOLFSENTRY_ERROR_ID_ITEM_NOT_FOUND         =  -16,
    WOLFSENTRY_ERROR_ID_ITEM_ALREADY_PRESENT   =  -17,
    WOLFSENTRY_ERROR_ID_ALREADY_STOPPED        =  -18,
    WOLFSENTRY_ERROR_ID_WRONG_OBJECT           =  -19,
    WOLFSENTRY_ERROR_ID_DATA_MISSING           =  -20,
    WOLFSENTRY_ERROR_ID_NOT_PERMITTED          =  -21,
    WOLFSENTRY_ERROR_ID_ALREADY                =  -22,
    WOLFSENTRY_ERROR_ID_CONFIG_INVALID_KEY     =  -23,
    WOLFSENTRY_ERROR_ID_CONFIG_INVALID_VALUE   =  -24,
    WOLFSENTRY_ERROR_ID_CONFIG_OUT_OF_SEQUENCE =  -25,
    WOLFSENTRY_ERROR_ID_CONFIG_UNEXPECTED      =  -26,
    WOLFSENTRY_ERROR_ID_CONFIG_MISPLACED_KEY   =  -27,
    WOLFSENTRY_ERROR_ID_CONFIG_PARSER          =  -28,
    WOLFSENTRY_ERROR_ID_CONFIG_MISSING_HANDLER =  -29,
    WOLFSENTRY_ERROR_ID_CONFIG_JSON_VALUE_SIZE =  -30,
    WOLFSENTRY_ERROR_ID_OP_NOT_SUPP_FOR_PROTO  =  -31,
    WOLFSENTRY_ERROR_ID_WRONG_TYPE             =  -32,
    WOLFSENTRY_ERROR_ID_BAD_VALUE              =  -33,
    WOLFSENTRY_ERROR_ID_DEADLOCK_AVERTED       =  -34,
    WOLFSENTRY_ERROR_ID_OVERFLOW_AVERTED       =  -35,
    WOLFSENTRY_ERROR_ID_LACKING_MUTEX          =  -36,
    WOLFSENTRY_ERROR_ID_LACKING_READ_LOCK      =  -37,
    WOLFSENTRY_ERROR_ID_LIB_MISMATCH           =  -38,
    WOLFSENTRY_ERROR_ID_LIBCONFIG_MISMATCH     =  -39,

    WOLFSENTRY_ERROR_ID_USER_BASE              = -128,

    WOLFSENTRY_SUCCESS_ID_OK                   =    0,
    WOLFSENTRY_SUCCESS_ID_LOCK_OK_AND_GOT_RESV =    1,
    WOLFSENTRY_SUCCESS_ID_HAVE_MUTEX           =    2,
    WOLFSENTRY_SUCCESS_ID_HAVE_READ_LOCK       =    3,
    WOLFSENTRY_SUCCESS_ID_USED_FALLBACK        =    4,
    WOLFSENTRY_SUCCESS_ID_USER_BASE            =  128
};

#ifdef WOLFSENTRY_ERROR_STRINGS
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_error_string_set(enum wolfsentry_error_id, const char *error_string);
#define WOLFSENTRY_REGISTER_ERROR(err, msg) wolfsentry_user_error_string_set(WOLFSENTRY_ERROR_ID_ ## err, msg)
#endif

#endif /* WOLFSENTRY_ERRCODES_H */
