/*
 * wolfsentry_errcodes.h
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

/*! @file wolfsentry_errcodes.h
    \brief Definitions for diagnostics.

    Included by `wolfsentry.h`.
 */

#ifndef WOLFSENTRY_ERRCODES_H
#define WOLFSENTRY_ERRCODES_H

/*! \addtogroup wolfsentry_errcode_t
 *  @{
 */

#ifdef WOLFSENTRY_FOR_DOXYGEN
#define WOLFSENTRY_SOURCE_ID
/*!< \brief In each source file in the wolfSentry library, `WOLFSENTRY_SOURCE_ID` is defined to a number that is decoded using `enum wolfsentry_source_id`.  Application source files that use the below error encoding and rendering macros must also define `WOLFSENTRY_SOURCE_ID` to a number, starting with `WOLFSENTRY_SOURCE_ID_USER_BASE`, and can use `wolfsentry_user_source_string_set()` or `WOLFSENTRY_REGISTER_SOURCE()` to arrange for error and warning messages that render the source code file by name. */
#endif

typedef int32_t wolfsentry_errcode_t; /*!< \brief The structured result code type for wolfSentry.  It encodes a failure or success code, a source code file ID, and a line number. */
#if defined(FREERTOS) || defined(THREADX)
#define WOLFSENTRY_ERRCODE_FMT "%d"
#elif defined(PRId32)
#define WOLFSENTRY_ERRCODE_FMT "%" PRId32
#else
#define WOLFSENTRY_ERRCODE_FMT "%d"
    /*!< \brief String-literal macro for formatting `wolfsentry_errcode_t` using `printf()`-type functions.  @hideinitializer */
#endif

/* these must be all-1s */
#define WOLFSENTRY_SOURCE_ID_MAX 127
#define WOLFSENTRY_ERROR_ID_MAX 255
#define WOLFSENTRY_LINE_NUMBER_MAX 65535

/*! @cond doxygen_all */

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
    wolfsentry_errcode_t _xret = (x);                                        \
    wolfsentry_static_assert2(((x) >= -WOLFSENTRY_ERROR_ID_MAX)              \
                   && ((x) <= WOLFSENTRY_ERROR_ID_MAX),                      \
                  "error code must be -"                                     \
                  _q(WOLFSENTRY_ERROR_ID_MAX)                                \
                  " <= e <= "                                                \
                  _q(WOLFSENTRY_ERROR_ID_MAX) )                              \
    wolfsentry_static_assert2(__LINE__ <= WOLFSENTRY_LINE_NUMBER_MAX,        \
                  "line number must be 1-" _q(WOLFSENTRY_LINE_NUMBER_MAX) )  \
    wolfsentry_static_assert2((WOLFSENTRY_SOURCE_ID >= 0)                    \
                  && (WOLFSENTRY_SOURCE_ID <= 0x7f),                         \
                  "source file ID must be 0-" _q(WOLFSENTRY_SOURCE_ID_MAX) ) \
    WOLFSENTRY_ERROR_ENCODE_0(_xret);                                        \
})
#else
#define WOLFSENTRY_ERROR_ENCODE_1(x) WOLFSENTRY_ERROR_ENCODE_0(x)
#endif

#define WOLFSENTRY_ERROR_DECODE_ERROR_CODE_1(x) ((int)(((x) < 0) ? -(-(x) & WOLFSENTRY_ERROR_ID_MAX) : ((x) & WOLFSENTRY_ERROR_ID_MAX)))
#define WOLFSENTRY_ERROR_DECODE_SOURCE_ID_1(x) ((int)(((x) < 0) ? ((-(x)) >> 24) : ((x) >> 24)))
#define WOLFSENTRY_ERROR_DECODE_LINE_NUMBER_1(x) ((int)(((x) < 0) ? (((-(x)) >> 8) & WOLFSENTRY_LINE_NUMBER_MAX) : (((x) >> 8) & WOLFSENTRY_LINE_NUMBER_MAX)))

/*! @endcond */

#ifdef WOLFSENTRY_NO_INLINE

#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
#define WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x) ({ wolfsentry_errcode_t _xret = (x); WOLFSENTRY_ERROR_DECODE_ERROR_CODE_1(_xret); })
    /*!< \brief Extract the bare error (negative) or success (zero/positive) code from an encoded `wolfsentry_errcode_t` @hideinitializer */
#define WOLFSENTRY_ERROR_DECODE_SOURCE_ID(x) ({ wolfsentry_errcode_t _xret = (x); WOLFSENTRY_ERROR_DECODE_SOURCE_ID_1(_xret); })
    /*!< \brief Extract the bare source file ID from an encoded `wolfsentry_errcode_t` @hideinitializer */
#define WOLFSENTRY_ERROR_DECODE_LINE_NUMBER(x) ({ wolfsentry_errcode_t _xret = (x); WOLFSENTRY_ERROR_DECODE_LINE_NUMBER_1(_xret); })
    /*!< \brief Extract the bare source line number from an encoded `wolfsentry_errcode_t` @hideinitializer */
#else
#define WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x) WOLFSENTRY_ERROR_DECODE_ERROR_CODE_1(x)
#define WOLFSENTRY_ERROR_DECODE_SOURCE_ID(x) WOLFSENTRY_ERROR_DECODE_SOURCE_ID_1(x)
#define WOLFSENTRY_ERROR_DECODE_LINE_NUMBER(x) WOLFSENTRY_ERROR_DECODE_LINE_NUMBER_1(x)
#endif

#else

static inline int WOLFSENTRY_ERROR_DECODE_ERROR_CODE(wolfsentry_errcode_t x) {
    return WOLFSENTRY_ERROR_DECODE_ERROR_CODE_1(x);
}
static inline int WOLFSENTRY_ERROR_DECODE_SOURCE_ID(wolfsentry_errcode_t x) {
    return WOLFSENTRY_ERROR_DECODE_SOURCE_ID_1(x);
}
static inline int WOLFSENTRY_ERROR_DECODE_LINE_NUMBER(wolfsentry_errcode_t x) {
    return WOLFSENTRY_ERROR_DECODE_LINE_NUMBER_1(x);
}

#endif

#define WOLFSENTRY_ERROR_RECODE(x) WOLFSENTRY_ERROR_ENCODE_0(WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x))
    /*!< \brief Take an encoded `wolfsentry_errcode_t` and recode it with the current source ID and line number. @hideinitializer */
#define WOLFSENTRY_ERROR_CODE_IS(x, name) (WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x) == WOLFSENTRY_ERROR_ID_ ## name)
    /*!< \brief Take an encoded `wolfsentry_errcode_t` `x` and test if its error code matches short-form error `name` (e.g. `INVALID_ARG`). @hideinitializer */
#define WOLFSENTRY_SUCCESS_CODE_IS(x, name) (WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x) == WOLFSENTRY_SUCCESS_ID_ ## name)
    /*!< \brief Take an encoded `wolfsentry_errcode_t` `x` and test if its error code matches short-form success `name` (e.g. `OK`). @hideinitializer */

#define WOLFSENTRY_IS_FAILURE(x) ((x)<0)
    /*!< \brief Evaluates to true if `x` is a `wolfsentry_errcode_t` that encodes a failure. @hideinitializer */
#define WOLFSENTRY_IS_SUCCESS(x) ((x)>=0)
    /*!< \brief Evaluates to true if `x` is a `wolfsentry_errcode_t` that encodes a success. @hideinitializer */

#ifdef WOLFSENTRY_ERROR_STRINGS
#define WOLFSENTRY_ERROR_FMT "code " WOLFSENTRY_ERRCODE_FMT " (%s), src " WOLFSENTRY_ERRCODE_FMT " (%s), line " WOLFSENTRY_ERRCODE_FMT
    /*!< \brief Convenience string-constant macro for formatting a `wolfsentry_errcode_t` for rendering by a `printf`-type function. @hideinitializer */
#define WOLFSENTRY_ERROR_FMT_ARGS(x) WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x), wolfsentry_errcode_error_string(x), WOLFSENTRY_ERROR_DECODE_SOURCE_ID(x), wolfsentry_errcode_source_string(x), WOLFSENTRY_ERROR_DECODE_LINE_NUMBER(x)
    /*!< \brief Convenience macro supplying args to match the format directives in `WOLFSENTRY_ERROR_FMT`. @hideinitializer */
#else
#define WOLFSENTRY_ERROR_FMT "code " WOLFSENTRY_ERRCODE_FMT ", src " WOLFSENTRY_ERRCODE_FMT ", line " WOLFSENTRY_ERRCODE_FMT
#define WOLFSENTRY_ERROR_FMT_ARGS(x) WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x), WOLFSENTRY_ERROR_DECODE_SOURCE_ID(x), WOLFSENTRY_ERROR_DECODE_LINE_NUMBER(x)
#endif /* WOLFSENTRY_ERROR_STRINGS */

#define WOLFSENTRY_ERROR_ENCODE(name) WOLFSENTRY_ERROR_ENCODE_0(WOLFSENTRY_ERROR_ID_ ## name)
    /*!< \brief Compute a `wolfsentry_errcode_t` encoding the current source ID and line number, and the designated short-form error `name` (e.g. `INVALID_ARG`). @hideinitializer */
#define WOLFSENTRY_SUCCESS_ENCODE(name) WOLFSENTRY_ERROR_ENCODE_0(WOLFSENTRY_SUCCESS_ID_ ## name)
    /*!< \brief Compute a `wolfsentry_errcode_t` encoding the current source ID and line number, and the designated short-form success `name` (e.g. `OK`). @hideinitializer */

#ifdef WOLFSENTRY_FOR_DOXYGEN
#define WOLFSENTRY_DEBUG_CALL_TRACE
/*!< \brief Define to build the library or application to output codepoint and error code info at each return point.
 *
 * In the wolfSentry library, and optionally in applications, all returns from
 * functions are through macros, typically `WOLFSENTRY_ERROR_RETURN()`.  In
 * normal builds, these macros just `return` as usual.  But if
 * `WOLFSENTRY_DEBUG_CALL_TRACE` is defined, then alternative implementations
 * are used that print trace info, using the `WOLFSENTRY_PRINTF_ERR()` macro,
 * which has platform-specific default definitions in `wolfsentry_settings.h`,
 * subject to override.
 */
#undef WOLFSENTRY_DEBUG_CALL_TRACE
#endif

#if defined(WOLFSENTRY_DEBUG_CALL_TRACE) && !defined(WOLFSENTRY_NO_STDIO_STREAMS)
    #define WOLFSENTRY_ERROR_RETURN(x) WOLFSENTRY_ERROR_RETURN_1(WOLFSENTRY_ERROR_ID_ ## x)
    #define WOLFSENTRY_SUCCESS_RETURN(x) WOLFSENTRY_ERROR_RETURN_1(WOLFSENTRY_SUCCESS_ID_ ## x)
    #if defined(WOLFSENTRY_ERROR_STRINGS) && defined(__GNUC__) && !defined(__STRICT_ANSI__)
        #ifdef WOLFSENTRY_CALL_DEPTH_RETURNS_STRING
        WOLFSENTRY_API const char *_wolfsentry_call_depth(void);
        #define _INDENT_FMT "%s"
        #define _INDENT_ARGS _wolfsentry_call_depth()
        #else
        WOLFSENTRY_API unsigned int _wolfsentry_call_depth(void);
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
        /*!< \brief Return a `wolfsentry_errcode_t` encoding the current source ID and line number, and the designated short-form error `name` (e.g. `INVALID_ARG`). @hideinitializer */
    #define WOLFSENTRY_SUCCESS_RETURN(x) return WOLFSENTRY_SUCCESS_ENCODE(x)
        /*!< \brief Return a `wolfsentry_errcode_t` encoding the current source ID and line number, and the designated short-form success `name` (e.g. `OK`). @hideinitializer */
    #define WOLFSENTRY_ERROR_RETURN_RECODED(x) return WOLFSENTRY_ERROR_ENCODE_0(WOLFSENTRY_ERROR_DECODE_ERROR_CODE(x))
        /*!< \brief Take an encoded `wolfsentry_errcode_t`, recode it with the current source ID and line number, and return it. @hideinitializer */
    #define WOLFSENTRY_ERROR_RERETURN(x) return (x)
        /*!< \brief Return an encoded `wolfsentry_errcode_t`. @hideinitializer */
    #define WOLFSENTRY_RETURN_VALUE(x) return (x)
        /*!< \brief Return an arbitrary value. @hideinitializer */
    #define WOLFSENTRY_RETURN_VOID return
        /*!< \brief Return from a void function. @hideinitializer */
#endif

#define WOLFSENTRY_SUCCESS_RETURN_RECODED(x) WOLFSENTRY_ERROR_RETURN_RECODED(x)
    /*!< \brief Take an encoded `wolfsentry_errcode_t`, recode it with the current source ID and line number, and return it. @hideinitializer */
#define WOLFSENTRY_SUCCESS_RERETURN(x) WOLFSENTRY_ERROR_RERETURN(x)
    /*!< \brief Return an encoded `wolfsentry_errcode_t`. @hideinitializer */

#ifdef WOLFSENTRY_THREADSAFE

    #define WOLFSENTRY_UNLOCK_FOR_RETURN_EX(ctx) do {           \
        wolfsentry_errcode_t _lock_ret;                         \
        if ((_lock_ret = wolfsentry_context_unlock(ctx, thread)) < 0) { \
            WOLFSENTRY_ERROR_RERETURN(_lock_ret);               \
        }                                                       \
    } while (0)
    /*!< \brief Unlock a previously locked `wolfsentry_context`, and if the unlock fails, return the error. @hideinitializer */

    #define WOLFSENTRY_UNLOCK_FOR_RETURN() WOLFSENTRY_UNLOCK_FOR_RETURN_EX(wolfsentry)
    /*!< \brief Unlock the current context, and if the unlock fails, return the error. @hideinitializer */

    #define WOLFSENTRY_UNLOCK_AND_UNRESERVE_FOR_RETURN_EX(ctx) do { \
        wolfsentry_errcode_t _lock_ret;                             \
        if ((_lock_ret = wolfsentry_context_unlock_and_abandon_reservation(ctx, thread)) < 0) { \
            WOLFSENTRY_ERROR_RERETURN(_lock_ret);                   \
        }                                                           \
    } while (0)
    /*!< \brief Unlock a previously locked `wolfsentry_context`, and abandon a held promotion reservation if any (see `wolfsentry_lock_unlock()`), and if the operation fails, return the error. @hideinitializer */

    #define WOLFSENTRY_UNLOCK_AND_UNRESERVE_FOR_RETURN() WOLFSENTRY_UNLOCK_AND_UNRESERVE_FOR_RETURN_EX(wolfsentry)
    /*!< \brief Unlock the current context, and abandon a held promotion reservation if any (see `wolfsentry_lock_unlock()`), and if the operation fails, return the error. @hideinitializer */

    #define WOLFSENTRY_MUTEX_EX(ctx) wolfsentry_context_lock_mutex_abstimed(ctx, thread, NULL)
    /*!< \brief Get a mutex on a `wolfsentry_context`, evaluating to the resulting `wolfsentry_errcode_t`. @hideinitializer */

    #define WOLFSENTRY_MUTEX_OR_RETURN() do {                   \
        wolfsentry_errcode_t _lock_ret;                         \
        if ((_lock_ret = WOLFSENTRY_MUTEX_EX(wolfsentry)) < 0)  \
            WOLFSENTRY_ERROR_RERETURN(_lock_ret);               \
    } while (0)
    /*!< \brief Get a mutex on the current context, and on failure, return the `wolfsentry_errcode_t`. @hideinitializer */

    #define WOLFSENTRY_SHARED_EX(ctx) wolfsentry_context_lock_shared_abstimed(ctx, thread, NULL)
    /*!< \brief Get a shared lock on a `wolfsentry_context`, evaluating to the resulting `wolfsentry_errcode_t`. @hideinitializer */

    #define WOLFSENTRY_SHARED_OR_RETURN() do {                  \
        wolfsentry_errcode_t _lock_ret;                         \
        if (thread == NULL)                                     \
            _lock_ret = WOLFSENTRY_MUTEX_EX(wolfsentry);        \
        else                                                    \
            _lock_ret = WOLFSENTRY_SHARED_EX(wolfsentry);       \
        WOLFSENTRY_RERETURN_IF_ERROR(_lock_ret);                \
    } while (0)
    /*!< \brief Get a shared lock on the current context, and on failure, return the `wolfsentry_errcode_t`. @hideinitializer */

    #define WOLFSENTRY_PROMOTABLE_EX(ctx) wolfsentry_context_lock_shared_with_reservation_abstimed(ctx, thread, NULL)
    /*!< \brief Get a mutex on a `wolfsentry_context`, evaluating to the resulting `wolfsentry_errcode_t`. @hideinitializer */

    #define WOLFSENTRY_PROMOTABLE_OR_RETURN() do {              \
        wolfsentry_errcode_t _lock_ret;                         \
        if (thread == NULL)                                     \
            _lock_ret = WOLFSENTRY_MUTEX_EX(wolfsentry);        \
        else                                                    \
            _lock_ret = WOLFSENTRY_PROMOTABLE_EX(wolfsentry);   \
        WOLFSENTRY_RERETURN_IF_ERROR(_lock_ret);                \
    } while (0)
    /*!< \brief Get a shared lock with mutex promotion reservation on the current context, and on failure, return the `wolfsentry_errcode_t`. @hideinitializer */

    #define WOLFSENTRY_UNLOCK_AND_RETURN(ret) do {              \
        WOLFSENTRY_UNLOCK_FOR_RETURN();                         \
        WOLFSENTRY_ERROR_RERETURN(ret);                         \
    } while (0)
    /*!< \brief Unlock the current context, and return the supplied `wolfsentry_errcode_t` . @hideinitializer */

#else
    #define WOLFSENTRY_UNLOCK_FOR_RETURN() DO_NOTHING
    #define WOLFSENTRY_UNLOCK_FOR_RETURN_EX(ctx) DO_NOTHING
    #define WOLFSENTRY_MUTEX_EX(ctx) ((void)(ctx), WOLFSENTRY_ERROR_ENCODE(OK))
    #define WOLFSENTRY_MUTEX_OR_RETURN() (void)wolfsentry
    #define WOLFSENTRY_SHARED_EX(ctx) (void)(ctx)
    #define WOLFSENTRY_SHARED_OR_RETURN() (void)wolfsentry
    #define WOLFSENTRY_PROMOTABLE_EX(ctx) (void)(ctx)
    #define WOLFSENTRY_PROMOTABLE_OR_RETURN() (void)wolfsentry
    #define WOLFSENTRY_UNLOCK_AND_RETURN(lock, ret) WOLFSENTRY_ERROR_RERETURN(ret)
#endif

#define WOLFSENTRY_ERROR_UNLOCK_AND_RETURN(name) do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_ERROR_RETURN(name); } while (0)
    /*!< \brief Unlock the current context, and return a `wolfsentry_errcode_t` encoding the current source ID and line number, and the designated short-form error `name` (e.g. `INVALID_ARG`). @hideinitializer */
#define WOLFSENTRY_ERROR_UNLOCK_AND_RETURN_RECODED(x) do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_ERROR_RETURN_RECODED(x); } while (0)
    /*!< \brief Unlock the current context, then take an encoded `wolfsentry_errcode_t` `x`, recode it with the current source ID and line number, and return it. @hideinitializer */
#define WOLFSENTRY_ERROR_UNLOCK_AND_RETURN_EX(ctx, name) do { WOLFSENTRY_UNLOCK_FOR_RETURN_EX(ctx); WOLFSENTRY_ERROR_RETURN(name); } while (0)
    /*!< \brief Unlock a previously locked `wolfsentry_context` `ctx`, and return a `wolfsentry_errcode_t` encoding the current source ID and line number, and the designated short-form error `name` (e.g. `INVALID_ARG`). @hideinitializer */
#define WOLFSENTRY_ERROR_UNLOCK_AND_RETURN_RECODED_EX(ctx, x) do { WOLFSENTRY_UNLOCK_FOR_RETURN_EX(ctx); WOLFSENTRY_ERROR_RETURN_RECODED(x); } while (0)
    /*!< \brief Unlock a previously locked `wolfsentry_context` `ctx`, then take an encoded `wolfsentry_errcode_t` `x`, recode it with the current source ID and line number, and return it. @hideinitializer */
#define WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(x) do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_ERROR_RERETURN(x); } while (0)
    /*!< \brief Unlock the current context, and return an encoded `wolfsentry_errcode_t`. @hideinitializer */
#define WOLFSENTRY_ERROR_RERETURN_AND_UNLOCK(y) do { wolfsentry_errcode_t _yret = (y); WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_ERROR_RERETURN(_yret); } while (0)
    /*!< \brief Calculate the `wolfsentry_errcode_t` return value for an expression `y`, then unlock the current context, and finally, return the encoded `wolfsentry_errcode_t`. @hideinitializer */

#define WOLFSENTRY_SUCCESS_UNLOCK_AND_RETURN(name) do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_SUCCESS_RETURN(name); } while (0)
    /*!< \brief Unlock the current context, and return a `wolfsentry_errcode_t` encoding the current source ID and line number, and the designated short-form success `name` (e.g. `INVALID_ARG`). @hideinitializer */
#define WOLFSENTRY_SUCCESS_UNLOCK_AND_RETURN_RECODED(x) do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_SUCCESS_RETURN_RECODED(x); } while (0)
    /*!< \brief Unlock the current context, then take an encoded `wolfsentry_errcode_t` `x`, recode it with the current source ID and line number, and return it. @hideinitializer */
#define WOLFSENTRY_SUCCESS_UNLOCK_AND_RERETURN(x) do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_SUCCESS_RERETURN(x); } while (0)
    /*!< \brief Unlock the current context, and return an encoded `wolfsentry_errcode_t`. @hideinitializer */
#define WOLFSENTRY_SUCCESS_RERETURN_AND_UNLOCK(y) do { wolfsentry_errcode_t _yret = (y); WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_SUCCESS_RERETURN(_yret); } while (0)
    /*!< \brief Calculate the `wolfsentry_errcode_t` return value for an expression `y`, then unlock the current context, and finally, return the encoded `wolfsentry_errcode_t`. @hideinitializer */

#define WOLFSENTRY_UNLOCK_AND_RETURN_VALUE(x) do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_RETURN_VALUE(x); } while (0)
    /*!< \brief Unlock the current context, and return a value `x`. @hideinitializer */
#define WOLFSENTRY_UNLOCK_AND_RETURN_VOID do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_RETURN_VOID; } while (0)
    /*!< \brief Unlock the current context, and return void. @hideinitializer */

#define WOLFSENTRY_RETURN_OK WOLFSENTRY_SUCCESS_RETURN(OK)
    /*!< \brief Return a `wolfsentry_errcode_t` encoding the current source ID and line number, and the success code `OK`. @hideinitializer */
#define WOLFSENTRY_UNLOCK_AND_RETURN_OK do { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_SUCCESS_RETURN(OK); } while (0)
    /*!< \brief Unlock the current context, and return a `wolfsentry_errcode_t` encoding the current source ID and line number, and the success code `OK`. @hideinitializer */
#define WOLFSENTRY_RERETURN_IF_ERROR(y) do { wolfsentry_errcode_t _yret = (y); if (_yret < 0) WOLFSENTRY_ERROR_RERETURN(_yret); } while (0)
    /*!< \brief If `wolfsentry_errcode_t` `y` is a failure code, return it. @hideinitializer */
#define WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(y) do { wolfsentry_errcode_t _yret = (y); if (_yret < 0) { WOLFSENTRY_UNLOCK_FOR_RETURN(); WOLFSENTRY_ERROR_RERETURN(_yret); } } while (0)
    /*!< \brief If `wolfsentry_errcode_t` `y` is a failure code, unlock the current context and return the code. @hideinitializer */

#ifdef WOLFSENTRY_ERROR_STRINGS
WOLFSENTRY_API const char *wolfsentry_errcode_source_string(wolfsentry_errcode_t e);
    /*!< \brief Return the name of the source code file associated with `wolfsentry_errcode_t` `e`, or "unknown user defined source", or "unknown source". @hideinitializer */
WOLFSENTRY_API const char *wolfsentry_errcode_error_string(wolfsentry_errcode_t e);
    /*!< \brief Return a description of the failure or success code associated with `wolfsentry_errcode_t` `e`, or various "unknown" strings if not known. @hideinitializer */
WOLFSENTRY_API const char *wolfsentry_errcode_error_name(wolfsentry_errcode_t e);
    /*!< \brief Return the short name of the failure or success code associated with `wolfsentry_errcode_t` `e`, or `wolfsentry_errcode_error_string(e)` if not known. @hideinitializer */
#endif

#if !defined(WOLFSENTRY_NO_STDIO_STREAMS) && !defined(WOLFSENTRY_NO_DIAG_MSGS)

#ifndef WOLFSENTRY_NETXDUO /* netxduo has its own errno.h */
#include <errno.h>
#endif

#ifdef __STRICT_ANSI__
#define WOLFSENTRY_WARN(fmt,...) WOLFSENTRY_PRINTF_ERR("%s@L%d " fmt, __FILE__, __LINE__, __VA_ARGS__)
#else
#define WOLFSENTRY_WARN(fmt,...) WOLFSENTRY_PRINTF_ERR("%s@L%d " fmt, __FILE__, __LINE__, ## __VA_ARGS__)
    /*!< \brief Render a warning message using `WOLFSENTRY_PRINTF_ERR()`, or if `WOLFSENTRY_NO_STDIO_STREAMS` or `WOLFSENTRY_NO_DIAG_MSGS` is set, `DO_NOTHING`. @hideinitializer */
#endif

#define WOLFSENTRY_WARN_ON_FAILURE(...) do { wolfsentry_errcode_t _ret = (__VA_ARGS__); if (_ret < 0) { WOLFSENTRY_WARN(#__VA_ARGS__ ": " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(_ret)); }} while(0)
    /*!< \brief Evaluate the supplied expression, and if the resulting `wolfsentry_errcode_t` encodes an error, render the expression and the decoded error using `WOLFSENTRY_PRINTF_ERR()`, but if `WOLFSENTRY_NO_STDIO_STREAMS` or `WOLFSENTRY_NO_DIAG_MSGS` is set, don't render a warning. @hideinitializer */
#define WOLFSENTRY_WARN_ON_FAILURE_LIBC(...) do { if ((__VA_ARGS__) < 0) { WOLFSENTRY_WARN(#__VA_ARGS__ ": %s\n", strerror(errno)); }} while(0)
    /*!< \brief Evaluate the supplied expression, and if it evaluates to a negative value, render the expression and the decoded `errno` using `WOLFSENTRY_PRINTF_ERR()`, but if `WOLFSENTRY_NO_STDIO_STREAMS` or `WOLFSENTRY_NO_DIAG_MSGS` is set, don't render a warning. @hideinitializer */

#else

#define WOLFSENTRY_WARN(fmt,...) DO_NOTHING
#define WOLFSENTRY_WARN_ON_FAILURE(...) do { if ((__VA_ARGS__) < 0) {} } while (0)
#define WOLFSENTRY_WARN_ON_FAILURE_LIBC(...) do { if ((__VA_ARGS__) < 0) {}} while (0)

#endif /* !WOLFSENTRY_NO_STDIO_STREAMS && !WOLFSENTRY_NO_DIAG_MSGS */

#ifdef WOLFSENTRY_CPPCHECK
    #undef WOLFSENTRY_ERROR_ENCODE
    #define WOLFSENTRY_ERROR_ENCODE(x) 0
    #undef WOLFSENTRY_SUCCESS_ENCODE
    #define WOLFSENTRY_SUCCESS_ENCODE(x) 0
#endif

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
    WOLFSENTRY_SOURCE_ID_ACTION_BUILTINS_C = 11,

    WOLFSENTRY_SOURCE_ID_USER_BASE  =  112
};

#ifdef WOLFSENTRY_ERROR_STRINGS
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_source_string_set(enum wolfsentry_source_id wolfsentry_source_id, const char *source_string);
    /*!< \brief Register a source code file so that `wolfsentry_errcode_source_string()`, and therefore `WOLFSENTRY_ERROR_FMT_ARGS()` and `WOLFSENTRY_WARN_ON_FAILURE()`, can render it.  Note that `source_string` must be a string constant or otherwise remain valid for the duration of runtime. @hideinitializer */
#define WOLFSENTRY_REGISTER_SOURCE() wolfsentry_user_source_string_set(WOLFSENTRY_SOURCE_ID,__FILE__)
    /*!< \brief Helper macro to call `wolfsentry_user_source_string_set()` with appropriate arguments. @hideinitializer */
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
    WOLFSENTRY_ERROR_ID_IO_FAILED              =  -40,
    WOLFSENTRY_ERROR_ID_WRONG_ATTRIBUTES       =  -41,

    WOLFSENTRY_ERROR_ID_USER_BASE              = -128,

    WOLFSENTRY_SUCCESS_ID_OK                   =    0,
    WOLFSENTRY_SUCCESS_ID_LOCK_OK_AND_GOT_RESV =    1,
    WOLFSENTRY_SUCCESS_ID_HAVE_MUTEX           =    2,
    WOLFSENTRY_SUCCESS_ID_HAVE_READ_LOCK       =    3,
    WOLFSENTRY_SUCCESS_ID_USED_FALLBACK        =    4,
    WOLFSENTRY_SUCCESS_ID_YES                  =    5,
    WOLFSENTRY_SUCCESS_ID_NO                   =    6,
    WOLFSENTRY_SUCCESS_ID_ALREADY_OK           =    7,
    WOLFSENTRY_SUCCESS_ID_DEFERRED             =    8,
    WOLFSENTRY_SUCCESS_ID_NO_DEADLINE          =    9,
    WOLFSENTRY_SUCCESS_ID_EXPIRED              =   10,
    WOLFSENTRY_SUCCESS_ID_NO_WAITING           =   11,
    WOLFSENTRY_SUCCESS_ID_USER_BASE            =  128
};

#ifdef WOLFSENTRY_ERROR_STRINGS
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_error_string_set(enum wolfsentry_error_id wolfsentry_error_id, const char *message_string);
    /*!< \brief Register an error (negative) or success (positive) code, and corresponding message, so that `wolfsentry_errcode_error_string()`, and therefore `WOLFSENTRY_ERROR_FMT_ARGS()` and `WOLFSENTRY_WARN_ON_FAILURE()`, can render it in human-readable form.  Note that `error_string` must be a string constant or otherwise remain valid for the duration of runtime. @hideinitializer */
#define WOLFSENTRY_REGISTER_ERROR(name, msg) wolfsentry_user_error_string_set(WOLFSENTRY_ERROR_ID_ ## name, msg)
    /*!< \brief Helper macro to call `wolfsentry_user_error_string_set()` with appropriate arguments, given a short-form `name` and freeform string `msg` . @hideinitializer */
#endif

/*! @} (end wolfsentry_errcode_t) */

#endif /* WOLFSENTRY_ERRCODES_H */
