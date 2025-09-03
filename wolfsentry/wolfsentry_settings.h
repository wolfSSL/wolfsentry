/*
 * wolfsentry_settings.h
 *
 * Copyright (C) 2022-2025 wolfSSL Inc.
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

/*! @file wolfsentry_settings.h
    \brief Target- and config-specific settings and abstractions for wolfSentry.

    This file is included by wolfsentry.h.
 */

#ifndef WOLFSENTRY_SETTINGS_H
#define WOLFSENTRY_SETTINGS_H

/*! \addtogroup wolfsentry_init
 * @{
 */
#ifdef WOLFSENTRY_FOR_DOXYGEN
#define WOLFSENTRY_USER_SETTINGS_FILE "the_path"
     /*!< \brief Define to the path of a user settings file to be included, containing extra and override definitions and directives.  Can be an absolute or a relative path, subject to a `-I` path supplied to `make` using `EXTRA_CFLAGS`.  Include quotes or <> around the path. */
#undef WOLFSENTRY_USER_SETTINGS_FILE
#endif

#ifdef WOLFSENTRY_USER_SETTINGS_FILE
    #include WOLFSENTRY_USER_SETTINGS_FILE
#endif

#if !defined(BUILDING_LIBWOLFSENTRY) && !defined(WOLFSENTRY_USER_SETTINGS_FILE)
    #include <wolfsentry/wolfsentry_options.h>
#endif

/*! @} */

/*! \addtogroup core_types
 *  @{
 */

#ifdef WOLFSENTRY_FOR_DOXYGEN
#define WOLFSENTRY_NO_ALLOCA /*!< \brief Build flag to use only implementations that avoid alloca(). */
#undef WOLFSENTRY_NO_ALLOCA
#define WOLFSENTRY_C89 /*!< \brief Build flag to use only constructs that are pedantically legal in C89. */
#undef WOLFSENTRY_C89
#endif

#ifdef WOLFSENTRY_C89
    #define WOLFSENTRY_NO_INLINE
    #ifndef WOLFSENTRY_NO_POSIX_MEMALIGN
        #define WOLFSENTRY_NO_POSIX_MEMALIGN
    #endif
    #define WOLFSENTRY_NO_DESIGNATED_INITIALIZERS
    #define WOLFSENTRY_NO_LONG_LONG
    #if !defined(WOLFSENTRY_USE_NONPOSIX_SEMAPHORES) && !defined(WOLFSENTRY_SINGLETHREADED)
        /* sem_timedwait() was added in POSIX 200112L */
        #define WOLFSENTRY_SINGLETHREADED
    #endif
#endif

#ifndef __attribute_maybe_unused__
#if defined(__GNUC__)
#define __attribute_maybe_unused__ __attribute__((unused))
    /*!< \brief Attribute abstraction to mark a function or variable (typically a `static`) as possibly unused. @hideinitializer */
#else
#define __attribute_maybe_unused__
#endif
#endif

#ifdef WOLFSENTRY_NO_INLINE
/*! @cond doxygen_all */
#define inline __attribute_maybe_unused__
/*! @endcond */
#endif

#ifndef DO_NOTHING
#define DO_NOTHING do {} while (0)
    /*!< \brief Statement-type abstracted construct that executes no code. @hideinitializer */
#endif

/*! @} */

#ifdef FREERTOS
    #include <FreeRTOS.h>
    #define WOLFSENTRY_CALL_DEPTH_RETURNS_STRING
    #if !defined(WOLFSENTRY_NO_STDIO_STREAMS) && !defined(WOLFSENTRY_PRINTF_ERR)
        #define WOLFSENTRY_PRINTF_ERR(...) printf(__VA_ARGS__)
    #endif

    #define FREERTOS_NANOSECONDS_PER_SECOND     1000000000L
    #define FREERTOS_NANOSECONDS_PER_TICK       (FREERTOS_NANOSECONDS_PER_SECOND / configTICK_RATE_HZ)

    #if !defined(SIZE_T_32) && !defined(SIZE_T_64)
        /* size_t is "unsigned int" in STM32 FreeRTOS */
        #define SIZE_T_32
    #endif
#endif

#ifdef THREADX
    #ifdef NEED_THREADX_TYPES
        #include <types.h>
        #include <stdio.h>
    #endif
    #include <tx_api.h>

    #if !defined(SIZE_T_32) && !defined(SIZE_T_64)
        /* size_t is "unsigned int" by default */
        #define SIZE_T_32
    #endif
#endif


/*! \addtogroup wolfsentry_init
 * @{
 */

#ifdef WOLFSENTRY_FOR_DOXYGEN
#define WOLFSENTRY_NO_INTTYPES_H
    /*!< \brief Define to inhibit inclusion of `inttypes.h` (alternative `typedef`s or `include` must be supplied with #WOLFSENTRY_USER_SETTINGS_FILE). */
#undef WOLFSENTRY_NO_INTTYPES_H
#endif
#ifndef WOLFSENTRY_NO_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef WOLFSENTRY_FOR_DOXYGEN
#define WOLFSENTRY_NO_STDINT_H
    /*!< \brief Define to inhibit inclusion of `stding.h` (alternative `typedef`s or `include` must be supplied with #WOLFSENTRY_USER_SETTINGS_FILE). */
#undef WOLFSENTRY_NO_STDINT_H
#endif
#ifndef WOLFSENTRY_NO_STDINT_H
#include <stdint.h>
#endif

/*! @} */

#if !defined(SIZE_T_32) && !defined(SIZE_T_64)
    #if defined(__WORDSIZE) && (__WORDSIZE == 64)
        #define SIZE_T_64
    #elif defined(INTPTR_MAX) && defined(INT64_MAX) && (INTPTR_MAX == INT64_MAX)
        #define SIZE_T_64
    #elif defined(__WORDSIZE) && (__WORDSIZE == 32)
        #define SIZE_T_32
    #elif defined(INTPTR_MAX) && defined(INT32_MAX) && (INTPTR_MAX == INT32_MAX)
        #define SIZE_T_32
    #else
        #error "must define SIZE_T_32 or SIZE_T_64 with user settings."
    #endif
#elif defined(SIZE_T_32) && defined(SIZE_T_64)
    #error "must define SIZE_T_32 xor SIZE_T_64."
#endif

/*! \addtogroup wolfsentry_errcode_t
 *  @{
 */

#if !defined(WOLFSENTRY_NO_STDIO_STREAMS) && !defined(WOLFSENTRY_PRINTF_ERR)
    #define WOLFSENTRY_PRINTF_ERR(...) (void)fprintf(stderr, __VA_ARGS__)
        /*!< \brief printf-like macro, expecting a format as first arg, used for rendering warning and error messages.  Can be overridden in #WOLFSENTRY_USER_SETTINGS_FILE. @hideinitializer */
#endif

/*! @} */

/*! \addtogroup wolfsentry_init
 * @{
 */

#ifdef WOLFSENTRY_FOR_DOXYGEN
#define WOLFSENTRY_SINGLETHREADED
    /*!< \brief Define to disable all thread handling and safety in wolfSentry. */
#undef WOLFSENTRY_SINGLETHREADED
#endif

#ifndef WOLFSENTRY_SINGLETHREADED

/*! @cond doxygen_all */
#define WOLFSENTRY_THREADSAFE
/*! @endcond */

#ifdef WOLFSENTRY_FOR_DOXYGEN

#define WOLFSENTRY_USE_NONPOSIX_SEMAPHORES
    /*!< \brief Define if POSIX semaphore API is not available.  If no non-POSIX builtin implementation is present in wolfsentry_util.c, then #WOLFSENTRY_NO_SEM_BUILTIN must be set, and the ::wolfsentry_host_platform_interface supplied to wolfSentry APIs must include a full semaphore implementation (shim set) in its ::wolfsentry_semcbs slot. */
#undef WOLFSENTRY_USE_NONPOSIX_SEMAPHORES

#define WOLFSENTRY_USE_NONPOSIX_THREADS
    /*!< \brief Define if POSIX thread API is not available.  `WOLFSENTRY_THREAD_INCLUDE`, `WOLFSENTRY_THREAD_ID_T`, and `WOLFSENTRY_THREAD_GET_ID_HANDLER` will need to be supplied in #WOLFSENTRY_USER_SETTINGS_FILE. */
#undef WOLFSENTRY_USE_NONPOSIX_THREADS

#define WOLFSENTRY_NO_GNU_ATOMICS
    /*!< \brief Define if gnu-style atomic intrinsics are not available.  `WOLFSENTRY_ATOMIC_*()` macro definitions for intrinsics will need to be supplied in #WOLFSENTRY_USER_SETTINGS_FILE (see wolfsentry_util.h). */
#undef WOLFSENTRY_NO_GNU_ATOMICS

#endif

#ifndef WOLFSENTRY_USE_NONPOSIX_SEMAPHORES
    #if defined(__MACH__) || defined(FREERTOS) || defined(_WIN32) || defined(THREADX)
        #define WOLFSENTRY_USE_NONPOSIX_SEMAPHORES
    #endif
#endif

#ifndef WOLFSENTRY_USE_NONPOSIX_THREADS
    #if defined(FREERTOS) || defined(_WIN32) || defined(THREADX)
        #define WOLFSENTRY_USE_NONPOSIX_THREADS
    #endif
#endif

/*! @cond doxygen_all */

#ifndef WOLFSENTRY_USE_NONPOSIX_SEMAPHORES
    #define WOLFSENTRY_USE_NATIVE_POSIX_SEMAPHORES
#endif

#ifndef WOLFSENTRY_USE_NONPOSIX_THREADS
    #define WOLFSENTRY_USE_NATIVE_POSIX_THREADS
#endif

#ifndef WOLFSENTRY_NO_GNU_ATOMICS
    #define WOLFSENTRY_HAVE_GNU_ATOMICS
#endif

/*! @endcond */

#endif /* !WOLFSENTRY_SINGLETHREADED */

#ifdef WOLFSENTRY_FOR_DOXYGEN

#define WOLFSENTRY_NO_CLOCK_BUILTIN
    /*!< \brief If defined, omit built-in time primitives; the ::wolfsentry_host_platform_interface supplied to wolfSentry APIs must include implementations of all functions in ::wolfsentry_timecbs. */
#undef WOLFSENTRY_NO_CLOCK_BUILTIN

#define WOLFSENTRY_NO_SEM_BUILTIN
    /*!< \brief If defined, omit built-in semaphore primitives; the ::wolfsentry_host_platform_interface supplied to wolfSentry APIs must include implementations of all functions in ::wolfsentry_semcbs. */
#undef WOLFSENTRY_NO_SEM_BUILTIN

#define WOLFSENTRY_NO_MALLOC_BUILTIN
    /*!< \brief If defined, omit built-in heap allocator primitives; the ::wolfsentry_host_platform_interface supplied to wolfSentry APIs must include implementations of all functions in ::wolfsentry_allocator. */
#undef WOLFSENTRY_NO_MALLOC_BUILTIN

#define WOLFSENTRY_NO_ERROR_STRINGS
    /*!< \brief If defined, omit APIs for rendering error codes and source code files in human readable form.  They will be rendered numerically. */
#undef WOLFSENTRY_NO_ERROR_STRINGS

#define WOLFSENTRY_NO_PROTOCOL_NAMES
    /*!< \brief If defined, omit APIs for rendering error codes and source code files in human readable form.  They will be rendered numerically. */
#undef WOLFSENTRY_NO_PROTOCOL_NAMES

#define WOLFSENTRY_NO_ADDR_BITMASK_MATCHING
    /*!< \brief If defined, omit support for bitmask matching of addresses, and support only prefix matching. */
#undef WOLFSENTRY_NO_ADDR_BITMASK_MATCHING

#define WOLFSENTRY_NO_IPV6
    /*!< \brief If defined, omit support for IPv6. */
#undef WOLFSENTRY_NO_IPV6

#endif /* WOLFSENTRY_FOR_DOXYGEN */

#ifndef WOLFSENTRY_MAX_BITMASK_MATCHED_AFS
    #define WOLFSENTRY_MAX_BITMASK_MATCHED_AFS 4
        /*!< \brief The maximum number of distinct address families that can use bitmask matching in routes.  Default value is 4.  @hideinitializer */
#endif

/*! @cond doxygen_all */

#ifndef WOLFSENTRY_NO_CLOCK_BUILTIN
    #define WOLFSENTRY_CLOCK_BUILTINS
#endif

#ifndef WOLFSENTRY_NO_MALLOC_BUILTIN
    #define WOLFSENTRY_MALLOC_BUILTINS
#endif

#ifndef WOLFSENTRY_NO_SEM_BUILTIN
    #define WOLFSENTRY_SEM_BUILTINS
#endif

#ifndef WOLFSENTRY_NO_ERROR_STRINGS
    #define WOLFSENTRY_ERROR_STRINGS
#endif

#ifndef WOLFSENTRY_NO_PROTOCOL_NAMES
    #define WOLFSENTRY_PROTOCOL_NAMES
#endif

#ifndef WOLFSENTRY_NO_JSON_DOM
    #define WOLFSENTRY_HAVE_JSON_DOM
#endif

#ifndef WOLFSENTRY_NO_ADDR_BITMASK_MATCHING
    #define WOLFSENTRY_ADDR_BITMASK_MATCHING
#endif

#ifndef WOLFSENTRY_NO_IPV6
    #define WOLFSENTRY_IPV6
#endif

/*! @endcond */

#if !defined(WOLFSENTRY_NO_GETPROTOBY) && (!defined(__GLIBC__) || !defined(__USE_MISC) || defined(WOLFSENTRY_C89))
    /* get*by*_r() is non-standard. */
    #define WOLFSENTRY_NO_GETPROTOBY
        /*!< \brief Define this to gate out calls to getprotobyname_r() and getservbyname_r(), necessitating numeric identification of protocols (e.g. 6 for TCP) and services (e.g. 25 for SMTP) in configuration JSON documents. */
#endif

/*! @} */

/*! \addtogroup core_types
 *  @{
 */

#if defined(WOLFSENTRY_USE_NATIVE_POSIX_SEMAPHORES) || defined(WOLFSENTRY_CLOCK_BUILTINS) || defined(WOLFSENTRY_MALLOC_BUILTINS)
#ifndef _XOPEN_SOURCE
#if __STDC_VERSION__ >= 201112L
#define _XOPEN_SOURCE 700
#elif __STDC_VERSION__ >= 199901L
#define _XOPEN_SOURCE 600
#else
#define _XOPEN_SOURCE 500
#endif /* __STDC_VERSION__ */
#endif
#endif

#if !defined(WOLFSENTRY_NO_POSIX_MEMALIGN) && (!defined(_POSIX_C_SOURCE) || (_POSIX_C_SOURCE < 200112L))
    #define WOLFSENTRY_NO_POSIX_MEMALIGN
        /*!< \brief Define if `posix_memalign()` is not available. */
#endif

#if defined(WOLFSENTRY_FLEXIBLE_ARRAY_SIZE)
    /* keep override value. */
#elif defined(__STRICT_ANSI__) || defined(WOLFSENTRY_PEDANTIC_C)
    #define WOLFSENTRY_FLEXIBLE_ARRAY_SIZE 1
#elif defined(__GNUC__) && !defined(__clang__)
    #define WOLFSENTRY_FLEXIBLE_ARRAY_SIZE
    /*!< \brief Value appropriate as a size for an array that will be allocated to a variable size.  Built-in value usually works. */
#else
    #define WOLFSENTRY_FLEXIBLE_ARRAY_SIZE 0
#endif

#if defined(__GNUC__) && !defined(__clang__) && !defined(WOLFSENTRY_NO_PRAGMAS)
    #define WOLFSENTRY_GCC_PRAGMAS
#endif

#if defined(__clang__) && !defined(WOLFSENTRY_NO_PRAGMAS)
    #define WOLFSENTRY_CLANG_PRAGMAS
#endif

/*! @cond doxygen_all */

#ifndef WOLFSENTRY_NO_TIME_H
#ifndef __USE_POSIX199309
/* glibc needs this for struct timespec with -std=c99 */
#define __USE_POSIX199309
#endif
#endif

/*! @endcond */

#ifndef SIZET_FMT
    #ifdef SIZE_T_32
        #define SIZET_FMT "%u"
    #elif __STDC_VERSION__ >= 199901L
        #define SIZET_FMT "%zu"
    #else
        #define SIZET_FMT "%lu"
            /*!< \brief printf-style format string appropriate for pairing with `size_t` @hideinitializer */
    #endif
#endif

#ifndef WOLFSENTRY_NO_STDDEF_H
#include <stddef.h>
#endif
#ifndef WOLFSENTRY_NO_ASSERT_H
#include <assert.h>
#endif
#ifndef WOLFSENTRY_NO_STDIO_H
#ifndef __USE_ISOC99
/* kludge to make glibc snprintf() prototype visible even when -std=c89 */
/*! @cond doxygen_all */
#define __USE_ISOC99
/*! @endcond */
#include <stdio.h>
#undef __USE_ISOC99
#else
#include <stdio.h>
#endif
#endif
#ifndef WOLFSENTRY_NO_STRING_H
#include <string.h>
#endif
#ifndef WOLFSENTRY_NO_STRINGS_H
#include <strings.h>
#endif
#ifndef WOLFSENTRY_NO_TIME_H
#include <time.h>
#endif

typedef unsigned char byte;
    /*!< \brief 8 bits unsigned */

typedef uint16_t wolfsentry_addr_family_t;
    /*!< \brief integer type for holding address family number */

typedef uint16_t wolfsentry_proto_t;
    /*!< \brief integer type for holding protocol number */
typedef uint16_t wolfsentry_port_t;
    /*!< \brief integer type for holding port number */

#ifdef WOLFSENTRY_ENT_ID_TYPE
typedef WOLFSENTRY_ENT_ID_TYPE wolfsentry_ent_id_t;
#else
typedef uint32_t wolfsentry_ent_id_t;
    /*!< \brief integer type for holding table entry ID */
#endif

#ifndef WOLFSENTRY_ENT_ID_FMT
    #ifdef PRIu32
        #define WOLFSENTRY_ENT_ID_FMT "%" PRIu32
    #elif (defined(__WORDSIZE) && (__WORDSIZE == 32)) || \
        (defined(INTPTR_MAX) && defined(INT32_MAX) && (INTPTR_MAX == INT32_MAX))
        #define WOLFSENTRY_ENT_ID_FMT "%lu"
    #else
        #define WOLFSENTRY_ENT_ID_FMT "%u"
            /*!< \brief printf-style format string appropriate for pairing with ::wolfsentry_ent_id_t @hideinitializer */
    #endif
#endif

#define WOLFSENTRY_ENT_ID_NONE 0
    /*!< \brief always-invalid object ID @hideinitializer */
typedef uint16_t wolfsentry_addr_bits_t;
    /*!< \brief integer type for address prefix lengths (in bits) */
#ifdef WOLFSENTRY_HITCOUNT_TYPE
typedef WOLFSENTRY_HITCOUNT_TYPE wolfsentry_hitcount_t;
#else
typedef uint32_t wolfsentry_hitcount_t;
    /*!< \brief integer type for holding hit count statistics */
#define WOLFSENTRY_HITCOUNT_FMT "%u"
    /*!< \brief printf-style format string appropriate for pairing with ::wolfsentry_hitcount_t @hideinitializer */
#endif
#ifdef WOLFSENTRY_TIME_TYPE
typedef WOLFSENTRY_TIME_TYPE wolfsentry_time_t;
#else
typedef int64_t wolfsentry_time_t;
    /*!< \brief integer type for holding absolute and relative times, using microseconds in built-in implementations. */
#endif

#ifdef WOLFSENTRY_PRIORITY_TYPE
typedef WOLFSENTRY_PRIORITY_TYPE wolfsentry_priority_t;
#else
typedef uint16_t wolfsentry_priority_t;
    /*!< \brief integer type for holding event priority (smaller number is higher priority) */
#endif

#ifndef attr_align_to
#ifdef __GNUC__
#define attr_align_to(x) __attribute__((aligned(x)))
#elif defined(_MSC_VER)
/* disable align warning, we want alignment ! */
#pragma warning(disable: 4324)
#define attr_align_to(x) __declspec(align(x))
#else
#error must supply definition for attr_align_to() macro.
#endif
#endif

#ifndef __wolfsentry_wur
#ifdef __wur
#define __wolfsentry_wur __wur
#elif defined(__must_check)
#define __wolfsentry_wur __must_check
#elif defined(__GNUC__) && (__GNUC__ >= 4)
#define __wolfsentry_wur __attribute__((warn_unused_result))
    /*!< \brief abstracted attribute designating that the return value must be checked to avoid a compiler warning @hideinitializer */
#else
#define __wolfsentry_wur
#endif
#endif

#ifndef wolfsentry_static_assert
#if defined(__GNUC__) && defined(static_assert) && !defined(__STRICT_ANSI__)
/* note semicolon included in expansion, so that assert can completely disappear in ISO C builds. */
#define wolfsentry_static_assert(c) static_assert(c, #c);
#define wolfsentry_static_assert2(c, m) static_assert(c, m);
#else
#define wolfsentry_static_assert(c)
/*!< \brief abstracted static assert -- `c` must be true, else `c` is printed @hideinitializer */
#define wolfsentry_static_assert2(c, m)
/*!< \brief abstracted static assert -- `c` must be true, else `m` is printed @hideinitializer */
#endif
#endif /* !wolfsentry_static_assert */

/*! @} */

/*! \addtogroup wolfsentry_thread_context
 *  @{
 */

#if defined(WOLFSENTRY_THREADSAFE)

#ifndef WOLFSENTRY_DEADLINE_NEVER
    #define WOLFSENTRY_DEADLINE_NEVER (-1)
    /*!< \brief Value returned in `deadline->tv_sec` and `deadline->tv_nsec` by wolfsentry_get_thread_deadline() when `thread` has no deadline set.  Not allowed as explicit values passed to wolfsentry_set_deadline_abs() -- use wolfsentry_clear_deadline() to clear any deadline.  Can be overridden with user settings. */
#endif
#ifndef WOLFSENTRY_DEADLINE_NOW
    #define WOLFSENTRY_DEADLINE_NOW (-2)
    /*!< \brief Value returned in `deadline->tv_sec` and `deadline->tv_nsec` by wolfsentry_get_thread_deadline() when `thread` is in non-blocking mode.  Not allowed as explicit values passed to wolfsentry_set_deadline_abs() -- use wolfsentry_set_deadline_rel_usecs(WOLFSENTRY_CONTEXT_ARGS_OUT, 0) to put thread in non-blocking mode.  Can be overridden with user settings. */
#endif

#ifdef WOLFSENTRY_USE_NATIVE_POSIX_SEMAPHORES

#ifdef WOLFSENTRY_SEMAPHORE_INCLUDE

#include WOLFSENTRY_SEMAPHORE_INCLUDE

#else /* !WOLFSENTRY_SEMAPHORE_INCLUDE */

#ifndef __USE_XOPEN2K
/* kludge to force glibc sem_timedwait() prototype visible with -std=c99 */
#define __USE_XOPEN2K
#include <semaphore.h>
#undef __USE_XOPEN2K
#else
#include <semaphore.h>
#endif

#endif /* !WOLFSENTRY_SEMAPHORE_INCLUDE */

#elif defined(__MACH__)

#include <dispatch/dispatch.h>
#include <semaphore.h>
#define sem_t dispatch_semaphore_t

#elif defined(FREERTOS)

#include <atomic.h>

#ifdef WOLFSENTRY_SEMAPHORE_INCLUDE
#include WOLFSENTRY_SEMAPHORE_INCLUDE
#else
#include <semphr.h>
#endif

#define SEM_VALUE_MAX        0x7FFFU

#define sem_t StaticSemaphore_t

#elif defined(THREADX)

#define sem_t TX_SEMAPHORE

#else

/*! @} */

/*! \addtogroup wolfsentry_init
 *  @{
 */

#ifdef WOLFSENTRY_FOR_DOXYGEN
#define WOLFSENTRY_SEMAPHORE_INCLUDE "the_path"
    /*!< \brief Define to the path of a header file declaring a semaphore API.  Can be an absolute or a relative path, subject to a `-I` path supplied to `make` using `EXTRA_CFLAGS`.  Include quotes or <> around the path. */
#undef WOLFSENTRY_SEMAPHORE_INCLUDE
#define WOLFSENTRY_THREAD_INCLUDE "the_path"
    /*!< \brief Define to the path of a header file declaring a threading API.  Can be an absolute or a relative path, subject to a `-I` path supplied to `make` using `EXTRA_CFLAGS`.  Include quotes or <> around the path. */
#undef WOLFSENTRY_THREAD_INCLUDE
#define WOLFSENTRY_THREAD_ID_T thread_id_type
    /*!< \brief Define to the appropriate type analogous to POSIX `pthread_t`. */
#undef WOLFSENTRY_THREAD_ID_T
#define WOLFSENTRY_THREAD_GET_ID_HANDLER pthread_self_ish_function
    /*!< \brief Define to the name of a void function analogous to POSIX `pthread_self`, returning a value of type #WOLFSENTRY_THREAD_ID_T. */
#undef WOLFSENTRY_THREAD_GET_ID_HANDLER
#endif

/*! @} */

/*! \addtogroup wolfsentry_thread_context
 *  @{
 */

#ifdef WOLFSENTRY_SEMAPHORE_INCLUDE
#include WOLFSENTRY_SEMAPHORE_INCLUDE
#endif

#endif

    #ifdef WOLFSENTRY_THREAD_INCLUDE
        #include WOLFSENTRY_THREAD_INCLUDE
    #elif defined(WOLFSENTRY_USE_NATIVE_POSIX_THREADS)
        #include <pthread.h>
    #endif
    #ifdef WOLFSENTRY_THREAD_ID_T
        typedef WOLFSENTRY_THREAD_ID_T wolfsentry_thread_id_t;
    #elif defined(WOLFSENTRY_USE_NATIVE_POSIX_THREADS)
        typedef pthread_t wolfsentry_thread_id_t;
    #elif defined(FREERTOS)
        typedef TaskHandle_t wolfsentry_thread_id_t;
    #elif defined(THREADX)
        typedef TX_THREAD* wolfsentry_thread_id_t;
    #else
        #error Must supply WOLFSENTRY_THREAD_ID_T for WOLFSENTRY_THREADSAFE on non-POSIX targets.
    #endif
    /* note WOLFSENTRY_THREAD_GET_ID_HANDLER must return WOLFSENTRY_THREAD_NO_ID on failure. */
    #ifdef WOLFSENTRY_THREAD_GET_ID_HANDLER
    #elif defined(WOLFSENTRY_USE_NATIVE_POSIX_THREADS)
       #define WOLFSENTRY_THREAD_GET_ID_HANDLER pthread_self
    #elif defined(FREERTOS)
       #define WOLFSENTRY_THREAD_GET_ID_HANDLER xTaskGetCurrentTaskHandle
    #elif defined(THREADX)
       #define WOLFSENTRY_THREAD_GET_ID_HANDLER tx_thread_identify
    #else
        #error Must supply WOLFSENTRY_THREAD_GET_ID_HANDLER for WOLFSENTRY_THREADSAFE on non-POSIX targets.
    #endif

    struct wolfsentry_thread_context;

    /* WOLFSENTRY_THREAD_NO_ID must be zero. */
    #define WOLFSENTRY_THREAD_NO_ID 0

    /*! \brief Right-sized, right-aligned opaque container for thread state */
    struct wolfsentry_thread_context_public {
        uint64_t opaque[8];
    };

    #define WOLFSENTRY_THREAD_CONTEXT_PUBLIC_INITIALIZER {0}
#endif

/*! @} */

/*! \addtogroup core_types
 *  @{
 */

/*! @cond doxygen_all */

#ifdef BUILDING_LIBWOLFSENTRY
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__) || \
        defined(_WIN32_WCE)
        #if defined(WOLFSENTRY_DLL)
            #define WOLFSENTRY_API_BASE __declspec(dllexport)
        #else
            #define WOLFSENTRY_API_BASE
        #endif
        #define WOLFSENTRY_LOCAL_BASE
    #elif defined(HAVE_VISIBILITY) && HAVE_VISIBILITY
        #define WOLFSENTRY_API_BASE   __attribute__ ((visibility("default")))
        #define WOLFSENTRY_LOCAL_BASE __attribute__ ((visibility("hidden")))
    #elif defined(__SUNPRO_C) && (__SUNPRO_C >= 0x550)
        #define WOLFSENTRY_API_BASE   __global
        #define WOLFSENTRY_LOCAL_BASE __hidden
    #else
        #define WOLFSENTRY_API_BASE
        #define WOLFSENTRY_LOCAL_BASE
    #endif /* HAVE_VISIBILITY */
#else /* !BUILDING_LIBWOLFSENTRY */
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__) || \
        defined(_WIN32_WCE)
        #if defined(WOLFSENTRY_DLL)
            #define WOLFSENTRY_API_BASE __declspec(dllimport)
        #else
            #define WOLFSENTRY_API_BASE
        #endif
        #define WOLFSENTRY_LOCAL_BASE
    #else
        #define WOLFSENTRY_API_BASE
        #define WOLFSENTRY_LOCAL_BASE
    #endif
#endif /* !BUILDING_LIBWOLFSENTRY */

/*! @endcond */

#define WOLFSENTRY_API_VOID WOLFSENTRY_API_BASE void
    /*!< \brief Function attribute for declaring/defining public void API functions @hideinitializer */
#define WOLFSENTRY_API WOLFSENTRY_API_BASE __wolfsentry_wur
    /*!< \brief Function attribute for declaring/defining public API functions with return values @hideinitializer */

#define WOLFSENTRY_LOCAL_VOID WOLFSENTRY_LOCAL_BASE void
    /*!< \brief Function attribute for declaring/defining private void functions @hideinitializer */
#define WOLFSENTRY_LOCAL WOLFSENTRY_LOCAL_BASE __wolfsentry_wur
    /*!< \brief Function attribute for declaring/defining private functions with return values @hideinitializer */

/*! @cond doxygen_all */

#ifndef WOLFSENTRY_NO_DESIGNATED_INITIALIZERS
#define WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
#endif

#ifndef WOLFSENTRY_NO_LONG_LONG
#define WOLFSENTRY_HAVE_LONG_LONG
#endif

/*! @endcond */

#ifndef WOLFSENTRY_MAX_ADDR_BYTES
#define WOLFSENTRY_MAX_ADDR_BYTES 16
    /*!< \brief The maximum size allowed for an address, in bytes.  Can be overridden.  Note that support for bitmask matching for an address family depends on #WOLFSENTRY_MAX_ADDR_BYTES at least twice the max size of a bare address in that family, as the address and mask are internally stored as a single double-length byte vector.  Note also that #WOLFSENTRY_MAX_ADDR_BYTES entails proportional overhead if wolfSentry is built #WOLFSENTRY_NO_ALLOCA or #WOLFSENTRY_C89. */
#elif WOLFSENTRY_MAX_ADDR_BYTES * 8 > 0xffff
#error WOLFSENTRY_MAX_ADDR_BYTES * 8 must fit in a uint16_t.
#endif

#ifndef WOLFSENTRY_MAX_ADDR_BITS
#define WOLFSENTRY_MAX_ADDR_BITS (WOLFSENTRY_MAX_ADDR_BYTES*8)
    /*!< \brief The maximum size allowed for an address, in bits.  Can be overridden. */
#else
#if WOLFSENTRY_MAX_ADDR_BITS > (WOLFSENTRY_MAX_ADDR_BYTES*8)
#error WOLFSENTRY_MAX_ADDR_BITS is too large for given/default WOLFSENTRY_MAX_ADDR_BYTES
#endif
#endif

#ifndef WOLFSENTRY_MAX_LABEL_BYTES
#define WOLFSENTRY_MAX_LABEL_BYTES 32
    /*!< \brief The maximum size allowed for a label, in bytes.  Can be overridden. */
#elif WOLFSENTRY_MAX_LABEL_BYTES > 0xff
#error WOLFSENTRY_MAX_LABEL_BYTES must fit in a byte.
#endif

#ifndef WOLFSENTRY_BUILTIN_LABEL_PREFIX
#define WOLFSENTRY_BUILTIN_LABEL_PREFIX "%"
    /*!< \brief The prefix string reserved for use in names of built-in actions and events. */
#endif

#ifndef WOLFSENTRY_KV_MAX_VALUE_BYTES
#define WOLFSENTRY_KV_MAX_VALUE_BYTES 16384
    /*!< \brief The maximum size allowed for scalar user-defined values.  Can be overridden. */
#endif

#ifndef WOLFSENTRY_RWLOCK_MAX_COUNT
#define WOLFSENTRY_RWLOCK_MAX_COUNT ((int)MAX_SINT_OF(int))
    /*!< \brief The maximum count allowed for any internal lock-counting value, limiting recursion.  Defaults to the maximum countable.  Can be overridden. */
#endif

#if defined(WOLFSENTRY_ENT_ID_TYPE) ||          \
    defined(WOLFSENTRY_HITCOUNT_TYPE) ||        \
    defined(WOLFSENTRY_TIME_TYPE) ||            \
    defined(WOLFSENTRY_PRIORITY_TYPE) ||        \
    defined(WOLFSENTRY_THREAD_ID_T) ||          \
    defined(SIZE_T_32) ||                       \
    defined(SIZE_T_64)
#define WOLFSENTRY_USER_DEFINED_TYPES
#endif

/*! @} */

/*! \addtogroup wolfsentry_init
 *  @{
 */

/*! @cond doxygen_all */

enum wolfsentry_build_flags {
    WOLFSENTRY_CONFIG_FLAG_ENDIANNESS_ONE = (1U << 0U),
    WOLFSENTRY_CONFIG_FLAG_USER_DEFINED_TYPES = (1U << 1U),
    WOLFSENTRY_CONFIG_FLAG_THREADSAFE = (1U << 2U),
    WOLFSENTRY_CONFIG_FLAG_CLOCK_BUILTINS = (1U << 3U),
    WOLFSENTRY_CONFIG_FLAG_MALLOC_BUILTINS = (1U << 4U),
    WOLFSENTRY_CONFIG_FLAG_ERROR_STRINGS = (1U << 5U),
    WOLFSENTRY_CONFIG_FLAG_PROTOCOL_NAMES = (1U << 6U),
    WOLFSENTRY_CONFIG_FLAG_NO_STDIO_STREAMS = (1U << 7U),
    WOLFSENTRY_CONFIG_FLAG_NO_JSON = (1U << 8U),
    WOLFSENTRY_CONFIG_FLAG_HAVE_JSON_DOM = (1U << 9U),
    WOLFSENTRY_CONFIG_FLAG_DEBUG_CALL_TRACE = (1U << 10U),
    WOLFSENTRY_CONFIG_FLAG_LWIP = (1U << 11U),
    WOLFSENTRY_CONFIG_FLAG_SHORT_ENUMS = (1U << 12U),
    WOLFSENTRY_CONFIG_FLAG_ADDR_BITMASKS = (1U << 13U),
    WOLFSENTRY_CONFIG_FLAG_NETXDUO = (1U << 14U),
    WOLFSENTRY_CONFIG_FLAG_MAX = WOLFSENTRY_CONFIG_FLAG_NETXDUO,
    WOLFSENTRY_CONFIG_FLAG_ENDIANNESS_ZERO = (0U << 31U)
};

/*! @endcond */

/*! \brief struct for passing the build version and configuration */
struct wolfsentry_build_settings {
    uint32_t version;
        /*!< Must be initialized to #WOLFSENTRY_VERSION. */
    uint32_t config;
        /*!< Must be initialized to #WOLFSENTRY_CONFIG_SIGNATURE. */
};

#if !defined(BUILDING_LIBWOLFSENTRY) || defined(WOLFSENTRY_DEFINE_BUILD_SETTINGS)

/*! @cond doxygen_all */

#ifdef WOLFSENTRY_USER_DEFINED_TYPES
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_USER_DEFINED_TYPES WOLFSENTRY_CONFIG_FLAG_USER_DEFINED_TYPES
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_USER_DEFINED_TYPES 0
#endif

#ifdef WOLFSENTRY_THREADSAFE
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_THREADSAFE WOLFSENTRY_CONFIG_FLAG_THREADSAFE
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_THREADSAFE 0
#endif

#ifdef WOLFSENTRY_CLOCK_BUILTINS
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_CLOCK_BUILTINS WOLFSENTRY_CONFIG_FLAG_CLOCK_BUILTINS
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_CLOCK_BUILTINS 0
#endif

#ifdef WOLFSENTRY_MALLOC_BUILTINS
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_MALLOC_BUILTINS WOLFSENTRY_CONFIG_FLAG_MALLOC_BUILTINS
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_MALLOC_BUILTINS 0
#endif

#ifdef WOLFSENTRY_ERROR_STRINGS
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_ERROR_STRINGS WOLFSENTRY_CONFIG_FLAG_ERROR_STRINGS
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_ERROR_STRINGS 0
#endif

#ifdef WOLFSENTRY_PROTOCOL_NAMES
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_PROTOCOL_NAMES WOLFSENTRY_CONFIG_FLAG_PROTOCOL_NAMES
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_PROTOCOL_NAMES 0
#endif

#ifdef WOLFSENTRY_NO_STDIO_STREAMS
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_NO_STDIO_STREAMS WOLFSENTRY_CONFIG_FLAG_NO_STDIO_STREAMS
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_NO_STDIO_STREAMS 0
#endif

#ifdef WOLFSENTRY_NO_JSON
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_NO_JSON WOLFSENTRY_CONFIG_FLAG_NO_JSON
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_NO_JSON 0
#endif

#ifdef WOLFSENTRY_HAVE_JSON_DOM
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_HAVE_JSON_DOM WOLFSENTRY_CONFIG_FLAG_HAVE_JSON_DOM
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_HAVE_JSON_DOM 0
#endif

#ifdef WOLFSENTRY_DEBUG_CALL_TRACE
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_DEBUG_CALL_TRACE WOLFSENTRY_CONFIG_FLAG_DEBUG_CALL_TRACE
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_DEBUG_CALL_TRACE 0
#endif

#ifdef WOLFSENTRY_LWIP
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_LWIP WOLFSENTRY_CONFIG_FLAG_LWIP
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_LWIP 0
#endif

#ifdef WOLFSENTRY_NETXDUO
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_NETXDUO WOLFSENTRY_CONFIG_FLAG_NETXDUO
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_NETXDUO 0
#endif

/* with compilers that can't evaluate the below expression as a compile-time
 * constant, WOLFSENTRY_SHORT_ENUMS can be defined in user settings to 0 or
 * 1 to avoid the dependency.
 */
#ifdef WOLFSENTRY_SHORT_ENUMS
#if WOLFSENTRY_SHORT_ENUMS == 0
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_SHORT_ENUMS 0
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_SHORT_ENUMS WOLFSENTRY_CONFIG_FLAG_SHORT_ENUMS
#endif
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_SHORT_ENUMS ((sizeof(wolfsentry_init_flags_t) < sizeof(int)) ? WOLFSENTRY_CONFIG_FLAG_SHORT_ENUMS : 0)
#endif

#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_ADDR_BITMASKS WOLFSENTRY_CONFIG_FLAG_ADDR_BITMASKS
#else
    #define _WOLFSENTRY_CONFIG_FLAG_VALUE_ADDR_BITMASKS 0
#endif

/*! @endcond */

/*! \brief Macro to use as the initializer for ::wolfsentry_build_settings.config and ::wolfsentry_host_platform_interface.caller_build_settings.  @hideinitializer */
#define WOLFSENTRY_CONFIG_SIGNATURE ( \
    WOLFSENTRY_CONFIG_FLAG_ENDIANNESS_ONE | \
    _WOLFSENTRY_CONFIG_FLAG_VALUE_USER_DEFINED_TYPES | \
    _WOLFSENTRY_CONFIG_FLAG_VALUE_THREADSAFE | \
    _WOLFSENTRY_CONFIG_FLAG_VALUE_CLOCK_BUILTINS | \
    _WOLFSENTRY_CONFIG_FLAG_VALUE_MALLOC_BUILTINS | \
    _WOLFSENTRY_CONFIG_FLAG_VALUE_ERROR_STRINGS | \
    _WOLFSENTRY_CONFIG_FLAG_VALUE_PROTOCOL_NAMES | \
    _WOLFSENTRY_CONFIG_FLAG_VALUE_NO_STDIO_STREAMS | \
    _WOLFSENTRY_CONFIG_FLAG_VALUE_NO_JSON | \
    _WOLFSENTRY_CONFIG_FLAG_VALUE_HAVE_JSON_DOM | \
    _WOLFSENTRY_CONFIG_FLAG_VALUE_DEBUG_CALL_TRACE | \
    _WOLFSENTRY_CONFIG_FLAG_VALUE_LWIP | \
    _WOLFSENTRY_CONFIG_FLAG_VALUE_NETXDUO | \
    _WOLFSENTRY_CONFIG_FLAG_VALUE_SHORT_ENUMS | \
    _WOLFSENTRY_CONFIG_FLAG_VALUE_ADDR_BITMASKS)

static __attribute_maybe_unused__ struct wolfsentry_build_settings wolfsentry_build_settings = {
#ifdef WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
    .version =
#endif
    WOLFSENTRY_VERSION,
#ifdef WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
    .config =
#endif
    WOLFSENTRY_CONFIG_SIGNATURE
};
    /*!< \brief Convenience constant struct, with properly initialized `wolfsentry_build_settings` values, to be passed to wolfsentry_init().  @hideinitializer */

#endif /* !BUILDING_LIBWOLFSENTRY || WOLFSENTRY_DEFINE_BUILD_SETTINGS */

/*! @} */

#endif /* WOLFSENTRY_SETTINGS_H */
