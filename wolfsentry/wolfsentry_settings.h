/*
 * wolfsentry_settings.h
 *
 * Copyright (C) 2022-2023 wolfSSL Inc.
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

#ifndef WOLFSENTRY_SETTINGS_H
#define WOLFSENTRY_SETTINGS_H

#ifdef WOLFSENTRY_USER_SETTINGS_FILE
#include WOLFSENTRY_USER_SETTINGS_FILE
#endif

#ifndef BUILDING_LIBWOLFSENTRY
#include <wolfsentry/wolfsentry_options.h>
#endif

#ifdef FREERTOS
    #include <FreeRTOS.h>
    #define WOLFSENTRY_CALL_DEPTH_RETURNS_STRING
    #if !defined(WOLFSENTRY_NO_STDIO) && !defined(WOLFSENTRY_PRINTF_ERR)
        #define WOLFSENTRY_PRINTF_ERR(...) printf(__VA_ARGS__)
    #endif

#ifdef WOLFSENTRY_LWIP
    #include <time.h>
    #include <lwip/inet.h>
    #include <lwip/sockets.h>
#endif

#endif

#if !defined(WOLFSENTRY_NO_STDIO) && !defined(WOLFSENTRY_PRINTF_ERR)
    #define WOLFSENTRY_PRINTF_ERR(...) fprintf(stderr, __VA_ARGS__)
#endif

#ifndef WOLFSENTRY_SINGLETHREADED

#define WOLFSENTRY_THREADSAFE

#if defined(__MACH__)
    #define WOLFSENTRY_USE_NONPOSIX_SEMAPHORES
#elif defined(FREERTOS)
    #define WOLFSENTRY_USE_NONPOSIX_SEMAPHORES
    #define WOLFSENTRY_USE_NONPOSIX_THREADS
#elif defined(_WIN32)
    #define WOLFSENTRY_USE_NONPOSIX_SEMAPHORES
    #define WOLFSENTRY_USE_NONPOSIX_THREADS
#endif

#ifndef WOLFSENTRY_USE_NONPOSIX_SEMAPHORES
    #define WOLFSENTRY_USE_NATIVE_POSIX_SEMAPHORES
#endif

#ifndef WOLFSENTRY_USE_NONPOSIX_THREADS
    #define WOLFSENTRY_USE_NATIVE_POSIX_THREADS
#endif

#ifndef WOLFSENTRY_HAVE_NONGNU_ATOMICS
    #define WOLFSENTRY_HAVE_GNU_ATOMICS
#endif

#endif /* !WOLFSENTRY_SINGLETHREADED */

#ifndef WOLFSENTRY_NO_CLOCK_BUILTIN
    #define WOLFSENTRY_CLOCK_BUILTINS
#endif

#ifndef WOLFSENTRY_NO_MALLOC_BUILTIN
    #define WOLFSENTRY_MALLOC_BUILTINS
#endif

#ifndef WOLFSENTRY_NO_ERROR_STRINGS
    #define WOLFSENTRY_ERROR_STRINGS
#endif

#ifndef WOLFSENTRY_NO_PROTOCOL_NAMES
    #define WOLFSENTRY_PROTOCOL_NAMES
#endif

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

#if defined(__STRICT_ANSI__)
#define WOLFSENTRY_FLEXIBLE_ARRAY_SIZE 1
#elif defined(__GNUC__) && !defined(__clang__)
#define WOLFSENTRY_FLEXIBLE_ARRAY_SIZE
#else
#define WOLFSENTRY_FLEXIBLE_ARRAY_SIZE 0
#endif

#ifndef WOLFSENTRY_NO_TIME_H
#ifndef __USE_POSIX199309
/* glibc needs this for struct timespec with -std=c99 */
#define __USE_POSIX199309
#endif
#endif

#ifdef FREERTOS
/* size_t is alias to "unsigned int" in STM32 FreeRTOS */
#define SIZET_FMT "%d"
#else
#define SIZET_FMT "%zd"
#endif

#ifndef WOLFSENTRY_NO_INTTYPES_H
#include <inttypes.h>
#endif
#ifndef WOLFSENTRY_NO_STDINT_H
#include <stdint.h>
#endif
#ifndef WOLFSENTRY_NO_STDDEF_H
#include <stddef.h>
#endif
#ifndef WOLFSENTRY_NO_ASSERT_H
#include <assert.h>
#endif
#ifndef WOLFSENTRY_NO_STDIO
#include <stdio.h>
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

typedef uint16_t wolfsentry_addr_family_t;
#include <wolfsentry/wolfsentry_af.h>

typedef uint16_t wolfsentry_proto_t;
typedef uint16_t wolfsentry_port_t;
#ifdef WOLFSENTRY_ENT_ID_TYPE
typedef WOLFSENTRY_ENT_ID_TYPE wolfsentry_ent_id_t;
#else
typedef uint32_t wolfsentry_ent_id_t;
#define WOLFSENTRY_ENT_ID_FMT "%u"
#endif
#define WOLFSENTRY_ENT_ID_NONE 0
typedef uint16_t wolfsentry_addr_bits_t;
#ifdef WOLFSENTRY_HITCOUNT_TYPE
typedef WOLFSENTRY_HITCOUNT_TYPE wolfsentry_hitcount_t;
#else
typedef uint32_t wolfsentry_hitcount_t;
#define WOLFSENTRY_HITCOUNT_FMT "%u"
#endif
#ifdef WOLFSENTRY_TIME_TYPE
typedef WOLFSENTRY_TIME_TYPE wolfsentry_time_t;
#else
typedef int64_t wolfsentry_time_t;
#endif

#ifdef WOLFSENTRY_PRIORITY_TYPE
typedef WOLFSENTRY_PRIORITY_TYPE wolfsentry_priority_t;
#else
typedef uint16_t wolfsentry_priority_t;
#endif

#ifndef __attribute_maybe_unused__
#if defined(__GNUC__)
#define __attribute_maybe_unused__ __attribute__((unused))
#else
#define __attribute_maybe_unused__
#endif
#endif

#ifndef wolfsentry_static_assert
#if defined(__GNUC__) && defined(static_assert) && !defined(__STRICT_ANSI__)
#define wolfsentry_static_assert(c, m) static_assert(c, m)
#else
#define wolfsentry_static_assert(c, m) do {} while ()
#endif
#endif /* !wolfsentry_static_assert */

#if defined(WOLFSENTRY_THREADSAFE)

#ifdef WOLFSENTRY_USE_NATIVE_POSIX_SEMAPHORES

#include <semaphore.h>

#elif defined(__MACH__)

#include <dispatch/dispatch.h>
#include <semaphore.h>
#define sem_t dispatch_semaphore_t

#elif defined(FREERTOS)

#include <semphr.h>
#include <atomic.h>

#define SEM_VALUE_MAX        0x7FFFU

#define sem_t StaticSemaphore_t

#else

#error semaphore shim set missing for target

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
    #else
        #error Must supply WOLFSENTRY_THREAD_ID_T for WOLFSENTRY_THREADSAFE on non-POSIX targets.
    #endif
    /* note WOLFSENTRY_THREAD_NO_ID needs to be the value returned by a failed call
     * to WOLFSENTRY_THREAD_GET_ID_HANDLER.
     */
    #ifdef WOLFSENTRY_THREAD_NO_ID
    #elif defined(WOLFSENTRY_USE_NATIVE_POSIX_THREADS)
        #define WOLFSENTRY_THREAD_NO_ID 0
    #elif defined(FREERTOS)
        /* xTaskGetCurrentTaskHandle() returns NULL if no tasks have been created,
         * and if that happens, we want wolfsentry_init_thread_context() to assign
         * an internally generated ID.
         */
        #define WOLFSENTRY_THREAD_NO_ID ((TaskHandle_t)0)
    #else
        #error Must supply WOLFSENTRY_THREAD_NO_ID for WOLFSENTRY_THREADSAFE on non-POSIX targets.
    #endif
    #ifdef WOLFSENTRY_THREAD_GET_ID_HANDLER
    #elif defined(WOLFSENTRY_USE_NATIVE_POSIX_THREADS)
       #define WOLFSENTRY_THREAD_GET_ID_HANDLER pthread_self
    #elif defined(FREERTOS)
       #define WOLFSENTRY_THREAD_GET_ID_HANDLER xTaskGetCurrentTaskHandle
    #else
        #error Must supply WOLFSENTRY_THREAD_GET_ID_HANDLER for WOLFSENTRY_THREADSAFE on non-POSIX targets.
    #endif

    struct wolfsentry_thread_context;

    struct wolfsentry_thread_context_public {
        uint64_t opaque[9];
    };
#endif

#ifdef BUILDING_LIBWOLFSENTRY
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__) || \
        defined(_WIN32_WCE)
        #if defined(WOLFSENTRY_DLL)
            #define WOLFSENTRY_API __declspec(dllexport)
        #else
            #define WOLFSENTRY_API
        #endif
        #define WOLFSENTRY_LOCAL
    #elif defined(HAVE_VISIBILITY) && HAVE_VISIBILITY
        #define WOLFSENTRY_API   __attribute__ ((visibility("default")))
        #define WOLFSENTRY_LOCAL __attribute__ ((visibility("hidden")))
    #elif defined(__SUNPRO_C) && (__SUNPRO_C >= 0x550)
        #define WOLFSENTRY_API   __global
        #define WOLFSENTRY_LOCAL __hidden
    #else
        #define WOLFSENTRY_API
        #define WOLFSENTRY_LOCAL
    #endif /* HAVE_VISIBILITY */
#else /* !BUILDING_LIBWOLFSENTRY */
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__) || \
        defined(_WIN32_WCE)
        #if defined(WOLFSENTRY_DLL)
            #define WOLFSENTRY_API __declspec(dllimport)
        #else
            #define WOLFSENTRY_API
        #endif
        #define WOLFSENTRY_LOCAL
    #else
        #define WOLFSENTRY_API
        #define WOLFSENTRY_LOCAL
    #endif
#endif /* !BUILDING_LIBWOLFSENTRY */

#ifdef WOLFSENTRY_NO_INLINE
#define inline __attribute_maybe_unused__
#endif

#ifndef WOLFSENTRY_MAX_ADDR_BYTES
#define WOLFSENTRY_MAX_ADDR_BYTES 16
#elif WOLFSENTRY_MAX_ADDR_BYTES * 8 > 0xffff
#error WOLFSENTRY_MAX_ADDR_BYTES * 8 must fit in a uint16_t.
#endif

#ifndef WOLFSENTRY_MAX_ADDR_BITS
#define WOLFSENTRY_MAX_ADDR_BITS (WOLFSENTRY_MAX_ADDR_BYTES*8)
#else
#if WOLFSENTRY_MAX_ADDR_BITS > (WOLFSENTRY_MAX_ADDR_BYTES*8)
#error WOLFSENTRY_MAX_ADDR_BITS is too large for given/default WOLFSENTRY_MAX_ADDR_BYTES
#endif
#endif

#ifndef WOLFSENTRY_MAX_LABEL_BYTES
#define WOLFSENTRY_MAX_LABEL_BYTES 32
#elif WOLFSENTRY_MAX_LABEL_BYTES > 0xff
#error WOLFSENTRY_MAX_LABEL_BYTES must fit in a byte.
#endif

#ifndef WOLFSENTRY_KV_MAX_VALUE_BYTES
#define WOLFSENTRY_KV_MAX_VALUE_BYTES 16384
#endif

#if defined(WOLFSENTRY_ENT_ID_TYPE) || \
    defined(WOLFSENTRY_HITCOUNT_TYPE) || \
    defined(WOLFSENTRY_TIME_TYPE) || \
    defined(WOLFSENTRY_PRIORITY_TYPE)
#define WOLFSENTRY_USER_DEFINED_TYPES
#endif

enum wolfsentry_build_flags {
    WOLFSENTRY_CONFIG_FLAG_ENDIANNESS_ONE = (1U << 0U),
    WOLFSENTRY_CONFIG_FLAG_USER_DEFINED_TYPES = (1U << 1U),
    WOLFSENTRY_CONFIG_FLAG_THREADSAFE = (1U << 2U),
    WOLFSENTRY_CONFIG_FLAG_CLOCK_BUILTINS = (1U << 3U),
    WOLFSENTRY_CONFIG_FLAG_MALLOC_BUILTINS = (1U << 4U),
    WOLFSENTRY_CONFIG_FLAG_ERROR_STRINGS = (1U << 5U),
    WOLFSENTRY_CONFIG_FLAG_PROTOCOL_NAMES = (1U << 6U),
    WOLFSENTRY_CONFIG_FLAG_NO_STDIO = (1U << 7U),
    WOLFSENTRY_CONFIG_FLAG_NO_JSON = (1U << 8U),
    WOLFSENTRY_CONFIG_FLAG_HAVE_JSON_DOM = (1U << 9U),
    WOLFSENTRY_CONFIG_FLAG_DEBUG_CALL_TRACE = (1U << 10U),
    WOLFSENTRY_CONFIG_FLAG_MAX = (1U << 10U),
    WOLFSENTRY_CONFIG_FLAG_ENDIANNESS_ZERO = (0U << 31U)
};

struct wolfsentry_build_settings {
    uint32_t version;
    uint32_t config;
};

#if !defined(BUILDING_LIBWOLFSENTRY) || defined(DEFINE_WOLFSENTRY_BUILD_SETTINGS)
static __attribute_maybe_unused__ struct wolfsentry_build_settings wolfsentry_build_settings = {
    .version = WOLFSENTRY_VERSION,
    .config = WOLFSENTRY_CONFIG_FLAG_ENDIANNESS_ONE
#ifdef WOLFSENTRY_USER_DEFINED_TYPES
    | WOLFSENTRY_CONFIG_FLAG_USER_DEFINED_TYPES
#endif
#ifdef WOLFSENTRY_THREADSAFE
    | WOLFSENTRY_CONFIG_FLAG_THREADSAFE
#endif
#ifdef WOLFSENTRY_CLOCK_BUILTINS
    | WOLFSENTRY_CONFIG_FLAG_CLOCK_BUILTINS
#endif
#ifdef WOLFSENTRY_MALLOC_BUILTINS
    | WOLFSENTRY_CONFIG_FLAG_MALLOC_BUILTINS
#endif
#ifdef WOLFSENTRY_ERROR_STRINGS
    | WOLFSENTRY_CONFIG_FLAG_ERROR_STRINGS
#endif
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    | WOLFSENTRY_CONFIG_FLAG_PROTOCOL_NAMES
#endif
#ifdef WOLFSENTRY_NO_STDIO
    | WOLFSENTRY_CONFIG_FLAG_NO_STDIO
#endif
#ifdef WOLFSENTRY_NO_JSON
    | WOLFSENTRY_CONFIG_FLAG_NO_JSON
#endif
#ifdef WOLFSENTRY_HAVE_JSON_DOM
    | WOLFSENTRY_CONFIG_FLAG_HAVE_JSON_DOM
#endif
#ifdef WOLFSENTRY_DEBUG_CALL_TRACE
    | WOLFSENTRY_CONFIG_FLAG_DEBUG_CALL_TRACE
#endif
};

#endif /* !BUILDING_LIBWOLFSENTRY || DEFINE_WOLFSENTRY_BUILD_SETTINGS */

#endif /* WOLFSENTRY_SETTINGS_H */
