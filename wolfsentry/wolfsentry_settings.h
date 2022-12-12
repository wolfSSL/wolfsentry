#ifndef WOLFSENTRY_SETTINGS_H
#define WOLFSENTRY_SETTINGS_H

#ifndef BUILDING_LIBWOLFSENTRY
#include <wolfsentry/wolfsentry_options.h>
#endif

#ifndef WOLFSENTRY_SINGLETHREADED

#define WOLFSENTRY_THREADSAFE

#if defined(__MACH__) || defined(FREERTOS) || defined(_WIN32)
#define WOLFSENTRY_USE_NONPOSIX_SEMAPHORES
#endif

#ifndef WOLFSENTRY_USE_NONPOSIX_SEMAPHORES
#define WOLFSENTRY_USE_NATIVE_POSIX_SEMAPHORES
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

typedef uint32_t enumint_t;

#ifndef __attribute_maybe_unused__
#if defined(__GNUC__)
#define __attribute_maybe_unused__ __attribute__((unused))
#else
#define __attribute_maybe_unused__
#endif
#endif

#if defined(WOLFSENTRY_THREADSAFE)
    #ifndef WOLFSENTRY_USE_NONPOSIX_SEMAPHORES
        #include <pthread.h>
    #elif defined(WOLFSENTRY_THREAD_INCLUDE)
        #include WOLFSENTRY_THREAD_INCLUDE
    #else
        #error Must supply WOLFSENTRY_THREAD_INCLUDE for WOLFSENTRY_THREADSAFE on non-POSIX targets.
    #endif
    #if !defined(WOLFSENTRY_THREAD_ID_T) && !defined(WOLFSENTRY_USE_NONPOSIX_SEMAPHORES)
        #define WOLFSENTRY_THREAD_ID_T pthread_t
    #endif
    #ifdef WOLFSENTRY_THREAD_ID_T
        typedef WOLFSENTRY_THREAD_ID_T wolfsentry_thread_id_t;
    #else
        #error Must supply WOLFSENTRY_THREAD_ID_T for WOLFSENTRY_THREADSAFE on non-POSIX targets.
    #endif
    #ifndef WOLFSENTRY_THREAD_NO_ID
        #define WOLFSENTRY_THREAD_NO_ID 0
    #endif
    #if !defined(WOLFSENTRY_THREAD_GET_ID)
        #if !defined(WOLFSENTRY_USE_NONPOSIX_SEMAPHORES)
            #define WOLFSENTRY_THREAD_GET_ID pthread_self()
        #else
            #error Must supply WOLFSENTRY_THREAD_GET_ID for WOLFSENTRY_THREADSAFE on non-POSIX targets.
        #endif
    #endif

    struct wolfsentry_thread_context;

    struct wolfsentry_thread_context_public {
        void *opaque[9];
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

#define WOLFSENTRY_CONFIG_VERSION_OFFSET 32UL
#define WOLFSENTRY_CONFIG_FLAG_USER_DEFINED_TYPES (1U << 0U)
#define WOLFSENTRY_CONFIG_FLAG_THREADSAFE (1U << 1U)
#define WOLFSENTRY_CONFIG_FLAG_CLOCK_BUILTINS (1U << 2U)
#define WOLFSENTRY_CONFIG_FLAG_MALLOC_BUILTINS (1U << 3U)
#define WOLFSENTRY_CONFIG_FLAG_ERROR_STRINGS (1U << 4U)
#define WOLFSENTRY_CONFIG_FLAG_PROTOCOL_NAMES (1U << 5U)
#define WOLFSENTRY_CONFIG_FLAG_NO_STDIO (1U << 6U)
#define WOLFSENTRY_CONFIG_FLAG_NO_JSON (1U << 7U)
#define WOLFSENTRY_CONFIG_FLAG_HAVE_JSON_DOM (1U << 8U)
#define WOLFSENTRY_CONFIG_FLAG_DEBUG_CALL_TRACE (1U << 9U)
#define WOLFSENTRY_CONFIG_FLAG_MAX WOLFSENTRY_CONFIG_FLAG_DEBUG_CALL_TRACE

#if !defined(BUILDING_LIBWOLFSENTRY) || defined(DEFINE_WOLFSENTRY_BUILD_SETTINGS)
static __attribute_maybe_unused__ uint64_t wolfsentry_build_settings =
    ((uint64_t)WOLFSENTRY_VERSION << WOLFSENTRY_CONFIG_VERSION_OFFSET)
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
    ;

#endif /* !BUILDING_LIBWOLFSENTRY || DEFINE_WOLFSENTRY_BUILD_SETTINGS */

#endif /* WOLFSENTRY_SETTINGS_H */
