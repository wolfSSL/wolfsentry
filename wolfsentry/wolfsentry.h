/*
 * wolfsentry.h
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

/*! @file wolfsentry.h
    \brief The main include file for wolfSentry applications.

    Include this file in your application for core wolfSentry capabilities.
 */

#ifndef WOLFSENTRY_H
#define WOLFSENTRY_H

/*!
 * \defgroup core_types Core Types and Macros
 * \defgroup wolfsentry_init Startup/Configuration/Shutdown Subsystem
 * \defgroup wolfsentry_errcode_t Diagnostics, Control Flow Helpers, and Compiler Attribute Helpers
 * \defgroup wolfsentry_route Route/Rule Subsystem
 * \defgroup wolfsentry_action Action Subsystem
 * \defgroup wolfsentry_event Event Subsystem
 * \defgroup wolfsentry_addr_family Address Family Subsystem
 * \defgroup wolfsentry_kv User-Defined Value Subsystem
 * \defgroup wolfsentry_table_ent_header Object Subsystem
 * \defgroup wolfsentry_thread_context Thread Synchronization Subsystem
 * \defgroup wolfsentry_allocator Allocator (Heap) Functions and Callbacks
 * \defgroup wolfsentry_timecbs Time Functions and Callbacks
 * \defgroup wolfsentry_semcbs Semaphore Function Callbacks
 * \defgroup wolfsentry_lwip lwIP Callback Activation Functions
 */

/*! \addtogroup wolfsentry_init
 * @{
 */

#define WOLFSENTRY_VERSION_MAJOR 1
    /*!< \brief Macro for major version number of installed headers.  @hideinitializer */
#define WOLFSENTRY_VERSION_MINOR 6
    /*!< \brief Macro for minor version number of installed headers.  @hideinitializer */
#define WOLFSENTRY_VERSION_TINY 2
    /*!< \brief Macro for tiny version number of installed headers.  @hideinitializer */
#define WOLFSENTRY_VERSION_ENCODE(major, minor, tiny) (((major) << 16U) | ((minor) << 8U) | (tiny))
    /*!< \brief Macro to convert a wolfSentry version to a single integer, for comparison to other similarly converted versions.  @hideinitializer */
#define WOLFSENTRY_VERSION WOLFSENTRY_VERSION_ENCODE(WOLFSENTRY_VERSION_MAJOR, WOLFSENTRY_VERSION_MINOR, WOLFSENTRY_VERSION_TINY)
    /*!< \brief The version recorded in wolfsentry.h, encoded as an integer @hideinitializer */
#define WOLFSENTRY_VERSION_GT(major, minor, tiny) (WOLFSENTRY_VERSION > WOLFSENTRY_VERSION_ENCODE(major, minor, tiny))
    /*!< \brief Helper macro that is true if the given version is greater than that in wolfsentry.h. @hideinitializer */
#define WOLFSENTRY_VERSION_GE(major, minor, tiny) (WOLFSENTRY_VERSION >= WOLFSENTRY_VERSION_ENCODE(major, minor, tiny))
    /*!< \brief Helper macro that is true if the given version is greater than or equal to that in wolfsentry.h. @hideinitializer */
#define WOLFSENTRY_VERSION_EQ(major, minor, tiny) (WOLFSENTRY_VERSION == WOLFSENTRY_VERSION_ENCODE(major, minor, tiny))
    /*!< \brief Helper macro that is true if the given version equals that in wolfsentry.h. @hideinitializer */
#define WOLFSENTRY_VERSION_LT(major, minor, tiny) (WOLFSENTRY_VERSION < WOLFSENTRY_VERSION_ENCODE(major, minor, tiny))
    /*!< \brief Helper macro that is true if the given version is less than that in wolfsentry.h. @hideinitializer */
#define WOLFSENTRY_VERSION_LE(major, minor, tiny) (WOLFSENTRY_VERSION <= WOLFSENTRY_VERSION_ENCODE(major, minor, tiny))
    /*!< \brief Helper macro that is true if the given version is less than or equal to that in wolfsentry.h. @hideinitializer */

/*! \brief flags to pass to wolfsentry_init_ex(), to be `OR`d together. */
typedef enum {
    WOLFSENTRY_INIT_FLAG_NONE = 0, /*!< \brief Default behavior @hideinitializer */
    WOLFSENTRY_INIT_FLAG_LOCK_SHARED_ERROR_CHECKING = 1<<0 /*!< \brief Enables supplementary error checking on shared lock usage (not currently implemented) @hideinitializer */
} wolfsentry_init_flags_t;

/*! @} */

#ifndef WOLFSENTRY
/*! @cond doxygen_all */
#define WOLFSENTRY /* activate wolfSentry codepaths in CentiJSON headers */
/*! @endcond */
#endif

#include <wolfsentry/wolfsentry_settings.h>
#include <wolfsentry/wolfsentry_af.h>
#include <wolfsentry/wolfsentry_errcodes.h>

struct wolfsentry_allocator;
struct wolfsentry_context;
struct wolfsentry_thread_context;

/*! \addtogroup wolfsentry_allocator
 *  @{
 */

#ifdef WOLFSENTRY_THREADSAFE

typedef void *(*wolfsentry_malloc_cb_t)(void *context, struct wolfsentry_thread_context *thread, size_t size);
   /*!< \brief Pointer to malloc-like function. Takes extra initial args `context` and, if `!defined(WOLFSENTRY_SINGLETHREADED)`, `thread` arg. */
typedef void (*wolfsentry_free_cb_t)(void *context, struct wolfsentry_thread_context *thread, void *ptr);
   /*!< \brief Pointer to free-like function.
    * Takes extra initial args `context` and, if `!defined(WOLFSENTRY_SINGLETHREADED)`, `thread` arg.
    */
typedef void *(*wolfsentry_realloc_cb_t)(void *context, struct wolfsentry_thread_context *thread, void *ptr, size_t size);
   /*!< \brief Pointer to realloc-like function.
    * Takes extra initial args `context` and, if `!defined(WOLFSENTRY_SINGLETHREADED)`, `thread` arg.
    */
typedef void *(*wolfsentry_memalign_cb_t)(void *context, struct wolfsentry_thread_context *thread, size_t alignment, size_t size);
   /*!< \brief Pointer to memalign-like function.
    * Takes extra initial args `context` and, if `!defined(WOLFSENTRY_SINGLETHREADED)`, `thread` arg.
    */
typedef void (*wolfsentry_free_aligned_cb_t)(void *context, struct wolfsentry_thread_context *thread, void *ptr);
   /*!< \brief Pointer to special-purpose free-like function, needed only if the `memalign` pointer in a `struct wolfsentry_allocator` is non-null.
    * Can be same as routine supplied as `wolfsentry_free_cb_t`, or can be a separate routine, e.g. with special handling for pad bytes.
    * Takes extra initial args `context` and, if `!defined(WOLFSENTRY_SINGLETHREADED)`, `thread` arg.
    */

#else /* !WOLFSENTRY_THREADSAFE */

typedef void *(*wolfsentry_malloc_cb_t)(void *context, size_t size);
typedef void (*wolfsentry_free_cb_t)(void *context, void *ptr);
typedef void *(*wolfsentry_realloc_cb_t)(void *context, void *ptr, size_t size);
typedef void *(*wolfsentry_memalign_cb_t)(void *context, size_t alignment, size_t size);
typedef void (*wolfsentry_free_aligned_cb_t)(void *context, void *ptr);

#endif /* WOLFSENTRY_THREADSAFE */

/*! \brief Struct for passing shims that abstract the native implementation of the heap allocator */
struct wolfsentry_allocator {
    void *context;
        /*!< \brief A user-supplied opaque handle to be passed as the first arg to all callbacks.  Can be null. */
    wolfsentry_malloc_cb_t malloc;
        /*!< \brief Required pointer. */
    wolfsentry_free_cb_t free;
        /*!< \brief Required pointer. */
    wolfsentry_realloc_cb_t realloc;
        /*!< \brief Required pointer. */
    wolfsentry_memalign_cb_t memalign;
        /*!< \brief Optional pointer.
         * Required only if a `struct wolfsentry_eventconfig` is passed in (e.g. to wolfsentry_init()`) with a nonzero `route_private_data_alignment`.
         */
    wolfsentry_free_aligned_cb_t free_aligned;
        /*!< \brief Optional pointer.  Required (and allowed) only if `memalign` pointer is non-null. */
};

/*! @} */

/*! \addtogroup wolfsentry_timecbs
 *  @{
 */

typedef wolfsentry_errcode_t (*wolfsentry_get_time_cb_t)(void *context, wolfsentry_time_t *ts);
   /*!< \brief Pointer to function that returns time denominated in `wolfsentry_time_t`.  Takes an initial `context` arg, which can be ignored.
    */
typedef wolfsentry_time_t (*wolfsentry_diff_time_cb_t)(wolfsentry_time_t earlier, wolfsentry_time_t later);
   /*!< \brief Pointer to function that subtracts `earlier` from `later`, returning the result. */
typedef wolfsentry_time_t (*wolfsentry_add_time_cb_t)(wolfsentry_time_t start_time, wolfsentry_time_t time_interval);
   /*!< \brief Pointer to function that adds two `wolfsentry_time_t` times, returning the result. */
typedef wolfsentry_errcode_t (*wolfsentry_to_epoch_time_cb_t)(wolfsentry_time_t when, time_t *epoch_secs, long *epoch_nsecs);
   /*!< \brief Pointer to function that converts a `wolfsentry_time_t` to seconds and nanoseconds since midnight UTC, 1970-Jan-1. */
typedef wolfsentry_errcode_t (*wolfsentry_from_epoch_time_cb_t)(time_t epoch_secs, long epoch_nsecs, wolfsentry_time_t *when);
   /*!< \brief Pointer to function that converts seconds and nanoseconds since midnight UTC, 1970-Jan-1, to a `wolfsentry_time_t`. */
typedef wolfsentry_errcode_t (*wolfsentry_interval_to_seconds_cb_t)(wolfsentry_time_t howlong, time_t *howlong_secs, long *howlong_nsecs);
   /*!< \brief Pointer to function that converts a `wolfsentry_time_t` expressing an interval to the corresponding seconds and nanoseconds. */
typedef wolfsentry_errcode_t (*wolfsentry_interval_from_seconds_cb_t)(time_t howlong_secs, long howlong_nsecs, wolfsentry_time_t *howlong);
   /*!< \brief Pointer to function that converts seconds and nanoseconds expressing an interval to the corresponding `wolfsentry_time_t`. */

/*! \brief Struct for passing shims that abstract the native implementation of time functions */
struct wolfsentry_timecbs {
    void *context;
        /*!< \brief A user-supplied opaque handle to be passed as the first arg to the `get_time` callback.  Can be null. */
    wolfsentry_get_time_cb_t get_time;
        /*!< \brief Required pointer. */
    wolfsentry_diff_time_cb_t diff_time;
        /*!< \brief Required pointer. */
    wolfsentry_add_time_cb_t add_time;
        /*!< \brief Required pointer. */
    wolfsentry_to_epoch_time_cb_t to_epoch_time;
        /*!< \brief Required pointer. */
    wolfsentry_from_epoch_time_cb_t from_epoch_time;
        /*!< \brief Required pointer. */
    wolfsentry_interval_to_seconds_cb_t interval_to_seconds;
        /*!< \brief Required pointer. */
    wolfsentry_interval_from_seconds_cb_t interval_from_seconds;
        /*!< \brief Required pointer. */
};

/*! @} */

#ifdef WOLFSENTRY_THREADSAFE

/*! \addtogroup wolfsentry_semcbs
 *  @{
 */

typedef int (*sem_init_cb_t)(sem_t *sem, int pshared, unsigned int value);
   /*!< Pointer to function with arguments and semantics of POSIX `sem_init()`.  Currently, `pshared` and `value` are always zero as called by wolfSentry, so implementations can ignore them. */
typedef int (*sem_post_cb_t)(sem_t *sem);
   /*!< Pointer to function with arguments and semantics of POSIX `sem_post()` */
typedef int (*sem_wait_cb_t)(sem_t *sem);
   /*!< Pointer to function with arguments and semantics of POSIX `sem_wait()` */
typedef int (*sem_timedwait_cb_t)(sem_t *sem, const struct timespec *abs_timeout);
   /*!< Pointer to function with arguments and semantics of POSIX `sem_timedwait()` */
typedef int (*sem_trywait_cb_t)(sem_t *sem);
   /*!< Pointer to function with arguments and semantics of POSIX `sem_trywait()` */
typedef int (*sem_destroy_cb_t)(sem_t *sem);
   /*!< Pointer to function with arguments and semantics of POSIX `sem_destroy()` */

/*! \brief Struct for passing shims that abstract the native implementation of counting semaphores */
struct wolfsentry_semcbs {
    sem_init_cb_t sem_init;
        /*!< \brief Required pointer. */
    sem_post_cb_t sem_post;
        /*!< \brief Required pointer. */
    sem_wait_cb_t sem_wait;
        /*!< \brief Required pointer. */
    sem_timedwait_cb_t sem_timedwait;
        /*!< \brief Required pointer. */
    sem_trywait_cb_t sem_trywait;
        /*!< \brief Required pointer. */
    sem_destroy_cb_t sem_destroy;
        /*!< \brief Required pointer. */
};

/*! @} */

#endif /* WOLFSENTRY_THREADSAFE */

/*! \addtogroup wolfsentry_init
 * @{
 */

/*! \brief struct for passing shims that abstract native implementations of the heap allocator, time functions, and semaphores */
struct wolfsentry_host_platform_interface {
    struct wolfsentry_build_settings caller_build_settings;
        /*!< Must be initialized as described for `wolfsentry_build_settings`. */ /* must be first */
    struct wolfsentry_allocator allocator;
        /*!< Either all-null, or initialized as described for `wolfsentry_allocator`. */
    struct wolfsentry_timecbs timecbs;
        /*!< Either all-null, or initialized as described for `wolfsentry_timecbs`. */
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_semcbs semcbs;
        /*!< Either all-null, or initialized as described for `wolfsentry_semcbs`. */
#endif
};

WOLFSENTRY_API struct wolfsentry_build_settings wolfsentry_get_build_settings(void);
    /*!< \brief Return the `wolfsentry_build_settings` of the library as built. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_build_settings_compatible(struct wolfsentry_build_settings caller_build_settings);
    /*!< \brief Return success if the application and library were built with mutually compatible wolfSentry version and configuration. */

/*! @} */

#ifdef WOLFSENTRY_THREADSAFE

/*! \addtogroup wolfsentry_thread_context
 *  @{
 */

/*! \brief `wolfsentry_thread_flags_t` flags are to be `OR`ed together. */
typedef enum {
    WOLFSENTRY_THREAD_FLAG_NONE = 0,
        /*!< \brief Default and normal thread state. @hideinitializer */
    WOLFSENTRY_THREAD_FLAG_DEADLINE = 1<<0,
        /*!< \brief This thread currently has a deadline associated with it, and will not wait for a lock beyond that deadline. @hideinitializer */
    WOLFSENTRY_THREAD_FLAG_READONLY = 1<<1
        /*!< \brief This thread can only get and hold shared locks. @hideinitializer */
} wolfsentry_thread_flags_t;

#define WOLFSENTRY_CONTEXT_ARGS_IN struct wolfsentry_context *wolfsentry, struct wolfsentry_thread_context *thread
    /*!< \brief Common context argument generator for use at the beginning of arg lists in function prototypes and definitions.  Pair with `WOLFSENTRY_CONTEXT_ARGS_OUT` in the caller argument list.  @hideinitializer */
#define WOLFSENTRY_CONTEXT_ARGS_IN_EX(ctx) ctx, struct wolfsentry_thread_context *thread
    /*!< \brief Variant of `WOLFSENTRY_CONTEXT_ARGS_IN` that allows a fully type-qualified `context`
     *   to be supplied explicitly (allowing contexts other than `struct wolfsentry_context`)
     *   @hideinitializer
     */
#define WOLFSENTRY_CONTEXT_ARGS_IN_EX4(ctx, thr) struct wolfsentry_context *ctx, struct wolfsentry_thread_context *thr
    /*!< \brief Variant of `WOLFSENTRY_CONTEXT_ARGS_IN` that allows the identifiers for `context` and `thread` pointers to be supplied explicitly @hideinitializer */
#define WOLFSENTRY_CONTEXT_ELEMENTS struct wolfsentry_context *wolfsentry; struct wolfsentry_thread_context *thread
    /*!< \brief Variant of `WOLFSENTRY_CONTEXT_ARGS_IN` for constructing `struct`s @hideinitializer */
#define WOLFSENTRY_CONTEXT_SET_ELEMENTS(s) (s).wolfsentry = wolfsentry; (s).thread = thread
    /*!< \brief Counterpart to `WOLFSENTRY_CONTEXT_ELEMENTS` to access the `wolfsentry` context @hideinitializer */
#define WOLFSENTRY_CONTEXT_GET_ELEMENTS(s) (s).wolfsentry, (s).thread
    /*!< \brief Counterpart to `WOLFSENTRY_CONTEXT_ELEMENTS` to access the `thread` context (exists only if `defined(WOLFSENTRY_THREADSAFE)`) @hideinitializer */
#define WOLFSENTRY_CONTEXT_ARGS_OUT wolfsentry, thread
    /*!< \brief Common context argument generator to use in calls to functions taking `WOLFSENTRY_CONTEXT_ARGS_IN` @hideinitializer */
#define WOLFSENTRY_CONTEXT_ARGS_OUT_EX(ctx) ctx, thread
    /*!< \brief Variant of `WOLFSENTRY_CONTEXT_ARGS_OUT` that allows passing an explicitly identified context argument generator to use in calls to functions taking `WOLFSENTRY_CONTEXT_ARGS_IN_EX` @hideinitializer */
#define WOLFSENTRY_CONTEXT_ARGS_OUT_EX2(x) (x)->wolfsentry, (x)->thread
    /*!< \brief Variant of `WOLFSENTRY_CONTEXT_ARGS_OUT` corresponding to `WOLFSENTRY_CONTEXT_ELEMENTS` @hideinitializer */
#define WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(x, y) (x)->y, (x)->thread
    /*!< \brief Special-purpose variant of `WOLFSENTRY_CONTEXT_ARGS_OUT_EX` for accessing context element `y` in structure pointer `x` @hideinitializer */
#define WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(x, y) x, y
    /*!< \brief Special-purpose variant of `WOLFSENTRY_CONTEXT_ARGS_OUT` that simply expands to `x` or `x, y` depending on `WOLFSENTRY_THREADSAFE` @hideinitializer */
#define WOLFSENTRY_CONTEXT_ARGS_NOT_USED (void)wolfsentry; (void)thread
    /*!< \brief Helper macro for function implementations that need to accept `WOLFSENTRY_CONTEXT_ARGS_IN` for API conformance, but don't actually use the arguments. @hideinitializer */
#define WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED (void)thread
    /*!< \brief Helper macro for function implementations that need to accept `WOLFSENTRY_CONTEXT_ARGS_IN` for API conformance, but don't actually use the `thread` argument. @hideinitializer */

/* note WOLFSENTRY_THREAD_HEADER_DECLS includes final semicolon. */
#define WOLFSENTRY_THREAD_HEADER_DECLS                                  \
    struct wolfsentry_thread_context_public thread_buffer =             \
        WOLFSENTRY_THREAD_CONTEXT_PUBLIC_INITIALIZER;                   \
    struct wolfsentry_thread_context *thread =                          \
        (struct wolfsentry_thread_context *)&thread_buffer;             \
    wolfsentry_errcode_t _thread_context_ret;
    /*!< \brief For `WOLFSENTRY_THREADSAFE` applications, this allocates the required thread context on the stack. @hideinitializer */

#define WOLFSENTRY_THREAD_HEADER_INIT(flags)                            \
    (_thread_context_ret =                                              \
        wolfsentry_init_thread_context(thread, flags, NULL /* user_context */))
    /*!< \brief For `WOLFSENTRY_THREADSAFE` applications, this performs the required thread context initialization, with options from its `wolfsentry_thread_flags_t` `flags` arg. @hideinitializer */

#define WOLFSENTRY_THREAD_HEADER_INIT_CHECKED(flags)                    \
    do {                                                                \
        _thread_context_ret =                                           \
            wolfsentry_init_thread_context(thread, flags, NULL /* user_context */); \
        if (_thread_context_ret < 0)                                    \
            return _thread_context_ret;                                 \
    } while (0)
    /*!< \brief For `WOLFSENTRY_THREADSAFE` applications, this performs the required thread context initialization, with options from its `wolfsentry_thread_flags_t` `flags` arg, and returns on failure. @hideinitializer */

#define WOLFSENTRY_THREAD_HEADER(flags)                                 \
    struct wolfsentry_thread_context_public thread_buffer =             \
        WOLFSENTRY_THREAD_CONTEXT_PUBLIC_INITIALIZER;                   \
    struct wolfsentry_thread_context *thread =                          \
        (struct wolfsentry_thread_context *)&thread_buffer;             \
    wolfsentry_errcode_t _thread_context_ret =                          \
        wolfsentry_init_thread_context(thread, flags, NULL /* user_context */)
    /*!< \brief For `WOLFSENTRY_THREADSAFE` applications, this allocates the required thread context on the stack, and initializes it with options from its `wolfsentry_thread_flags_t` `flags` arg. @hideinitializer */

#define WOLFSENTRY_THREAD_HEADER_CHECK()                                \
    do {                                                                \
        if (_thread_context_ret < 0)                                    \
            return _thread_context_ret;                                 \
    } while (0)
    /*!< \brief For `WOLFSENTRY_THREADSAFE` applications, checks if thread context initialization succeeded, and returns on failure. @hideinitializer */

#define WOLFSENTRY_THREAD_HEADER_CHECKED(flags)                         \
    WOLFSENTRY_THREAD_HEADER(flags);                                    \
    WOLFSENTRY_THREAD_HEADER_CHECK()
    /*!< \brief For `WOLFSENTRY_THREADSAFE` applications, this allocates the required thread context on the stack, and initializes it with options from its `wolfsentry_thread_flags_t` `flags` arg, returning on failure. @hideinitializer */

#define WOLFSENTRY_THREAD_TAILER(flags) (_thread_context_ret = wolfsentry_destroy_thread_context(thread, flags))
    /*!< \brief For `WOLFSENTRY_THREADSAFE` applications, this cleans up a thread context allocated with `WOLFSENTRY_THREAD_HEADER*`, with options from its `wolfsentry_thread_flags_t` `flags` arg, storing the result. @hideinitializer */
#define WOLFSENTRY_THREAD_TAILER_CHECKED(flags) do { WOLFSENTRY_THREAD_TAILER(flags); if (_thread_context_ret < 0) return _thread_context_ret; } while (0)
    /*!< \brief For `WOLFSENTRY_THREADSAFE` applications, this cleans up a thread context allocated with `WOLFSENTRY_THREAD_HEADER*`, with options from its `wolfsentry_thread_flags_t` `flags` arg, returning on error. @hideinitializer */
#define WOLFSENTRY_THREAD_GET_ERROR _thread_context_ret
    /*!< \brief For `WOLFSENTRY_THREADSAFE` applications, this evaluates to the most recent result from `WOLFSENTRY_THREAD_HEADER_INIT()` or `WOLFSENTRY_THREAD_TAILER()` @hideinitializer */

/*! \brief flags to pass to `wolfsentry_lock_*()` functions, to be `OR`d together */
typedef enum {
    WOLFSENTRY_LOCK_FLAG_NONE = 0,
        /*!< \brief Default lock behavior @hideinitializer */
    WOLFSENTRY_LOCK_FLAG_PSHARED = 1<<0,
        /*!< \brief Initialize lock to be shared between processes (currently not used, only allowed by wolfsentry_lock_init(), and only functional on POSIX targets) @hideinitializer */
    WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING = 1<<1,
        /*!< \brief Enables supplementary error checking on shared lock usage (not currently implemented) @hideinitializer */
    WOLFSENTRY_LOCK_FLAG_NONRECURSIVE_MUTEX = 1<<2,
        /*!< \brief Don't allow recursive mutex locking in this call @hideinitializer */
    WOLFSENTRY_LOCK_FLAG_NONRECURSIVE_SHARED = 1<<3,
        /*!< \brief Don't allow recursive shared locking in this call @hideinitializer */
    WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO = 1<<4,
        /*!< \brief If a shared lock is gotten in this call, require that a mutex upgrade reservation also be gotten. @hideinitializer */
    WOLFSENTRY_LOCK_FLAG_TRY_RESERVATION_TOO = 1<<5,
        /*!< \brief If a shared lock is gotten in this call, try to get a mutex upgrade reservation too. @hideinitializer */
    WOLFSENTRY_LOCK_FLAG_ABANDON_RESERVATION_TOO = 1<<6,
        /*!< \brief In a call to wolfsentry_lock_unlock(), if a shared lock is released and a mutex upgrade reservation is held, drop it too. @hideinitializer */
    WOLFSENTRY_LOCK_FLAG_AUTO_DOWNGRADE = 1<<7,
        /*!< \brief In a call to wolfsentry_lock_unlock(), if a held mutex was previously gotten by an upgrade, and this release will restore the recursion depth at which the upgrade was gotten, downgrade to a shared lock. @hideinitializer */
    WOLFSENTRY_LOCK_FLAG_RETAIN_SEMAPHORE = 1<<8
        /*!< \brief For use in an interrupt handler: get an async-signal-safe mutex on the lock.  Implicitly has `try` dynamics (immediate return). @hideinitializer */
} wolfsentry_lock_flags_t;

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_init_thread_context(struct wolfsentry_thread_context *thread_context, wolfsentry_thread_flags_t init_thread_flags, void *user_context);
    /*!< \brief Initialize `thread_context` according to `init_thread_flags`, storing `user_context` for later retrieval with wolfsentry_get_thread_user_context(). */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_alloc_thread_context(struct wolfsentry_host_platform_interface *hpi, struct wolfsentry_thread_context **thread_context, wolfsentry_thread_flags_t init_thread_flags, void *user_context);
    /*!< \brief Allocate space for `thread_context` using the allocator in `hpi`, then call wolfsentry_init_thread_context(). */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_get_thread_id(struct wolfsentry_thread_context *thread, wolfsentry_thread_id_t *id);
    /*!< \brief Write the `wolfsentry_thread_id_t` of `thread` to `id`. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_get_thread_user_context(struct wolfsentry_thread_context *thread, void **user_context);
    /*!< \brief Store to `user_context` the pointer previously passed to wolfsentry_init_thread_context(). */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_get_thread_deadline(struct wolfsentry_thread_context *thread, struct timespec *deadline);
    /*!< \brief Store the deadline for `thread` to `deadline`, or if the thread has no deadline set, store #WOLFSENTRY_DEADLINE_NEVER to `deadline->tv_sec` and `deadline->tv_nsec`. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_get_thread_flags(struct wolfsentry_thread_context *thread, wolfsentry_thread_flags_t *thread_flags);
    /*!< \brief Store the flags of `thread` to `thread_flags`. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_destroy_thread_context(struct wolfsentry_thread_context *thread_context, wolfsentry_thread_flags_t thread_flags);
    /*!< \brief Perform final integrity checking on the thread state, and deallocate its ID. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_free_thread_context(struct wolfsentry_host_platform_interface *hpi, struct wolfsentry_thread_context **thread_context, wolfsentry_thread_flags_t thread_flags);
    /*!< \brief Call `wolfsentry_destroy_thread_context()` on `*thread_context`, and if that succeeds, deallocate the thread object previously allocated by wolfsentry_alloc_thread_context(). */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_set_deadline_rel_usecs(WOLFSENTRY_CONTEXT_ARGS_IN, int usecs);
    /*!< \brief Set the thread deadline to `usecs` in the future.  The thread will not wait for a lock beyond that deadline. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_set_deadline_abs(WOLFSENTRY_CONTEXT_ARGS_IN, time_t epoch_secs, long epoch_nsecs);
    /*!< \brief Set the thread deadline to the time identified by `epoch_secs` and `epoch_nsecs`.  The thread will not wait for a lock beyond that deadline. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_clear_deadline(WOLFSENTRY_CONTEXT_ARGS_IN);
    /*!< \brief Clear any thread deadline previously set.  On time-unbounded calls such as wolfsentry_lock_shared() and wolfsentry_lock_mutex(), the thread will sleep until the lock is available. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_set_thread_readonly(struct wolfsentry_thread_context *thread_context);
    /*!< \brief Set the thread state to allow only readonly locks to be gotten, allowing multiple shared locks to be concurrently held.  If any mutexes or reservations are currently held, the call will fail. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_set_thread_readwrite(struct wolfsentry_thread_context *thread_context);
    /*!< \brief Set the thread state to allow both readonly and mutex locks to be gotten.  If multiple shared locks are currently held, the call will fail. */

struct wolfsentry_rwlock;

/*!
   \brief This initializes a semaphore lock structure created by the user

   \param hpi the `wolfsentry_host_platform_interface`
   \param thread pointer to the `wolfsentry_thread_context`
   \param lock a pointer to a lock structure to be initialized
   \param flags the initial `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa wolfsentry_lock_alloc
   \sa wolfsentry_lock_destroy
   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_init(struct wolfsentry_host_platform_interface *hpi, struct wolfsentry_thread_context *thread, struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags);
WOLFSENTRY_API size_t wolfsentry_lock_size(void);
/*!
   \brief Allocates and initializes a semaphore lock structure for use with wolfSentry.

   \param hpi the `wolfsentry_host_platform_interface`
   \param thread pointer to the `wolfsentry_thread_context`
   \param lock a pointer to a pointer to a lock structure to be allocated and initialized
   \param flags the initial `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa wolfsentry_lock_init
   \sa wolfsentry_lock_free
   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE()
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_alloc(struct wolfsentry_host_platform_interface *hpi, struct wolfsentry_thread_context *thread, struct wolfsentry_rwlock **lock, wolfsentry_lock_flags_t flags);
/*!
   \brief Requests a shared lock

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags);
/*!
   \brief Requests a shared lock with an absolute timeout

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param abs_timeout the absolute timeout for the lock
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared_abstimed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, const struct timespec *abs_timeout, wolfsentry_lock_flags_t flags);
/*!
   \brief Requests a shared lock with a relative timeout

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param max_wait how long to wait for the timeout
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared_timed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_time_t max_wait, wolfsentry_lock_flags_t flags);
/*!
   \brief Requests an exclusive lock

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_mutex(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags);
/*!
   \brief Requests an exclusive lock with an absolute timeout

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param abs_timeout the absolute timeout for the lock
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_mutex_abstimed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, const struct timespec *abs_timeout, wolfsentry_lock_flags_t flags);
/*!
   \brief Requests an exclusive lock with a relative timeout

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param max_wait how long to wait for the timeout
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_mutex_timed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_time_t max_wait, wolfsentry_lock_flags_t flags);
/*!
   \brief Downgrade an exclusive lock to a shared lock

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_mutex2shared(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags);
/*!
   \brief Upgrade a shared lock to an exclusive lock

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags);
/*!
   \brief Attempt to upgrade a shared lock to an exclusive lock with an absolute timeout

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param abs_timeout the absolute timeout for the lock
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_abstimed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, const struct timespec *abs_timeout, wolfsentry_lock_flags_t flags);
/*!
   \brief Attempt to upgrade a shared lock to an exclusive lock with a relative timeout

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param max_wait how long to wait for the timeout
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_timed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_time_t max_wait, wolfsentry_lock_flags_t flags);
/*!
   \brief Attempt to reserve a upgrade of a shared lock to an exclusive lock

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa wolfsentry_lock_shared2mutex_redeem
   \sa wolfsentry_lock_shared2mutex_redeem_abstimed
   \sa wolfsentry_lock_shared2mutex_redeem_timed
   \sa wolfsentry_lock_shared2mutex_abandon
   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_reserve(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags);
/*!
   \brief Redeem a reservation of a lock upgrade from shared to exclusive

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags);
/*!
   \brief Redeem a reservation of a lock upgrade from shared to exclusive with an absolute timeout

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param abs_timeout the absolute timeout for the lock
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem_abstimed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, const struct timespec *abs_timeout, wolfsentry_lock_flags_t flags);
/*!
   \brief Redeem a reservation of a lock upgrade from shared to exclusive with a relative timeout

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param max_wait how long to wait for the timeout
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem_timed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_time_t max_wait, wolfsentry_lock_flags_t flags);
/*!
   \brief Abandon a reservation of a lock upgrade from shared to exclusive

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_abandon(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags);
/*!
   \brief Check if the lock is held in shared state

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return When decoded using `WOLFSENTRY_ERROR_DECODE_ERROR_CODE()`, `WOLFSENTRY_SUCCESS_ID_HAVE_READ_LOCK` if it is a held shared lock,
   `WOLFSENTRY_ERROR_ID_LACKING_READ_LOCK` if the lock is valid but not held by the designated `thread`,
   or `WOLFSENTRY_ERROR_ID_INVALID_ARG` if the lock is not properly initialized.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_have_shared(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags);
/*!
   \brief Check if the lock is held in exclusive state

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return When decoded using `WOLFSENTRY_ERROR_DECODE_ERROR_CODE()`, `WOLFSENTRY_SUCCESS_ID_HAVE_MUTEX` if
   it is a held mutex lock, `WOLFSENTRY_ERROR_ID_LACKING_MUTEX` if the lock is not in mutex state, `WOLFSENTRY_ERROR_ID_NOT_PERMITTED`
   if the mutex is held by another thread, or `WOLFSENTRY_ERROR_ID_INVALID_ARG` if the lock is not properly initialized.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_have_mutex(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags);
/*!
   \brief Check if the lock is held in either shared or exclusive state

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return When decoded using `WOLFSENTRY_ERROR_DECODE_ERROR_CODE()`, `WOLFSENTRY_SUCCESS_ID_HAVE_MUTEX` if
   it is a held mutex lock, `WOLFSENTRY_SUCCESS_ID_HAVE_READ_LOCK` if it is a held shared lock,
   `WOLFSENTRY_ERROR_ID_LACKING_READ_LOCK` if the lock is valid but not held by the designated `thread`,
   or `WOLFSENTRY_ERROR_ID_INVALID_ARG` if the lock is not properly initialized.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_have_either(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags);
/*!
   \brief Check if an upgrade reservation is held on the lock

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK if
   it is shared lock. Or WOLFSENTRY_ERROR_ID_NOT_OK if it is not a shared lock.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_have_shared2mutex_reservation(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags);
/*!
   \brief Extract the current flags from the lock

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_get_flags(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t *flags);
/*!
   \brief Unlock a lock

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_unlock(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags);
/*!
   \brief Destroy a lock that was created with wolfsentry_lock_init()

   \param lock a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa wolfsentry_lock_init
   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_destroy(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags);
/*!
   \brief Destroy and free a lock that was created with wolfsentry_lock_alloc(). The
   lock's pointer will also be set to NULL.

   \param lock a pointer to a pointer to the lock
   \param thread pointer to the `wolfsentry_thread_context`
   \param flags optional `wolfsentry_lock_flags_t`

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa wolfsentry_lock_alloc
   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_free(struct wolfsentry_rwlock **lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags);

#else /* !WOLFSENTRY_THREADSAFE */

#define WOLFSENTRY_CONTEXT_ARGS_IN struct wolfsentry_context *wolfsentry
#define WOLFSENTRY_CONTEXT_ARGS_IN_EX(ctx) ctx
#define WOLFSENTRY_CONTEXT_ELEMENTS struct wolfsentry_context *wolfsentry
#define WOLFSENTRY_CONTEXT_SET_ELEMENTS(s) (s).wolfsentry = wolfsentry
#define WOLFSENTRY_CONTEXT_GET_ELEMENTS(s) (s).wolfsentry
#define WOLFSENTRY_CONTEXT_ARGS_OUT wolfsentry
#define WOLFSENTRY_CONTEXT_ARGS_OUT_EX(ctx) ctx
#define WOLFSENTRY_CONTEXT_ARGS_OUT_EX2(x) (x)->wolfsentry
#define WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(x, y) (x)->y
#define WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(x, y) x
#define WOLFSENTRY_CONTEXT_ARGS_NOT_USED (void)wolfsentry
#define WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED DO_NOTHING

#define WOLFSENTRY_THREAD_HEADER_DECLS
#define WOLFSENTRY_THREAD_HEADER(flags) DO_NOTHING
#define WOLFSENTRY_THREAD_HEADER_INIT(flags) 0
#define WOLFSENTRY_THREAD_HEADER_INIT_CHECKED(flags) DO_NOTHING
#define WOLFSENTRY_THREAD_HEADER_CHECKED(flags) DO_NOTHING
#define WOLFSENTRY_THREAD_HEADER_CHECK() DO_NOTHING
#define WOLFSENTRY_THREAD_GET_ERROR 0
#define WOLFSENTRY_THREAD_TAILER(flags) 0
#define WOLFSENTRY_THREAD_TAILER_CHECKED(flags) DO_NOTHING

#define wolfsentry_lock_init(x, y, z, w) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_alloc(x, y, z, w) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared_abstimed(x, y, z, w) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_mutex_timed(x, y, z, w) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_mutex(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_mutex_abstimed(x, y, z, w) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_mutex_timed(x, y, z, w) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_mutex2shared(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex_abstimed(x, y, z, w) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex_timed(x, y, z, w) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex_reserve(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex_redeem(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex_redeem_abstimed(x, y, z, w) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex_redeem_timed(x, y, z, w) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex_abandon(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_have_shared(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_have_mutex(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_have_either(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_have_shared2mutex_reservation(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_unlock(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_destroy(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_free(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)

#endif /* WOLFSENTRY_THREADSAFE */

/*! @} (end wolfsentry_thread_context) */

/*! \addtogroup wolfsentry_table_ent_header
 *  @{
 */

/*! \brief enum for communicating the type of an object. */
typedef enum {
    WOLFSENTRY_OBJECT_TYPE_UNINITED = 0,
        /*!< \brief Object is null or uninitialized. @hideinitializer */
    WOLFSENTRY_OBJECT_TYPE_TABLE,
        /*!< \brief Not currently used. @hideinitializer */
    WOLFSENTRY_OBJECT_TYPE_ACTION,
        /*!< \brief Object is a `struct wolfsentry_action`. @hideinitializer */
    WOLFSENTRY_OBJECT_TYPE_EVENT,
        /*!< \brief Object is a `struct wolfsentry_event`. @hideinitializer */
    WOLFSENTRY_OBJECT_TYPE_ROUTE,
        /*!< \brief Object is a `struct wolfsentry_route`. @hideinitializer */
    WOLFSENTRY_OBJECT_TYPE_KV,
        /*!< \brief Object is a `struct wolfsentry_kv_pair_internal`. @hideinitializer */
    WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNUMBER,
        /*!< \brief Object is a `struct wolfsentry_addr_family_bynumber`. @hideinitializer */
    WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNAME
        /*!< \brief Object is a `struct wolfsentry_addr_family_byname`. @hideinitializer */
} wolfsentry_object_type_t;

/*! @} (end wolfsentry_table_ent_header) */

/*! \addtogroup wolfsentry_action
 * @{
 */

/*! \brief enum for communicating attributes of an action object */
typedef enum {
    WOLFSENTRY_ACTION_FLAG_NONE       = 0U,
        /*!< \brief Default attributes @hideinitializer */
    WOLFSENTRY_ACTION_FLAG_DISABLED   = 1U << 0U
        /*!< \brief Disable this action -- while this bit is set, dispatches will not call this action @hideinitializer */
} wolfsentry_action_flags_t;

/*! \brief enum communicating (to action handlers and internal logic) what type of action is being evaluated */
typedef enum {
    WOLFSENTRY_ACTION_TYPE_NONE = 0,
        /*!< \brief no action @hideinitializer */
    WOLFSENTRY_ACTION_TYPE_POST = 1,
        /*!< \brief called when an event is posted. @hideinitializer */
    WOLFSENTRY_ACTION_TYPE_INSERT = 2,
        /*!< \brief called when a route is added to the route table for this event. @hideinitializer */
    WOLFSENTRY_ACTION_TYPE_MATCH = 3,
        /*!< \brief called by wolfsentry_route_dispatch() for a route match. @hideinitializer */
    WOLFSENTRY_ACTION_TYPE_UPDATE = 4,
        /*!< \brief called by wolfsentry_route_dispatch() when the logical state (currently, flags) of an existing route changes. @hideinitializer */
    WOLFSENTRY_ACTION_TYPE_DELETE = 5,
        /*!< \brief called when a route associated with this event expires or is otherwise deleted. @hideinitializer */
    WOLFSENTRY_ACTION_TYPE_DECISION = 6
        /*!< \brief called after final decision has been made by wolfsentry_route_event_dispatch*(). @hideinitializer */
} wolfsentry_action_type_t;

/*! \brief bit field used to communicate states and attributes through the evaluation pipeline. */
typedef enum {
    WOLFSENTRY_ACTION_RES_NONE        = 0U,
        /*!< \brief initializer for wolfsentry_action_res_t. @hideinitializer */
    WOLFSENTRY_ACTION_RES_ACCEPT      = 1U << 0U,
        /*!< \brief the route state or an action determined the event should be allowed. @hideinitializer */
    WOLFSENTRY_ACTION_RES_REJECT      = 1U << 1U,
        /*!< \brief the route state or an action determined the event should be forbidden. @hideinitializer */
    WOLFSENTRY_ACTION_RES_CONNECT     = 1U << 2U,
        /*!< \brief caller-preinited bit signaling that a connection was established. @hideinitializer */
    WOLFSENTRY_ACTION_RES_DISCONNECT  = 1U << 3U,
        /*!< \brief caller-preinited bit signaling that a connection was dissolved. @hideinitializer */
    WOLFSENTRY_ACTION_RES_DEROGATORY  = 1U << 4U,
        /*!< \brief the caller or an action designated this event derogatory for the peer. @hideinitializer */
    WOLFSENTRY_ACTION_RES_COMMENDABLE = 1U << 5U,
        /*!< \brief the caller or an action designated this event commendable for the peer. @hideinitializer */
/*! @cond doxygen_all */
    WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES = WOLFSENTRY_ACTION_RES_DEROGATORY | WOLFSENTRY_ACTION_RES_COMMENDABLE, /* internal use -- overload used by wolfsentry_route_lookup_0() */
/*! @endcond */
    WOLFSENTRY_ACTION_RES_STOP        = 1U << 6U,
        /*!< \brief when an action returns this, don't evaluate any more actions in the current action list. @hideinitializer */
    WOLFSENTRY_ACTION_RES_DEALLOCATED = 1U << 7U,
        /*!< \brief when an API call returns this, an object and its associated ID were deallocated from the system. @hideinitializer */
    WOLFSENTRY_ACTION_RES_INSERTED    = 1U << 8U,
        /*!< \brief a side-effect route insertion was performed. @hideinitializer */
    WOLFSENTRY_ACTION_RES_ERROR       = 1U << 9U,
        /*!< \brief an error occurred while processing actions. @hideinitializer */
    WOLFSENTRY_ACTION_RES_FALLTHROUGH = 1U << 10U,
        /*!< \brief dispatch classification (ACCEPT/REJECT) was by fallthrough policy. @hideinitializer */
    WOLFSENTRY_ACTION_RES_UPDATE      = 1U << 11U,
        /*!< \brief signals to subsequent actions and the caller that the route state was updated (e.g. penaltyboxed). @hideinitializer */
    WOLFSENTRY_ACTION_RES_PORT_RESET  = 1U << 12U,
        /*!< \brief when an action returns this, send a TCP reset or ICMP port unreachable packet. @hideinitializer */
    WOLFSENTRY_ACTION_RES_SENDING     = 1U << 13U,
        /*!< \brief caller-preinited bit signaling outbound traffic. @hideinitializer */
    WOLFSENTRY_ACTION_RES_RECEIVED    = 1U << 14U,
        /*!< \brief caller-preinited bit signaling inbound traffic. @hideinitializer */
    WOLFSENTRY_ACTION_RES_BINDING     = 1U << 15U,
        /*!< \brief caller-preinited bit signaling that a socket will be bound. @hideinitializer */
    WOLFSENTRY_ACTION_RES_LISTENING   = 1U << 16U,
        /*!< \brief caller-preinited bit signaling that a socket will be listened. @hideinitializer */
    WOLFSENTRY_ACTION_RES_STOPPED_LISTENING = 1U << 17U,
        /*!< \brief caller-preinited bit signaling that a socket will stop being listened. @hideinitializer */
    WOLFSENTRY_ACTION_RES_CONNECTING_OUT = 1U << 18U,
        /*!< \brief caller-preinited bit signaling that an outbound connection will be attempted. @hideinitializer */
    WOLFSENTRY_ACTION_RES_CLOSED      = 1U << 19U,
        /*!< \brief caller-preinited bit signaling that an association has closed/ended that wasn't created with _CONNECT. @hideinitializer */
    WOLFSENTRY_ACTION_RES_UNREACHABLE = 1U << 20U,
        /*!< \brief caller-preinited bit signaling that traffic destination was unreachable (unbound/unlistened). @hideinitializer */
    WOLFSENTRY_ACTION_RES_SOCK_ERROR  = 1U << 21U,
        /*!< \brief caller-preinited bit signaling that a transport error occurred. @hideinitializer */
    WOLFSENTRY_ACTION_RES_CLOSE_WAIT  = 1U << 22U,
        /*!< \brief caller-preinited bit signaling that an association has entered CLOSE_WAIT and will be closed. @hideinitializer */
/*! @cond doxygen_all */
    WOLFSENTRY_ACTION_RES_RESERVED23  = 1U << 23U,
/*! @endcond */
    WOLFSENTRY_ACTION_RES_USER0       = 1U << 24U,
        /*!< \brief user-defined result bit #1 of 8. @hideinitializer */
    WOLFSENTRY_ACTION_RES_USER1       = 1U << 25U,
        /*!< \brief user-defined result bit #2 of 8. @hideinitializer */
    WOLFSENTRY_ACTION_RES_USER2       = 1U << 26U,
        /*!< \brief user-defined result bit #3 of 8. @hideinitializer */
    WOLFSENTRY_ACTION_RES_USER3       = 1U << 27U,
        /*!< \brief user-defined result bit #4 of 8. @hideinitializer */
    WOLFSENTRY_ACTION_RES_USER4       = 1U << 28U,
        /*!< \brief user-defined result bit #5 of 8. @hideinitializer */
    WOLFSENTRY_ACTION_RES_USER5       = 1U << 29U,
        /*!< \brief user-defined result bit #6 of 8. @hideinitializer */
    WOLFSENTRY_ACTION_RES_USER6       = 1U << 30U
        /*!< \brief user-defined result bit #7 of 8. @hideinitializer */
    /* see macro definition of WOLFSENTRY_ACTION_RES_USER7 below. */

        /*!< \brief start of user-defined results, with user-defined scheme (bit field, sequential, or other).  8 bits are available. @hideinitializer */
} wolfsentry_action_res_t;

/*! @cond doxygen_all */
#define WOLFSENTRY_ACTION_RES_USER_BASE WOLFSENTRY_ACTION_RES_USER0
/*! @endcond */

#define WOLFSENTRY_ACTION_RES_USER_SHIFT 24U
    /*!< \brief Bit shift for user-defined bit span in ::wolfsentry_action_res_t */
#define WOLFSENTRY_ACTION_RES_USER7 (1U << 31U)
    /*!< \brief user-defined result bit #8 of 8.  Defined with a macro to retain ISO C compliance on enum range. */

/*! @} (end wolfsentry_action) */

struct wolfsentry_table_header;
struct wolfsentry_table_ent_header;
struct wolfsentry_route;
struct wolfsentry_route_table;
struct wolfsentry_event;
struct wolfsentry_event_table;
struct wolfsentry_action;
struct wolfsentry_action_table;
struct wolfsentry_action_list;
struct wolfsentry_action_list_ent;
struct wolfsentry_cursor;

/*! \addtogroup wolfsentry_action
 *  @{
 */

/*!
   \brief A callback that is triggered when an action is taken

   \param action a pointer to action details
   \param handler_arg an opaque pointer registered with `wolfsentry_action_insert()`, passed to every invocation of the handler
   \param caller_arg an opaque pointer supplied by the caller to the dispatching `wolfsentry_route_*()` API
   \param trigger_event the event which triggered the action, if any
   \param action_type the action type
   \param trigger_route a pointer to the subject route, reflecting instantaneous traffic attributes and contents
   \param route_table a pointer to the implicated route table
   \param rule_route a pointer to the matched route, reflecting rule logic
   \param action_results a pointer to the action results, to be read and/or updated by the handler

   \return #WOLFSENTRY_RETURN_OK if there is no error

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
typedef wolfsentry_errcode_t (*wolfsentry_action_callback_t)(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *trigger_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results);

/*! @} (end wolfsentry_action) */

/*! \addtogroup wolfsentry_route
 * @{
 */

#define WOLFSENTRY_ROUTE_DEFAULT_POLICY_MASK (WOLFSENTRY_ACTION_RES_ACCEPT | WOLFSENTRY_ACTION_RES_REJECT | WOLFSENTRY_ACTION_RES_STOP | WOLFSENTRY_ACTION_RES_ERROR)
    /*!< \brief Bit mask spanning the bits allowed by wolfsentry_route_table_default_policy_set() */

/*! \brief bit field specifying attributes of a route/rule */
typedef enum {
    WOLFSENTRY_ROUTE_FLAG_NONE                           = 0U,
        /*!< No attributes */
    /* note the wildcard bits need to be at the start, in order of field
     * comparison by wolfsentry_route_key_cmp_1(), due to math in
     * wolfsentry_route_lookup_0().
     */
    WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD             = 1U<<0U,
        /*!< \brief Address family is wildcard -- match all traffic in specified direction(s), optionally with specified interfaces @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD        = 1U<<1U,
        /*!< \brief Remote address is wildcard -- match any remote address @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD              = 1U<<2U,
        /*!< \brief Protocol is wildcard -- match any protocol @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD         = 1U<<3U,
        /*!< \brief Local port is wildcard -- match any local port @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD         = 1U<<4U,
        /*!< \brief Local address is wildcard -- match any local address @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD        = 1U<<5U,
        /*!< \brief Remote port is wildcard -- match any remote port @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD      = 1U<<6U,
        /*!< \brief Ingestion interface is wildcard -- match any ingestion interface @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD       = 1U<<7U,
        /*!< \brief Local interface (usually same as remote interface) is wildcard -- match any local interface @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD          = 1U<<8U,
        /*!< \brief Match regardless of parent event mismatch @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS           = 1U<<9U,
        /*!< \brief Interpret port names using TCP/UDP mappings (available unless build option #WOLFSENTRY_NO_GETPROTOBY is defined) @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN                   = 1U<<10U,
        /*!< \brief Match inbound traffic @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT                  = 1U<<11U,
        /*!< \brief Match outbound traffic (if #WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN and #WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT are both set, traffic in both directions is matched) @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK            = 1U<<12U,
        /*!< \brief Supplied remote address consists of an address followed by a bitmask, and its addr_len is the total bit count for the address and mask.  The bit count for the address and bitmask must be equal, and each must be a multiple of 8, i.e. aligned to a byte boundary.  Matching will be performed by checking that masked addresses are equal. @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK             = 1U<<13U,
        /*!< \brief Supplied local address consists of an address followed by a bitmask, and its addr_len is the total bit count for the address and mask.  The bit count for the address and bitmask must be equal, and each must be a multiple of 8, i.e. aligned to a byte boundary.  Matching will be performed by checking that masked addresses are equal. @hideinitializer */

    /* immutable above here. */

    /* internal use from here... */
    WOLFSENTRY_ROUTE_FLAG_IN_TABLE                       = 1U<<14U,
        /*!< \brief Internal use -- marks route as resident in table @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_PENDING_DELETE                 = 1U<<15U,
        /*!< \brief Internal use -- marks route as deleted @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_INSERT_ACTIONS_CALLED          = 1U<<16U,
        /*!< \brief Internal use -- records that route insertion actions have been completed @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_DELETE_ACTIONS_CALLED          = 1U<<17U,
        /*!< \brief Internal use -- records that route deletion actions have been completed @hideinitializer */

    /* ...to here. */

    /* mutable below here. */

    WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED                   = 1U<<20U,
        /*!< \brief Traffic that matches a route with this flag set will be rejected. @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_GREENLISTED                    = 1U<<21U,
        /*!< \brief Traffic that matches a route with this flag set will be accepted. @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_HITS                = 1U<<22U,
        /*!< \brief Don't keep traffic statistics for this rule (avoid counting overhead) @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_CURRENT_CONNECTIONS = 1U<<23U,
        /*!< \brief Don't keep concurrent connection count for this rule (don't impose connection limit, even if set in the applicable `wolfsentry_eventconfig`) @hideinitializer */
    WOLFSENTRY_ROUTE_FLAG_PORT_RESET                     = 1U<<24U
        /*!< \brief If traffic is rejected by this rule, set #WOLFSENTRY_ACTION_RES_PORT_RESET in the returned ::wolfsentry_action_res_t, prompting generation by the network stack of a TCP reset, ICMP unreachable, or other applicable reply packet. @hideinitializer */
} wolfsentry_route_flags_t;

/* note, _PARENT_EVENT_WILDCARD is excluded because it isn't an intrinsic attribute of network/bus traffic. */
#define WOLFSENTRY_ROUTE_WILDCARD_FLAGS ((wolfsentry_route_flags_t)WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD - 1U)
    /*!< \brief Bit mask for the wildcard bits in a ::wolfsentry_route_flags_t.  @hideinitializer */

#define WOLFSENTRY_ROUTE_IMMUTABLE_FLAGS ((wolfsentry_route_flags_t)WOLFSENTRY_ROUTE_FLAG_IN_TABLE - 1U)
    /*!< \brief Bit mask for the bits in a ::wolfsentry_route_flags_t that can't change after the implicated route has been inserted in the route table.  @hideinitializer */

#define WOLFSENTRY_ROUTE_INTERNAL_FLAGS ((wolfsentry_route_flags_t) \
                                         (WOLFSENTRY_ROUTE_FLAG_IN_TABLE | \
                                          WOLFSENTRY_ROUTE_FLAG_PENDING_DELETE | \
                                          WOLFSENTRY_ROUTE_FLAG_INSERT_ACTIONS_CALLED | \
                                          WOLFSENTRY_ROUTE_FLAG_DELETE_ACTIONS_CALLED))

/*! @cond doxygen_all */
#define WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD /* xxx backward compatibility */
/*! @endcond */

/*! \brief struct for exporting socket addresses, with fixed-length fields */
struct wolfsentry_route_endpoint {
    wolfsentry_port_t sa_port;
        /*!< \brief The port number -- only treated as a TCP/IP port number if the route has the #WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS flag set. */
    wolfsentry_addr_bits_t addr_len;
        /*!< \brief The number of significant bits in the address.  The address data itself is in the parent `wolfsentry_route_exports` struct. */
    byte extra_port_count;
        /*!< \brief The number of extra ports in the route -- not currently supported */
    byte interface;
        /*!< \brief The interface ID of the route */
};

/*! \brief struct for exporting route metadata for access by applications */
struct wolfsentry_route_metadata_exports {
    wolfsentry_time_t insert_time;
        /*!< \brief The time the route was inserted */
    wolfsentry_time_t last_hit_time;
        /*!< \brief The most recent time the route was matched */
    wolfsentry_time_t last_penaltybox_time;
        /*!< \brief The most recent time the route had its #WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED flag set */
    wolfsentry_time_t purge_after;
        /*!< \brief The expiration time of the route, if any.  Persistent routes have `0` here, and the setting can be modified with `wolfsentry_route_purge_time_set()`. */
    uint16_t connection_count;
        /*!< \brief The current connection count (informational/approximate) */
    uint16_t derogatory_count;
        /*!< \brief The current derogatory event count (informational/approximate) */
    uint16_t commendable_count;
        /*!< \brief The current commendable event count (informational/approximate) */
    wolfsentry_hitcount_t hit_count;
        /*!< \brief The lifetime match count (informational/approximate, and only maintained if the #WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_HITS flag is clear) */
};

/*! \brief struct for exporting a route for access by applications */
struct wolfsentry_route_exports {
    const char *parent_event_label;
        /*!< \brief Label of the parent event, or null if none */
    int parent_event_label_len;
        /*!< \brief Length (not including terminating null) of label of the parent event, if any */
    wolfsentry_route_flags_t flags;
        /*!< \brief Current route flags (mutable bits are informational/approximate) */
    wolfsentry_addr_family_t sa_family;
        /*!< \brief Address family for this route */
    wolfsentry_proto_t sa_proto;
        /*!< \brief Protocol for this route */
    struct wolfsentry_route_endpoint remote;
        /*!< \brief Remote socket address for this route */
    struct wolfsentry_route_endpoint local;
        /*!< \brief Local socket address for this route */
    const byte *remote_address;
        /*!< \brief Binary address data for the remote end of this route */
    const byte *local_address;
        /*!< \brief Binary address data for the local end of this route */
    const wolfsentry_port_t *remote_extra_ports;
        /*!< \brief array of extra remote ports that match this route -- not yet implemented */
    const wolfsentry_port_t *local_extra_ports;
        /*!< \brief array of extra local ports that match this route -- not yet implemented */
    struct wolfsentry_route_metadata_exports meta;
        /*!< \brief The current route metadata */
    void *private_data;
        /*!< \brief The private data segment (application-defined), if any */
    size_t private_data_size;
        /*!< \brief The size of the private data segment, if any, or zero */
};

/*! \brief struct for passing socket addresses into `wolfsentry_route_*()` API routines */
struct wolfsentry_sockaddr {
    wolfsentry_addr_family_t sa_family;
        /*!< \brief Address family number */
    wolfsentry_proto_t sa_proto;
        /*!< \brief Protocol number */
    wolfsentry_port_t sa_port;
        /*!< \brief Port number */
    wolfsentry_addr_bits_t addr_len;
        /*!< \brief Significant bits in address */
    byte interface;
        /*!< \brief Interface ID number */
    attr_align_to(4) byte addr[WOLFSENTRY_FLEXIBLE_ARRAY_SIZE];
        /*!< \brief Binary big-endian address data */
};

#define WOLFSENTRY_SOCKADDR(n) struct {         \
    wolfsentry_addr_family_t sa_family;         \
    wolfsentry_proto_t sa_proto;                \
    wolfsentry_port_t sa_port;                  \
    wolfsentry_addr_bits_t addr_len;            \
    byte interface;                             \
    attr_align_to(4) byte addr[WOLFSENTRY_BITS_TO_BYTES(n)];    \
}
/*!< \brief Macro to instantiate a wolfsentry_sockaddr with an `addr` field sized to hold `n` bits of address data.  Cast to `struct wolfsentry_sockaddr` to pass as API argument. @hideinitializer */

/*! \brief bit field with options for rendering */
typedef enum {
    WOLFSENTRY_FORMAT_FLAG_NONE = 0,
        /*!< \brief Default rendering behavior @hideinitializer */
    WOLFSENTRY_FORMAT_FLAG_ALWAYS_NUMERIC = 1U << 0U
        /*!< \brief When rendering address families and protocols, always render as bare integers.  Currently honored by wolfsentry_route_format_json(). @hideinitializer */
} wolfsentry_format_flags_t;

/*! @} (end wolfsentry_route) */

/*! \addtogroup wolfsentry_event
 * @{
 */

/*! \brief bit field with attribute flags for events */
typedef enum {
    WOLFSENTRY_EVENT_FLAG_NONE = 0,
        /*!< \brief Default attributes @hideinitializer */
    WOLFSENTRY_EVENT_FLAG_IS_PARENT_EVENT = 1U << 0U,
        /*!< \brief Internally set -- Event is parent of one or more routes. @hideinitializer */
    WOLFSENTRY_EVENT_FLAG_IS_SUBEVENT = 1U << 1U
        /*!< \brief Internally set -- Event is subevent of another event. @hideinitializer */
} wolfsentry_event_flags_t;

/*! \brief bit field with config flags for events */
typedef enum {
    WOLFSENTRY_EVENTCONFIG_FLAG_NONE = 0U,
        /*!< \brief Default config @hideinitializer */
    WOLFSENTRY_EVENTCONFIG_FLAG_DEROGATORY_THRESHOLD_IGNORE_COMMENDABLE = 1U << 0U,
        /*!< \brief If set, then counts from `WOLFSENTRY_ACTION_RES_COMMENDABLE` are not subtracted from the derogatory count when checking for automatic penalty boxing. @hideinitializer */
    WOLFSENTRY_EVENTCONFIG_FLAG_COMMENDABLE_CLEARS_DEROGATORY = 1U << 1U,
        /*!< \brief If set, then each count from `WOLFSENTRY_ACTION_RES_COMMENDABLE` zeroes the derogatory count. @hideinitializer */
    WOLFSENTRY_EVENTCONFIG_FLAG_INHIBIT_ACTIONS = 1U << 2U
        /*!< \brief Internal use -- Inhibits dispatch of actions listed in this event. @hideinitializer */
} wolfsentry_eventconfig_flags_t;

/*! \brief struct for representing event configuration */
struct wolfsentry_eventconfig {
    size_t route_private_data_size;
        /*!< \brief bytes to allocate for private use for application data */
    size_t route_private_data_alignment;
        /*!< \brief alignment for private data allocation */
    uint32_t max_connection_count;
        /*!< \brief If nonzero, the concurrent connection limit, beyond which additional connection requests are rejected. */
    wolfsentry_hitcount_t derogatory_threshold_for_penaltybox;
        /*!< \brief If nonzero, the threshold at which accumulated derogatory counts (from `WOLFSENTRY_ACTION_RES_DEROGATORY` incidents) automatically penalty boxes a route. */
    wolfsentry_time_t penaltybox_duration;
        /*!< \brief The duration that a route stays in penalty box status before automatic release.  Zero means time-unbounded. */
    wolfsentry_time_t route_idle_time_for_purge;
        /*!< \brief The time after the most recent dispatch match for a route to be garbage-collected.  Zero means no automatic purge. */
    wolfsentry_eventconfig_flags_t flags;
        /*!< \brief Config flags */
    wolfsentry_route_flags_t route_flags_to_add_on_insert;
        /*!< \brief List of route flags to set on new routes upon insertion. */
    wolfsentry_route_flags_t route_flags_to_clear_on_insert;
        /*!< \brief List of route flags to clear on new routes upon insertion. */
    wolfsentry_action_res_t action_res_filter_bits_set;
        /*!< \brief List of result flags that must be set at lookup time (dispatch) for referring routes to match. */
    wolfsentry_action_res_t action_res_filter_bits_unset;
        /*!< \brief List of result flags that must be clear at lookup time (dispatch) for referring routes to match. */
    wolfsentry_action_res_t action_res_bits_to_add;
        /*!< \brief List of result flags to be set upon match. */
    wolfsentry_action_res_t action_res_bits_to_clear;
        /*!< \brief List of result flags to be cleared upon match. */
};

/*! @} (end wolfsentry_event) */

/*! \addtogroup wolfsentry_timecbs
 *  @{
 */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_time_now_plus_delta(struct wolfsentry_context *wolfsentry, wolfsentry_time_t td, wolfsentry_time_t *res);
    /*!< \brief Generate a ::wolfsentry_time_t at a given offset from current time. */

#ifdef WOLFSENTRY_THREADSAFE
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_time_to_timespec(struct wolfsentry_context *wolfsentry, wolfsentry_time_t t, struct timespec *ts);
    /*!< \brief Convert a ::wolfsentry_time_t to a `struct timespec`. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_time_now_plus_delta_timespec(struct wolfsentry_context *wolfsentry, wolfsentry_time_t td, struct timespec *ts);
    /*!< \brief Generate a `struct timespec` at a given offset, supplied as ::wolfsentry_time_t, from current time. */
#endif

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_get_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t *time_p);
    /*!< \brief Get current time as ::wolfsentry_time_t. */
WOLFSENTRY_API wolfsentry_time_t wolfsentry_diff_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t later, wolfsentry_time_t earlier);
    /*!< \brief Compute the interval between \p later and \p earlier, using ::wolfsentry_time_t. */
WOLFSENTRY_API wolfsentry_time_t wolfsentry_add_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t start_time, wolfsentry_time_t time_interval);
    /*!< \brief Compute the time \p time_interval after \p start_time, using ::wolfsentry_time_t. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_to_epoch_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t when, time_t *epoch_secs, long *epoch_nsecs);
    /*!< \brief Convert a ::wolfsentry_time_t to seconds and nanoseconds since 1970-Jan-1 0:00 UTC. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_from_epoch_time(struct wolfsentry_context *wolfsentry, time_t epoch_secs, long epoch_nsecs, wolfsentry_time_t *when);
    /*!< \brief Convert seconds and nanoseconds since 1970-Jan-1 0:00 UTC to a ::wolfsentry_time_t. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_interval_to_seconds(struct wolfsentry_context *wolfsentry, wolfsentry_time_t howlong, time_t *howlong_secs, long *howlong_nsecs);
    /*!< \brief Convert an interval in ::wolfsentry_time_t to seconds and nanoseconds. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_interval_from_seconds(struct wolfsentry_context *wolfsentry, time_t howlong_secs, long howlong_nsecs, wolfsentry_time_t *howlong);
    /*!< \brief Convert an interval in seconds and nanoseconds to ::wolfsentry_time_t. */

WOLFSENTRY_API struct wolfsentry_timecbs *wolfsentry_get_timecbs(struct wolfsentry_context *wolfsentry);
    /*!< \brief Return the active time handlers from the supplied context. */

/*! @} */

/*! \addtogroup wolfsentry_table_ent_header
 *  @{
 */
typedef wolfsentry_errcode_t (*wolfsentry_make_id_cb_t)(void *context, wolfsentry_ent_id_t *id);
/*! @} */

/*! \addtogroup wolfsentry_allocator
 *  @{
 */
WOLFSENTRY_API void *wolfsentry_malloc(WOLFSENTRY_CONTEXT_ARGS_IN, size_t size);
   /*!< \brief Allocate `size` bytes using the `malloc` configured in the wolfSentry context. */
WOLFSENTRY_API_VOID wolfsentry_free(WOLFSENTRY_CONTEXT_ARGS_IN, void *ptr);
   /*!< \brief Free `ptr` using the `free` configured in the wolfSentry context. */
WOLFSENTRY_API void *wolfsentry_realloc(WOLFSENTRY_CONTEXT_ARGS_IN, void *ptr, size_t size);
   /*!< \brief Reallocate `ptr` to `size` bytes using the `realloc` configured in the wolfSentry context. */
WOLFSENTRY_API void *wolfsentry_memalign(WOLFSENTRY_CONTEXT_ARGS_IN, size_t alignment, size_t size);
   /*!< \brief Allocate `size` bytes, aligned to `alignment`, using the `memalign` configured in the wolfSentry context. */
WOLFSENTRY_API_VOID wolfsentry_free_aligned(WOLFSENTRY_CONTEXT_ARGS_IN, void *ptr);
   /*!< \brief Free `ptr`, previously allocated with `wolfsentry_memalign()`, using the `free_aligned` configured in the wolfSentry context. */
#if (defined(WOLFSENTRY_MALLOC_BUILTINS) && defined(WOLFSENTRY_MALLOC_DEBUG)) || defined(WOLFSENTRY_FOR_DOXYGEN)
WOLFSENTRY_API int _wolfsentry_get_n_mallocs(void);
   /*!< \brief In library builds with `WOLFSENTRY_MALLOC_BUILTINS` and `WOLFSENTRY_MALLOC_DEBUG` defined, this returns the _net_ number of allocations performed as of time of call.  I.e., it returns zero iff all allocations have been freed. */
#endif

WOLFSENTRY_API struct wolfsentry_allocator *wolfsentry_get_allocator(struct wolfsentry_context *wolfsentry);
    /*!< \brief Return a pointer to the `wolfsentry_allocator` associated with the supplied `wolfsentry_context`, mainly for passing to `json_init()`, `json_parse()`, `json_value_*()`, and `json_dom_*()`. */

/*! @} */

#if defined(WOLFSENTRY_PROTOCOL_NAMES) || !defined(WOLFSENTRY_NO_JSON)
/*! \addtogroup wolfsentry_action
 * @{
 */
WOLFSENTRY_API const char *wolfsentry_action_res_assoc_by_flag(wolfsentry_action_res_t res, unsigned int bit);
    /*!< \brief Given a \p bit number (from 0 to 31), return the name of that bit if set in \p res, else return a null pointer. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_res_assoc_by_name(const char *bit_name, int bit_name_len, wolfsentry_action_res_t *res);
    /*!< \brief Given a \p bit_name, set \p *res to the corresponding bit number if known, failing which, return `ITEM_NOT_FOUND`. */
/*! @} */
#endif

/*! \addtogroup wolfsentry_init
 * @{
 */

WOLFSENTRY_API struct wolfsentry_host_platform_interface *wolfsentry_get_hpi(struct wolfsentry_context *wolfsentry);
    /*!< \brief Return a pointer to the `wolfsentry_host_platform_interface` associated with the supplied `wolfsentry_context`, mainly for passing to `wolfsentry_alloc_thread_context()`, `wolfsentry_free_thread_context()`, `wolfsentry_lock_init()`, and `wolfsentry_lock_alloc()`. */

typedef void (*wolfsentry_cleanup_callback_t)(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *cleanup_arg);
    /*!< \brief Function type to pass to wolfsentry_cleanup_push() */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_cleanup_push(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_cleanup_callback_t handler,
    void *arg);
   /*!< \brief Register `handler` to be called at shutdown with arg `arg`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_cleanup_pop(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    int execute_p);
   /*!< \brief Remove the most recently registered and unpopped handler from the cleanup stack, and if `execute_p` is nonzero, call it with the `arg` with which it was registered. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_cleanup_all(
    WOLFSENTRY_CONTEXT_ARGS_IN);
   /*!< \brief Iteratively call wolfsentry_cleanup_pop(), executing each handler as it is popped, passing it the `arg` with which it was registered. */

/*! @} (end wolfsentry_init) */

/*! \addtogroup wolfsentry_addr_family
 *  @{
 */

/* must return _BUFFER_TOO_SMALL and set *addr_internal_bits to an
 * accurate value when supplied with a NULL output buf ptr.
 * whenever _BUFFER_TOO_SMALL is returned, *addr_*_bits must be set to an
 * accurate value.
 */
typedef wolfsentry_errcode_t (*wolfsentry_addr_family_parser_t)(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *addr_text,
    int addr_text_len,
    byte *addr_internal,
    wolfsentry_addr_bits_t *addr_internal_bits);
    /*!< \brief Function type for parsing handler, to pass to wolfsentry_addr_family_handler_install() */

typedef wolfsentry_errcode_t (*wolfsentry_addr_family_formatter_t)(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const byte *addr_internal,
    unsigned int addr_internal_bits,
    char *addr_text,
    int *addr_text_len);
    /*!< \brief Function type for formatting handler, to pass to wolfsentry_addr_family_handler_install() */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_handler_install(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_addr_family_t family_bynumber,
    const char *family_byname, /* if defined(WOLFSENTRY_PROTOCOL_NAMES), must not be NULL, else ignored. */
    int family_byname_len,
    wolfsentry_addr_family_parser_t parser,
    wolfsentry_addr_family_formatter_t formatter,
    int max_addr_bits);
    /*!< \brief Install handlers for an address family */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_get_parser(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_addr_family_t family,
    wolfsentry_addr_family_parser_t *parser);
    /*!< \brief Retrieve the parsing handler for an address family */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_get_formatter(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_addr_family_t family,
    wolfsentry_addr_family_formatter_t *formatter);
    /*!< \brief Retrieve the formatting handler for an address family */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_handler_remove_bynumber(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_addr_family_t family_bynumber,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Remove the handlers for an address family */

struct wolfsentry_addr_family_bynumber;

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_drop_reference(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_addr_family_bynumber *family_bynumber,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Release an address family record previously returned by wolfsentry_addr_family_ntop() */

#ifdef WOLFSENTRY_PROTOCOL_NAMES

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_handler_remove_byname(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *family_byname,
    int family_byname_len,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Remove the handlers for an address family */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_pton(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *family_name,
    int family_name_len,
    wolfsentry_addr_family_t *family_number);
    /*!< \brief Look up an address family by name, returning its number */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_ntop(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_addr_family_t family,
    struct wolfsentry_addr_family_bynumber **addr_family,
    const char **family_name);
    /*!< \brief Look up an address family by number, returning a pointer to its name.  The caller must release \p addr_family, using wolfsentry_addr_family_drop_reference(), when done accessing \p family_name. */

#endif /* WOLFSENTRY_PROTOCOL_NAMES */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_max_addr_bits(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_addr_family_t family,
    wolfsentry_addr_bits_t *bits);
    /*!< \brief Look up the max address size for an address family identified by number */

/*! @} (end wolfsentry_addr_family) */

/*! \addtogroup wolfsentry_event
 * @{
 */

/*!
   \brief Initializes a wolfsentry_eventconfig struct with the defaults from the wolfsentry context. If
   no wolfsentry context is provided this will initialize to zero.

   \param wolfsentry the wolfsentry context
   \param config the pointer to the config to initialize

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_eventconfig_init(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_eventconfig *config);
/*!
   \brief Checks the config for self-consistency and validity

   \param config the pointer to the config to check

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_eventconfig_check(
    const struct wolfsentry_eventconfig *config);

/*! @} (end wolfsentry_event) */

/*! \addtogroup wolfsentry_init
 * @{
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_init_ex(
    struct wolfsentry_build_settings caller_build_settings,
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(const struct wolfsentry_host_platform_interface *hpi),
    const struct wolfsentry_eventconfig *config,
    struct wolfsentry_context **wolfsentry,
    wolfsentry_init_flags_t flags);
/*!< \brief Variant of wolfsentry_init() that accepts a \p flags argument, for additional control over configuration. */

/*!
   \brief Allocates and initializes the wolfsentry context

   \param caller_build_settings Pass #wolfsentry_build_settings here (definition is in `wolfsentry_settings.h`)
   \param config a pointer to a `wolfsentry_eventconfig` to use (can be NULL)
   \param wolfsentry a pointer to the wolfsentry_context to initialize

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa struct wolfsentry_host_platform_interface
   \sa WOLFSENTRY_CONTEXT_ARGS_IN_EX
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_init(
    struct wolfsentry_build_settings caller_build_settings,
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(const struct wolfsentry_host_platform_interface *hpi),
    const struct wolfsentry_eventconfig *config,
    struct wolfsentry_context **wolfsentry);
/*!
   \brief Get the default config from a wolfsentry context

   \param config a config struct to be loaded with a copy of the config

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_defaultconfig_get(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_eventconfig *config);
/*!
   \brief Updates mutable fields of the default config (all but wolfsentry_eventconfig::route_private_data_size and wolfsentry_eventconfig::route_private_data_alignment)

   \param config the config struct to load from

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_defaultconfig_update(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_eventconfig *config);
/*!
   \brief Flushes the route, event, and user value tables from the wolfsentry context

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_flush(WOLFSENTRY_CONTEXT_ARGS_IN);
/*!
   \brief Frees the wolfsentry context and the tables within it. The wolfsentry context will be a pointer
   to NULL upon success

   \return WOLFSENTRY_IS_SUCCESS(ret) is true, and `*wolfsentry` is `NULL`, on success.

   \sa wolfsentry_context_shutdown
   \sa WOLFSENTRY_CONTEXT_ARGS_IN_EX
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_free(WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_context **wolfsentry));
/*!
   \brief Shut down wolfSentry, freeing all resources.  Gets an exclusive lock on the context, then calls wolfsentry_context_free().

   \return WOLFSENTRY_IS_SUCCESS(ret) is true, and `*wolfsentry` is `NULL`, on success.

   \sa wolfsentry_context_free
   \sa WOLFSENTRY_CONTEXT_ARGS_IN_EX
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_context **wolfsentry));
/*!
   \brief Disable automatic dispatch of actions on the wolfsentry context

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_inhibit_actions(WOLFSENTRY_CONTEXT_ARGS_IN);
/*!
   \brief Re-enable automatic dispatch of actions on the wolfsentry context

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_enable_actions(WOLFSENTRY_CONTEXT_ARGS_IN);

/*! \brief Flags to be `OR`d together to control the dynamics of wolfsentry_context_clone() and other cloning functions. */
typedef enum {
    WOLFSENTRY_CLONE_FLAG_NONE = 0U,
        /*!< \brief Default behavior @hideinitializer */
    WOLFSENTRY_CLONE_FLAG_AS_AT_CREATION = 1U << 0U,
        /*!< \brief Don't copy routes, events, or user values, and copy default config as it existed upon return from `wolfsentry_init()`.  Action and address family tables are copied as usual. @hideinitializer */
    WOLFSENTRY_CLONE_FLAG_NO_ROUTES = 2U << 0U
        /*!< \brief Don't copy route table entries.  Route table config, default config, and all other tables, are copied as usual. @hideinitializer */
} wolfsentry_clone_flags_t;
/*!
   \brief Clones a wolfsentry context

   \param clone the destination wolfsentry context, should be a pointer to a NULL pointer as this function will malloc
   \param flags set to WOLFSENTRY_CLONE_FLAG_AT_CREATION to use the config at the creation of the original wolfsentry context instead of the current configuration

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_clone(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_context **clone, wolfsentry_clone_flags_t flags);
/*!
   \brief Swaps information between two wolfsentry contexts

   \param wolfsentry2 the new context to swap into the primary context

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_exchange(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_context *wolfsentry2);

/*! @} (end wolfsentry_init) */

/*! \addtogroup wolfsentry_thread_context
 *  @{
 */

#ifdef WOLFSENTRY_THREADSAFE

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex(
    WOLFSENTRY_CONTEXT_ARGS_IN);
    /*!< \brief Calls wolfsentry_lock_mutex() on the context. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex_abstimed(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct timespec *abs_timeout);
    /*!< \brief Calls wolfsentry_lock_mutex_abstimed() on the context. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex_abstimed_ex(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct timespec *abs_timeout,
    wolfsentry_lock_flags_t flags);
    /*!< \brief variant of wolfsentry_context_lock_mutex_abstimed() with a `flags` arg. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex_timed(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_time_t max_wait);
    /*!< \brief Calls wolfsentry_lock_mutex_timed() on the context. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex_timed_ex(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_time_t max_wait,
    wolfsentry_lock_flags_t flags);
    /*!< \brief variant of wolfsentry_context_lock_mutex_timed() with a `flags` arg. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared(
    WOLFSENTRY_CONTEXT_ARGS_IN);
    /*!< \brief Calls wolfsentry_lock_shared() on the context. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared_abstimed(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct timespec *abs_timeout);
    /*!< \brief Calls wolfsentry_lock_shared_abstimed() on the context. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared_with_reservation_abstimed(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct timespec *abs_timeout);
    /*!< \brief Calls wolfsentry_lock_shared_abstimed() on the context, with the `WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO` flag. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared_timed(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_time_t max_wait);
    /*!< \brief Calls wolfsentry_lock_shared_timed() on the context. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared_with_reservation_timed(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_time_t max_wait);
    /*!< \brief Calls wolfsentry_lock_shared_timed() on the context, with the `WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO` flag. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_unlock(
    WOLFSENTRY_CONTEXT_ARGS_IN);
    /*!< \brief Calls wolfsentry_lock_unlock() on the context. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_unlock_and_abandon_reservation(
    WOLFSENTRY_CONTEXT_ARGS_IN);
    /*!< \brief Calls wolfsentry_lock_unlock() on the context, with the `WOLFSENTRY_LOCK_FLAG_ABANDON_RESERVATION_TOO` flag. */

#else /* !WOLFSENTRY_THREADSAFE */

#define wolfsentry_context_lock_mutex(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_mutex_abstimed(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_mutex_timed(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared_abstimed(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared_with_reservation_abstimed(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared_timed(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_unlock(x) WOLFSENTRY_ERROR_ENCODE(OK)

#endif /* WOLFSENTRY_THREADSAFE */

/*! @} (end wolfsentry_thread_context) */

#define WOLFSENTRY_LENGTH_NULL_TERMINATED (-1)
    /*!< \brief A macro with a painfully long name that can be passed as a length to routines taking a length argument, to signify that the associated string is null-terminated and its length should be computed on that basis. @hideinitializer */

/*! \addtogroup wolfsentry_table_ent_header
 *  @{
 */

/*!
   \brief Get the object type from a wolfsentry object pointer

   \param object a pointer to the object

   \return the object type, or WOLFSENTRY_OBJECT_TYPE_UNINITED on error.
*/
WOLFSENTRY_API wolfsentry_object_type_t wolfsentry_get_object_type(const void *object);

/*!
   \brief Get the ID from a wolfsentry object pointer

   \param object a pointer to the object

   \return the object ID, or WOLFSENTRY_OBJECT_TYPE_UNINITED on error.
*/
WOLFSENTRY_API wolfsentry_ent_id_t wolfsentry_get_object_id(const void *object);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_table_ent_get_by_id(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_ent_id_t id,
    struct wolfsentry_table_ent_header **ent);
    /*!< \brief Retrieve an object pointer given its ID.  Lock must be obtained before entry, and ent is only valid while lock is held, or if wolfsentry_object_checkout() is called for the object. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_object_checkout(WOLFSENTRY_CONTEXT_ARGS_IN, void *object);
    /*!< \brief Increment the refcount for an object, making it safe from deallocation until wolfsentry_object_release().  Caller must have a context lock on entry. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_object_release(WOLFSENTRY_CONTEXT_ARGS_IN, void *object, wolfsentry_action_res_t *action_results);
    /*!< \brief Decrement the refcount for an object, deallocating it if no references remain.  Caller does not need to have a context lock on entry. */

/*!
   \brief Get the number of inserts into a table

   \param table the table to get the inserts for

   \returns the total insert count
*/
WOLFSENTRY_API wolfsentry_hitcount_t wolfsentry_table_n_inserts(struct wolfsentry_table_header *table);

/*!
   \brief Get the number of deletes from a table

   \param table the table to get the deletes for

   \returns the total delete count
*/
WOLFSENTRY_API wolfsentry_hitcount_t wolfsentry_table_n_deletes(struct wolfsentry_table_header *table);

/*! @} (end wolfsentry_table_ent_header) */

/*! \addtogroup wolfsentry_route
 * @{
 */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_check_flags_sensical(
    wolfsentry_route_flags_t flags);
/*!< \brief Check the self-consistency of \p flags. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert_into_table(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    wolfsentry_ent_id_t *id,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Variant of wolfsentry_route_insert() that takes an explicit \p route_table */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert_by_exports_into_table(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_route_exports *route_exports,
    wolfsentry_ent_id_t *id,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Variant of wolfsentry_route_insert() that accepts the new route as ::wolfsentry_route_exports, and takes an explicit \p route_table */

/*!
   \brief Insert a route into the route table

   \param caller_arg an arbitrary pointer to be passed to callbacks
   \param remote the remote sockaddr for the route
   \param local the local sockaddr for the route
   \param flags flags for the route
   \param event_label a label for the route
   \param event_label_len the length of the event_label parameter
   \param id the object ID
   \param action_results a pointer to results of the insert action

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    wolfsentry_ent_id_t *id,
    wolfsentry_action_res_t *action_results);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert_by_exports(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_route_exports *route_exports,
    wolfsentry_ent_id_t *id,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Variant of wolfsentry_route_insert() that accepts the new route as ::wolfsentry_route_exports */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert_into_table_and_check_out(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    struct wolfsentry_route **route,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Variant of wolfsentry_route_insert() that takes an explicit \p route_table, and returns the inserted route, which the caller must eventually drop using wolfsentry_route_drop_reference() or wolfsentry_object_release() */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert_by_exports_into_table_and_check_out(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_route_exports *route_exports,
    struct wolfsentry_route **route,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Variant of wolfsentry_route_insert() that accepts the new route as ::wolfsentry_route_exports, takes an explicit \p route_table, and returns the inserted route, which the caller must eventually drop using wolfsentry_route_drop_reference() or wolfsentry_object_release() */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert_and_check_out(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    struct wolfsentry_route **route,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Variant of wolfsentry_route_insert() that returns the inserted route, which the caller must eventually drop using wolfsentry_route_drop_reference() or wolfsentry_object_release() */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert_by_exports_and_check_out(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_route_exports *route_exports,
    struct wolfsentry_route **route,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Variant of wolfsentry_route_insert() that accepts the new route as ::wolfsentry_route_exports and returns the inserted route, which the caller must eventually drop using wolfsentry_route_drop_reference() or wolfsentry_object_release() */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_delete_from_table(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_res_t *action_results,
    int *n_deleted);
    /*!< \brief Variant of wolfsentry_route_delete() that takes an explicit \p route_table */

/*!
   \brief Delete route from the route table.  The supplied parameters, including the flags, must match the route exactly, else `ITEM_NOT_FOUND` will result.  To avoid fidgety parameter matching, use wolfsentry_route_delete_by_id().  The supplied trigger event, if any, is passed to action handlers, and has no bearing on route matching.

   \param caller_arg an arbitrary pointer to be passed to callbacks
   \param remote the remote sockaddr for the route
   \param local the local sockaddr for the route
   \param flags flags for the route
   \param trigger_label a label for the trigger event (or null)
   \param trigger_label_len the length of the trigger_label parameter
   \param action_results a pointer to results of the insert action -- all bits are cleared on entry.
   \param n_deleted a counter for the number of entries deleted

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_delete(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *trigger_label,
    int trigger_label_len,
    wolfsentry_action_res_t *action_results,
    int *n_deleted);

/*!
   \brief Delete a route from its route table using its ID.  The supplied trigger event, if any, is passed to action handlers, and has no bearing on route matching.

   \param caller_arg an arbitrary pointer to be passed to callbacks
   \param id the object ID, as returned by wolfsentry_route_insert() or wolfsentry_get_object_id()
   \param trigger_label a label for a trigger event (or null)
   \param trigger_label_len the length of the trigger_label parameter
   \param action_results a pointer to results of the insert action -- all bits are cleared on entry.

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_delete_by_id(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_ent_id_t id,
    const char *trigger_label,
    int trigger_label_len,
    wolfsentry_action_res_t *action_results);

/*!
   \brief Get a pointer to the internal route table.  Caller must have a lock on the context at entry.

   \param table a pointer to a pointer to a table which will be filled

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa #WOLFSENTRY_SHARED_OR_RETURN()
   \sa #WOLFSENTRY_UNLOCK_AND_RETURN()
   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_main_table(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table **table);

/*!
   \brief Open a cursor to interate through a routes table.  Caller must have a lock on the context at entry.

   \param table a pointer to the table to open the cursor on
   \param cursor a pointer to a pointer for the cursor

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa #WOLFSENTRY_SHARED_OR_RETURN()
   \sa #WOLFSENTRY_UNLOCK_AND_RETURN()
   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_start(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor **cursor);

/*!
   \brief Reset the cursor to the beginning of a table

   \param table the table for the cursor
   \param cursor a poiner for the cursor

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_seek_to_head(
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor);

/*!
   \brief Move the cursor to the end of a table

   \param table the table for the cursor
   \param cursor a poiner for the cursor

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_seek_to_tail(
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor);

/*!
   \brief Get the current position for the table cursor

   \param table the table for the cursor
   \param cursor a poiner for the cursor
   \param route a pointer to a pointer for the returned route

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_current(
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_route **route);

/*!
   \brief Get the previous position for the table cursor

   \param table the table for the cursor
   \param cursor a poiner for the cursor
   \param route a pointer to a pointer for the returned route

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_prev(
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_route **route);

/*!
   \brief Get the next position for the table cursor

   \param table the table for the cursor
   \param cursor a poiner for the cursor
   \param route a pointer to a pointer for the returned route

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_next(
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_route **route);

/*!
   \brief Frees the table cursor.  Caller must have a lock on the context at entry.

   \param table the table for the cursor
   \param cursor a poiner to a pointer for the cursor to free

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa #WOLFSENTRY_SHARED_OR_RETURN()
   \sa #WOLFSENTRY_UNLOCK_AND_RETURN()
   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_end(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor **cursor);

/*!
   \brief Set a table's default policy

   \param table the table to set the policy for
   \param default_policy the policy to set

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_default_policy_set(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t default_policy);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_default_policy_set(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_action_res_t default_policy);
    /*!< \brief variant of wolfsentry_route_table_default_policy_set() that uses the main route table implicitly, and takes care of context locking. */

/*!
   \brief Get a table's default policy.  Caller must have a lock on the context at entry.

   \param table the table to set the policy for
   \param default_policy the policy retrieved

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa wolfsentry_defaultconfig_update()
   \sa #WOLFSENTRY_SHARED_OR_RETURN()
   \sa #WOLFSENTRY_UNLOCK_AND_RETURN()
   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_default_policy_get(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *default_policy);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_default_policy_get(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_action_res_t *default_policy);
    /*!< \brief variant of wolfsentry_route_table_default_policy_get() that uses the main route table implicitly.  Caller must have a lock on the context at entry. */

/*!
   \brief Increments a reference counter for a route

   \param table the table to get the route from
   \param remote the remote sockaddr
   \param local the local sockaddr
   \param flags flags for the route
   \param event_label a label for the event
   \param event_label_len the length of the event_label parameter
   \param exact_p set to 1 for exact matches only
   \param inexact_matches wildcard flags hit
   \param route the route returned

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_reference(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route_table *table,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    int exact_p,
    wolfsentry_route_flags_t *inexact_matches,
    struct wolfsentry_route **route);

/*!
   \brief Decrease a reference counter for a route

   \param route the route to drop the reference for
   \param action_results a pointer to results of the action

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_drop_reference(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_clear_default_event(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table);
    /*!< \brief Clear an event previously set by wolfsentry_route_table_set_default_event(). */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_set_default_event(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    const char *event_label,
    int event_label_len);
    /*!< \brief Set an event to be used as a foster parent event for routes with no parent event of their own. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_get_default_event(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    char *event_label,
    int *event_label_len);
    /*!< \brief Get the event, if any, set by wolfsentry_route_table_set_default_event() */

/*!
    \brief Retrieve the default route in a route table, chiefly to pass to wolfsentry_route_update_flags().

    Caller must have a shared or mutex lock on the context at entry, but can release the lock on return and safely continue to access or update the route.  Caller must drop the route when done, using wolfsentry_route_drop_reference() or wolfsentry_object_release().

   \sa #WOLFSENTRY_SHARED_OR_RETURN()
   \sa #WOLFSENTRY_UNLOCK_FOR_RETURN()
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_fallthrough_route_get(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
    const struct wolfsentry_route **fallthrough_route);

/*!
    \brief Extract numeric address family and binary address pointers from a `wolfsentry_route`

    \p local_addr and \p remote_addr remain valid only as long as the wolfsentry lock
    is held (shared or exclusive), unless the route was obtained via
    wolfsentry_route_get_reference(), in which case it's valid until
    wolfsentry_route_drop_reference().
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_addrs(
    const struct wolfsentry_route *route,
    wolfsentry_addr_family_t *af,
    wolfsentry_addr_bits_t *local_addr_len,
    const byte **local_addr,
    wolfsentry_addr_bits_t *remote_addr_len,
    const byte **remote_addr);

/*!
   \brief Exports a route.

   \p route_exports remains valid only as long as the wolfsentry lock is held
   (shared or exclusive), unless the route was obtained via
   wolfsentry_route_get_reference(), in which case it's valid until
   wolfsentry_route_drop_reference().

   \param route the route to export
   \param route_exports the struct to export into

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_export(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route *route,
    struct wolfsentry_route_exports *route_exports);

/* returned wolfsentry_event remains valid only as long as the wolfsentry lock
 * is held (shared or exclusive), unless the route was obtained via
 * wolfsentry_route_get_reference(), in which case it's valid until
 * wolfsentry_route_drop_reference()..
 */
/*!
   \brief Get a parent event from a given route. Typically used in the wolfsentry_action_callback_t callback. Note: returned wolfsentry_event remains valid only as long as the wolfsentry lock is held (shared or exclusive).

   \param route a pointer to the route

   \return a pointer to the parent event

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API const struct wolfsentry_event *wolfsentry_route_parent_event(const struct wolfsentry_route *route);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_with_table(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_ent_id_t *id,
    wolfsentry_route_flags_t *inexact_matches,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Variant of wolfsentry_route_event_dispatch() that accepts an explicit \p route_table. */

/*!
   \brief Submit an event into wolfsentry and pass it through the filters. The action_results are cleared on entry, and can be checked to see what actions wolfsentry took, and what actions the caller should take (most saliently, #WOLFSENTRY_ACTION_RES_ACCEPT or #WOLFSENTRY_ACTION_RES_REJECT).  \p action_results can be filtered with constructs like `WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT)`

   \param remote the remote sockaddr details
   \param local the local sockaddr details
   \param flags the flags for the event, set to #WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN for an incoming event
   \param event_label an optional label for a trigger event
   \param event_label_len the length of event_label
   \param caller_arg an arbitrary pointer to be passed to action callbacks
   \param id an optional pointer to a ::wolfsentry_ent_id_t that will be set to the ID of the matched route, if any
   \param inexact_matches details for inexact matches
   \param action_results a pointer to a ::wolfsentry_action_res_t, which will be used to record actions taken and to be taken

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s). */
    wolfsentry_ent_id_t *id,
    wolfsentry_route_flags_t *inexact_matches,
    wolfsentry_action_res_t *action_results);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_with_table_with_inited_result(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_ent_id_t *id,
    wolfsentry_route_flags_t *inexact_matches,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Variant of wolfsentry_route_event_dispatch() that accepts an explicit \p route_table, and doesn't clear \p action_results on entry. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_with_inited_result(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s). */
    wolfsentry_ent_id_t *id,
    wolfsentry_route_flags_t *inexact_matches,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Variant of wolfsentry_route_event_dispatch() that doesn't clear \p action_results on entry. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_id(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_ent_id_t id,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_action_res_t *action_results
    );
    /*!< \brief Variant of wolfsentry_route_event_dispatch() that preselects the matched route by ID, mainly for use by application code that tracks ID/session relationships. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_id_with_inited_result(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_ent_id_t id,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_action_res_t *action_results
    );
    /*!< \brief Variant of wolfsentry_route_event_dispatch() that preselects the matched route by ID, and doesn't clear \p action_results on entry, mainly for use by application code that tracks ID/session relationships. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_route(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_action_res_t *action_results
    );
    /*!< \brief Variant of wolfsentry_route_event_dispatch() that preselects the matched route by ID, mainly for use by application code that tracks route/session relationships. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_route_with_inited_result(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_action_res_t *action_results
    );
    /*!< \brief Variant of wolfsentry_route_event_dispatch() that preselects the matched route by ID, and doesn't clear \p action_results on entry, mainly for use by application code that tracks route/session relationships. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_max_purgeable_routes_get(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_hitcount_t *max_purgeable_routes);
    /*!< \brief Retrieve the current limit for ephemeral routes in \p table.  Caller must have a lock on the context at entry. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_max_purgeable_routes_set(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_hitcount_t max_purgeable_routes);
    /*!< \brief Set the limit for ephemeral routes in \p table.  Caller must have a mutex on the context at entry. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_max_purgeable_idle_time_get(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_time_t *max_purgeable_idle_time);
    /*!< \brief Retrieve the current absolute maximum idle time for a purgeable route (controls forced purges of routes with nonzero ::wolfsentry_route_metadata_exports.connection_count).  Caller must have a lock on the context at entry. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_max_purgeable_idle_time_set(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_time_t max_purgeable_idle_time);
    /*!< \brief Set the maximum idle time for a purgeable route (controls forced purges of routes with nonzero ::wolfsentry_route_metadata_exports.connection_count).  Default is no limit.  Caller must have a mutex on the context at entry. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_purge_time_set(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    wolfsentry_time_t purge_after);
    /*!< \brief Set the time after which `route` in `table` is to be subject to automatic purge.  `0` sets the route as persistent.  Caller must have a mutex on the context at entry. */

/*!
   \brief Purges all stale (expired) routes from \p table

   \param table the table to purge from
   \param action_results the result bit field, pooling results from all constituent operations

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_stale_purge(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *action_results);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_stale_purge_one(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Variant of wolfsentry_route_stale_purge() that purges at most one stale route, to limit time spent working. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_stale_purge_one_opportunistically(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Variant of wolfsentry_route_stale_purge() that purges at most one stale route, and only if the context lock is uncontended. */

/*!
   \brief Flush routes from a given table

   \param table the table to purge
   \param action_results the result bit field, pooling results from all constituent operations

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_flush_table(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *action_results);

/*!
   \brief Clears the #WOLFSENTRY_ROUTE_FLAG_INSERT_ACTIONS_CALLED flag on all routes in the table

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa wolfsentry_route_bulk_insert_actions()
   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_bulk_clear_insert_action_status(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_action_res_t *action_results);

/*!
   \brief Executes the insert actions for all routes in the table that don't have #WOLFSENTRY_ROUTE_FLAG_INSERT_ACTIONS_CALLED set.

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa wolfsentry_route_bulk_clear_insert_action_status()
   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_bulk_insert_actions(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_action_res_t *action_results);

/*!
   \brief Gets the private data for a given route

   \param route the route to get the data from
   \param private_data a pointer to a pointer that will receive the data
   \param private_data_size a pointer that will recieve the size of the data

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_private_data(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    void **private_data,
    size_t *private_data_size);

/*!
   \brief Gets the flags for a route

   \param route the route to get the flags for
   \param flags a pointer to receive the flags

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_flags(
    const struct wolfsentry_route *route,
    wolfsentry_route_flags_t *flags);

/*!
   \brief Gets the metadata for a route

   \param route the route to get the metadata for
   \param metadata a pointer to a pointer to receive the metadata

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_metadata(
    const struct wolfsentry_route *route,
    struct wolfsentry_route_metadata_exports *metadata);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_reset_metadata_exports(
    struct wolfsentry_route_exports *route_exports);
    /*!< \brief clear metadata counts (wolfsentry_route_metadata_exports::purge_after, wolfsentry_route_metadata_exports::connection_count, wolfsentry_route_metadata_exports::derogatory_count, and wolfsentry_route_metadata_exports::commendable_count) in ::wolfsentry_route_exports to prepare for use with wolfsentry_route_insert_by_exports() */

/*!
   \brief Update the route flags

   \param route the route to update the flags for
   \param flags_to_set new flags to set
   \param flags_to_clear old flags to clear
   \param flags_before a pointer that will be filled with the flags before the change
   \param flags_after a pointer that will be filled with flags after the change
   \param action_results the results bit field

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_update_flags(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    wolfsentry_route_flags_t flags_to_set,
    wolfsentry_route_flags_t flags_to_clear,
    wolfsentry_route_flags_t *flags_before,
    wolfsentry_route_flags_t *flags_after,
    wolfsentry_action_res_t *action_results);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_increment_derogatory_count(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    int count_to_add,
    int *new_derogatory_count_ptr);
    /*!< \brief Increase the derogatory event count of a route */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_increment_commendable_count(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    int count_to_add,
    int *new_commendable_count);
    /*!< \brief Increase the commendable event count of a route */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_reset_derogatory_count(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    int *old_derogatory_count_ptr);
    /*!< \brief Reset the derogatory event count of a route */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_reset_commendable_count(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    int *old_commendable_count_ptr);
    /*!< \brief Reset the commendable event count of a route */

/*!
   \brief Set wildcard flags for a route

   \param route the route to set the flags for
   \param wildcards_to_set the wildcards to be set

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_set_wildcard(
    struct wolfsentry_route *route,
    wolfsentry_route_flags_t wildcards_to_set);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_format_address(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_addr_family_t sa_family,
    const byte *addr,
    unsigned int addr_bits,
    char *buf,
    int *buflen);
    /*!< \brief Render a binary address in human-readable form to a buffer */

#if defined(WOLFSENTRY_PROTOCOL_NAMES) || defined(WOLFSENTRY_JSON_DUMP_UTILS) || !defined(WOLFSENTRY_NO_JSON)

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_flag_assoc_by_flag(
    wolfsentry_route_flags_t flag,
    const char **name);
    /*!< \brief Retrieve the name of a route flag, given its numeric value.  Note that \p flag must have exactly one bit set, else `ITEM_NOT_FOUND` will be returned. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_flag_assoc_by_name(
    const char *name,
    int len,
    wolfsentry_route_flags_t *flag);
    /*!< \brief Retrieve the numeric value of a route flag, given its name. */

#endif /* WOLFSENTRY_PROTOCOL_NAMES || WOLFSENTRY_JSON_DUMP_UTILS || !WOLFSENTRY_NO_JSON */

#if !defined(WOLFSENTRY_NO_JSON) || defined(WOLFSENTRY_JSON_DUMP_UTILS)

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_format_json(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route *r,
    unsigned char **json_out,
    size_t *json_out_len,
    wolfsentry_format_flags_t flags);
    /*!< \brief Render a route to an output buffer, in JSON format, advancing the output buffer pointer by the length of the rendered output. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_dump_json_start(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor **cursor,
    unsigned char **json_out,
    size_t *json_out_len,
    wolfsentry_format_flags_t flags);
    /*!< \brief Start a rendering loop to export the route table contents as a JSON document that is valid input for wolfsentry_config_json_feed() or wolfsentry_config_json_oneshot(), advancing the output buffer pointer by the length of the rendered output, and decrementing \p json_out_len by the same amount.  Caller must have a shared or exclusive lock on the context at entry. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_dump_json_next(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor,
    unsigned char **json_out,
    size_t *json_out_len,
    wolfsentry_format_flags_t flags);
    /*!< \brief Render a route within a loop started with wolfsentry_route_table_dump_json_start(), advancing the output buffer pointer by the length of the rendered output, and decrementing \p json_out_len by the same amount. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_dump_json_end(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor **cursor,
    unsigned char **json_out,
    size_t *json_out_len,
    wolfsentry_format_flags_t flags);
    /*!< \brief Finish a rendering loop started with wolfsentry_route_table_dump_json_start(), advancing the output buffer pointer by the length of the rendered output, and decrementing \p json_out_len by the same amount. */

#endif /* !WOLFSENTRY_NO_JSON || WOLFSENTRY_JSON_DUMP_UTILS */

#ifndef WOLFSENTRY_NO_STDIO_STREAMS
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_render_flags(wolfsentry_route_flags_t flags, FILE *f);
    /*!< \brief Render route flags in human-readable form to a stream. */

/*!
   \brief Renders route information to a file pointer

   \param r the route to render
   \param f the pointer to render to

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_render(WOLFSENTRY_CONTEXT_ARGS_IN, const struct wolfsentry_route *r, FILE *f);
/*!
   \brief Renders route exports information to a file pointer

   \param r the route exports to render
   \param f the pointer to render to

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_exports_render(WOLFSENTRY_CONTEXT_ARGS_IN, const struct wolfsentry_route_exports *r, FILE *f);
#endif

/*! @} (end wolfsentry_route) */

/*! \addtogroup wolfsentry_action
 * @{
 */

/*!
   \brief Insert a new action into wolfsentry

   \param label the label for the action
   \param label_len the length of the label, use WOLFSENTRY_LENGTH_NULL_TERMINATED for a NUL terminated string
   \param flags set flags for the action
   \param handler a callback handler when the action commences
   \param handler_arg an arbitrary pointer for the handler callback
   \param id the returned ID for the inserted action

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_insert(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *label,
    int label_len,
    wolfsentry_action_flags_t flags,
    wolfsentry_action_callback_t handler,
    void *handler_arg,
    wolfsentry_ent_id_t *id);

/*!
   \brief Delete an action from wolfsentry

   \param label the label of the action to delete
   \param label_len the length of the label, use WOLFSENTRY_LENGTH_NULL_TERMINATED for a NUL terminated string
   \param action_results the returned result of the delete

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_delete(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *label,
    int label_len,
    wolfsentry_action_res_t *action_results);

/*!
   \brief Flush all actions from wolfsentry

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_flush_all(WOLFSENTRY_CONTEXT_ARGS_IN);

/*!
   \brief Get a reference to an action

   \param label the label of the action to get the reference for
   \param label_len the length of the label, use WOLFSENTRY_LENGTH_NULL_TERMINATED for a NUL terminated string
   \param action a pointer to a pointer for the action returned

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_get_reference(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *label,
    int label_len,
    struct wolfsentry_action **action);

/*!
   \brief Drop a reference to an action

   \param action the action to drop the reference for
   \param action_results a pointer to the result of the function

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_drop_reference(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action *action,
    wolfsentry_action_res_t *action_results);

/*!
   \brief Get the label for an action. This is the internal pointer to the label so should not be freed by the application.

   \param action the action to get the label for

   \returns the label for the action
*/
WOLFSENTRY_API const char *wolfsentry_action_get_label(const struct wolfsentry_action *action);

/*!
   \brief Get the flags for an action

   \param action the action to get the flags for
   \param flags the flags to be returned

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_get_flags(
    struct wolfsentry_action *action,
    wolfsentry_action_flags_t *flags);

/*!
   \brief Update the flags for an action

   \param action the action to update
   \param flags_to_set new flags to set
   \param flags_to_clear old flags to clear
   \param flags_before the flags before the change
   \param flags_after the flags after the change

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_update_flags(
    struct wolfsentry_action *action,
    wolfsentry_action_flags_t flags_to_set,
    wolfsentry_action_flags_t flags_to_clear,
    wolfsentry_action_flags_t *flags_before,
    wolfsentry_action_flags_t *flags_after);

/*! @} (end wolfsentry_action) */

/*! \addtogroup wolfsentry_event
 * @{
 */

/*!
   \brief Insert an event into wolfsentry

   \param label the label for the event
   \param label_len the length of the label
   \param priority the priorty of the event
   \param config event configuration details
   \param flags the flags for the event
   \param id the returned ID for the event

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_insert(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *label,
    int label_len,
    wolfsentry_priority_t priority,
    const struct wolfsentry_eventconfig *config,
    wolfsentry_event_flags_t flags,
    wolfsentry_ent_id_t *id);

/*!
   \brief Delete an event from wolfsentry

   \param label the label of the even to delete
   \param label_len the length of the label
   \param action_results the result of the delete action

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_delete(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *label,
    int label_len,
    wolfsentry_action_res_t *action_results);

/*!
   \brief Flush all events from wolfsentry

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_flush_all(WOLFSENTRY_CONTEXT_ARGS_IN);

/*!
   \brief Get the label for an event. This is the internal pointer to the label so should not be freed by the application.

   \param event the event to get the label for

   \returns the label for the event
*/
WOLFSENTRY_API const char *wolfsentry_event_get_label(const struct wolfsentry_event *event);

/*!
   \brief Get the flags for an event

   \param event the event to get the flags for

   \return the current flags of the event
*/
WOLFSENTRY_API wolfsentry_event_flags_t wolfsentry_event_get_flags(const struct wolfsentry_event *event);

/*!
   \brief Get the configuration for an event

   \param label the label for the event to get the config for
   \param label_len the length of the label
   \param config the configuration returned

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_get_config(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *label,
    int label_len,
    struct wolfsentry_eventconfig *config);

/*!
   \brief Update the configuration for an event

   \param label the label for the event to get the config for
   \param label_len the length of the label
   \param config the updated configuration

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_update_config(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *label,
    int label_len,
    const struct wolfsentry_eventconfig *config);

/*!
   \brief Get a reference to an event

   \param label the label of the event to get the reference for
   \param label_len the length of the label, use WOLFSENTRY_LENGTH_NULL_TERMINATED for a NUL terminated string
   \param event a pointer to a pointer for the event returned

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_get_reference(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *label,
    int label_len,
    struct wolfsentry_event **event);

/*!
   \brief Drop a reference to an event

   \param event the event to drop the reference for
   \param action_results a pointer to the result of the function

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_drop_reference(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_event *event,
    wolfsentry_action_res_t *action_results);

/*!
   \brief Prepend an action into an event

   \param event_label the label of the event to prepend the action into
   \param event_label_len the length of the event_label
   \param which_action_list the action list of the event to update
   \param action_label the label of the action to insert
   \param action_label_len the length of the action_label

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_prepend(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t which_action_list,
    const char *action_label,
    int action_label_len);

/*!
   \brief Append an action into an event

   \param event_label the label of the event to append the action into
   \param event_label_len the length of the event_label
   \param which_action_list the action list of the event to update
   \param action_label the label of the action to insert
   \param action_label_len the length of the action_label

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_append(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t which_action_list,
    const char *action_label,
    int action_label_len);

/*!
   \brief Insert an action into an event after another action

   \param event_label the label of the event to insert the action into
   \param event_label_len the length of the event_label
   \param which_action_list the action list of the event to update
   \param action_label the label of the action to insert
   \param action_label_len the length of the action_label
   \param point_action_label the label of the action to insert after
   \param point_action_label_len the length of the point_action_label

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_insert_after(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t which_action_list,
    const char *action_label,
    int action_label_len,
    const char *point_action_label,
    int point_action_label_len);

/*!
   \brief Delete an action from an event

   \param event_label the label of the event to delete the action from
   \param event_label_len the length of the event_label
   \param which_action_list the action list of the event to update
   \param action_label the label of the action to delete
   \param action_label_len the length of the action_label

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_delete(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t which_action_list,
    const char *action_label,
    int action_label_len);

/*!
   \brief Set an auxiliary event for an event

   \param event_label the parent event label
   \param event_label_len the length of the event_label
   \param aux_event_label the aux event label
   \param aux_event_label_len the length of the aux event_label

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_set_aux_event(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *event_label,
    int event_label_len,
    const char *aux_event_label,
    int aux_event_label_len);

WOLFSENTRY_API const struct wolfsentry_event *wolfsentry_event_get_aux_event(
    const struct wolfsentry_event *event);
    /*!< \brief Retrieve an auxiliary event previously set with wolfsentry_event_set_aux_event(). */

/*!
   \brief Open a cursor for the actions in an event.  Caller must have a lock on the context at entry.

   \param event_label the event label to open the iterator for
   \param event_label_len the length of the event_label
   \param which_action_list the action list of the event to list
   \param cursor a pointer to a pointer for the cursor to open

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa #WOLFSENTRY_SHARED_OR_RETURN()
   \sa #WOLFSENTRY_UNLOCK_AND_RETURN()
   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_list_start(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t which_action_list,
    struct wolfsentry_action_list_ent **cursor);

/*!
   \brief Get the next action in an event cursor.  Caller must have a lock on the context at entry.

   \param cursor a pointer to a pointer for the cursor
   \param action_label a pointer to a pointer to the returned action_label
   \param action_label_len the length of action_label

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa #WOLFSENTRY_SHARED_OR_RETURN()
   \sa #WOLFSENTRY_UNLOCK_AND_RETURN()
   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_list_next(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list_ent **cursor,
    const char **action_label,
    int *action_label_len);

/*!
   \brief End iteration started with wolfsentry_event_action_list_start().  Caller must have a lock on the context at entry.

   \param cursor a pointer to a pointer for the cursor

   \return WOLFSENTRY_IS_SUCCESS(ret) is true on success.

   \sa #WOLFSENTRY_SHARED_OR_RETURN()
   \sa #WOLFSENTRY_UNLOCK_AND_RETURN()
   \sa WOLFSENTRY_CONTEXT_ARGS_IN
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_list_done(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list_ent **cursor);

/*! @} (end wolfsentry_event) */

#ifdef WOLFSENTRY_HAVE_JSON_DOM
#include <wolfsentry/centijson_dom.h>
#endif

/*! \addtogroup wolfsentry_kv
 * @{
 */

/*! \brief enum to represent the type of a user-defined value */
typedef enum {
    WOLFSENTRY_KV_NONE = 0,
    WOLFSENTRY_KV_NULL,
    WOLFSENTRY_KV_TRUE,
    WOLFSENTRY_KV_FALSE,
    WOLFSENTRY_KV_UINT,
    WOLFSENTRY_KV_SINT,
    WOLFSENTRY_KV_FLOAT,
    WOLFSENTRY_KV_STRING,
    WOLFSENTRY_KV_BYTES,
    WOLFSENTRY_KV_JSON,
    WOLFSENTRY_KV_FLAG_READONLY = 1<<30
} wolfsentry_kv_type_t;

#define WOLFSENTRY_KV_FLAG_MASK WOLFSENTRY_KV_FLAG_READONLY
    /*!< \brief A bit mask to retain only the flag bits in a `wolfsentry_kv_type_t`. @hideinitializer */

/*! \brief public structure for passing user-defined values in/out of wolfSentry */
struct wolfsentry_kv_pair {
    int key_len;
        /*!< \brief the length of the key, not including the terminating null */
    wolfsentry_kv_type_t v_type;
        /*!< \brief the type of value */
    union {
        uint64_t v_uint;
            /*!< \brief The value when `v_type` is `WOLFSENTRY_KV_UINT` */
        int64_t v_sint;
            /*!< \brief The value when `v_type` is `WOLFSENTRY_KV_SINT` */
        double v_float;
            /*!< \brief The value when `v_type` is `WOLFSENTRY_KV_FLOAT` */
        size_t string_len;
            /*!< \brief The length of the value when `v_type` is `WOLFSENTRY_KV_STRING` */
        size_t bytes_len;
            /*!< \brief The length of the value when `v_type` is `WOLFSENTRY_KV_BYTES` */
#ifdef WOLFSENTRY_HAVE_JSON_DOM
        JSON_VALUE v_json;
            /*!< \brief The value when `v_type` is `WOLFSENTRY_KV_JSON` */ /* 16 bytes */
#endif
    } a;
    byte b[WOLFSENTRY_FLEXIBLE_ARRAY_SIZE];
        /*!< \brief A flexible-length buffer to hold the key, and for strings and bytes, the data.
         *
         * For atomic values and `WOLFSENTRY_KV_JSON`, this is just the key, with a terminating null at the end.  For `WOLFSENTRY_KV_STRING` and `WOLFSENTRY_KV_BYTES`, the value itself appears right after the key with its terminating null.
         */
};

#define WOLFSENTRY_KV_KEY_LEN(kv) ((kv)->key_len)
    /*!< \brief Evaluates to the length of the key of a `wolfsentry_kv_pair`. @hideinitializer */
#define WOLFSENTRY_KV_KEY(kv) ((char *)((kv)->b))
    /*!< \brief Evaluates to the key of a `wolfsentry_kv_pair`. @hideinitializer */
#define WOLFSENTRY_KV_TYPE(kv) ((uint32_t)(kv)->v_type & ~(uint32_t)WOLFSENTRY_KV_FLAG_MASK)
    /*!< \brief Evaluates to the type of a `wolfsentry_kv_pair`, with flag bits masked out. @hideinitializer */
#define WOLFSENTRY_KV_V_UINT(kv) ((kv)->a.v_uint)
    /*!< \brief Evaluates to the `uint64_t` value of a `wolfsentry_kv_pair` of type `WOLFSENTRY_KV_UINT`. @hideinitializer */
#define WOLFSENTRY_KV_V_SINT(kv) ((kv)->a.v_sint)
    /*!< \brief Evaluates to the `int64_t` value of a `wolfsentry_kv_pair` of type `WOLFSENTRY_KV_INT`. @hideinitializer */
#define WOLFSENTRY_KV_V_FLOAT(kv) ((kv)->a.v_float)
    /*!< \brief Evaluates to the `double` value of a `wolfsentry_kv_pair` of type `WOLFSENTRY_KV_FLOAT`. @hideinitializer */
#define WOLFSENTRY_KV_V_STRING_LEN(kv) ((kv)->a.string_len)
    /*!< \brief Evaluates to the `size_t` length of the value of a `wolfsentry_kv_pair` of type `WOLFSENTRY_KV_STRING`. @hideinitializer */
#define WOLFSENTRY_KV_V_STRING(kv) ((char *)((kv)->b + (kv)->key_len + 1))
    /*!< \brief Evaluates to the `char *` value of a `wolfsentry_kv_pair` of type `WOLFSENTRY_KV_STRING`. @hideinitializer */
#define WOLFSENTRY_KV_V_BYTES_LEN(kv) ((kv)->a.bytes_len)
    /*!< \brief Evaluates to the `size_t` length of the value of a `wolfsentry_kv_pair` of type `WOLFSENTRY_KV_BYTES`. @hideinitializer */
#define WOLFSENTRY_KV_V_BYTES(kv) ((kv)->b + (kv)->key_len + 1)
    /*!< \brief Evaluates to the `byte *` value of a `wolfsentry_kv_pair` of type `WOLFSENTRY_KV_BYTES`. @hideinitializer */
#ifdef WOLFSENTRY_HAVE_JSON_DOM
#define WOLFSENTRY_KV_V_JSON(kv) (&(kv)->a.v_json)
    /*!< \brief Evaluates to the `JSON_VALUE *` value of a `wolfsentry_kv_pair` of type `WOLFSENTRY_KV_JSON`. @hideinitializer */
#endif

typedef wolfsentry_errcode_t (*wolfsentry_kv_validator_t)(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_pair *kv);
    /*!< Function type for user-supplied value validators. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_set_validator(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_kv_validator_t validator,
    wolfsentry_action_res_t *action_results);
    /*!< \brief Install a supplied `wolfsentry_kv_validator_t` to validate all user values before inserting them into the value table. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_set_mutability(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    int mutable);
    /*!< \brief Set the user-defined value with the designated `key` as readwrite (`mutable`=1) or readonly (`mutable`=0). A readonly value cannot be changed or deleted. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_mutability(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    int *mutable);
    /*!< \brief Query the mutability of the user-defined value with the designated `key`.  Readonly value cannot be changed or deleted. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_type(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    wolfsentry_kv_type_t *type);
    /*!< \brief Returns the type of the value with the designated `key`, using `WOLFSENTRY_KV_TYPE()`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_delete(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len);
    /*!< \brief Deletes the value with the designated `key`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_null(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    int overwrite_p);
    /*!< \brief Inserts or overwrites a `WOLFSENTRY_KV_NULL` value with the designated `key`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_bool(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    wolfsentry_kv_type_t value,
    int overwrite_p);
    /*!< \brief Inserts or overwrites a `WOLFSENTRY_KV_TRUE` or `WOLFSENTRY_KV_FALSE` value with the designated `key`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_bool(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    wolfsentry_kv_type_t *value);
    /*!< \brief Gets a `WOLFSENTRY_KV_TRUE` or `WOLFSENTRY_KV_FALSE` value with the designated `key`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_uint(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    uint64_t value,
    int overwrite_p);
    /*!< \brief Inserts or overwrites a `WOLFSENTRY_KV_UINT` value with the designated `key`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_uint(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    uint64_t *value);
    /*!< \brief Gets a `WOLFSENTRY_KV_UINT` value with the designated `key`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_sint(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    int64_t value,
    int overwrite_p);
    /*!< \brief Inserts or overwrites a `WOLFSENTRY_KV_SINT` value with the designated `key`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_sint(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    int64_t *value);
    /*!< \brief Gets a `WOLFSENTRY_KV_UINT` value with the designated `key`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_double(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    double value,
    int overwrite_p);
    /*!< \brief Inserts or overwrites a `WOLFSENTRY_KV_FLOAT` value with the designated `key`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_float(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    double *value);
    /*!< \brief Gets a `WOLFSENTRY_KV_UINT` value with the designated `key`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_string(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    const char *value,
    int value_len,
    int overwrite_p);
    /*!< \brief Inserts or overwrites a `WOLFSENTRY_KV_STRING` value with the designated `key`. */

struct wolfsentry_kv_pair_internal;

/*! \brief Gets a `WOLFSENTRY_KV_STRING` value with the designated `key`.
 *
 * The `user_value_record` will be used to store a pointer to an internal structure,
 * which acts as a lease on the `value`.  This must be released with
 * `wolfsentry_user_value_release_record()` when done.
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_string(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    const char **value,
    int *value_len,
    struct wolfsentry_kv_pair_internal **user_value_record);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_bytes(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    const byte *value,
    int value_len,
    int overwrite_p);
    /*!< \brief Inserts or overwrites a `WOLFSENTRY_KV_BYTES` value with the designated `key` and a binary-clean `value`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_bytes_base64(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    const char *value,
    int value_len,
    int overwrite_p);
    /*!< \brief Inserts or overwrites a `WOLFSENTRY_KV_BYTES` value with the designated `key` and a base64-encoded `value`. */

/*! \brief Gets a `WOLFSENTRY_KV_BYTES` value with the designated `key`.
 *
 * The `user_value_record` will be used to store a pointer to an internal structure,
 * which acts as a lease on the `value`.  This must be released with
 * `wolfsentry_user_value_release_record()` when done.
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_bytes(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    const byte **value,
    int *value_len,
    struct wolfsentry_kv_pair_internal **user_value_record);

#ifdef WOLFSENTRY_HAVE_JSON_DOM
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_json(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    JSON_VALUE *value,
    int overwrite_p);
    /*!< \brief Inserts or overwrites a `WOLFSENTRY_KV_JSON` value with the designated `key` and a `value` from `json_dom_parse()` (or built up programmatically with the `centijson_value.h` API). */

/*! \brief Gets a `WOLFSENTRY_KV_JSON` value with the designated `key`.
 *
 * The `user_value_record` will be used to store a pointer to an internal structure,
 * which acts as a lease on the `value`.  This must be released with
 * `wolfsentry_user_value_release_record()` when done.
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_json(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    JSON_VALUE **value,
    struct wolfsentry_kv_pair_internal **user_value_record);
#endif /* WOLFSENTRY_HAVE_JSON_DOM */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_release_record(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_pair_internal **user_value_record);
    /*!< \brief Release a `user_value_record` from `wolfsentry_user_value_get_string()`, `wolfsentry_user_value_get_bytes()`, or `wolfsentry_user_value_get_json()`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_kv_pair_export(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_pair_internal *kv,
    const struct wolfsentry_kv_pair **kv_exports);
    /*!< \brief Extract the `struct wolfsentry_kv_pair` from a `struct wolfsentry_kv_pair_internal`.  Caller must have a shared or exclusive lock on the context. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_kv_type_to_string(
    wolfsentry_kv_type_t type,
    const char **out);
    /*!< \brief Return a human-readable rendering of a `wolfsentry_kv_type_t`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_kv_render_value(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_pair *kv,
    char *out,
    int *out_len);
    /*!< \brief Render `kv` in human-readable form to caller-preallocated buffer `out`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_values_iterate_start(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_cursor **cursor);
    /*!< \brief Start an iteration loop on the user values table of this context.  Caller must have a lock on the context at entry. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_values_iterate_seek_to_head(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_cursor *cursor);
    /*!< \brief Move the cursor to point to the start of the user values table.  Caller must have a lock on the context at entry. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_values_iterate_seek_to_tail(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_cursor *cursor);
    /*!< \brief Move the cursor to point to the end of the user values table.  Caller must have a lock on the context at entry. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_values_iterate_current(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_kv_pair_internal **kv);
    /*!< \brief Return the item to which the cursor currently points, without moving the cursor.  Caller must have a lock on the context at entry. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_values_iterate_prev(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_kv_pair_internal **kv);
    /*!< \brief Move the cursor to the previous item, and return it.  Caller must have a lock on the context at entry. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_values_iterate_next(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_kv_pair_internal **kv);
    /*!< \brief Move the cursor to the next item, and return it.  Caller must have a lock on the context at entry. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_values_iterate_end(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_cursor **cursor);
    /*!< \brief End an iteration loop started with wolfsentry_user_values_iterate_start().  Caller must have a lock on the context at entry. */

#define WOLFSENTRY_BASE64_DECODED_BUFSPC(buf, len) \
    (((((len)+3)/4)*3) - ((len) > 1 ? \
                          ((buf)[(len)-1] == '=') : \
                          0) \
     - ((len) > 2 ? ((buf)[(len)-2] == '=') : 0)) \
    /*!< \brief Given valid base64 string `buf` of length `len`, evaluates to the exact decoded length. @hideinitializer */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_base64_decode(
    const char *src,
    size_t src_len,
    byte *dest,
    size_t *dest_spc,
    int ignore_junk_p);
    /*!< \brief Convert base64-encoded input \p src to binary output \p dest, optionally ignoring (with nonzero \p ignore_junk_p) non-base64 characters in \p src. */

/*! @} (end wolfsentry_kv) */

#ifdef WOLFSENTRY_LWIP
    #include "wolfsentry/wolfsentry_lwip.h"
#endif

/* conditionally include wolfsentry_util.h last -- none of the above rely on it.
 */
#ifndef WOLFSENTRY_NO_UTIL_H
#include <wolfsentry/wolfsentry_util.h>
#endif

#endif /* WOLFSENTRY_H */
