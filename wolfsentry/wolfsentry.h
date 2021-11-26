/*
 * wolfsentry.h
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

#ifndef WOLFSENTRY_H
#define WOLFSENTRY_H

#ifndef BUILDING_LIBWOLFSENTRY
#include <wolfsentry/wolfsentry_options.h>
#endif

#ifdef WOLFSENTRY_USER_SETTINGS_FILE
#include WOLFSENTRY_USER_SETTINGS_FILE
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

#ifndef WOLFSENTRY_NO_STDINT_H
#include <stdint.h>
#endif

#ifndef WOLFSENTRY_NO_STDDEF_H
#include <stddef.h>
#endif

#ifndef WOLFSENTRY_NO_INTTYPES_H
#include <inttypes.h>
#endif

#ifndef WOLFSENTRY_NO_ASSERT_H
#include <assert.h>
#endif

#ifdef WOLFSENTRY_THREADSAFE
#ifndef WOLFSENTRY_NO_SEMAPHORE_H
#include <semaphore.h>
#endif
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

typedef unsigned char byte;

#include <wolfsentry/wolfsentry_af.h>

typedef uint16_t wolfsentry_proto_t;
typedef uint16_t wolfsentry_port_t;
#ifdef WOLFSENTRY_ENT_ID_TYPE
typedef WOLFSENTRY_ENT_ID_TYPE wolfsentry_ent_id_t;
#else
typedef uint32_t wolfsentry_ent_id_t;
#endif
#define WOLFSENTRY_ENT_ID_NONE 0
typedef uint16_t wolfsentry_addr_bits_t;
#ifdef WOLFSENTRY_HITCOUNT_TYPE
typedef WOLFSENTRY_HITCOUNT_TYPE wolfsentry_hitcount_t;
#else
typedef uint32_t wolfsentry_hitcount_t;
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
#define WOLFSENTRY_PRIORITY_NEXT 0

#ifndef __unused
#define __unused __attribute__((unused))
#endif

typedef uint32_t enumint_t;

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

#include <wolfsentry/wolfsentry_errcodes.h>

struct wolfsentry_context;

#ifdef WOLFSENTRY_THREADSAFE

struct wolfsentry_rwlock;

/*!
   \brief This initializes a semaphore lock structure created by the user

   \param lock the lock structure to initialize
   \param pshared the shared lock ID for the semaphore

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa wolfsentry_lock_alloc
   \sa wolfsentry_lock_destroy
   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_init(struct wolfsentry_rwlock *lock, int pshared);

/*!
   \brief Allocates and initializes a semaphore lock structure for use with wolfSentry.

   \param wolfsentry the wolfsentry context
   \param lock a pointer to a pointer of a lock structure to be allocated
   \param pshared the shared lock ID for the semaphore

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa wolfsentry_lock_init
   \sa wolfsentry_lock_free
   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE()
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_alloc(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock **lock, int pshared);

/*!
   \brief Attempts to get a shared lock

   \param lock a pointer to the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared(struct wolfsentry_rwlock *lock);

/*!
   \brief Attempts to get a shared lock with an absolute timeout

   \param lock a pointer to the lock
   \param abs_timeout the absolute timeout for the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared_abstimed(struct wolfsentry_rwlock *lock, struct timespec *abs_timeout);

/*!
   \brief Attempts to gain a shared lock with a relative timeout

   \param wolfsentry a pointer to the wolfsentry context
   \param lock a pointer to the lock
   \param max_wait how long to wait for the timeout

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared_timed(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock *lock, wolfsentry_time_t max_wait);

/*!
   \brief Attempt to lock a shared lock and reserve to right to escalate to an exclusive lock

   \param lock a pointer to the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared_and_reserve_shared2mutex(
    struct wolfsentry_rwlock *lock);

/*!
   \brief Attempts to lock a shared lock and reserve the right to escalate to an exclusive lock with an absolute timeout

   \param lock a pointer to the lock
   \param abs_timeout the absolute timeout for the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared_abstimed_and_reserve_shared2mutex(
    struct wolfsentry_rwlock *lock,
    struct timespec *abs_timeout);

/*!
   \brief Attempts to lock a shared lock and reserve the right to escalate to an exclusive lock with a relative timeout

   \param wolfsentry a pointer to the wolfsentry context
   \param lock a pointer to the lock
   \param max_wait how long to wait for the timeout

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared_timed_and_reserve_shared2mutex(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_rwlock *lock,
    wolfsentry_time_t max_wait);

/*!
   \brief Attempts to get an exclusive lock

   \param lock a pointer to the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_mutex(struct wolfsentry_rwlock *lock);

/*!
   \brief Attempts to get an exclusive lock with an absolute timeout

   \param lock a pointer to the lock
   \param abs_timeout the absolute timeout for the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_mutex_abstimed(struct wolfsentry_rwlock *lock, struct timespec *abs_timeout);

/*!
   \brief Attempts to gain an exclusive lock with a relative timeout

   \param wolfsentry a pointer to the wolfsentry context
   \param lock a pointer to the lock
   \param max_wait how long to wait for the timeout

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_mutex_timed(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock *lock, wolfsentry_time_t max_wait);

/*!
   \brief Attempt to de-escalate an exclusive lock to a shared lock on a semaphore

   \param lock a pointer to the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_mutex2shared(struct wolfsentry_rwlock *lock);

/*!
   \brief Attempt to de-escalate an exclusive lock to a shared lock on a
   semaphore, reserving the right to re-escalate to an exclusive lock.

   \param lock a pointer to the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_mutex2shared_and_reserve_shared2mutex(
    struct wolfsentry_rwlock *lock);

/*!
   \brief Escalate a shared lock to an exclusive lock

   \param lock a pointer to the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex(struct wolfsentry_rwlock *lock);

/*!
   \brief Attempt to de-escalate an exclusive lock to a shared lock on a semaphore with an absolute timeout

   \param lock a pointer to the lock
   \param abs_timeout the absolute timeout for the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_abstimed(struct wolfsentry_rwlock *lock, struct timespec *abs_timeout);

/*!
   \brief Attempt to de-escalate an exclusive lock to a shared lock on a semaphore with a relative timeout

   \param wolfsentry a pointer to the wolfsentry context
   \param lock a pointer to the lock
   \param max_wait how long to wait for the timeout

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_timed(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock *lock, wolfsentry_time_t max_wait);

/*!
   \brief Attempt to reserve an escalation of a shared lock to an exclusive lock

   \param lock a pointer to the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa wolfsentry_lock_shared2mutex_redeem
   \sa wolfsentry_lock_shared2mutex_redeem_abstimed
   \sa wolfsentry_lock_shared2mutex_redeem_timed
   \sa wolfsentry_lock_shared2mutex_abandon
   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_reserve(struct wolfsentry_rwlock *lock);

/*!
   \brief Redeem a reservation of a lock escalation from shared to exclusive

   \param lock a pointer to the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem(struct wolfsentry_rwlock *lock);

/*!
   \brief Redeem a reservation of a lock escalation from shared to exclusive with an absolute timeout

   \param lock a pointer to the lock
   \param abs_timeout the absolute timeout for the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem_abstimed(struct wolfsentry_rwlock *lock, struct timespec *abs_timeout);

/*!
   \brief Redeem a reservation of a lock escalation from shared to exclusive with a relative timeout

   \param wolfsentry a pointer to the wolfsentry context
   \param lock a pointer to the lock
   \param max_wait how long to wait for the timeout

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem_timed(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock *lock, wolfsentry_time_t max_wait);

/*!
   \brief Abandon a reservation of a lock escalation from shared to exclusive

   \param lock a pointer to the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_abandon(struct wolfsentry_rwlock *lock);

/*!
   \brief Check if the lock is a shared lock

   \param lock a pointer to the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK if
   it is shared lock. Or WOLFSENTRY_ERROR_ID_NOT_OK if it is not a shared lock.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_have_shared(struct wolfsentry_rwlock *lock);

/*!
   \brief Check if the lock is a exclusive lock

   \param lock a pointer to the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK if
   it is exclusive lock. Or WOLFSENTRY_ERROR_ID_NOT_OK if it is not a exclusive lock.

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_have_mutex(struct wolfsentry_rwlock *lock);

/*!
   \brief Unlock a lock

   \param lock a pointer to the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_unlock(struct wolfsentry_rwlock *lock);

/*!
   \brief Destroy a lock that was created with wolfsentry_lock_init()

   \param lock a pointer to the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa wolfsentry_lock_init
   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_destroy(struct wolfsentry_rwlock *lock);

/*!
   \brief Destroy and free a lock that was created with wolfsentry_lock_alloc(). The
   lock's pointer will also be set to NULL.

   \param wolfsentry a pointer to the wolfsentry context
   \param lock a pointer to a pointer to the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa wolfsentry_lock_alloc
   \sa WOLFSENTRY_ERROR_DECODE_ERROR_CODE
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_free(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock **lock);

#else /* !WOLFSENTRY_THREADSAFE */

#define wolfsentry_lock_init(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_alloc(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared_abstimed(y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared_and_reserve_shared2mutex(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared_abstimed_and_reserve_shared2mutex(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared_timed_and_reserve_shared2mutex(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_mutex_timed(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_mutex(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_mutex_abstimed(y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_mutex_timed(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_mutex2shared(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_mutex2shared_and_reserve_shared2mutex(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex_abstimed(y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex_timed(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex_reserve(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex_redeem(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex_redeem_abstimed(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex_redeem_timed(x, y, z) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_shared2mutex_abandon(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_have_shared(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_have_mutex(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_unlock(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_destroy(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_lock_free(x, y) WOLFSENTRY_ERROR_ENCODE(OK)

#endif /* WOLFSENTRY_THREADSAFE */

typedef enum {
    WOLFSENTRY_OBJECT_TYPE_TABLE,
    WOLFSENTRY_OBJECT_TYPE_ACTION,
    WOLFSENTRY_OBJECT_TYPE_EVENT,
    WOLFSENTRY_OBJECT_TYPE_ROUTE
} wolfsentry_object_type_t;

typedef enum {
    WOLFSENTRY_ACTION_FLAG_NONE       = 0U,
    WOLFSENTRY_ACTION_FLAG_DISABLED   = 1U << 0U
} wolfsentry_action_flags_t;

typedef enum {
    WOLFSENTRY_ACTION_TYPE_NONE = 0,
    WOLFSENTRY_ACTION_TYPE_POST = 1, /* called when an event is posted. */
    WOLFSENTRY_ACTION_TYPE_INSERT = 2, /* called when a route is added to the route table for this event. */
    WOLFSENTRY_ACTION_TYPE_MATCH = 3, /* called by wolfsentry_route_dispatch() for a route match. */
    WOLFSENTRY_ACTION_TYPE_DELETE = 4 /* called when a route associated with this event expires or is otherwise deleted. */
} wolfsentry_action_type_t;

#define WOLFSENTRY_ACTION_RES_USER_SHIFT 16U

typedef enum {
    WOLFSENTRY_ACTION_RES_NONE        = 0U,
    WOLFSENTRY_ACTION_RES_ACCEPT      = 1U << 0U,
    WOLFSENTRY_ACTION_RES_REJECT      = 1U << 1U,
    WOLFSENTRY_ACTION_RES_CONNECT     = 1U << 2U, /* when an action returns this, increment the connection count for the route. */
    WOLFSENTRY_ACTION_RES_DISCONNECT  = 1U << 3U, /* when an action returns this, decrement the connection count for the route. */
    WOLFSENTRY_ACTION_RES_DEROGATORY  = 1U << 4U,
    WOLFSENTRY_ACTION_RES_COMMENDABLE = 1U << 5U,
    WOLFSENTRY_ACTION_RES_CONTINUE    = 1U << 6U,
    WOLFSENTRY_ACTION_RES_STOP        = 1U << 7U, /* when an action returns this, don't evaluate any more actions in the current action list. */
    WOLFSENTRY_ACTION_RES_INSERT      = 1U << 8U, /* when an action returns this, that means the route should be added to the route table if it isn't already in it. */
    WOLFSENTRY_ACTION_RES_DELETE      = 1U << 9U, /* when an action returns this, delete the route from the table. */
    WOLFSENTRY_ACTION_RES_DEALLOCATED = 1U << 10U, /* when an API call returns this, the route and its associated ID were deallocated from the system. */
    WOLFSENTRY_ACTION_RES_ERROR       = 1U << 11U,
    WOLFSENTRY_ACTION_RES_USER_BASE   = 1U << WOLFSENTRY_ACTION_RES_USER_SHIFT /* start of user-defined results, with user-defined scheme (bitfield, sequential, or other) */
} wolfsentry_action_res_t;

#define WOLFSENTRY_ROUTE_DEFAULT_POLICY_MASK (WOLFSENTRY_ACTION_RES_ACCEPT | WOLFSENTRY_ACTION_RES_REJECT | WOLFSENTRY_ACTION_RES_STOP | WOLFSENTRY_ACTION_RES_ERROR)

struct wolfsentry_table_header;
struct wolfsentry_route;
struct wolfsentry_route_table;
struct wolfsentry_event;
struct wolfsentry_event_table;
struct wolfsentry_action;
struct wolfsentry_action_table;
struct wolfsentry_action_list;
struct wolfsentry_action_list_ent;
struct wolfsentry_cursor;

/*!
   \brief A callback that is triggered when an action is taken

   \param wolfsentry a pointer to the wolfsentry context
   \param action a pointer to action details
   \param handler_arg
   \param caller_arg
   \param trigger_event the event which triggered the action
   \param action_type the action type
   \param route_table a pointer to the route table
   \param route a pointer to the current route
   \param action_results a pointer to the action results

   \return 0 if there is no error
*/
typedef wolfsentry_errcode_t (*wolfsentry_action_callback_t)(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    struct wolfsentry_route_table *route_table,
    const struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results);

typedef enum {
    WOLFSENTRY_ROUTE_FLAG_NONE                           = 0U,
    WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD          = 1U<<0U,
    WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD      = 1U<<1U,
    WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD       = 1U<<2U,
    WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD             = 1U<<3U,
    WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD        = 1U<<4U,
    WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD         = 1U<<5U,
    WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD              = 1U<<6U,
    WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD        = 1U<<7U,
    WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD         = 1U<<8U,
    WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS           = 1U<<9U,
    WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN                   = 1U<<10U,
    WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT                  = 1U<<11U,

    /* immutable above here. */

    /* internal use from here... */
    WOLFSENTRY_ROUTE_FLAG_IN_TABLE                       = 1U<<12U,
    WOLFSENTRY_ROUTE_FLAG_PENDING_DELETE                 = 1U<<13U,
    WOLFSENTRY_ROUTE_FLAG_INSERT_ACTIONS_CALLED          = 1U<<14U,
    WOLFSENTRY_ROUTE_FLAG_DELETE_ACTIONS_CALLED          = 1U<<15U,

    /* ...to here. */

    /* mutable below here. */

    WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED                   = 1U<<16U,
    WOLFSENTRY_ROUTE_FLAG_GREENLISTED                    = 1U<<17U,
    WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_HITS                = 1U<<18U,
    WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_CURRENT_CONNECTIONS = 1U<<19U
} wolfsentry_route_flags_t;

#define WOLFSENTRY_ROUTE_IMMUTABLE_FLAGS ((wolfsentry_route_flags_t)WOLFSENTRY_ROUTE_FLAG_IN_TABLE - 1U)

#define WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD /* xxx backward compatibility */

struct wolfsentry_route_endpoint {
    wolfsentry_port_t sa_port;
    wolfsentry_addr_bits_t addr_len;
    byte extra_port_count;
    byte interface;
};

struct wolfsentry_route_metadata {
    wolfsentry_time_t insert_time;
    wolfsentry_time_t last_hit_time;
    wolfsentry_time_t last_penaltybox_time;
    uint16_t connection_count;
    uint16_t derogatory_count;
    uint16_t commendable_count;}
;

struct wolfsentry_route_exports {
    const char *parent_event_label;
    size_t parent_event_label_len;
    wolfsentry_route_flags_t flags;
    wolfsentry_family_t sa_family;
    wolfsentry_proto_t sa_proto;
    struct wolfsentry_route_endpoint remote, local;
    const byte *remote_address, *local_address;
    const wolfsentry_port_t *remote_extra_ports, *local_extra_ports;
    const struct wolfsentry_route_metadata *meta;
    void *private_data;
    size_t private_data_size;
};

typedef enum {
    WOLFSENTRY_EVENT_FLAG_NONE = 0,
    WOLFSENTRY_EVENT_FLAG_IS_PARENT_EVENT = 1U << 0U,
    WOLFSENTRY_EVENT_FLAG_IS_SUBEVENT = 2U << 0U
} wolfsentry_event_flags_t;

typedef enum {
    WOLFSENTRY_EVENTCONFIG_FLAG_NONE = 0U,
    WOLFSENTRY_EVENTCONFIG_FLAG_INHIBIT_ACTIONS = 1U << 0U
} wolfsentry_eventconfig_flags_t;

struct wolfsentry_eventconfig {
    size_t route_private_data_size;
    size_t route_private_data_alignment;
    uint32_t max_connection_count;
    wolfsentry_time_t penaltybox_duration; /* zero means time-unbounded. */
    wolfsentry_eventconfig_flags_t flags;
};

#define WOLFSENTRY_TIME_NEVER ((wolfsentry_time_t)0)

#ifndef WOLFSENTRY_MAX_ADDR_BYTES
#define WOLFSENTRY_MAX_ADDR_BYTES 16
#elif WOLFSENTRY_MAX_ADDR_BYTES * 8 > 0xffff
#error WOLFSENTRY_MAX_ADDR_BYTES * 8 must fit in a uint16_t.
#endif

#define WOLFSENTRY_SOCKADDR_MEMBERS(n) {        \
    wolfsentry_family_t sa_family;              \
    wolfsentry_proto_t sa_proto;                \
    wolfsentry_port_t sa_port;                  \
    wolfsentry_addr_bits_t addr_len;            \
    byte interface;                             \
    byte addr[n];                               \
}

struct wolfsentry_sockaddr WOLFSENTRY_SOCKADDR_MEMBERS(WOLFSENTRY_FLEXIBLE_ARRAY_SIZE);

#define WOLFSENTRY_SOCKADDR(n) struct WOLFSENTRY_SOCKADDR_MEMBERS(WOLFSENTRY_BITS_TO_BYTES(n))

typedef wolfsentry_errcode_t (*wolfsentry_get_time_cb_t)(void *context, wolfsentry_time_t *ts);
typedef wolfsentry_time_t (*wolfsentry_diff_time_cb_t)(wolfsentry_time_t earlier, wolfsentry_time_t later);
typedef wolfsentry_time_t (*wolfsentry_add_time_cb_t)(wolfsentry_time_t start_time, wolfsentry_time_t time_interval);
typedef wolfsentry_errcode_t (*wolfsentry_to_epoch_time_cb_t)(wolfsentry_time_t when, long *epoch_secs, long *epoch_nsecs);
typedef wolfsentry_errcode_t (*wolfsentry_from_epoch_time_cb_t)(long epoch_secs, long epoch_nsecs, wolfsentry_time_t *when);
typedef wolfsentry_errcode_t (*wolfsentry_interval_to_seconds_cb_t)(wolfsentry_time_t howlong, long *howlong_secs, long *howlong_nsecs);
typedef wolfsentry_errcode_t (*wolfsentry_interval_from_seconds_cb_t)(long howlong_secs, long howlong_nsecs, wolfsentry_time_t *howlong);

wolfsentry_errcode_t wolfsentry_time_now_plus_delta(struct wolfsentry_context *wolfsentry, wolfsentry_time_t td, wolfsentry_time_t *res);

#ifdef WOLFSENTRY_THREADSAFE
wolfsentry_errcode_t wolfsentry_time_to_timespec(struct wolfsentry_context *wolfsentry, wolfsentry_time_t t, struct timespec *ts);
wolfsentry_errcode_t wolfsentry_time_now_plus_delta_timespec(struct wolfsentry_context *wolfsentry, wolfsentry_time_t td, struct timespec *ts);
#endif

/*!
   \brief A callback function for a malloc() override to be set in the wolfsentry_allocator struct as part of wolfsentry_init
*/
typedef void *(*wolfsentry_malloc_cb_t)(void *context, size_t size);

/*!
   \brief A callback function for a free() override to be set in the wolfsentry_allocator struct as part of wolfsentry_init
*/
typedef void (*wolfsentry_free_cb_t)(void *context, void *ptr);

/*!
   \brief A callback function for a realloc() override to be set in the wolfsentry_allocator struct as part of wolfsentry_init
*/
typedef void *(*wolfsentry_realloc_cb_t)(void *context, void *ptr, size_t size);

/*!
   \brief A callback function for a posix_memalign() override to be set in the wolfsentry_allocator struct as part of wolfsentry_init
*/
typedef void *(*wolfsentry_memalign_cb_t)(void *context, size_t alignment, size_t size);

/*!
   \brief A callback function for a free() override used to free aligned allocations to be set in the wolfsentry_allocator struct as part of wolfsentry_init
*/
typedef void (*wolfsentry_free_aligned_cb_t)(void *context, void *ptr);

typedef wolfsentry_errcode_t (*wolfsentry_make_id_cb_t)(void *context, wolfsentry_object_type_t object_type, wolfsentry_ent_id_t *id);

struct wolfsentry_allocator {
    void *context;
    wolfsentry_malloc_cb_t malloc;
    wolfsentry_free_cb_t free;
    wolfsentry_realloc_cb_t realloc;
    wolfsentry_memalign_cb_t memalign;
    wolfsentry_free_aligned_cb_t free_aligned;
};

struct wolfsentry_timecbs {
    void *context;
    wolfsentry_get_time_cb_t get_time;
    wolfsentry_diff_time_cb_t diff_time;
    wolfsentry_add_time_cb_t add_time;
    wolfsentry_to_epoch_time_cb_t to_epoch_time;
    wolfsentry_from_epoch_time_cb_t from_epoch_time;
    wolfsentry_interval_to_seconds_cb_t interval_to_seconds;
    wolfsentry_interval_from_seconds_cb_t interval_from_seconds;
};

/*!
   \brief Calls the built-in malloc function. By default this is malloc() on POSIX systems.
*/
WOLFSENTRY_API void *wolfsentry_malloc(struct wolfsentry_context *wolfsentry, size_t size);

/*!
   \brief Calls the built-in free function. By default this is free() on POSIX systems.
*/
WOLFSENTRY_API void wolfsentry_free(struct wolfsentry_context *wolfsentry, void *ptr);

/*!
   \brief Calls the built-in realloc function. By default this is realloc() on POSIX systems.
*/
WOLFSENTRY_API void *wolfsentry_realloc(struct wolfsentry_context *wolfsentry, void *ptr, size_t size);

/*!
   \brief Calls the built-in memalign function. By default this is posix_memalign() on POSIX systems.
*/
WOLFSENTRY_API void *wolfsentry_memalign(struct wolfsentry_context *wolfsentry, size_t alignment, size_t size);

/*!
   \brief Calls the built-in free aligned function. By default this is free() on POSIX systems.
*/
WOLFSENTRY_API void wolfsentry_free_aligned(struct wolfsentry_context *wolfsentry, void *ptr);

/*!
   \brief Calls the built-in get_time function. By default this is get_time() on POSIX systems.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_get_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t *time_p);

/*!
   \brief Calls the built-in diff_time function. By default this is an internal function that simply subtracts of the parameters
*/
WOLFSENTRY_API wolfsentry_time_t wolfsentry_diff_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t later, wolfsentry_time_t earlier);

/*!
   \brief Calls the built-in add_time function. By default this is an internal function that adds the parameters.
*/
WOLFSENTRY_API wolfsentry_time_t wolfsentry_add_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t start_time, wolfsentry_time_t time_interval);

/*!
   \brief Calls the built-in to_epoch_time function. By default this is an internal function which converts a time_t to epoch time
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_to_epoch_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t when, long *epoch_secs, long *epoch_nsecs);

/*!
   \brief Calls the built-in from_epoch_time function. By default this is an internal function which converts epoch time to a time_t.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_from_epoch_time(struct wolfsentry_context *wolfsentry, long epoch_secs, long epoch_nsecs, wolfsentry_time_t *when);

/*!
   \brief Calls the built-in inverval_to_seconds function. By default this is the same internal function as wolfsentry_to_epoch_time.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_interval_to_seconds(struct wolfsentry_context *wolfsentry, wolfsentry_time_t howlong, long *howlong_secs, long *howlong_nsecs);

/*!
   \brief Calls the built-in inverval_from_seconds function. By default this is the same internal function as wolfsentry_from_epoch_time.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_interval_from_seconds(struct wolfsentry_context *wolfsentry, long howlong_secs, long howlong_nsecs, wolfsentry_time_t *howlong);

struct wolfsentry_host_platform_interface {
    struct wolfsentry_allocator *allocator;
    struct wolfsentry_timecbs *timecbs;
};

/*!
   \brief Initializes a wolfsentry_eventconfig struct with the defaults from the wolfsentry context. If
   no wolfsentry context is provided this will initialize to zero.

   \param wolfsentry the wolfsentry context
   \param config the pointer to the config to initialize

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_eventconfig_init(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_eventconfig *config);

/*!
   \brief Checks the config private data size and alignment for validity

   \param config the pointer to the config to check

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_eventconfig_check(
    const struct wolfsentry_eventconfig *config);

/*!
   \brief Initializes the wolfsentry context

   \param hpi a pointer to the host platform interface (can be NULL)
   \param config a pointer to configuration to use (can be NULL)
   \param wolfsentry a pointer to the wolfsentry context to initialize

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_init(
    const struct wolfsentry_host_platform_interface *hpi,
    const struct wolfsentry_eventconfig *config,
    struct wolfsentry_context **wolfsentry);

/*!
   \brief Get the default config from a wolfsentry context

   \param wolfsentry the wolfsentry context
   \param config a config struct to be loaded with a copy of the config

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_defaultconfig_get(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_eventconfig *config);

/*!
   \brief Updates the max_connection_count and penaltybox_duration for the default config

   \param wolfsentry the wolfsentry context
   \param config the config struct to load from

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_defaultconfig_update(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_eventconfig *config);

/*!
   \brief Flushes the routes and events tables from the wolfsentry context

   \param wolfsentry the wolfsentry context

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_flush(struct wolfsentry_context *wolfsentry);

/*!
   \brief Frees the wolfsentry context and the tables within it. The wolfsentry context will be a pointer
   to NULL upon success

   \param wolfsentry a pointer to a pointer of the wolfsentry context
   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_free(struct wolfsentry_context **wolfsentry);

/*!
   \brief An alias for wolfsentry_context_free()

   \sa wolfsentry_context_free
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_shutdown(struct wolfsentry_context **wolfsentry);

/*!
   \brief Disable actions on the wolfsentry context

   \param wolfsentry the wolfsentry context

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_inhibit_actions(struct wolfsentry_context *wolfsentry);

/*!
   \brief Re-enable actions on the wolfsentry context

   \param wolfsentry the wolfsentry context

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_enable_actions(struct wolfsentry_context *wolfsentry);

typedef enum {
    WOLFSENTRY_CLONE_FLAG_NONE = 0U,
    WOLFSENTRY_CLONE_FLAG_AS_AT_CREATION = 1U << 0U
} wolfsentry_clone_flags_t;

/*!
   \brief Clones a wolfsentry context

   \param wolfsentry the source wolfsentry context
   \param clone the destination wolfsentry context, should be a pointer to a NULL pointer as this function will malloc
   \param flags set to WOLFSENTRY_CLONE_FLAG_AT_CREATION to use the config at the creation of the original wolfsentry context instead of the current configuration

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_clone(struct wolfsentry_context *wolfsentry, struct wolfsentry_context **clone, wolfsentry_clone_flags_t flags);

/*!
   \brief Swaps information between two wolfsentry contexts

   \param wolfsentry1 the first context to swap
   \param wolfsentry2 the second context to swap

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_exchange(struct wolfsentry_context *wolfsentry1, struct wolfsentry_context *wolfsentry2);

#ifdef WOLFSENTRY_THREADSAFE

/*!
   \brief Lock the wolfsentry context lock with a shared lock

   \param wolfsentry a pointer to the wolfsentry context

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared(
    struct wolfsentry_context *wolfsentry);

/*!
   \brief Lock the wolfsentry context lock with a shared lock with an absolute timeout

   \param wolfsentry a pointer to the wolfsentry context
   \param abs_timeout the absolute timeout for the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared_abstimed(
    struct wolfsentry_context *wolfsentry,
    struct timespec *abs_timeout);

/*!
   \brief Lock the wolfsentry context lock with a shared lock with a relative timeout

   \param wolfsentry a pointer to the wolfsentry context
   \param max_wait how long to wait for the timeout

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared_timed(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_time_t max_wait);

/*!
   \brief Lock the wolfsentry context lock with a shared lock and reserve the right to escalate to an exclusive lock

   \param wolfsentry a pointer to the wolfsentry context

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared_and_reserve_shared2mutex(
    struct wolfsentry_context *wolfsentry);

/*!
   \brief Lock the wolfsentry context lock with a shared lock with an absolute timeout and reserve the right to escalate to an exclusive lock

   \param wolfsentry a pointer to the wolfsentry context
   \param abs_timeout the absolute timeout for the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared_abstimed_and_reserve_shared2mutex(
    struct wolfsentry_context *wolfsentry,
    struct timespec *abs_timeout);

/*!
   \brief Lock the wolfsentry context lock with a shared lock with a relative timeout and reserve the right to escalate to an exclusive lock

   \param wolfsentry a pointer to the wolfsentry context
   \param max_wait how long to wait for the timeout

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared_timed_and_reserve_shared2mutex(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_time_t max_wait);

/*!
   \brief Escalate the wolfsentry context lock to an exclusive lock

   \param wolfsentry a pointer to the wolfsentry context

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex(
    struct wolfsentry_context *wolfsentry);

/*!
   \brief Escalate the wolfsentry context lock to an exclusive lock with an absolute timeout

   \param wolfsentry a pointer to the wolfsentry context
   \param abs_timeout the absolute timeout for the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_abstimed(
    struct wolfsentry_context *wolfsentry,
    struct timespec *abs_timeout);

/*!
   \brief Escalate the wolfsentry context lock to an exclusive lock with a relative timeout

   \param wolfsentry a pointer to the wolfsentry context
   \oaram max_wait how long to wait for the timeout

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_timed(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_time_t max_wait);

/*!
   \brief Reserve the escalation of the wolfsentry context lock to an exclusive lock

   \param wolfsentry a pointer to the wolfsentry context

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_reserve(
    struct wolfsentry_context *wolfsentry);

/*!
   \brief Redeem the reserved escalation of the wolfsentry context lock to an exclusive lock

   \param wolfsentry a pointer to the wolfsentry context

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_redeem(
    struct wolfsentry_context *wolfsentry);

/*!
   \brief Redeem the reserved escalation of the wolfsentry context lock to an exclusive lock with an absolute timeout

   \param wolfsentry a pointer to the wolfsentry context
   \param abs_timeout the absolute timeout for the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_redeem_abstimed(
    struct wolfsentry_context *wolfsentry,
    struct timespec *abs_timeout);

/*!
   \brief Redeem the reserved escalation of the wolfsentry context lock to an exclusive lock with a relative timeout

   \param wolfsentry a pointer to the wolfsentry context
   \param max_wait how long to wait for the timeout

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_redeem_timed(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_time_t max_wait);

/*!
   \brief Abandon the escalation of the wolfsentry context lock to an exclusive lock

   \param wolfsentry a pointer to the wolfsentry context

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_abandon(
    struct wolfsentry_context *wolfsentry);

/*!
   \brief Lock the wolfsentry context lock with an exclusive lock

   \param wolfsentry a pointer to the wolfsentry context

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex(
    struct wolfsentry_context *wolfsentry);

/*!
   \brief Lock the wolfsentry context lock with an exclusive lock with an absolute timeout

   \param wolfsentry a pointer to the wolfsentry context
   \param abs_timeout the absolute timeout for the lock

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex_abstimed(
    struct wolfsentry_context *wolfsentry,
    struct timespec *abs_timeout);

/*!
   \brief Lock the wolfsentry context lock with an exclusive lock with a relative timeout

   \param wolfsentry a pointer to the wolfsentry context
   \param max_wait how long to wait for the timeout

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex_timed(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_time_t max_wait);

/*!
   \brief De-escalate the wolfsentry context lock to an shared lock

   \param wolfsentry a pointer to the wolfsentry context

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex2shared(
    struct wolfsentry_context *wolfsentry);

/*!
   \brief De-escalate the wolfsentry context lock to an shared lock and reserve the right to re-escalate to an exclusive lock

   \param wolfsentry a pointer to the wolfsentry context

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex2shared_and_reserve_shared2mutex(
    struct wolfsentry_context *wolfsentry);

/*!
   \brief Unlock the wolfsentry context lock

   \param wolfsentry a pointer to the wolfsentry context

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_unlock(
    struct wolfsentry_context *wolfsentry);

#else /* !WOLFSENTRY_THREADSAFE */

#define wolfsentry_context_lock_shared(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared_abstimed(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared_timed(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared_and_reserve_shared2mutex(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared_abstimed_and_reserve_shared2mutex(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared_timed_and_reserve_shared2mutex(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared2mutex(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared2mutex_abstimed(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared2mutex_timed(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared2mutex_reserve(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared2mutex_redeem(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared2mutex_redeem_abstimed(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared2mutex_redeem_timed(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_shared2mutex_abandon(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_mutex(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_mutex_abstimed(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_mutex_timed(x, y) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_mutex2shared(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_lock_mutex2shared_and_reserve_shared2mutex(x) WOLFSENTRY_ERROR_ENCODE(OK)
#define wolfsentry_context_unlock(x) WOLFSENTRY_ERROR_ENCODE(OK)

#endif /* WOLFSENTRY_THREADSAFE */

#ifndef WOLFSENTRY_MAX_LABEL_BYTES
#define WOLFSENTRY_MAX_LABEL_BYTES 32
#elif WOLFSENTRY_MAX_LABEL_BYTES > 0xff
#error WOLFSENTRY_MAX_LABEL_BYTES must fit in a byte.
#endif

#define WOLFSENTRY_LENGTH_NULL_TERMINATED -1

/*!
   \brief Get the ID from a wolfsentry table pointer

   \param table a pointer to the table

   \return the table entry ID
*/
WOLFSENTRY_API wolfsentry_ent_id_t wolfsentry_get_table_id(const void *table);

/*!
   \brief Get the ID from a wolfsentry entry pointer

   \param object a pointer to the entry

   \return the entry ID
*/
WOLFSENTRY_API wolfsentry_ent_id_t wolfsentry_get_object_id(const void *object);

/*!
   \brief Insert a route into the static table

   \param wolfsentry the wolfsentry context
   \param caller_arg an arbitrary pointer to be passed to callbacks
   \param remote the remote sockaddr for the entry
   \param local the local sockaddr for the entry
   \param flags flags for the entry
   \param event_label a label for the entry
   \param event_label_len the length of the event_label parameter
   \param id the entry ID
   \param action_results a pointer to results of the insert action

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert_static(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    wolfsentry_ent_id_t *id,
    wolfsentry_action_res_t *action_results);

/*!
   \brief Delete routes from the static table

   \param wolfsentry the wolfsentry context
   \param caller_arg an arbitrary pointer to be passed to callbacks
   \param remote the remote sockaddr for the entry
   \param local the local sockaddr for the entry
   \param flags flags for the entry
   \param trigger_label a label for the trigger
   \param trigger_label_len the length of the trigger_label parameter
   \param action_results a pointer to results of the insert action
   \param n_deleted a counter for the number of entries deleted

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_delete_static(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *trigger_label,
    int trigger_label_len,
    wolfsentry_action_res_t *action_results,
    int *n_deleted);

/*!
   \brief Delete routes from the dynamic table

   \param wolfsentry the wolfsentry context
   \param caller_arg an arbitrary pointer to be passed to callbacks
   \param remote the remote sockaddr for the entry
   \param local the local sockaddr for the entry
   \param flags flags for the entry
   \param trigger_label a label for the trigger
   \param trigger_label_len the length of the trigger_label parameter
   \param action_results a pointer to results of the insert action
   \param n_deleted a counter for the number of entries deleted

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_delete_dynamic(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *trigger_label,
    int trigger_label_len,
    wolfsentry_action_res_t *action_results,
    int *n_deleted);

/*!
   \brief Delete routes from the static and dynamic tables

   \param wolfsentry the wolfsentry context
   \param caller_arg an arbitrary pointer to be passed to callbacks
   \param remote the remote sockaddr for the entry
   \param local the local sockaddr for the entry
   \param flags flags for the entry
   \param trigger_label a label for the trigger
   \param trigger_label_len the length of the trigger_label parameter
   \param action_results a pointer to results of the insert action
   \param n_deleted a counter for the number of entries deleted

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_delete_everywhere(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *trigger_label,
    int trigger_label_len,
    wolfsentry_action_res_t *action_results,
    int *n_deleted);

/*!
   \brief Delete a route using an ID

   \param wolfsentry the wolfsentry context
   \param caller_arg an arbitrary pointer to be passed to callbacks
   \param id the entry ID
   \param event_label a label for the event
   \param event_label_len the length of the event_label parameter
   \param action_results a pointer to results of the insert action

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_delete_by_id(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_ent_id_t id,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_res_t *action_results);

/*!
   \brief Get a pointer to the internal static routes table

   \param wolfsentry the wolfsentry context
   \param table a pointer to a pointer to a table which will be filled

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_table_static(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table **table);

/*!
   \brief Get a pointer to the internal dynamic routes table

   \param wolfsentry the wolfsentry context
   \param table a pointer to a pointer to a table which will be filled

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_table_dynamic(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table **table);

/*!
   \brief Open a cursor to interate through a routes table

   \param wolfsentry the wolfsentry context
   \param table a pointer to the table to open the cursor on
   \param cursor a pointer to a pointer for the cursor

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_start(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor **cursor);

/*!
   \brief Reset the cursor to the beginning of a table

   \param wolfsentry the wolfsentry context
   \param table the table for the cursor
   \param cursor a poiner for the cursor

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_seek_to_head(
    const struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor);

/*!
   \brief Move the cursor to the end of a table

   \param wolfsentry the wolfsentry context
   \param table the table for the cursor
   \param cursor a poiner for the cursor

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_seek_to_tail(
    const struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor);

/*!
   \brief Get the current position for the table cursor

   \param wolfsentry the wolfsentry context
   \param table the table for the cursor
   \param cursor a poiner for the cursor
   \param route a pointer to a pointer for the returned route

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_current(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_route **route);

/*!
   \brief Get the previous position for the table cursor

   \param wolfsentry the wolfsentry context
   \param table the table for the cursor
   \param cursor a poiner for the cursor
   \param route a pointer to a pointer for the returned route

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_prev(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_route **route);

/*!
   \brief Get the next position for the table cursor

   \param wolfsentry the wolfsentry context
   \param table the table for the cursor
   \param cursor a poiner for the cursor
   \param route a pointer to a pointer for the returned route

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_next(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_route **route);

/*!
   \brief Frees the table cursor

   \param wolfsentry the wolfsentry context
   \param table the table for the cursor
   \param cursor a poiner to a pointer for the cursor to free

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_end(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor **cursor);

/*!
   \brief Set a table's default policy

   \param wolfsentry the wolfsentry context (currently unused)
   \param table the table to set the policy for
   \param the policy to set

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_default_policy_set(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t default_policy);

/*!
   \brief Get a table's default policy

   \param wolfsentry the wolfsentry context (currently unused)
   \param table the table to set the policy for
   \param the policy retrieved

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_default_policy_get(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *default_policy);

/*!
   \brief Increments a reference counter for a route

   \param wolfsentry the wolfsentry context
   \param table the table to get the route from
   \param remote the remote sockaddr
   \param local the local sockaddr
   \param flags flags for the entry
   \param event_label a label for the event
   \param event_label_len the length of the event_label parameter
   \param exact_p set to 1 for exact matches only
   \param inexact_matches wildcard flags hit
   \param route the route returned

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_reference(
    struct wolfsentry_context *wolfsentry,
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

   \param wolfsenry the wolfsentry object
   \param route the route to drop the reference for
   \param action_results a pointer to results of the action

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_drop_reference(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results);

/* route_exports remains valid only as long as the wolfsentry lock is held (shared or exclusive). */
/*!
   \brief Exports a route. Note: route_exports remains valid only as long as the wolfsentry lock is held (shared or exclusive).

   \param wolfsentry the wolfsentry object
   \param route the route to export
   \param route_exports the struct to export into

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_export(
    const struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route *route,
    struct wolfsentry_route_exports *route_exports);

/* returned wolfsentry_event remains valid only as long as the wolfsentry lock is held (shared or exclusive). */
/*!
   \brief Get a parent event from a given route. Typically used in the wolfsentry_action_callback_t callback. Note: returned wolfsentry_event remains valid only as long as the wolfsentry lock is held (shared or exclusive).

   \param a pointer to the route

   \return a pointer to the parent event
*/
WOLFSENTRY_API const struct wolfsentry_event *wolfsentry_route_parent_event(const struct wolfsentry_route *route);

/*!
   \brief Submit an event into wolfsentry and pass it through the filters. The action_results can be checked to see what action wolfsentry says should be taken.

   \param wolfsentry the wolfsentry object
   \param remote the remote sockaddr details
   \param local the local sockaddr details
   \param flags the flags for the event, set to WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN for an incoming event
   \param event_label a label for the event
   \param event_label_len the length of event_label
   \param caller_arg an arbitrary pointer to be passed to action callbacks
   \param id an ID for the entry
   \param inexact_matches details for inexact matches
   \param action_results a pointer which will be filled with the result action to be take, can be filtered like this WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT)

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success, greater than zero if there has been a rejection match.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s). */
    wolfsentry_ent_id_t *id,
    wolfsentry_route_flags_t *inexact_matches,
    wolfsentry_action_res_t *action_results);

/*!
   \brief Submit an event into wolfsentry and pass it through the filters. The action_results can be checked to see what action wolfsentry says should be taken. This variant allows pre-initialized action_results to signify the event type (WOLFSENTRY_ACTION_RES_CONNECT or WOLFSENTRY_ACTION_RES_DISCONNECT for example).

   \param wolfsentry the wolfsentry object
   \param remote the remote sockaddr details
   \param local the local sockaddr details
   \param flags the flags for the event, set to WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN for an incoming event
   \param event_label a label for the event
   \param event_label_len the length of event_label
   \param caller_arg an arbitrary pointer to be passed to action callbacks
   \param id an ID for the entry
   \param inexact_matches details for inexact matches
   \param action_results a pointer which will be filled with the result action to be take, can be filtered like this WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT)

   \return When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success, greater than zero if there has been a rejection match.
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_with_inited_result(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s). */
    wolfsentry_ent_id_t *id,
    wolfsentry_route_flags_t *inexact_matches,
    wolfsentry_action_res_t *action_results);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_id(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_ent_id_t id,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_action_res_t *action_results
    );

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_id_with_inited_result(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_ent_id_t id,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_action_res_t *action_results
    );

/*!
   \brief Purges stale routes from a table

   \param wolfsentry the wolfsentry object
   \param table the table to purge from

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_stale_purge(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *table);

/*!
   \brief Flush routes from a given table

   \param wolfsentry the wolfsentry object
   \param table the table to purge

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_flush_table(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *table);

/*!
   \brief Executes wolfsentry_route_clear_insert_action_status() on the whole dynamic table

   \param wolfsentry the wolfsentry object

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa wolfsentry_route_clear_insert_action_status
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_bulk_clear_insert_action_status(
    struct wolfsentry_context *wolfsentry);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_bulk_insert_actions(
    struct wolfsentry_context *wolfsentry);

/*!
   \brief Gets the private data for a given route

   \param wolfsentry the wolfsentry object
   \param route the route to get the data from
   \param private_data a pointer to a pointer that will receive the data
   \param private_data_size a pointer that will recieve the size of the data

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_private_data(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route *route,
    void **private_data,
    size_t *private_data_size);

/*!
   \brief Gets the flags for a route

   \param route the route to get the flags for
   \param flags a pointer to receive the flags

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_flags(
    struct wolfsentry_route *route,
    wolfsentry_route_flags_t *flags);

/*!
   \brief Gets the metadata for a route

   \param route the route to get the metadata for
   \param metadata a pointer to a pointer to receive the metadata

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_metadata(
    struct wolfsentry_route *route,
    const struct wolfsentry_route_metadata **metadata);

/*!
   \brief Update the route flags

   \param wolfsentry the wolfsentry object
   \param route the route to update the flags for
   \param flags_to_set new flags to set
   \param flags_to_clear old flags to clear
   \param flags_before a pointer that will be filled with the flags before the change
   \param flags_after a pointer that will be filled with flags after the change

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_update_flags(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route *route,
    wolfsentry_route_flags_t flags_to_set,
    wolfsentry_route_flags_t flags_to_clear,
    wolfsentry_route_flags_t *flags_before,
    wolfsentry_route_flags_t *flags_after);

/*!
   \brief Set wildcard flags for a route

   \param route the route to set the flags for
   \param wildcards_to_set the wildcards to be set

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_set_wildcard(
    struct wolfsentry_route *route,
    wolfsentry_route_flags_t wildcards_to_set);

#ifndef WOLFSENTRY_NO_STDIO

/*!
   \brief Renders route information to a file pointer

   \param r the route to render
   \param f the pointer to render to

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_render(const struct wolfsentry_route *r, FILE *f);

/*!
   \brief Renders route exports information to a file pointer

   \param r the route exports to render
   \param f the pointer to render to

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_exports_render(const struct wolfsentry_route_exports *r, FILE *f);
#endif

/*!
   \brief Insert a new action into wolfsentry

   \param wolfsentry the wolfsentry object
   \param label the label for the action
   \param label_len the length of the label, use WOLFSENTRY_LENGTH_NULL_TERMINATED for a NUL terminated string
   \param flags set flags for the action
   \param handler a callback handler when the action commences
   \param void an arbitrary pointer for the handler callback
   \param id the returned ID for the inserted action

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_insert(
    struct wolfsentry_context *wolfsentry,
    const char *label,
    int label_len,
    wolfsentry_action_flags_t flags,
    wolfsentry_action_callback_t handler,
    void *handler_arg,
    wolfsentry_ent_id_t *id);

/*!
   \brief Delete an action from wolfsentry

   \param wolfsentry the wolfsentry object
   \param label the label of the action to delete
   \param label_len the length of the label, use WOLFSENTRY_LENGTH_NULL_TERMINATED for a NUL terminated string
   \param action_results teh retured result of the delete

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_delete(
    struct wolfsentry_context *wolfsentry,
    const char *label,
    int label_len,
    wolfsentry_action_res_t *action_results);

/*!
   \brief Flush all actions from wolfsentry

   \param wolfsentry the wolfsentry object

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_flush_all(struct wolfsentry_context *wolfsentry);

/*!
   \brief Get a reference to an action

   \param wolfsentry the wolfsentry object
   \param label the label of the action to get the reference for
   \param label_len the length of the label, use WOLFSENTRY_LENGTH_NULL_TERMINATED for a NUL terminated string
   \param action a pointer to a pointer for the action returned

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_get_reference(
    struct wolfsentry_context *wolfsentry,
    const char *label,
    int label_len,
    struct wolfsentry_action **action);

/*!
   \brief Drop a reference to an action

   \param wolfsentry the wolfsentry object
   \param action the action to drop the reference for
   \param action_results a pointer to the result of the function

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_drop_reference(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_action *action,
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

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_get_flags(
    struct wolfsentry_action *action,
    wolfsentry_action_flags_t *flags);

/*!
   \brief Update the flags for an action

   \param flags_to_set new flags to set
   \param flags_to_clear old flags to clear
   \param flags_before the flags before the change
   \param flags_after the flags after the change

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_update_flags(
    struct wolfsentry_action *action,
    wolfsentry_action_flags_t flags_to_set,
    wolfsentry_action_flags_t flags_to_clear,
    wolfsentry_action_flags_t *flags_before,
    wolfsentry_action_flags_t *flags_after);

/*!
   \brief Insert an event into wolfsentry

   \param wolfsentry the wolfsentry object
   \param label the label for the event
   \param label_len the length of the label
   \param priority the priorty of the event
   \param config event configuration details
   \param flags the flags for the event
   \param id the returned ID for the event
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_insert(
    struct wolfsentry_context *wolfsentry,
    const char *label,
    int label_len,
    wolfsentry_priority_t priority,
    const struct wolfsentry_eventconfig *config,
    wolfsentry_event_flags_t flags,
    wolfsentry_ent_id_t *id);

/*!
   \brief Delete an event from wolfsentry

   \param wolfsentry the wolfsentry object
   \param label the label of the even to delete
   \param label_len the length of the label
   \param action_results the result of the delete action

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_delete(
    struct wolfsentry_context *wolfsentry,
    const char *label,
    int label_len,
    wolfsentry_action_res_t *action_results);

/*!
   \brief Flush all events from wolfsentry

   \param wolfsentry the wolfsentry object

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_flush_all(struct wolfsentry_context *wolfsentry);

/*!
   \brief Get the label for an event. This is the internal pointer to the label so should not be freed by the application.

   \param event the event to get the label for

   \returns the label for the event
*/
WOLFSENTRY_API const char *wolfsentry_event_get_label(const struct wolfsentry_event *event);

/*!
   \brief Get the flags for an event

   \param event the event to get the flags for
   \param flags the flags to be returned

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_event_flags_t wolfsentry_event_get_flags(const struct wolfsentry_event *event);

/*!
   \brief Get the configuration for an event

   \param wolfsentry the wolfsentry object
   \param label the label for the event to get the config for
   \param label_len the length of the label
   \param config the configuration returned

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_get_config(
    struct wolfsentry_context *wolfsentry,
    const char *label,
    int label_len,
    struct wolfsentry_eventconfig *config);

/*!
   \brief Update the configuration for an event

   \param wolfsentry the wolfsentry object
   \param label the label for the event to get the config for
   \param label_len the length of the label
   \param config the updated configuration

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_update_config(
    struct wolfsentry_context *wolfsentry,
    const char *label,
    int label_len,
    struct wolfsentry_eventconfig *config);

/*!
   \brief Get a reference to an event

   \param wolfsentry the wolfsentry object
   \param trigger_label the label of the event to get the reference for
   \param trigger_label_len the length of the label, use WOLFSENTRY_LENGTH_NULL_TERMINATED for a NUL terminated string
   \param event a pointer to a pointer for the event returned

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_get_reference(
    struct wolfsentry_context *wolfsentry,
    const char *trigger_label,
    int trigger_label_len,
    struct wolfsentry_event **event);

/*!
   \brief Drop a reference to an event

   \param wolfsentry the wolfsentry object
   \param event the event to drop the reference for
   \param action_results a pointer to the result of the function

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_drop_reference(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_event *event,
    wolfsentry_action_res_t *action_results);

/*!
   \brief Prepend an action into an event

   \param wolfsentry the wolfsentry object
   \param event_label the label of the event to prepend the action into
   \param event_label_len the length of the event_label
   \param action_label the label of the action to insert
   \param action_label_len the length of the action_label

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_prepend(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    const char *action_label,
    int action_label_len);

/*!
   \brief Append an action into an event

   \param wolfsentry the wolfsentry object
   \param event_label the label of the event to append the action into
   \param event_label_len the length of the event_label
   \param action_label the label of the action to insert
   \param action_label_len the length of the action_label

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_append(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    const char *action_label,
    int action_label_len);

/*!
   \brief Insert an action into an event after another action

   \param wolfsentry the wolfsentry object
   \param event_label the label of the event to insert the action into
   \param event_label_len the length of the event_label
   \param action_label the label of the action to insert
   \param action_label_len the length of the action_label
   \param point_action_label the label of the action to insert after
   \param point_action_label_len the length of the point_action_label

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_insert_after(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    const char *action_label,
    int action_label_len,
    const char *point_action_label,
    int point_action_label_len);

/*!
   \brief Delete an action from an event

   \param wolfsentry the wolfsentry object
   \param event_label the label of the event to delete the action from
   \param event_label_len the length of the event_label
   \param action_label the label of the action to delete
   \param action_label_len the length of the action_label

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_delete(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    const char *action_label,
    int action_label_len);

/*!
   \brief Set a subevent for an event

   \param wolfsentry the wolfsentry object
   \param event_label the main event label
   \param event_label_len the length of the event_label
   \param subevent_type the type of subevent
   \param subevent_label the subevent label
   \param subevent_label_len the length of the subevent_label

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_set_subevent(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t subevent_type,
    const char *subevent_label,
    int subevent_label_len);

/*!
   \brief Open a cursor for the actions in an event

   \param wolfsentry the wolfsentry object
   \param event_label the event label to open the iterator for
   \param event_label_len the length of the event_label
   \param cursor a pointer to a pointer for the cursor to open

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_list_start(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    struct wolfsentry_action_list_ent **cursor);

/*!
   \brief Get the next action in an event cursor

   \param wolfsentry the wolfsentry object
   \param cursor a pointer to a pointer for the cursor
   \param action_label a pointer to a pointer of the returned action_label
   \param action_label_len the length of action_label

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_list_next(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_action_list_ent **cursor,
    const char **action_label,
    int *action_label_len);

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

/* conditionally include wolfsentry_util.h last -- none of the above rely on it.
 */
#ifndef WOLFSENTRY_NO_UTIL_H
#include <wolfsentry/wolfsentry_util.h>
#endif

#endif /* WOLFSENTRY_H */
