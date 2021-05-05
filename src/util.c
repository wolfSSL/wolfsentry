/*
 * util.c
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

#include "wolfsentry_internal.h"

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_UTIL_C

#ifdef WOLFSENTRY_ERROR_STRINGS

const char *wolfsentry_errcode_source_string(wolfsentry_errcode_t e)
{
    enum wolfsentry_source_id i = (enum wolfsentry_source_id)WOLFSENTRY_ERROR_DECODE_SOURCE_ID(e);
    switch(i) {
    case WOLFSENTRY_SOURCE_ID_UNSET:
        return "<unset>";
    case WOLFSENTRY_SOURCE_ID_ACTIONS_C:
        return "actions.c";
    case WOLFSENTRY_SOURCE_ID_EVENTS_C:
        return "events.c";
    case WOLFSENTRY_SOURCE_ID_INTERNAL_C:
        return "internal.c";
    case WOLFSENTRY_SOURCE_ID_ROUTES_C:
        return "routes.c";
    case WOLFSENTRY_SOURCE_ID_UTIL_C:
        return "util.c";
    case WOLFSENTRY_SOURCE_ID_USER_BASE:
        break;
    }
    if (i >= WOLFSENTRY_SOURCE_ID_USER_BASE)
        return "user defined source";
    else
        return "unknown source";
}

const char *wolfsentry_errcode_error_string(wolfsentry_errcode_t e)
{
    enum wolfsentry_error_id i = (enum wolfsentry_error_id)WOLFSENTRY_ERROR_DECODE_ERROR_CODE(e);
    switch(i) {
    case WOLFSENTRY_ERROR_ID_OK:
        return "OK, operation succeeded";
    case WOLFSENTRY_ERROR_ID_NOT_OK:
        return "Error, not otherwise specified";
    case WOLFSENTRY_ERROR_ID_INTERNAL_CHECK_FATAL:
        return "Internal consistency check failed, not recoverable";
    case WOLFSENTRY_ERROR_ID_SYS_OP_FATAL:
        return "Host system operation failed, not recoverable";
    case WOLFSENTRY_ERROR_ID_SYS_OP_FAILED:
        return "Host system operation failed, normal error (recoverable)";
    case WOLFSENTRY_ERROR_ID_SYS_RESOURCE_FAILED:
        return "Host system resource exhausted/failed, normal error (recoverable)";
    case WOLFSENTRY_ERROR_ID_INCOMPATIBLE_STATE:
        return "Request was incompatible with current state of the designated object";
    case WOLFSENTRY_ERROR_ID_TIMED_OUT:
        return "Operation timed out";
    case WOLFSENTRY_ERROR_ID_INVALID_ARG:
        return "Supplied argument was invalid";
    case WOLFSENTRY_ERROR_ID_BUSY:
        return "A resource required to fulfill the request was unavailable because busy";
    case WOLFSENTRY_ERROR_ID_NUMERIC_ARG_TOO_BIG:
        return "Numeric arg is impermissibly large";
    case WOLFSENTRY_ERROR_ID_NUMERIC_ARG_TOO_SMALL:
        return "Numeric arg is impermissibly small";
    case WOLFSENTRY_ERROR_ID_STRING_ARG_TOO_LONG:
        return "String or vector arg is impermissibly long";
    case WOLFSENTRY_ERROR_ID_BUFFER_TOO_SMALL:
        return "Buffer too small to complete operation";
    case WOLFSENTRY_ERROR_ID_IMPLEMENTATION_MISSING:
        return "Function or mechanism not compiled in or not implemented";
    case WOLFSENTRY_ERROR_ID_ITEM_NOT_FOUND:
        return "No matching item found";
    case WOLFSENTRY_ERROR_ID_ITEM_ALREADY_PRESENT:
        return "New item would collide with existing item";
    case WOLFSENTRY_ERROR_ID_ALREADY_STOPPED:
        return "Operation attempted with object already marked as stopped";
    case WOLFSENTRY_ERROR_ID_WRONG_OBJECT:
        return "Operation attempted on wrong type of object";
    case WOLFSENTRY_ERROR_ID_NOT_INSERTED:
        return "Object was not inserted in table (informational, not an error)";
    case WOLFSENTRY_ERROR_ID_DATA_MISSING:
        return "Requested data or buffer is not present";
    case WOLFSENTRY_ERROR_ID_NOT_PERMITTED:
        return "Illegal access attempted";
    case WOLFSENTRY_ERROR_ID_ALREADY:
        return "Object already has requested condition";
    case WOLFSENTRY_ERROR_ID_CONFIG_INVALID_KEY:
        return "Configuration contains an invalid key";
    case WOLFSENTRY_ERROR_ID_CONFIG_INVALID_VALUE:
        return "Configuration contains an invalid value";
    case WOLFSENTRY_ERROR_ID_CONFIG_UNEXPECTED:
        return "Configuration has unexpected or invalid structure";
    case WOLFSENTRY_ERROR_ID_USER_BASE:
        break;
    }
    if (i >= WOLFSENTRY_ERROR_ID_USER_BASE)
        return "user defined error code";
    else
        return "unknown error code";
}

#endif /* WOLFSENTRY_ERROR_STRINGS */

#ifdef WOLFSENTRY_MALLOC_BUILTINS

#include <stdlib.h>

static void *wolfsentry_builtin_malloc(void *context, size_t size) {
    (void)context;
    return malloc(size);
}

static void wolfsentry_builtin_free(void *context, void *ptr) {
    (void)context;
    free(ptr);
}

static void *wolfsentry_builtin_realloc(void *context, void *ptr, size_t size) {
    (void)context;
    return realloc(ptr, size);
}

static void *wolfsentry_builtin_memalign(void *context, size_t alignment, size_t size) {
    (void)context;
    if (alignment <= sizeof(void *))
        return malloc(size);
#ifdef WOLFSENTRY_NO_POSIX_MEMALIGN
    else
        return NULL;
#else
    else {
        void *ret = 0;
        if (posix_memalign(&ret, alignment, size) < 0)
            return NULL;
        return ret;
    }
#endif
}

static const struct wolfsentry_allocator default_allocator = {
#ifdef __GNUC__
    .context = NULL,
    .malloc = wolfsentry_builtin_malloc,
    .free = wolfsentry_builtin_free,
    .realloc = wolfsentry_builtin_realloc,
    .memalign = wolfsentry_builtin_memalign
#else
    NULL,
    wolfsentry_builtin_malloc,
    wolfsentry_builtin_free,
    wolfsentry_builtin_realloc,
    wolfsentry_builtin_memalign
#endif
};

#endif /* WOLFSENTRY_MALLOC_BUILTINS */

wolfsentry_errcode_t wolfsentry_id_generate(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_object_type_t object_type,
    wolfsentry_ent_id_t *id)
{
    for (;;) {
        if (wolfsentry->mk_id_cb) {
            wolfsentry_errcode_t ret = wolfsentry->mk_id_cb(wolfsentry->mk_id_cb_state.mk_id_cb_arg, object_type, id);
            if (ret < 0)
                return ret;
        } else {
            *id = ++wolfsentry->mk_id_cb_state.id_counter;
        }

        if (wolfsentry->ents_by_id.head == NULL)
            WOLFSENTRY_RETURN_OK;

        if ((*id > wolfsentry->ents_by_id.tail->id) ||
            (*id < wolfsentry->ents_by_id.head->id))
            WOLFSENTRY_RETURN_OK;

        {
            struct wolfsentry_table_ent_header *ent;
            if (wolfsentry_table_ent_get_by_id(wolfsentry, *id, &ent) < 0)
                WOLFSENTRY_RETURN_OK;
        }
    }
    /* not reached */
}

#ifdef WOLFSENTRY_THREADSAFE

#include <errno.h>

/* this lock facility depends on POSIX-compliant (counting, async-signal-safe)
 * implementations of sem_{init,post,wait,timedwait,trywait,getvalue,destroy}(),
 * which can be native, or shims to native facilities.
 */

/* ARM-specific low level locks: https://github.com/PacktPublishing/Embedded-Systems-Architecture/tree/master/Chapter10/os-safe (tip from Danielinux) */

/* sem wrappers layered on various target-specific semaphore implementations:
 * https://github.com/wolfSSL/wolfMQTT/blob/master/src/mqtt_client.c#L43 (note
 * that the "counting semaphore" facility is needed for wolfsentry_lock_*() on
 * FreeRTOS).
 */

wolfsentry_errcode_t wolfsentry_lock_init(struct wolfsentry_rwlock *lock, int pshared) {
    memset(lock,0,sizeof *lock);
    if (sem_init(&lock->sem, pshared, 1 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if (sem_init(&lock->sem_read_waiters, pshared, 0 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if (sem_init(&lock->sem_write_waiters, pshared, 0 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if (sem_init(&lock->sem_read2write_waiters, pshared, 0 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_alloc(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock **lock, int pshared) {
    wolfsentry_errcode_t ret;
    if ((*lock = WOLFSENTRY_MALLOC(sizeof **lock)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if ((ret = wolfsentry_lock_init(*lock, pshared)) < 0) {
        WOLFSENTRY_FREE(*lock);
        *lock = NULL;
        return ret;
    }
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_destroy(struct wolfsentry_rwlock *lock) {
    int ret, val;
    do {
        ret = sem_trywait(&lock->sem);
    } while ((ret < 0) && (errno == EINTR));
    if (ret < 0) {
        if (errno == EAGAIN)
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
        else
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    }
    if ((lock->state != WOLFSENTRY_LOCK_UNLOCKED) ||
        (lock->shared_count > 0) ||
        (lock->read_waiter_count > 0) ||
        (lock->write_waiter_count > 0) ||
        (lock->read2write_waiter_count > 0)) {
        WOLFSENTRY_WARN("attempt to destroy used lock {%d,%d,%d,%d,%d}\n", lock->state, lock->shared_count, lock->read_waiter_count, lock->write_waiter_count, lock->read2write_waiter_count);
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    if (sem_getvalue(&lock->sem_read_waiters, &val) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (val > 0)
        WOLFSENTRY_WARN("lock->sem_read_waiters = %d\n",ret);
    if (sem_destroy(&lock->sem_read_waiters) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    if (sem_getvalue(&lock->sem_write_waiters, &val) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (val > 0)
        WOLFSENTRY_WARN("lock->sem_write_waiters = %d\n",ret);
    if (sem_destroy(&lock->sem_write_waiters) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    if (sem_getvalue(&lock->sem_read2write_waiters, &val) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (val > 0)
        WOLFSENTRY_WARN("lock->sem_read2write_waiters = %d\n",ret);
    if (sem_destroy(&lock->sem_read2write_waiters) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    if (sem_getvalue(&lock->sem, &val) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (val > 0)
        WOLFSENTRY_WARN("lock->sem = %d\n",ret);
    if (sem_destroy(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_free(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock **lock) {
    wolfsentry_errcode_t ret = wolfsentry_lock_destroy(*lock);
    if (ret < 0)
        return ret;
    WOLFSENTRY_FREE(*lock);
    *lock = NULL;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_shared(struct wolfsentry_rwlock *lock) {
  again:
    if (sem_wait(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if ((lock->state == WOLFSENTRY_LOCK_EXCLUSIVE) || (lock->write_waiter_count > 0) || (lock->read2write_waiter_count > 0)) {
        ++lock->read_waiter_count;
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        if (sem_wait(&lock->sem_read_waiters) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        goto again;
    } else if (lock->state == WOLFSENTRY_LOCK_UNLOCKED)
        lock->state = WOLFSENTRY_LOCK_SHARED;
    ++lock->shared_count;
    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    else
        WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_shared_abstimed(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock *lock, struct timespec *abs_timeout) {
    wolfsentry_errcode_t ret;

    (void)wolfsentry;

  again:
    if (abs_timeout == NULL) {
        ret = sem_trywait(&lock->sem);
        if ((ret < 0) && (errno == EAGAIN))
            WOLFSENTRY_ERROR_RETURN(BUSY);
    } else
        ret = sem_wait(&lock->sem);
    if (ret < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if ((lock->state == WOLFSENTRY_LOCK_EXCLUSIVE) || (lock->write_waiter_count > 0) || (lock->read2write_waiter_count > 0)) {
        if (abs_timeout == NULL) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else
                WOLFSENTRY_ERROR_RETURN(BUSY);
        }
        ++lock->read_waiter_count;
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        if (sem_timedwait(&lock->sem_read_waiters, abs_timeout) < 0) {
            wolfsentry_errcode_t ret2;
            if (errno == ETIMEDOUT)
                ret = WOLFSENTRY_ERROR_ENCODE(TIMED_OUT);
            else
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
            /* trap and retry for EINTR to avoid unnecessary failures. */
            do {
                WOLFSENTRY_WARN_ON_FAILURE_LIBC(ret2 = sem_wait(&lock->sem));
            } while ((ret2 < 0) && (errno == EINTR));
            if (ret2 < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

            /*
             * now that we own lock->sem, we can retry lock->sem_read_waiters,
             * in case an unlock (and associated post to lock->sem_read_waiters)
             * occured after a sem_timedwait() timeout.
             */
            if (sem_trywait(&lock->sem_read_waiters) == 0) {
                if (sem_post(&lock->sem) < 0)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
                goto again;
            }

            --lock->read_waiter_count;
            WOLFSENTRY_WARN_ON_FAILURE_LIBC(sem_post(&lock->sem));
            return ret;
        }
        goto again;
    } else if (lock->state == WOLFSENTRY_LOCK_UNLOCKED)
        lock->state = WOLFSENTRY_LOCK_SHARED;
    ++lock->shared_count;
    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    else
        WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_shared_timed(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock *lock, wolfsentry_time_t max_wait) {
    wolfsentry_time_t now;
    struct timespec abs_timeout;
    wolfsentry_errcode_t ret;

    if (max_wait < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (max_wait > 0) {
        if ((ret = WOLFSENTRY_GET_TIME(&now)) < 0)
            return ret;
        if ((ret = WOLFSENTRY_TO_EPOCH_TIME(WOLFSENTRY_ADD_TIME(now,max_wait), &abs_timeout.tv_sec, &abs_timeout.tv_nsec)) < 0)
            return ret;
        return wolfsentry_lock_shared_abstimed(wolfsentry, lock, &abs_timeout);
    } else
        return wolfsentry_lock_shared_abstimed(wolfsentry, lock, NULL);
}

wolfsentry_errcode_t wolfsentry_lock_mutex(struct wolfsentry_rwlock *lock) {
  again:
    if (sem_wait(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (lock->state != WOLFSENTRY_LOCK_UNLOCKED) {
        ++lock->write_waiter_count;
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        if (sem_wait(&lock->sem_write_waiters) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        goto again;
    }
    lock->state = WOLFSENTRY_LOCK_EXCLUSIVE;
    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    else
        WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_mutex_abstimed(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock *lock, struct timespec *abs_timeout) {
    wolfsentry_errcode_t ret;

    (void)wolfsentry;

  again:
    if (abs_timeout == NULL) {
        ret = sem_trywait(&lock->sem);
        if ((ret < 0) && (errno == EAGAIN))
            WOLFSENTRY_ERROR_RETURN(BUSY);
    } else
        ret = sem_wait(&lock->sem);
    if (ret < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (lock->state != WOLFSENTRY_LOCK_UNLOCKED) {
        if (abs_timeout == NULL) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            WOLFSENTRY_ERROR_RETURN(BUSY);
        }
        ++lock->write_waiter_count;
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        if (sem_timedwait(&lock->sem_write_waiters, abs_timeout) < 0) {
            wolfsentry_errcode_t ret2;
            if (errno == ETIMEDOUT)
                ret = WOLFSENTRY_ERROR_ENCODE(TIMED_OUT);
            else
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
            /* trap and retry for EINTR to avoid unnecessary failures. */
            do {
                WOLFSENTRY_WARN_ON_FAILURE_LIBC(ret2 = sem_wait(&lock->sem));
            } while ((ret2 < 0) && (errno == EINTR));
            if (ret2 < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

            /*
             * now that we own lock->sem, we can retry lock->sem_write_waiters,
             * in case an unlock (and associated post to
             * lock->sem_write_waiters) occured after a sem_timedwait() timeout.
             */
            if (sem_trywait(&lock->sem_write_waiters) == 0) {
                if (sem_post(&lock->sem) < 0)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
                goto again;
            }

            --lock->write_waiter_count;
            WOLFSENTRY_WARN_ON_FAILURE_LIBC(sem_post(&lock->sem));
            return ret;
        }
        goto again;
    }
    lock->state = WOLFSENTRY_LOCK_EXCLUSIVE;
    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    else
        WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_mutex_timed(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock *lock, wolfsentry_time_t max_wait) {
    wolfsentry_time_t now;
    struct timespec abs_timeout;
    wolfsentry_errcode_t ret;

    if (max_wait < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (max_wait > 0) {
        if ((ret = WOLFSENTRY_GET_TIME(&now)) < 0)
            return ret;
        if ((ret = WOLFSENTRY_TO_EPOCH_TIME(WOLFSENTRY_ADD_TIME(now,max_wait), &abs_timeout.tv_sec, &abs_timeout.tv_nsec)) < 0)
            return ret;
        return wolfsentry_lock_mutex_abstimed(wolfsentry, lock, &abs_timeout);
    } else
        return wolfsentry_lock_mutex_abstimed(wolfsentry, lock, NULL);
}

wolfsentry_errcode_t wolfsentry_lock_mutex2shared(struct wolfsentry_rwlock *lock) {
    if (lock->state == WOLFSENTRY_LOCK_SHARED)
        WOLFSENTRY_ERROR_RETURN(ALREADY);

    if (sem_wait(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (lock->state != WOLFSENTRY_LOCK_EXCLUSIVE) {
        WOLFSENTRY_WARN_ON_FAILURE_LIBC(sem_post(&lock->sem));
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }
    lock->state = WOLFSENTRY_LOCK_SHARED;
    lock->shared_count = 1;
    if ((lock->write_waiter_count == 0) &&
        (lock->read_waiter_count > 0)) {
        int i;
        for (i = 0; i < lock->read_waiter_count; ++i) {
            if (sem_post(&lock->sem_read_waiters) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        }
        lock->read_waiter_count = 0;
    }
    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    WOLFSENTRY_RETURN_OK;
}

/* if another thread is already waiting for read2write, then this
 * returns BUSY, and the caller must _unlock() to resolve the
 * deadlock, then reattempt its transaction with a fresh lock (ideally
 * with a _lock_mutex() at the open).
 */
wolfsentry_errcode_t wolfsentry_lock_shared2mutex(struct wolfsentry_rwlock *lock) {
    if (lock->state == WOLFSENTRY_LOCK_EXCLUSIVE)
        WOLFSENTRY_ERROR_RETURN(ALREADY);
  again:
    if (sem_wait(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (lock->state != WOLFSENTRY_LOCK_SHARED) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }
    if (lock->read2write_waiter_count > 0) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(BUSY);
    }
    if (lock->shared_count == 1) {
        lock->shared_count = 0;
        lock->state = WOLFSENTRY_LOCK_EXCLUSIVE;
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_RETURN_OK;
    }

    ++lock->read2write_waiter_count;
    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (sem_wait(&lock->sem_read2write_waiters) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    goto again;

    /* not reached */
}

wolfsentry_errcode_t wolfsentry_lock_shared2mutex_abstimed(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock *lock, struct timespec *abs_timeout) {
    wolfsentry_errcode_t ret;

    (void)wolfsentry;

    /* silently and cheaply tolerate repeat calls to _shared2mutex*(). */
    if (lock->state == WOLFSENTRY_LOCK_EXCLUSIVE)
        WOLFSENTRY_RETURN_OK;

  again:
    if (abs_timeout == NULL) {
        ret = sem_trywait(&lock->sem);
        if ((ret < 0) && (errno == EAGAIN))
            WOLFSENTRY_ERROR_RETURN(BUSY);
    } else
        ret = sem_wait(&lock->sem);
    if (ret < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (lock->state != WOLFSENTRY_LOCK_SHARED) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }
    if (lock->read2write_waiter_count > 0) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(BUSY);
    }
    if (lock->shared_count == 1) {
        lock->shared_count = 0;
        lock->state = WOLFSENTRY_LOCK_EXCLUSIVE;
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_RETURN_OK;
    }

    if (abs_timeout == NULL) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(BUSY);
    }

    ++lock->read2write_waiter_count;
    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (sem_timedwait(&lock->sem_read2write_waiters, abs_timeout) < 0) {
        wolfsentry_errcode_t ret2;
        if (errno == ETIMEDOUT)
            ret = WOLFSENTRY_ERROR_ENCODE(TIMED_OUT);
        else
            ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
        /* trap and retry for EINTR to avoid unnecessary failures. */
        do {
            ret2 = sem_wait(&lock->sem);
        } while ((ret2 < 0) && (errno == EINTR));
        if (ret2 < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

        /*
         * now that we own lock->sem, we can retry lock->sem_read2write_waiters,
         * in case an unlock (and associated post to
         * lock->sem_read2write_waiters) occured after a sem_timedwait()
         * timeout.
         */
        if (sem_trywait(&lock->sem_read2write_waiters) == 0) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            goto again;
        }

        --lock->read2write_waiter_count;
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_RETURN_OK;
    }
    goto again;

    /* not reached */
}

wolfsentry_errcode_t wolfsentry_lock_shared2mutex_timed(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock *lock, wolfsentry_time_t max_wait) {
    wolfsentry_time_t now;
    struct timespec abs_timeout;
    wolfsentry_errcode_t ret;

    /* silently and cheaply tolerate repeat calls to _shared2mutex*(). */
    if (lock->state == WOLFSENTRY_LOCK_EXCLUSIVE)
        WOLFSENTRY_RETURN_OK;

    if (max_wait < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (max_wait > 0) {
        if ((ret = WOLFSENTRY_GET_TIME(&now)) < 0)
            return ret;
        if ((ret = WOLFSENTRY_TO_EPOCH_TIME(WOLFSENTRY_ADD_TIME(now,max_wait), &abs_timeout.tv_sec, &abs_timeout.tv_nsec)) < 0)
            return ret;
        return wolfsentry_lock_shared2mutex_abstimed(wolfsentry, lock, &abs_timeout);
    } else
        return wolfsentry_lock_shared2mutex_abstimed(wolfsentry, lock, NULL);
}

wolfsentry_errcode_t wolfsentry_lock_unlock(struct wolfsentry_rwlock *lock) {
    wolfsentry_errcode_t ret;
    /* trap and retry for EINTR to avoid unnecessary failures. */
    do {
        ret = sem_wait(&lock->sem);
    } while ((ret < 0) && (errno == EINTR));
    if (ret < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (lock->state == WOLFSENTRY_LOCK_SHARED) {
        if (--lock->shared_count == 0)
            lock->state = WOLFSENTRY_LOCK_UNLOCKED;
        else if ((lock->read2write_waiter_count > 0) && (lock->shared_count == 1)) {
            --lock->read2write_waiter_count;
            if (sem_post(&lock->sem_read2write_waiters) < 0)
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
            else
                ret = WOLFSENTRY_ERROR_ENCODE(OK);
            goto out;
        }
    } else if (lock->state == WOLFSENTRY_LOCK_EXCLUSIVE)
        lock->state = WOLFSENTRY_LOCK_UNLOCKED;
    else {
        WOLFSENTRY_WARN("wolfsentry_lock_unlock with state=%d\n", lock->state);
        ret = WOLFSENTRY_ERROR_ENCODE(INCOMPATIBLE_STATE);
        goto out;
    }
    if (lock->write_waiter_count > 0)  {
        if (lock->state == WOLFSENTRY_LOCK_UNLOCKED) {
            --lock->write_waiter_count;
            if (sem_post(&lock->sem_write_waiters) < 0) {
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
                goto out;
            }
        }
    } else if (lock->read_waiter_count > 0) {
        int i;
        for (i = 0; i < lock->read_waiter_count; ++i) {
            if (sem_post(&lock->sem_read_waiters) < 0) {
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
                goto out;
            }
        }
        lock->read_waiter_count = 0;
    }

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    return ret;
}

wolfsentry_errcode_t wolfsentry_context_lock_shared(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_shared(&wolfsentry->lock);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared_abstimed(
    struct wolfsentry_context *wolfsentry,
    struct timespec *abs_timeout) {
    return wolfsentry_lock_shared_abstimed(wolfsentry, &wolfsentry->lock, abs_timeout);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared_timed(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_time_t max_wait) {
    return wolfsentry_lock_shared_timed(wolfsentry, &wolfsentry->lock, max_wait);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_shared2mutex(&wolfsentry->lock);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_abstimed(
    struct wolfsentry_context *wolfsentry,
    struct timespec *abs_timeout) {
    return wolfsentry_lock_shared2mutex_abstimed(wolfsentry, &wolfsentry->lock, abs_timeout);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_timed(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_time_t max_wait) {
    return wolfsentry_lock_shared2mutex_timed(wolfsentry, &wolfsentry->lock, max_wait);
}

wolfsentry_errcode_t wolfsentry_context_lock_mutex(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_mutex(&wolfsentry->lock);
}

wolfsentry_errcode_t wolfsentry_context_lock_mutex_abstimed(
    struct wolfsentry_context *wolfsentry,
    struct timespec *abs_timeout) {
    return wolfsentry_lock_mutex_abstimed(wolfsentry, &wolfsentry->lock, abs_timeout);
}

wolfsentry_errcode_t wolfsentry_context_lock_mutex_timed(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_time_t max_wait) {
    return wolfsentry_lock_mutex_timed(wolfsentry, &wolfsentry->lock, max_wait);
}

wolfsentry_errcode_t wolfsentry_context_lock_mutex2shared(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_mutex2shared(&wolfsentry->lock);
}

wolfsentry_errcode_t wolfsentry_context_unlock(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_unlock(&wolfsentry->lock);
}

#endif /* WOLFSENTRY_THREADSAFE */

#ifdef WOLFSENTRY_CLOCK_BUILTINS

#include <time.h>

static wolfsentry_errcode_t wolfsentry_builtin_get_time(void *context, wolfsentry_time_t *now) {
    struct timespec ts;
    (void)context;
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    *now = ((wolfsentry_time_t)ts.tv_sec * (wolfsentry_time_t)1000000) + ((wolfsentry_time_t)ts.tv_nsec / (wolfsentry_time_t)1000);
    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_time_t wolfsentry_builtin_diff_time(wolfsentry_time_t later, wolfsentry_time_t earlier) {
    return later - earlier;
}

static wolfsentry_time_t wolfsentry_builtin_add_time(wolfsentry_time_t start_time, wolfsentry_time_t time_interval) {
    return start_time + time_interval;
}

static wolfsentry_errcode_t wolfsentry_builtin_to_epoch_time(wolfsentry_time_t when, long *epoch_secs, long *epoch_nsecs) {
    if (when / (wolfsentry_time_t)1000000 > MAX_SINT_OF(*epoch_secs))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    *epoch_secs = (long)(when / (wolfsentry_time_t)1000000);
    *epoch_nsecs = (long)((when % (wolfsentry_time_t)1000000) * (wolfsentry_time_t)1000);
    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_builtin_from_epoch_time(long epoch_secs, long epoch_nsecs, wolfsentry_time_t *when) {
    if ((wolfsentry_time_t)epoch_secs > MAX_SINT_OF(*when) / (wolfsentry_time_t)1000000)
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    *when = ((wolfsentry_time_t)epoch_secs * (wolfsentry_time_t)1000000) + ((wolfsentry_time_t)epoch_nsecs / (wolfsentry_time_t)1000);
    WOLFSENTRY_RETURN_OK;
}

static const struct wolfsentry_timecbs default_timecbs = {
#ifdef __GNUC__
    .context = NULL,
    .get_time = wolfsentry_builtin_get_time,
    .diff_time = wolfsentry_builtin_diff_time,
    .add_time = wolfsentry_builtin_add_time,
    .to_epoch_time = wolfsentry_builtin_to_epoch_time,
    .from_epoch_time = wolfsentry_builtin_from_epoch_time,
    .interval_to_seconds = wolfsentry_builtin_to_epoch_time,
    .interval_from_seconds = wolfsentry_builtin_from_epoch_time
#else
    NULL,
    wolfsentry_builtin_get_time,
    wolfsentry_builtin_diff_time,
    wolfsentry_builtin_add_time,
    wolfsentry_builtin_epoch_time,
    wolfsentry_builtin_to_epoch_time,
    wolfsentry_builtin_from_epoch_time,
    wolfsentry_builtin_to_epoch_time,
    wolfsentry_builtin_from_epoch_time
#endif
};

#endif /* WOLFSENTRY_CLOCK_BUILTINS */

wolfsentry_errcode_t wolfsentry_time_now_plus_delta(struct wolfsentry_context *wolfsentry, wolfsentry_time_t td, wolfsentry_time_t *res) {
    wolfsentry_errcode_t ret = WOLFSENTRY_GET_TIME(res);
    if (ret < 0)
        return ret;
    *res = WOLFSENTRY_ADD_TIME(*res, td);
    WOLFSENTRY_RETURN_OK;
}

#ifdef WOLFSENTRY_THREADSAFE
wolfsentry_errcode_t wolfsentry_time_to_timespec(struct wolfsentry_context *wolfsentry, wolfsentry_time_t t, struct timespec *ts) {
    long int epoch_secs, epoch_nsecs;
    WOLFSENTRY_TO_EPOCH_TIME(t, &epoch_secs, &epoch_nsecs);
    ts->tv_sec = epoch_secs;
    ts->tv_nsec = epoch_nsecs;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_time_now_plus_delta_timespec(struct wolfsentry_context *wolfsentry, wolfsentry_time_t td, struct timespec *ts) {
    wolfsentry_time_t now;
    long int epoch_secs, epoch_nsecs;
    wolfsentry_errcode_t ret = WOLFSENTRY_GET_TIME(&now);
    if (ret < 0)
        return ret;
    WOLFSENTRY_TO_EPOCH_TIME(WOLFSENTRY_ADD_TIME(now, td), &epoch_secs, &epoch_nsecs);
    ts->tv_sec = epoch_secs;
    ts->tv_nsec = epoch_nsecs;
    WOLFSENTRY_RETURN_OK;
}
#endif /* WOLFSENTRY_THREADSAFE */

void *wolfsentry_malloc(struct wolfsentry_context *wolfsentry, size_t size) {
    return wolfsentry->allocator.malloc(wolfsentry->allocator.context, size);
}
void wolfsentry_free(struct wolfsentry_context *wolfsentry, void *ptr) {
    wolfsentry->allocator.free(wolfsentry->allocator.context, ptr);
}
void *wolfsentry_realloc(struct wolfsentry_context *wolfsentry, void *ptr, size_t size) {
    return wolfsentry->allocator.realloc(wolfsentry->allocator.context, ptr, size);
}
void *wolfsentry_memalign(struct wolfsentry_context *wolfsentry, size_t alignment, size_t size) {
    return wolfsentry->allocator.memalign ? wolfsentry->allocator.memalign(wolfsentry->allocator.context, alignment, size) : NULL;
}

wolfsentry_errcode_t wolfsentry_get_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t *time_p) {
    return wolfsentry->timecbs.get_time(wolfsentry->timecbs.context, time_p);
}
wolfsentry_time_t wolfsentry_diff_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t later, wolfsentry_time_t earlier) {
    return wolfsentry->timecbs.diff_time(later, earlier);
}
wolfsentry_time_t wolfsentry_add_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t start_time, wolfsentry_time_t time_interval) {
    return wolfsentry->timecbs.add_time(start_time, time_interval);
}
wolfsentry_errcode_t wolfsentry_to_epoch_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t when, long *epoch_secs, long *epoch_nsecs) {
    return wolfsentry->timecbs.to_epoch_time(when, epoch_secs, epoch_nsecs);
}
wolfsentry_errcode_t wolfsentry_from_epoch_time(struct wolfsentry_context *wolfsentry, long epoch_secs, long epoch_nsecs, wolfsentry_time_t *when) {
    return wolfsentry->timecbs.from_epoch_time(epoch_secs, epoch_nsecs, when);
}
wolfsentry_errcode_t wolfsentry_interval_to_seconds(struct wolfsentry_context *wolfsentry, wolfsentry_time_t howlong, long *howlong_secs, long *howlong_nsecs) {
    return wolfsentry->timecbs.interval_to_seconds(howlong, howlong_secs, howlong_nsecs);
}
wolfsentry_errcode_t wolfsentry_interval_from_seconds(struct wolfsentry_context *wolfsentry, long howlong_secs, long howlong_nsecs, wolfsentry_time_t *howlong) {
    return wolfsentry->timecbs.interval_from_seconds(howlong_secs, howlong_nsecs, howlong);
}

wolfsentry_errcode_t wolfsentry_eventconfig_init(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_eventconfig *config)
{
    if (config == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (wolfsentry)
        *config = wolfsentry->config.config;
    else
        memset(config, 0, sizeof *config);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_eventconfig_check(
    const struct wolfsentry_eventconfig *config)
{
    if (config == NULL)
        WOLFSENTRY_RETURN_OK;
    if (config->route_private_data_size == 0) {
        if (config->route_private_data_alignment != 0)
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    } else {
        if ((config->route_private_data_alignment != 0) &&
            ((config->route_private_data_alignment < sizeof(void *)) ||
             ((config->route_private_data_alignment & (config->route_private_data_alignment - 1)) != 0)))
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

    if (config->route_private_data_alignment > 0) {
        size_t private_data_slop = offsetof(struct wolfsentry_route, data) % config->route_private_data_alignment;
        if (private_data_slop > 0) {
            if (config->route_private_data_size + private_data_slop > MAX_UINT_OF(((struct wolfsentry_route *)0)->data_addr_offset))
                WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
        }
    }

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_eventconfig_load(
    const struct wolfsentry_eventconfig *supplied,
    struct wolfsentry_eventconfig_internal *internal)
{
    if (internal == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    memset(internal, 0, sizeof *internal);
    if (supplied == NULL)
        WOLFSENTRY_RETURN_OK;
    memcpy(&internal->config, supplied, sizeof internal->config);
    if (internal->config.route_private_data_alignment > 0) {
        size_t private_data_slop = offsetof(struct wolfsentry_route, data) % internal->config.route_private_data_alignment;
        if (private_data_slop > 0) {
            internal->route_private_data_padding = internal->config.route_private_data_alignment - private_data_slop;
            internal->config.route_private_data_size += private_data_slop;
        }
    }

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_eventconfig_update_1(
    const struct wolfsentry_eventconfig *supplied,
    struct wolfsentry_eventconfig_internal *internal)
{
    if (supplied == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (internal == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    internal->config.max_connection_count = supplied->max_connection_count;
    internal->config.penaltybox_duration = supplied->penaltybox_duration;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_eventconfig_get_1(
    const struct wolfsentry_eventconfig_internal *internal,
    struct wolfsentry_eventconfig *exported)
{
    if (internal == NULL)
        WOLFSENTRY_ERROR_RETURN(DATA_MISSING);
    if (exported == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    *exported = internal->config;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_defaultconfig_get(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_eventconfig *config)
{
    return wolfsentry_eventconfig_get_1(&wolfsentry->config, config);
}

wolfsentry_errcode_t wolfsentry_defaultconfig_update(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_eventconfig *config)
{
    return wolfsentry_eventconfig_update_1(config, &wolfsentry->config);
}

wolfsentry_errcode_t wolfsentry_init(
    const struct wolfsentry_host_platform_interface *hpi,
    const struct wolfsentry_eventconfig *config,
    struct wolfsentry_context **wolfsentry)
{
    const struct wolfsentry_allocator *allocator = NULL;
    const struct wolfsentry_timecbs *timecbs = NULL;
    wolfsentry_errcode_t ret = wolfsentry_eventconfig_check(config);
    if (ret < 0)
        return ret;

    if ((hpi == NULL) || (hpi->allocator == NULL)) {
#ifndef WOLFSENTRY_MALLOC_BUILTINS
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
#else
        allocator = &default_allocator;
#endif
    } else
        allocator = hpi->allocator;

    if ((allocator->malloc == NULL) ||
        (allocator->free == NULL) ||
        (allocator->realloc == NULL))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((hpi == NULL) || (hpi->timecbs == NULL)) {
#ifndef WOLFSENTRY_CLOCK_BUILTINS
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
#else
        timecbs = &default_timecbs;
#endif
    } else
        timecbs = hpi->timecbs;

    if ((timecbs->get_time == NULL) ||
        (timecbs->diff_time == NULL) ||
        (timecbs->add_time == NULL) ||
        (timecbs->to_epoch_time == NULL) ||
        (timecbs->from_epoch_time == NULL) ||
        (timecbs->interval_to_seconds == NULL) ||
        (timecbs->interval_from_seconds == NULL))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((allocator->memalign == NULL) && config && (config->route_private_data_alignment > 0))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((*wolfsentry = (struct wolfsentry_context *)allocator->malloc(allocator->context, sizeof **wolfsentry)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);

    memset(*wolfsentry, 0, sizeof **wolfsentry);

    (*wolfsentry)->allocator = *allocator;
    (*wolfsentry)->timecbs = *timecbs;

    if ((ret = wolfsentry_eventconfig_load(config, &(*wolfsentry)->config)) < 0)
        goto out;

    (*wolfsentry)->events.header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_event_key_cmp;
    (*wolfsentry)->events.header.free_fn = (wolfsentry_ent_free_fn_t)wolfsentry_event_drop_reference;
    (*wolfsentry)->events.header.ent_type = WOLFSENTRY_OBJECT_TYPE_EVENT;
    (*wolfsentry)->actions.header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_action_key_cmp;
    (*wolfsentry)->actions.header.free_fn = (wolfsentry_ent_free_fn_t)wolfsentry_action_drop_reference;
    (*wolfsentry)->actions.header.ent_type = WOLFSENTRY_OBJECT_TYPE_ACTION;
    (*wolfsentry)->routes_static.header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_route_key_cmp;
    (*wolfsentry)->routes_dynamic.header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_route_key_cmp;
    (*wolfsentry)->routes_static.header.free_fn = (wolfsentry_ent_free_fn_t)wolfsentry_route_drop_reference;
    (*wolfsentry)->routes_dynamic.header.free_fn = (wolfsentry_ent_free_fn_t)wolfsentry_route_drop_reference;
    (*wolfsentry)->routes_static.header.ent_type = WOLFSENTRY_OBJECT_TYPE_ROUTE;
    (*wolfsentry)->routes_dynamic.header.ent_type = WOLFSENTRY_OBJECT_TYPE_ROUTE;

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    if (ret < 0)
        allocator->free(allocator->context, *wolfsentry);

    return ret;
}

wolfsentry_errcode_t wolfsentry_shutdown(struct wolfsentry_context **wolfsentry) {
    wolfsentry_free_cb_t free_cb = (*wolfsentry)->allocator.free;

    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_table_free_ents(*wolfsentry, &(*wolfsentry)->routes_static.header));
    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_table_free_ents(*wolfsentry, &(*wolfsentry)->routes_dynamic.header));
    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_table_free_ents(*wolfsentry, &(*wolfsentry)->actions.header));
    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_table_free_ents(*wolfsentry, &(*wolfsentry)->events.header));

    free_cb((*wolfsentry)->allocator.context, *wolfsentry);
    *wolfsentry = NULL;
    WOLFSENTRY_RETURN_OK;
}
