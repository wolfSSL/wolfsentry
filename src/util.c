/*
 * util.c
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

#include "wolfsentry_internal.h"

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_UTIL_C

#ifdef WOLFSENTRY_ERROR_STRINGS

static const char *user_defined_sources[WOLFSENTRY_SOURCE_ID_MAX - WOLFSENTRY_SOURCE_ID_USER_BASE + 1] = {0};

wolfsentry_errcode_t wolfsentry_user_source_string_set(enum wolfsentry_source_id wolfsentry_source_id, const char *source_string) {
    if ((wolfsentry_source_id < WOLFSENTRY_SOURCE_ID_USER_BASE) || (wolfsentry_source_id > WOLFSENTRY_SOURCE_ID_MAX))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (user_defined_sources[wolfsentry_source_id - WOLFSENTRY_SOURCE_ID_USER_BASE] != NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_ALREADY_PRESENT);
    else {
        user_defined_sources[wolfsentry_source_id - WOLFSENTRY_SOURCE_ID_USER_BASE] = source_string;
        WOLFSENTRY_RETURN_OK;
    }
}

/* note, returns not instrumented, to avoid noise when debugging. */
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
    case WOLFSENTRY_SOURCE_ID_WOLFSENTRY_INTERNAL_C:
        return "wolfsentry_internal.c";
    case WOLFSENTRY_SOURCE_ID_ROUTES_C:
        return "routes.c";
    case WOLFSENTRY_SOURCE_ID_UTIL_C:
        return "util.c";
    case WOLFSENTRY_SOURCE_ID_KV_C:
        return "kv.c";
    case WOLFSENTRY_SOURCE_ID_ADDR_FAMILIES_C:
        return "addr_families.c";
    case WOLFSENTRY_SOURCE_ID_JSON_LOAD_CONFIG_C:
        return "json/load_config.c";
    case WOLFSENTRY_SOURCE_ID_JSON_JSON_UTIL_C:
        return "json/json_util.c";
    case WOLFSENTRY_SOURCE_ID_USER_BASE:
        break;
    }
    if (i >= WOLFSENTRY_SOURCE_ID_USER_BASE) {
        if (user_defined_sources[i - WOLFSENTRY_SOURCE_ID_USER_BASE])
            return user_defined_sources[i - WOLFSENTRY_SOURCE_ID_USER_BASE];
        else
            return "user defined source";
    } else
        return "unknown source";
}

static const char *user_defined_errors[WOLFSENTRY_ERROR_ID_MAX - WOLFSENTRY_ERROR_ID_USER_BASE + 1] = {0};

wolfsentry_errcode_t wolfsentry_user_error_string_set(enum wolfsentry_error_id wolfsentry_error_id, const char *error_string) {
    if ((wolfsentry_error_id < WOLFSENTRY_ERROR_ID_USER_BASE) || (wolfsentry_error_id > WOLFSENTRY_ERROR_ID_MAX))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (user_defined_errors[wolfsentry_error_id - WOLFSENTRY_ERROR_ID_USER_BASE] != NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_ALREADY_PRESENT);
    else {
        user_defined_errors[wolfsentry_error_id - WOLFSENTRY_ERROR_ID_USER_BASE] = error_string;
        WOLFSENTRY_RETURN_OK;
    }
}

/* note, returns not instrumented, to avoid noise when debugging. */
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
    case WOLFSENTRY_ERROR_ID_INTERRUPTED:
        return "Operation was interrupted by a signal";
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
    case WOLFSENTRY_ERROR_ID_CONFIG_OUT_OF_SEQUENCE:
        return "Configuration clause is not in the correct sequence";
    case WOLFSENTRY_ERROR_ID_CONFIG_UNEXPECTED:
        return "Configuration has unexpected or invalid structure";
    case WOLFSENTRY_ERROR_ID_CONFIG_MISPLACED_KEY:
        return "Configuration uses a key in the wrong context";
    case WOLFSENTRY_ERROR_ID_CONFIG_PARSER:
        return "Configuration parsing failed";
    case WOLFSENTRY_ERROR_ID_CONFIG_MISSING_HANDLER:
        return "Configuration processing failed due to missing handler";
    case WOLFSENTRY_ERROR_ID_CONFIG_JSON_VALUE_SIZE:
        return "Configuration contains an overlong JSON value";
    case WOLFSENTRY_ERROR_ID_OP_NOT_SUPP_FOR_PROTO:
        return "Operation not supported for protocol";
    case WOLFSENTRY_ERROR_ID_WRONG_TYPE:
        return "Item type does not match request";
    case WOLFSENTRY_ERROR_ID_BAD_VALUE:
        return "Bad value";
    case WOLFSENTRY_ERROR_ID_DEADLOCK_AVERTED:
        return "Deadlock averted";
    case WOLFSENTRY_ERROR_ID_OVERFLOW_AVERTED:
        return "Overflow averted";
    case WOLFSENTRY_ERROR_ID_USER_BASE:
        break;
    }
    if (i >= WOLFSENTRY_ERROR_ID_USER_BASE) {
        if (user_defined_errors[i - WOLFSENTRY_ERROR_ID_USER_BASE])
            return user_defined_errors[i - WOLFSENTRY_ERROR_ID_USER_BASE];
        else
            return "user defined error code";
    } else
        return "unknown error code";
}

/* note, returns not instrumented, to avoid noise when debugging. */
const char *wolfsentry_errcode_error_name(wolfsentry_errcode_t e)
{
    enum wolfsentry_error_id i = (enum wolfsentry_error_id)WOLFSENTRY_ERROR_DECODE_ERROR_CODE(e);
    switch(i) {
    case WOLFSENTRY_ERROR_ID_OK:
        return "OK";
    case WOLFSENTRY_ERROR_ID_NOT_OK:
        return "NOT_OK";
    case WOLFSENTRY_ERROR_ID_INTERNAL_CHECK_FATAL:
        return "INTERNAL_CHECK_FATAL";
    case WOLFSENTRY_ERROR_ID_SYS_OP_FATAL:
        return "SYS_OP_FATAL";
    case WOLFSENTRY_ERROR_ID_SYS_OP_FAILED:
        return "SYS_OP_FAILED";
    case WOLFSENTRY_ERROR_ID_SYS_RESOURCE_FAILED:
        return "SYS_RESOURCE_FAILED";
    case WOLFSENTRY_ERROR_ID_INCOMPATIBLE_STATE:
        return "INCOMPATIBLE_STATE";
    case WOLFSENTRY_ERROR_ID_TIMED_OUT:
        return "TIMED_OUT";
    case WOLFSENTRY_ERROR_ID_INVALID_ARG:
        return "INVALID_ARG";
    case WOLFSENTRY_ERROR_ID_BUSY:
        return "BUSY";
    case WOLFSENTRY_ERROR_ID_INTERRUPTED:
        return "INTERRUPTED";
    case WOLFSENTRY_ERROR_ID_NUMERIC_ARG_TOO_BIG:
        return "NUMERIC_ARG_TOO_BIG";
    case WOLFSENTRY_ERROR_ID_NUMERIC_ARG_TOO_SMALL:
        return "NUMERIC_ARG_TOO_SMALL";
    case WOLFSENTRY_ERROR_ID_STRING_ARG_TOO_LONG:
        return "STRING_ARG_TOO_LONG";
    case WOLFSENTRY_ERROR_ID_BUFFER_TOO_SMALL:
        return "BUFFER_TOO_SMALL";
    case WOLFSENTRY_ERROR_ID_IMPLEMENTATION_MISSING:
        return "IMPLEMENTATION_MISSING";
    case WOLFSENTRY_ERROR_ID_ITEM_NOT_FOUND:
        return "ITEM_NOT_FOUND";
    case WOLFSENTRY_ERROR_ID_ITEM_ALREADY_PRESENT:
        return "ITEM_ALREADY_PRESENT";
    case WOLFSENTRY_ERROR_ID_ALREADY_STOPPED:
        return "ALREADY_STOPPED";
    case WOLFSENTRY_ERROR_ID_WRONG_OBJECT:
        return "WRONG_OBJECT";
    case WOLFSENTRY_ERROR_ID_DATA_MISSING:
        return "DATA_MISSING";
    case WOLFSENTRY_ERROR_ID_NOT_PERMITTED:
        return "NOT_PERMITTED";
    case WOLFSENTRY_ERROR_ID_ALREADY:
        return "ALREADY";
    case WOLFSENTRY_ERROR_ID_CONFIG_INVALID_KEY:
        return "CONFIG_INVALID_KEY";
    case WOLFSENTRY_ERROR_ID_CONFIG_INVALID_VALUE:
        return "CONFIG_INVALID_VALUE";
    case WOLFSENTRY_ERROR_ID_CONFIG_OUT_OF_SEQUENCE:
        return "CONFIG_OUT_OF_SEQUENCE";
    case WOLFSENTRY_ERROR_ID_CONFIG_UNEXPECTED:
        return "CONFIG_UNEXPECTED";
    case WOLFSENTRY_ERROR_ID_CONFIG_MISPLACED_KEY:
        return "CONFIG_MISPLACED_KEY";
    case WOLFSENTRY_ERROR_ID_CONFIG_PARSER:
        return "CONFIG_PARSER";
    case WOLFSENTRY_ERROR_ID_CONFIG_MISSING_HANDLER:
        return "CONFIG_MISSING_HANDLER";
    case WOLFSENTRY_ERROR_ID_CONFIG_JSON_VALUE_SIZE:
        return "CONFIG_JSON_VALUE_SIZE";
    case WOLFSENTRY_ERROR_ID_OP_NOT_SUPP_FOR_PROTO:
        return "OP_NOT_SUPP_FOR_PROTO";
    case WOLFSENTRY_ERROR_ID_WRONG_TYPE:
        return "WRONG_TYPE";
    case WOLFSENTRY_ERROR_ID_BAD_VALUE:
        return "BAD_VALUE";
    case WOLFSENTRY_ERROR_ID_DEADLOCK_AVERTED:
        return "DEADLOCK_AVERTED";
    case WOLFSENTRY_ERROR_ID_OVERFLOW_AVERTED:
        return "OVERFLOW_AVERTED";
    case WOLFSENTRY_ERROR_ID_USER_BASE:
        break;
    }
    return wolfsentry_errcode_error_string(e);
}

#if defined(WOLFSENTRY_DEBUG_CALL_TRACE) && defined(__GNUC__) && !defined(__STRICT_ANSI__)
_Pragma("GCC diagnostic push");
_Pragma("GCC diagnostic ignored \"-Wframe-address\"");
unsigned int _wolfsentry_call_depth(void) {
    unsigned int i;
    void *p = __builtin_frame_address(0);
    if (p == 0)
        return 0;
    for (i=1;;++i) {
        void *q = 0;
        switch(i) {
        case 1: q = __builtin_frame_address(1); break;
        case 2: q = __builtin_frame_address(2); break;
        case 3: q = __builtin_frame_address(3); break;
        case 4: q = __builtin_frame_address(4); break;
        case 5: q = __builtin_frame_address(5); break;
        case 6: q = __builtin_frame_address(6); break;
        case 7: q = __builtin_frame_address(7); break;
        case 8: q = __builtin_frame_address(8); break;
        case 9: q = __builtin_frame_address(9); break;
        case 10: q = __builtin_frame_address(10); break;
        case 11: q = __builtin_frame_address(11); break;
        case 12: q = __builtin_frame_address(12); break;
        case 13: q = __builtin_frame_address(13); break;
        case 14: q = __builtin_frame_address(14); break;
        case 15: q = __builtin_frame_address(15); break;
        case 16: q = __builtin_frame_address(16); break;
        }
        if ((q == 0) || ((ptrdiff_t)p - (ptrdiff_t)q > 0x10000) || ((ptrdiff_t)p - (ptrdiff_t)q < -0x10000))
            break;
    }
    return i - 1;
}
_Pragma("GCC diagnostic pop");
#endif

const char *wolfsentry_action_res_decode(wolfsentry_action_res_t res, unsigned int bit) {
    if (bit > 31)
        WOLFSENTRY_RETURN_VALUE("(out-of-range)");
    if (res & (1U << bit)) {
        switch(1U << bit) {
        case WOLFSENTRY_ACTION_RES_NONE: /* not reachable */
            WOLFSENTRY_RETURN_VALUE("none");
        case WOLFSENTRY_ACTION_RES_ACCEPT:
            WOLFSENTRY_RETURN_VALUE("accept");
        case WOLFSENTRY_ACTION_RES_REJECT:
            WOLFSENTRY_RETURN_VALUE("reject");
        case WOLFSENTRY_ACTION_RES_CONNECT:
            WOLFSENTRY_RETURN_VALUE("connect");
        case WOLFSENTRY_ACTION_RES_DISCONNECT:
            WOLFSENTRY_RETURN_VALUE("disconnect");
        case WOLFSENTRY_ACTION_RES_DEROGATORY:
            WOLFSENTRY_RETURN_VALUE("derogatory");
        case WOLFSENTRY_ACTION_RES_COMMENDABLE:
            WOLFSENTRY_RETURN_VALUE("commendable");
        case WOLFSENTRY_ACTION_RES_CONTINUE:
            WOLFSENTRY_RETURN_VALUE("continue");
        case WOLFSENTRY_ACTION_RES_STOP:
            WOLFSENTRY_RETURN_VALUE("stop");
        case WOLFSENTRY_ACTION_RES_INSERT:
            WOLFSENTRY_RETURN_VALUE("insert");
        case WOLFSENTRY_ACTION_RES_DELETE:
            WOLFSENTRY_RETURN_VALUE("delete");
        case WOLFSENTRY_ACTION_RES_DEALLOCATED:
            WOLFSENTRY_RETURN_VALUE("deallocated");
        case WOLFSENTRY_ACTION_RES_ERROR:
            WOLFSENTRY_RETURN_VALUE("error");
        case WOLFSENTRY_ACTION_RES_FALLTHROUGH:
            WOLFSENTRY_RETURN_VALUE("fallthrough");
        case WOLFSENTRY_ACTION_RES_UPDATE:
            WOLFSENTRY_RETURN_VALUE("update");
        case WOLFSENTRY_ACTION_RES_USER_BASE:
            WOLFSENTRY_RETURN_VALUE("user+0");
        case WOLFSENTRY_ACTION_RES_USER_BASE << 1U:
            WOLFSENTRY_RETURN_VALUE("user+1");
        case WOLFSENTRY_ACTION_RES_USER_BASE << 2U:
            WOLFSENTRY_RETURN_VALUE("user+2");
        case WOLFSENTRY_ACTION_RES_USER_BASE << 3U:
            WOLFSENTRY_RETURN_VALUE("user+3");
        case WOLFSENTRY_ACTION_RES_USER_BASE << 4U:
            WOLFSENTRY_RETURN_VALUE("user+4");
        case WOLFSENTRY_ACTION_RES_USER_BASE << 5U:
            WOLFSENTRY_RETURN_VALUE("user+5");
        case WOLFSENTRY_ACTION_RES_USER_BASE << 6U:
            WOLFSENTRY_RETURN_VALUE("user+6");
        case WOLFSENTRY_ACTION_RES_USER_BASE << 7U:
            WOLFSENTRY_RETURN_VALUE("user+7");
        case WOLFSENTRY_ACTION_RES_USER_BASE << 8U:
            WOLFSENTRY_RETURN_VALUE("user+8");
        case WOLFSENTRY_ACTION_RES_USER_BASE << 9U:
            WOLFSENTRY_RETURN_VALUE("user+9");
        case WOLFSENTRY_ACTION_RES_USER_BASE << 10U:
            WOLFSENTRY_RETURN_VALUE("user+10");
        case WOLFSENTRY_ACTION_RES_USER_BASE << 11U:
            WOLFSENTRY_RETURN_VALUE("user+11");
        case WOLFSENTRY_ACTION_RES_USER_BASE << 12U:
            WOLFSENTRY_RETURN_VALUE("user+12");
        case WOLFSENTRY_ACTION_RES_USER_BASE << 13U:
            WOLFSENTRY_RETURN_VALUE("user+13");
        case WOLFSENTRY_ACTION_RES_USER_BASE << 14U:
            WOLFSENTRY_RETURN_VALUE("user+14");
        case (unsigned)WOLFSENTRY_ACTION_RES_USER_BASE << 15U:
            WOLFSENTRY_RETURN_VALUE("user+15");
        }
        WOLFSENTRY_RETURN_VALUE("(?)");
    } else
        WOLFSENTRY_RETURN_VALUE(NULL);
}

#endif /* WOLFSENTRY_ERROR_STRINGS */

#ifdef WOLFSENTRY_MALLOC_BUILTINS

#include <stdlib.h>

static void *wolfsentry_builtin_malloc(void *context, size_t size) {
    (void)context;
    WOLFSENTRY_RETURN_VALUE(malloc(size));
}

static void wolfsentry_builtin_free(void *context, void *ptr) {
    (void)context;
    free(ptr);
    WOLFSENTRY_RETURN_VOID;
}

static void *wolfsentry_builtin_realloc(void *context, void *ptr, size_t size) {
    (void)context;
    WOLFSENTRY_RETURN_VALUE(realloc(ptr, size));
}

static void *wolfsentry_builtin_memalign(void *context, size_t alignment, size_t size) {
    (void)context;
#ifdef WOLFSENTRY_NO_POSIX_MEMALIGN
    void *ptr = NULL;
    if (alignment && size) {
        uint32_t hdr_size = sizeof(uint16_t) + (alignment - 1);
        void *p = malloc(size + hdr_size);
        if (p) {
            /* Align to powers of two */
            ptr = (void *) ((((uintptr_t)p + sizeof(uint16_t)) + (alignment - 1)) & ~(alignment - 1));
            *((uint16_t *)ptr - 1) = (uint16_t)((uintptr_t)ptr - (uintptr_t)p);
        }
    }
    WOLFSENTRY_RETURN_VALUE(ptr);
#else
    if (alignment <= sizeof(void *))
        WOLFSENTRY_RETURN_VALUE(malloc(size));
    else {
        void *ret = 0;
        if (posix_memalign(&ret, alignment, size) < 0)
            WOLFSENTRY_RETURN_VALUE(NULL);
        WOLFSENTRY_RETURN_VALUE(ret);
    }
#endif
}

static void wolfsentry_builtin_free_aligned(void *context, void *ptr) {
    (void)context;
#ifdef WOLFSENTRY_NO_POSIX_MEMALIGN
    uint16_t offset = *((uint16_t *)ptr - 1);
    void *p = (void *)((uint8_t *)ptr - offset);
    free(p);
#else
    free(ptr);
#endif
    WOLFSENTRY_RETURN_VOID;
}

static const struct wolfsentry_allocator default_allocator = {
#ifdef __GNUC__
    .context = NULL,
    .malloc = wolfsentry_builtin_malloc,
    .free = wolfsentry_builtin_free,
    .realloc = wolfsentry_builtin_realloc,
    .memalign = wolfsentry_builtin_memalign,
    .free_aligned = wolfsentry_builtin_free_aligned
#else
    NULL,
    wolfsentry_builtin_malloc,
    wolfsentry_builtin_free,
    wolfsentry_builtin_realloc,
    wolfsentry_builtin_memalign,
    wolfsentry_builtin_free_aligned
#endif
};

#endif /* WOLFSENTRY_MALLOC_BUILTINS */

#ifdef WOLFSENTRY_THREADSAFE

wolfsentry_errcode_t wolfsentry_init_thread_context(struct wolfsentry_thread_context *thread_context, wolfsentry_thread_flags_t init_thread_flags) {
    memset(thread_context, 0, sizeof *thread_context);
    thread_context->id = WOLFSENTRY_THREAD_GET_ID;
    if (thread_context->id == WOLFSENTRY_THREAD_NO_ID)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FAILED);
    thread_context->deadline.tv_sec = WOLFSENTRY_DEADLINE_NEVER;
    thread_context->deadline.tv_nsec = WOLFSENTRY_DEADLINE_NEVER;
    thread_context->current_thread_flags = init_thread_flags;
    WOLFSENTRY_RETURN_OK;
};

wolfsentry_errcode_t wolfsentry_alloc_thread_context(struct wolfsentry_host_platform_interface *hpi, struct wolfsentry_thread_context **thread_context, wolfsentry_thread_flags_t init_thread_flags) {
    wolfsentry_errcode_t ret;
    if ((*thread_context = (struct wolfsentry_thread_context *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof **thread_context)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    ret = wolfsentry_init_thread_context(*thread_context, init_thread_flags);
    if (ret < 0) {
        WOLFSENTRY_FREE_1(hpi->allocator, *thread_context);
        *thread_context = NULL;
    }
    return ret;
}

wolfsentry_errcode_t wolfsentry_free_thread_context(struct wolfsentry_host_platform_interface *hpi, struct wolfsentry_thread_context **thread_context) {
    WOLFSENTRY_FREE_1(hpi->allocator, *thread_context);
    *thread_context = NULL;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_set_deadline_rel_usecs(WOLFSENTRY_CONTEXT_ARGS_IN, int usecs) {
    wolfsentry_time_t now;
    wolfsentry_errcode_t ret;

    if (usecs < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (usecs > 0) {
        if ((ret = WOLFSENTRY_GET_TIME(&now)) < 0)
            return ret;
        return WOLFSENTRY_TO_EPOCH_TIME(WOLFSENTRY_ADD_TIME(now, usecs), &thread->deadline.tv_sec, &thread->deadline.tv_nsec);
    } else {
        thread->deadline.tv_sec = WOLFSENTRY_DEADLINE_NOW;
        thread->deadline.tv_nsec = WOLFSENTRY_DEADLINE_NOW;
        WOLFSENTRY_RETURN_OK;
    }
}

wolfsentry_errcode_t wolfsentry_set_deadline_abs(WOLFSENTRY_CONTEXT_ARGS_IN, long epoch_secs, long epoch_nsecs) {
    (void)wolfsentry;
    if ((epoch_nsecs < 0) || (epoch_nsecs >= 1000000000))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if ((epoch_secs == WOLFSENTRY_DEADLINE_NEVER) ||
        (epoch_secs == WOLFSENTRY_DEADLINE_NOW))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    thread->deadline.tv_sec = epoch_secs;
    thread->deadline.tv_nsec = epoch_nsecs;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_clear_deadline(WOLFSENTRY_CONTEXT_ARGS_IN) {
    (void)wolfsentry;
    thread->deadline.tv_sec = WOLFSENTRY_DEADLINE_NEVER;
    thread->deadline.tv_nsec = WOLFSENTRY_DEADLINE_NEVER;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_set_thread_readonly(struct wolfsentry_thread_context *thread_context) {
    if (thread_context->mutex_and_reservation_count > 0)
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    thread_context->current_thread_flags |= WOLFSENTRY_THREAD_FLAG_READONLY;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_set_thread_readwrite(struct wolfsentry_thread_context *thread_context) {
    if (thread_context->shared_count > thread_context->recursion_of_shared_lock)
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    thread_context->current_thread_flags &= ~(enumint_t)WOLFSENTRY_THREAD_FLAG_READONLY;
    WOLFSENTRY_RETURN_OK;
}

#if defined(WOLFSENTRY_LOCK_DEBUGGING) && !defined(WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING)
    #error WOLFSENTRY_LOCK_DEBUGGING requires WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
#endif

/* this lock facility depends on POSIX-compliant (counting, async-signal-safe)
 * implementations of sem_{init,post,wait,timedwait,trywait,destroy}(),
 * which can be native, or shims to native facilities.
 */

/* ARM-specific low level locks: https://github.com/PacktPublishing/Embedded-Systems-Architecture/tree/master/Chapter10/os-safe (tip from Danielinux) */

/* sem wrappers layered on various target-specific semaphore implementations:
 * https://github.com/wolfSSL/wolfMQTT/blob/master/src/mqtt_client.c#L43 (note
 * that the "counting semaphore" facility is needed for wolfsentry_lock_*() on
 * FreeRTOS).
 */

#ifdef WOLFSENTRY_USE_NATIVE_POSIX_SEMAPHORES
#include <errno.h>
#endif

#ifdef WOLFSENTRY_USE_NONPOSIX_SEMAPHORES

#ifdef __MACH__

#include <errno.h>

/* Apple style dispatch semaphores -- this uses the only unnamed semaphore
 * facility available in Darwin since POSIX sem_* deprecation.  see
 * https://stackoverflow.com/questions/27736618/why-are-sem-init-sem-getvalue-sem-destroy-deprecated-on-mac-os-x-and-w
 *
 * note, experimentally, dispatch_semaphore_wait() is not interrupted by handled signals.
 */
static int darwin_sem_init(sem_t *sem, int pshared, unsigned int value)
{
    dispatch_semaphore_t new_sem;
    if (pshared) {
        errno = ENOSYS;
        WOLFSENTRY_RETURN_VALUE(-1);
    }
    if (value != 0) {
        /* note, dispatch_release() fails hard, with Trace/BPT trap signal, if
         * the sem's internal count is less than the value passed in with
         * dispatch_semaphore_create().  force init with zero count to prevent
         * this from happening.
         */
        errno = EINVAL;
        WOLFSENTRY_RETURN_VALUE(-1);
    }
    new_sem = dispatch_semaphore_create((intptr_t)value);
    if (new_sem == NULL) {
        errno = ENOMEM;
        WOLFSENTRY_RETURN_VALUE(-1);
    }
    *sem = new_sem;
    WOLFSENTRY_RETURN_VALUE(0);
}
#define sem_init darwin_sem_init

static int darwin_sem_post(sem_t *sem)
{
    if (dispatch_semaphore_signal(*sem) < 0) {
        errno = EINVAL;
        WOLFSENTRY_RETURN_VALUE(-1);
    } else
        WOLFSENTRY_RETURN_VALUE(0);
}
#define sem_post darwin_sem_post

static int darwin_sem_wait(sem_t *sem)
{
    if (dispatch_semaphore_wait(*sem, DISPATCH_TIME_FOREVER) == 0)
        WOLFSENTRY_RETURN_VALUE(0);
    else {
        errno = EINVAL;
        WOLFSENTRY_RETURN_VALUE(-1);
    }
}
#define sem_wait darwin_sem_wait

static int darwin_sem_timedwait(sem_t *sem, struct timespec *abs_timeout) {
    if (dispatch_semaphore_wait(*sem, dispatch_walltime(abs_timeout, 0)) == 0)
        WOLFSENTRY_RETURN_VALUE(0);
    else {
        errno = ETIMEDOUT;
        WOLFSENTRY_RETURN_VALUE(-1);
    }
}
#define sem_timedwait darwin_sem_timedwait

static int darwin_sem_trywait(sem_t *sem) {
    if (dispatch_semaphore_wait(*sem, DISPATCH_TIME_NOW) == 0)
        WOLFSENTRY_RETURN_VALUE(0);
    else {
        errno = EAGAIN;
        WOLFSENTRY_RETURN_VALUE(-1);
    }
}
#define sem_trywait darwin_sem_trywait

static int darwin_sem_destroy(sem_t *sem)
{
    if (*sem == NULL) {
        errno = EINVAL;
        WOLFSENTRY_RETURN_VALUE(-1);
    }

    /* note, dispatch_release() fails hard, with Trace/BPT trap signal, if the
     * sem's internal count is less than the value passed in with
     * dispatch_semaphore_create().  but this can't happen if the sem is inited
     * with value 0, hence forcing that value in darwin_sem_init() above.
     */
    dispatch_release(*sem);
    *sem = NULL;
    WOLFSENTRY_RETURN_VALUE(0);
}
#define sem_destroy darwin_sem_destroy

#elif defined FREERTOS
/* Based on FreeRTOS-POSIX */

static int freertos_sem_init( sem_t * sem,
              int pshared,
              unsigned value )
{
    /* Silence warnings about unused parameters. */
    ( void ) pshared;

    /* Check value parameter. */
    if( value > SEM_VALUE_MAX )
    {
        errno = EINVAL;
        WOLFSENTRY_RETURN_VALUE(-1);
    }

    /* Create the FreeRTOS semaphore.
     * This is only used to queue threads when no semaphore is available.
     * Initializing with semaphore initial count zero.
     * This call will not fail because the memory for the semaphore has already been allocated.
     */
    ( void ) xSemaphoreCreateCountingStatic( SEM_VALUE_MAX, value, sem );

    WOLFSENTRY_RETURN_VALUE(0);
}

#define sem_init freertos_sem_init

static int freertos_sem_post( sem_t * sem )
{
    /* Give the semaphore using the FreeRTOS API. */
    ( void ) xSemaphoreGive(sem);

    WOLFSENTRY_RETURN_VALUE(0);
}

#define sem_post freertos_sem_post


static void UTILS_NanosecondsToTimespec( int64_t llSource,
        struct timespec * const pxDestination )
{
	long lCarrySec = 0;

	/* Convert to timespec. */
	pxDestination->tv_sec = ( time_t ) ( llSource / FREERTOS_NANOSECONDS_PER_SECOND );
	pxDestination->tv_nsec = ( long ) ( llSource % FREERTOS_NANOSECONDS_PER_SECOND );

	/* Subtract from tv_sec if tv_nsec < 0. */
	if( pxDestination->tv_nsec < 0L )
	{
		/* Compute the number of seconds to carry. */
		lCarrySec = ( pxDestination->tv_nsec / ( long ) FREERTOS_NANOSECONDS_PER_SECOND ) + 1L;

		pxDestination->tv_sec -= ( time_t ) ( lCarrySec );
		pxDestination->tv_nsec += lCarrySec * ( long ) FREERTOS_NANOSECONDS_PER_SECOND;
	}
        WOLFSENTRY_RETURN_VOID;
}

static int UTILS_TimespecCompare( const struct timespec * const x,
                           const struct timespec * const y )
{
    int iStatus = 0;

    /* Check parameters */
    if( ( x == NULL ) && ( y == NULL ) )
    {
        iStatus = 0;
    }
    else if( y == NULL )
    {
        iStatus = 1;
    }
    else if( x == NULL )
    {
        iStatus = -1;
    }
    else if( x->tv_sec > y->tv_sec )
    {
        iStatus = 1;
    }
    else if( x->tv_sec < y->tv_sec )
    {
        iStatus = -1;
    }
    else
    {
        /* seconds are equal compare nano seconds */
        if( x->tv_nsec > y->tv_nsec )
        {
            iStatus = 1;
        }
        else if( x->tv_nsec < y->tv_nsec )
        {
            iStatus = -1;
        }
        else
        {
            iStatus = 0;
        }
    }

    WOLFSENTRY_RETURN_VALUE(iStatus);
}



static int UTILS_TimespecSubtract( const struct timespec * const x,
                            const struct timespec * const y,
                            struct timespec * const pxResult )
{
    int iCompareResult = 0;
    int iStatus = 0;

    /* Check parameters. */
    if( ( pxResult == NULL ) || ( x == NULL ) || ( y == NULL ) )
    {
        iStatus = -1;
    }

    if( iStatus == 0 )
    {
        iCompareResult = UTILS_TimespecCompare( x, y );

        /* if x < y then result would be negative, WOLFSENTRY_RETURN_VALUE(1 */
        if( iCompareResult == -1 )
        {
            iStatus = 1);
        }
        else if( iCompareResult == 0 )
        {
            /* if times are the same WOLFSENTRY_RETURN_VALUE(zero */
            pxResult->tv_sec = 0);
            pxResult->tv_nsec = 0;
        }
        else
        {
            /* If x > y Perform subtraction. */
            pxResult->tv_sec = x->tv_sec - y->tv_sec;
            pxResult->tv_nsec = x->tv_nsec - y->tv_nsec;

            /* check if nano seconds value needs to borrow */
            if( pxResult->tv_nsec < 0 )
            {
                /* Based on comparison, tv_sec > 0 */
                pxResult->tv_sec--;
                pxResult->tv_nsec += ( long ) FREERTOS_NANOSECONDS_PER_SECOND;
            }

            /* if nano second is negative after borrow, it is an overflow error */
            if( pxResult->tv_nsec < 0 )
            {
                iStatus = -1;
            }
        }
    }

    WOLFSENTRY_RETURN_VALUE(iStatus);
}

static int UTILS_ValidateTimespec( const struct timespec * const pxTimespec )
{
    int xWOLFSENTRY_RETURN_VALUE(= 0);

    if( pxTimespec != NULL )
    {
        /* Verify 0 <= tv_nsec < 1000000000. */
        if( ( pxTimespec->tv_nsec >= 0 ) &&
            ( pxTimespec->tv_nsec < FREERTOS_NANOSECONDS_PER_SECOND ) )
        {
            xWOLFSENTRY_RETURN_VALUE(= 1);
        }
    }

    WOLFSENTRY_RETURN_VALUE(xReturn);
}

static int UTILS_TimespecToTicks( const struct timespec * const pxTimespec,
                           TickType_t * const pxResult )
{
    int iStatus = 0;
    int64_t llTotalTicks = 0;
    long lNanoseconds = 0;

    /* Check parameters. */
    if( ( pxTimespec == NULL ) || ( pxResult == NULL ) )
    {
        iStatus = EINVAL;
    }
    else if( ( iStatus == 0 ) && ( UTILS_ValidateTimespec( pxTimespec ) == 0 ) )
    {
        iStatus = EINVAL;
    }

    if( iStatus == 0 )
    {
        /* Convert timespec.tv_sec to ticks. */
        llTotalTicks = ( int64_t ) configTICK_RATE_HZ * ( pxTimespec->tv_sec );

        /* Convert timespec.tv_nsec to ticks. This value does not have to be checked
         * for overflow because a valid timespec has 0 <= tv_nsec < 1000000000 and
         * FREERTOS_NANOSECONDS_PER_TICK > 1. */
        lNanoseconds = pxTimespec->tv_nsec / ( long ) FREERTOS_NANOSECONDS_PER_TICK + /* Whole nanoseconds. */
                       ( long ) ( pxTimespec->tv_nsec % ( long ) FREERTOS_NANOSECONDS_PER_TICK != 0 ); /* Add 1 to round up if needed. */

        /* Add the nanoseconds to the total ticks. */
        llTotalTicks += ( int64_t ) lNanoseconds;

        /* Check for overflow */
        if( llTotalTicks < 0 )
        {
            iStatus = EINVAL;
        }
        else
        {
            /* check if TickType_t is 32 bit or 64 bit */
            uint32_t ulTickTypeSize = sizeof( TickType_t );

            /* check for downcast overflow */
            if( ulTickTypeSize == sizeof( uint32_t ) )
            {
                if( llTotalTicks > UINT_MAX )
                {
                    iStatus = EINVAL;
                }
            }
        }

        /* Write result. */
        *pxResult = ( TickType_t ) llTotalTicks;
    }

    WOLFSENTRY_RETURN_VALUE(iStatus);
}



static int UTILS_AbsoluteTimespecToDeltaTicks( const struct timespec * const pxAbsoluteTime,
                                        const struct timespec * const pxCurrentTime,
                                        TickType_t * const pxResult )
{
    int iStatus = 0;
    struct timespec xDifference = { 0 };

    /* Check parameters. */
    if( ( pxAbsoluteTime == NULL ) || ( pxCurrentTime == NULL ) || ( pxResult == NULL ) )
    {
        iStatus = EINVAL;
    }

    /* Calculate the difference between the current time and absolute time. */
    if( iStatus == 0 )
    {
        iStatus = UTILS_TimespecSubtract( pxAbsoluteTime, pxCurrentTime, &xDifference );

        if( iStatus == 1 )
        {
            /* pxAbsoluteTime was in the past. */
            iStatus = ETIMEDOUT;
        }
        else if( iStatus == -1 )
        {
            /* error */
            iStatus = EINVAL;
        }
    }

    /* Convert the time difference to ticks. */
    if( iStatus == 0 )
    {
        iStatus = UTILS_TimespecToTicks( &xDifference, pxResult );
    }

    WOLFSENTRY_RETURN_VALUE(iStatus);
}


static wolfsentry_errcode_t wolfsentry_builtin_get_time(void *context, wolfsentry_time_t *now);

#define clock_gettime wolfsentry_builtin_get_time

static int freertos_sem_timedwait( sem_t * sem,
                   const struct timespec * abstime )
{
    int iStatus = 0;
    TickType_t xDelay = portMAX_DELAY;

    if( abstime != NULL )
    {
        /* If the provided timespec is invalid, still attempt to take the
         * semaphore without blocking, per POSIX spec. */
        if( UTILS_ValidateTimespec( abstime ) == 0 )
        {
            xDelay = 0;
            iStatus = EINVAL;
        }
        else
        {
            struct timespec xCurrentTime = { 0 };

            /* Get current time */
            if( clock_gettime( CLOCK_REALTIME, &xCurrentTime ) != 0 )
            {
                iStatus = EINVAL;
            }
            else
            {
                iStatus = UTILS_AbsoluteTimespecToDeltaTicks( abstime, &xCurrentTime, &xDelay );
            }

            /* If abstime was in the past, still attempt to take the semaphore without
             * blocking, per POSIX spec. */
            if( iStatus == ETIMEDOUT )
            {
                xDelay = 0;
            }
        }
    }

    /* Take the semaphore using the FreeRTOS API. */
    if( xSemaphoreTake( ( SemaphoreHandle_t ) sem,
                        xDelay ) != pdTRUE )
    {
        if( iStatus == 0 )
        {
            errno = ETIMEDOUT;
        }
        else
        {
            errno = iStatus;
        }

        iStatus = -1;
    }
    else
    {
        iStatus = 0;
    }

    WOLFSENTRY_RETURN_VALUE(iStatus);
}

#define sem_timedwait freertos_sem_timedwait

static int freertos_sem_wait( sem_t * sem )
{
    WOLFSENTRY_RETURN_VALUE(freertos_sem_timedwait( sem, NULL ));
}

#define sem_wait freertos_sem_wait

static int freertos_sem_trywait( sem_t * sem )
{
    int iStatus = 0;

    /* Setting an absolute timeout of 0 (i.e. in the past) will cause sem_timedwait
     * to not block. */
    struct timespec xTimeout = { 0 };

    iStatus = freertos_sem_timedwait( sem, &xTimeout );

    /* POSIX specifies that this function should set errno to EAGAIN and not
     * ETIMEDOUT. */
    if( ( iStatus == -1 ) && ( errno == ETIMEDOUT ) )
    {
        errno = EAGAIN;
    }

    WOLFSENTRY_RETURN_VALUE(iStatus);
}

#define sem_trywait freertos_sem_trywait

static int freertos_sem_destroy( sem_t * sem )
{
    /* Free the resources in use by the semaphore. */
    vSemaphoreDelete( sem );

    WOLFSENTRY_RETURN_VALUE(0);
}

#define sem_destroy freertos_sem_destroy


#else

#error semaphore shim set missing for target

#endif

#endif /* WOLFSENTRY_USE_NONPOSIX_SEMAPHORES */

static const struct timespec timespec_deadline_now = {WOLFSENTRY_DEADLINE_NOW, WOLFSENTRY_DEADLINE_NOW};

wolfsentry_errcode_t wolfsentry_lock_init(struct wolfsentry_host_platform_interface *hpi, struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;

    memset(lock,0,sizeof *lock);

#ifdef WOLFSENTRY_LOCK_DEBUGGING
    if (! (flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING))
        flags |= WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING;
#endif
    lock->flags = flags;
    lock->write_lock_holder = WOLFSENTRY_THREAD_NO_ID;
    lock->read2write_reservation_holder = WOLFSENTRY_THREAD_NO_ID;
    lock->hpi = hpi;
#ifndef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
#endif

    if (sem_init(&lock->sem, flags & WOLFSENTRY_LOCK_FLAG_PSHARED, 0 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (sem_init(&lock->sem_read_waiters, flags & WOLFSENTRY_LOCK_FLAG_PSHARED, 0 /* value */) < 0) {
        ret = WOLFSENTRY_ERROR_ENCODE(SYS_RESOURCE_FAILED);
        goto free_sem;
    }
    if (sem_init(&lock->sem_write_waiters, flags & WOLFSENTRY_LOCK_FLAG_PSHARED, 0 /* value */) < 0) {
        ret = WOLFSENTRY_ERROR_ENCODE(SYS_RESOURCE_FAILED);
        goto free_read_waiters;
    }
    if (sem_init(&lock->sem_read2write_waiters, flags & WOLFSENTRY_LOCK_FLAG_PSHARED, 0 /* value */) < 0) {
        ret = WOLFSENTRY_ERROR_ENCODE(SYS_RESOURCE_FAILED);
        goto free_write_waiters;
    }

    ret = WOLFSENTRY_ERROR_ENCODE(OK);
    lock->state = WOLFSENTRY_LOCK_UNLOCKED;
    goto out;

  free_write_waiters:
    if (sem_init(&lock->sem_write_waiters, flags & WOLFSENTRY_LOCK_FLAG_PSHARED, 0 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
  free_read_waiters:
    if (sem_init(&lock->sem_read_waiters, flags & WOLFSENTRY_LOCK_FLAG_PSHARED, 0 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
  free_sem:
    if (sem_init(&lock->sem, flags & WOLFSENTRY_LOCK_FLAG_PSHARED, 1 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);

  out:

    WOLFSENTRY_ERROR_RERETURN(ret);
}

wolfsentry_errcode_t wolfsentry_lock_alloc(struct wolfsentry_host_platform_interface *hpi, struct wolfsentry_rwlock **lock, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;
    if ((*lock = (struct wolfsentry_rwlock *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof **lock)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if ((ret = wolfsentry_lock_init(hpi, *lock, flags)) < 0) {
        WOLFSENTRY_FREE_1(hpi->allocator, *lock);
        *lock = NULL;
        WOLFSENTRY_ERROR_RERETURN(ret);
    }
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_destroy(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
    int ret;

    (void)flags;

    if (lock->state == WOLFSENTRY_LOCK_UNINITED)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

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
        (lock->holder_count.read > 0) ||
        (lock->read_waiter_count > 0) ||
        (lock->write_waiter_count > 0) ||
        (lock->read2write_reserver_count > 0)) {
        WOLFSENTRY_WARN("attempt to destroy used lock {%d,%d,%d,%d,%d}\n", lock->state, lock->holder_count.read, lock->read_waiter_count, lock->write_waiter_count, lock->read2write_reserver_count);
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (lock->shared_locker_list.header.head) {
        WOLFSENTRY_WARN("attempt to destroy lock with non-null shared_locker_list.header.head\n");
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }
#endif

    if (sem_destroy(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (sem_destroy(&lock->sem_read_waiters) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (sem_destroy(&lock->sem_write_waiters) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (sem_destroy(&lock->sem_read2write_waiters) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    lock->state = WOLFSENTRY_LOCK_UNINITED;

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_free(struct wolfsentry_rwlock **lock, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;
    if ((*lock)->state != WOLFSENTRY_LOCK_UNINITED) {
        if ((ret = wolfsentry_lock_destroy(*lock, flags)) < 0)
            return ret;
    }
    WOLFSENTRY_FREE_1((*lock)->hpi->allocator, *lock);
    *lock = NULL;
    WOLFSENTRY_RETURN_OK;
}


#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING

static inline struct wolfsentry_locker_list_ent *_shared_locker_list_assoc_self(struct wolfsentry_rwlock *lock) {
    wolfsentry_thread_id_t self = WOLFSENTRY_THREAD_GET_ID;
    struct wolfsentry_list_ent_header *i = NULL;
    for(wolfsentry_list_ent_get_first(&lock->shared_locker_list.header, &i);
        i;
        wolfsentry_list_ent_get_next(&lock->shared_locker_list.header, &i))
    {
        if (((struct wolfsentry_shared_locker_list_ent *)i)->thread == self)
            break;
    }
    return (struct wolfsentry_shared_locker_list_ent *)i;
}

static inline wolfsentry_errcode_t _shared_locker_list_insert_self(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t_ flags, enumint_t state, struct wolfsentry_locker_list_ent **new_p) {
    wolfsentry_thread_id_t self = WOLFSENTRY_THREAD_GET_ID;
    struct wolfsentry_list_ent_header *i = NULL;
    struct wolfsentry_shared_locker_list_ent *new;
    for(wolfsentry_list_ent_get_first(&lock->shared_locker_list.header, &i);
        i;
        wolfsentry_list_ent_get_next(&lock->shared_locker_list.header, &i))
    {
        if (((struct wolfsentry_shared_locker_list_ent *)i)->thread >= self)
            break;
    }
    if (i && (((struct wolfsentry_shared_locker_list_ent *)i)->thread == self)) {
        if (new_p)
            *new_p = (struct wolfsentry_shared_locker_list_ent *)i;

        if ((((struct wolfsentry_shared_locker_list_ent *)i)->thread_state == state) ||
            ((((struct wolfsentry_shared_locker_list_ent *)i)->thread_state == WOLFSENTRY_LOCK_HAVE_READ) && (state == WOLFSENTRY_LOCK_WAIT_READ))) {
            if (! (flags & WOLFSENTRY_LOCK_FLAG_RECURSIVE_SHARED))
                WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
            else
                WOLFSENTRY_ERROR_RETURN(ALREADY);
        } else if (((((struct wolfsentry_shared_locker_list_ent *)i)->thread_state == WOLFSENTRY_LOCK_HAVE_READ) && (state & WOLFSENTRY_LOCK_WAIT_WRITE)) ||
                 ((((struct wolfsentry_shared_locker_list_ent *)i)->thread_state == WOLFSENTRY_LOCK_HAVE_READ) && (state & WOLFSENTRY_LOCK_WAIT_R2W_REDEMPTION)))
        {
            ((struct wolfsentry_shared_locker_list_ent *)i)->thread_state = state;
            WOLFSENTRY_RETURN_OK;
        } else
            WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    }

    if ((new = lock->allocator->malloc(lock->allocator->context, sizeof *new)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    memset(new, 0, sizeof *new);
    new->thread = self;
    new->thread_state = state;

    wolfsentry_list_ent_insert_after(&lock->shared_locker_list.header, i, &new->header);

    if (new_p)
        *new_p = new;

    WOLFSENTRY_RETURN_OK;
}

static inline void _shared_locker_list_delete(struct wolfsentry_rwlock *lock, struct wolfsentry_shared_locker_list_ent *ent) {
    wolfsentry_list_ent_delete(&lock->shared_locker_list.header, &ent->header);
    lock->allocator->free(lock->allocator->context, ent);
}

static wolfsentry_errcode_t _shared_locker_list_check_ent_consistency(struct wolfsentry_rwlock *lock, struct wolfsentry_shared_locker_list_ent *ent) {
    enumint_t thread_state = WOLFSENTRY_ATOMIC_LOAD(ent->thread_state);
    if ((thread_state & WOLFSENTRY_LOCK_HAVE_READ) && (lock->state != WOLFSENTRY_LOCK_SHARED))
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if ((thread_state & WOLFSENTRY_LOCK_WAIT_READ) && (lock->read_waiter_count == 0))
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if ((thread_state & WOLFSENTRY_LOCK_WAIT_WRITE) && (lock->write_waiter_count == 0))
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if ((thread_state & WOLFSENTRY_LOCK_WAIT_R2W_REDEMPTION) && (lock->read2write_reserver_count == 0))
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if ((thread_state & WOLFSENTRY_LOCK_WAIT_R2W_REDEMPTION) && (lock->holder_count.read < 2))
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if ((thread_state & WOLFSENTRY_LOCK_WAIT_R2W_REDEMPTION) && (! (thread_state & WOLFSENTRY_LOCK_HAVE_READ)))
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    WOLFSENTRY_RETURN_OK;
}

#define LOCKER_LIST_ASSERT_ENT_CONSISTENCY(lock, ll_ent) do { \
        wolfsentry_errcode_t ws_ret = _locker_list_check_ent_consistency(lock, ll_ent); \
        if (ws_ret < 0) \
            WOLFSENTRY_ERROR_RETURN_RECODED(ws_ret); \
    } while(0)


#ifdef WOLFSENTRY_LOCK_DEBUGGING
static wolfsentry_errcode_t _shared_locker_list_check_consistency(struct wolfsentry_rwlock *lock) {
    wolfsentry_errcode_t ret;
    struct wolfsentry_list_ent_header *i = NULL;

    int incoherency_expected = WOLFSENTRY_ATOMIC_LOAD(lock->shared_locker_list.incoherency_expected);

    if (incoherency_expected > 0)
        WOLFSENTRY_RETURN_OK;
    else if (incoherency_expected < 0)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);

    /* if incoherency_expected is 0, it will stay 0 for the whole run of the list,
       because _shared_locker_list_check_consistency() is only called with lock.sem held,
       and incoherency_expected is only incremented with lock.sem held.
    */
/* xxx need to check lock->holder_count.{read,write} for consistency with total held_lock_count */
    for(wolfsentry_list_ent_get_first(&lock->shared_locker_list.header, &i);
        i;
        wolfsentry_list_ent_get_next(&lock->shared_locker_list.header, &i))
    {
        if ((ret = _shared_locker_list_check_ent_consistency(lock, (struct wolfsentry_shared_locker_list_ent *)i)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
    }
    WOLFSENTRY_RETURN_OK;
}

#define SHARED_LOCKER_LIST_ASSERT_CONSISTENCY(lock) if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) do { \
        wolfsentry_errcode_t ws_ret = _shared_locker_list_check_consistency(lock); \
        if (ws_ret < 0) {                                               \
            dprintf(2, "_shared_locker_list_check_consistency(): " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ws_ret)); \
            WOLFSENTRY_ERROR_RETURN_RECODED(ws_ret); \
        }                                      \
    } while(0)

#endif /* WOLFSENTRY_LOCK_DEBUGGING */

#endif /* WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING */

#ifndef SHARED_LOCKER_LIST_ASSERT_CONSISTENCY
#define SHARED_LOCKER_LIST_ASSERT_CONSISTENCY(lock) do {} while (0)
#endif

wolfsentry_errcode_t wolfsentry_lock_shared_abstimed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, const struct timespec *abs_timeout, wolfsentry_lock_flags_t flags) {
    int ret;

    if (WOLFSENTRY_ATOMIC_LOAD(lock->state) == WOLFSENTRY_LOCK_UNINITED)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((flags & WOLFSENTRY_LOCK_FLAG_RECURSIVE_MUTEX) &&
        (WOLFSENTRY_ATOMIC_LOAD(lock->write_lock_holder) == WOLFSENTRY_THREAD_GET_ID)) {
        return wolfsentry_lock_mutex_abstimed(lock, abs_timeout, flags);
    }

    if (abs_timeout == NULL) {
        for (;;) {
            ret = sem_wait(&lock->sem);
            if ((ret == 0) || (errno != EINTR))
                break;
        }
    } else if (abs_timeout == &timespec_deadline_now) {
        ret = sem_trywait(&lock->sem);
        if ((ret < 0) && (errno == EAGAIN))
            WOLFSENTRY_ERROR_RETURN(BUSY);
    } else {
        ret = sem_timedwait(&lock->sem, abs_timeout);
        if (ret < 0) {
            if (errno == ETIMEDOUT)
                WOLFSENTRY_ERROR_RETURN(TIMED_OUT);
            else if (errno == EINTR)
                WOLFSENTRY_ERROR_RETURN(INTERRUPTED);
            else if (errno == EINVAL)
                WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        }
    }
    if (ret < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    SHARED_LOCKER_LIST_ASSERT_CONSISTENCY(lock);

    if ((lock->state == WOLFSENTRY_LOCK_EXCLUSIVE) || (lock->write_waiter_count > 0)) {
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
        struct wolfsentry_locker_list_ent *ll_ent = NULL;
#endif

        if (abs_timeout == &timespec_deadline_now) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else
                WOLFSENTRY_ERROR_RETURN(BUSY);
        }

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
        if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
            wolfsentry_errcode_t ws_ret = _locker_list_insert_self(lock, WOLFSENTRY_LOCK_WAIT_READ | WOLFSENTRY_LOCK_WAIT_READ2WRITE, &ll_ent);
            if (ws_ret < 0) {
                if (sem_post(&lock->sem) < 0)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
                else
                    WOLFSENTRY_ERROR_RETURN_RECODED(ws_ret);
            }
        }
#endif

        lock->read_waiter_count += 2; /* suppress posts to sem_read2write_waiters until wolfsentry_lock_shared2mutex_redeem() is entered. */

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

        if (abs_timeout == NULL) {
            for (;;) {
                ret = sem_wait(&lock->sem_read_waiters);
                if (ret == 0)
                    break;
                else if (errno == EINTR)
                    continue;
                else
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            }
        } else
            ret = sem_timedwait(&lock->sem_read_waiters, abs_timeout);
        if (ret < 0) {
            if (errno == ETIMEDOUT)
                ret = WOLFSENTRY_ERROR_ENCODE(TIMED_OUT);
            else if (errno == EINTR)
                ret = WOLFSENTRY_ERROR_ENCODE(INTERRUPTED);
            else
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);

            /* note, recovery from timeout/interruption requires untimed and uninterruptible wait on lock->sem. */
            for (;;) {
                int ret2 = sem_wait(&lock->sem);
                if (ret2 == 0)
                    break;
                else {
                    if (errno != EINTR)
                        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
                }
            }

            /*
             * now that we own lock->sem, we can retry lock->sem_read_waiters,
             * in case an unlock (and associated post to lock->sem_read_waiters)
             * occured after a sem_timedwait() timeout.
             */
            if (sem_trywait(&lock->sem_read_waiters) == 0) {
                if (sem_post(&lock->sem) < 0)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
                if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
#ifdef WOLFSENTRY_LOCK_DEBUGGING
                    WOLFSENTRY_ATOMIC_STORE(ll_ent->thread_state, WOLFSENTRY_LOCK_HAVE_READ);
                    WOLFSENTRY_ATOMIC_DECREMENT(lock->locker_list.incoherency_expected, 1);
#else
                    ll_ent->thread_state = WOLFSENTRY_LOCK_HAVE_READ;
#endif
                }
#endif
                WOLFSENTRY_RETURN_OK;
            }

            --lock->read_waiter_count;

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
            if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
                _locker_list_delete(lock, ll_ent);
#endif

            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

            WOLFSENTRY_ERROR_RERETURN(ret);
        }

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
        if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
#ifdef WOLFSENTRY_LOCK_DEBUGGING
            WOLFSENTRY_ATOMIC_STORE(ll_ent->thread_state, WOLFSENTRY_LOCK_HAVE_READ);
            WOLFSENTRY_ATOMIC_DECREMENT(lock->locker_list.incoherency_expected, 1);
#else
            ll_ent->thread_state = WOLFSENTRY_LOCK_HAVE_READ;
            ++ll_ent->held_lock_count;
#endif
        }
#endif

        WOLFSENTRY_RETURN_OK;
    } else if ((lock->state == WOLFSENTRY_LOCK_UNLOCKED) ||
               (lock->state == WOLFSENTRY_LOCK_SHARED))
    {
        int store_reservation = 0;

        if (flags & (WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO | WOLFSENTRY_LOCK_FLAG_TRY_RESERVATION_TOO)) {
            if (lock->read2write_reserver_count > 0) {
                if (lock->read2write_reservation_holder == WOLFSENTRY_THREAD_GET_ID)
                    ret = 0;
                else if (flags & WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO)
                    ret = WOLFSENTRY_ERROR_ENCODE(BUSY);
                else
                    ret = 0;
                if (ret < 0) {
                    if (sem_post(&lock->sem) < 0)
                        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
                    return ret;
                }
            } else
                store_reservation = 1;
        }

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
        if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
            wolfsentry_errcode_t ws_ret = _locker_list_insert_self(lock, WOLFSENTRY_LOCK_HAVE_READ | (store_reservation ? WOLFSENTRY_LOCK_HAVE_READ2WRITE_RESERVED : 0), &ll_ent, flags);
            if (ws_ret < 0) {
                if (sem_post(&lock->sem) < 0)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
                else
                    WOLFSENTRY_ERROR_RETURN_RECODED(ws_ret);
            }
            ++ll_ent->held_lock_count;
        }
#endif

        if (lock->state == WOLFSENTRY_LOCK_UNLOCKED)
            lock->state = WOLFSENTRY_LOCK_SHARED;

        if (store_reservation) {
            ++lock->read2write_reserver_count;
            lock->read2write_reservation_holder = WOLFSENTRY_THREAD_GET_ID;
            lock->holder_count.read += 2; /* suppress posts to sem_read2write_waiters until wolfsentry_lock_shared2mutex_redeem() is entered. */
        } else
            ++lock->holder_count.read;

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_RETURN_OK;
    } else
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
}

wolfsentry_errcode_t wolfsentry_lock_shared_timed(struct wolfsentry_rwlock *lock, wolfsentry_time_t max_wait, wolfsentry_lock_flags_t flags) {
    wolfsentry_time_t now;
    struct timespec abs_timeout;
    wolfsentry_errcode_t ret;

    if (max_wait < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (max_wait > 0) {
        if ((ret = WOLFSENTRY_GET_TIME_1(lock->hpi->timecbs, &now)) < 0)
            return ret;
        if ((ret = WOLFSENTRY_TO_EPOCH_TIME_1(lock->hpi->timecbs, WOLFSENTRY_ADD_TIME_1(lock->hpi->timecbs, now,max_wait), &abs_timeout.tv_sec, &abs_timeout.tv_nsec)) < 0)
            return ret;
        return wolfsentry_lock_shared_abstimed(lock, &abs_timeout, flags);
    } else
        return wolfsentry_lock_shared_abstimed(lock, &timespec_deadline_now, flags);
}

wolfsentry_errcode_t wolfsentry_lock_shared(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
    return wolfsentry_lock_shared_abstimed(lock, NULL, flags);
}

wolfsentry_errcode_t wolfsentry_lock_mutex_abstimed(struct wolfsentry_rwlock *lock, const struct timespec *abs_timeout, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;

    if (flags & WOLFSENTRY_LOCK_FLAG_RECURSIVE_MUTEX) {
        switch (WOLFSENTRY_ATOMIC_LOAD(lock->state)) {
        case WOLFSENTRY_LOCK_EXCLUSIVE:
            if (WOLFSENTRY_ATOMIC_LOAD(lock->write_lock_holder) == WOLFSENTRY_THREAD_GET_ID) {
                /* recursively locking while holding write is effectively uncontended. */
                ++lock->holder_count.write;
                WOLFSENTRY_RETURN_OK;
            } else
                break; /* regular semantics */
        case WOLFSENTRY_LOCK_SHARED: {
            wolfsentry_thread_id_t read2write_reservation_holder = WOLFSENTRY_ATOMIC_LOAD(lock->read2write_reservation_holder);
            if (read2write_reservation_holder == WOLFSENTRY_THREAD_GET_ID) {
                ret = wolfsentry_lock_shared2mutex_redeem_abstimed(lock, abs_timeout, flags);
                if (ret < 0)
                    return ret;
                ++lock->holder_count.write;
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
                xxx need to pass a flag to wolfsentry_lock_shared2mutex_redeem_abstimed to get it to delete the ll_ent and increment the lock count.
                ++lock->write_locker_list_ent->held_lock_count;
#endif
                WOLFSENTRY_RETURN_OK;
            } else if (read2write_reservation_holder != WOLFSENTRY_THREAD_NO_ID)
                WOLFSENTRY_ERROR_RETURN(DEADLOCK_AVERTED); /* opportunistic error checking */
            else
                break; /* regular semantics -- will deadlock if caller owns a shared lock and !_LOCK_ERROR_CHECKING. */
        }
        case WOLFSENTRY_LOCK_UNLOCKED:
            break; /* regular semantics */
        case WOLFSENTRY_LOCK_UNINITED:
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        }
    } else {
        if (WOLFSENTRY_ATOMIC_LOAD(lock->state) == WOLFSENTRY_LOCK_UNINITED)
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

    if (abs_timeout == NULL) {
        for (;;) {
            ret = sem_wait(&lock->sem);
            if ((ret == 0) || (errno != EINTR))
                break;
        }
    } else if (abs_timeout == &timespec_deadline_now) {
        ret = sem_trywait(&lock->sem);
        if ((ret < 0) && (errno == EAGAIN))
            WOLFSENTRY_ERROR_RETURN(BUSY);
    } else {
        ret = sem_timedwait(&lock->sem, abs_timeout);
        if (ret < 0) {
            if (errno == ETIMEDOUT)
                WOLFSENTRY_ERROR_RETURN(TIMED_OUT);
            else if (errno == EINTR)
                WOLFSENTRY_ERROR_RETURN(INTERRUPTED);
            else if (errno == EINVAL)
                WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        }
    }
    if (ret < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    SHARED_LOCKER_LIST_ASSERT_CONSISTENCY(lock);

    if (lock->state != WOLFSENTRY_LOCK_UNLOCKED) {
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
        struct wolfsentry_locker_list_ent *ll_ent = NULL;
#endif

        if (abs_timeout == &timespec_deadline_now) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            WOLFSENTRY_ERROR_RETURN(BUSY);
        }

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
        if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
            wolfsentry_errcode_t ws_ret = _locker_list_insert_self(lock, WOLFSENTRY_LOCK_WAIT_WRITE, &ll_ent);
            if (ws_ret < 0) {
                if (sem_post(&lock->sem) < 0)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
                else
                    WOLFSENTRY_ERROR_RETURN_RECODED(ws_ret);
            }
        }
#endif

        ++lock->write_waiter_count;

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

        if (abs_timeout == NULL) {
            for (;;) {
                ret = sem_wait(&lock->sem_write_waiters);
                if (ret == 0)
                    break;
                else {
                    if (errno != EINTR)
                        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
                }
            }
        } else
            ret = sem_timedwait(&lock->sem_write_waiters, abs_timeout);
        if (ret < 0) {
            if (errno == ETIMEDOUT)
                ret = WOLFSENTRY_ERROR_ENCODE(TIMED_OUT);
            else if (errno == EINTR)
                ret = WOLFSENTRY_ERROR_ENCODE(INTERRUPTED);
            else
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);

            /* note, recovery from timeout/interruption requires untimed and uninterruptible wait on lock->sem. */
            for (;;) {
                int ret2 = sem_wait(&lock->sem);
                if (ret2 == 0)
                    break;
                else {
                    if (errno != EINTR)
                        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
                }
            }

            /*
             * now that we own lock->sem, we can retry lock->sem_write_waiters,
             * in case an unlock (and associated post to
             * lock->sem_write_waiters) occured after a sem_timedwait() timeout
             * but before this thread retook lock->sem.
             */
            if (sem_trywait(&lock->sem_write_waiters) == 0) {
                if (sem_post(&lock->sem) < 0)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
                if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
#ifdef WOLFSENTRY_LOCK_DEBUGGING
                    WOLFSENTRY_ATOMIC_STORE(ll_ent->thread_state, WOLFSENTRY_LOCK_HAVE_WRITE);
                    WOLFSENTRY_ATOMIC_DECREMENT(lock->locker_list.incoherency_expected, 1);
#else
                    ll_ent->thread_state = WOLFSENTRY_LOCK_HAVE_WRITE;
#endif
                }
#endif
                WOLFSENTRY_RETURN_OK;
            }

            --lock->write_waiter_count;

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
            if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
                _locker_list_delete(lock, ll_ent);
#endif

            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

            return ret;
        }

        WOLFSENTRY_ATOMIC_STORE(lock->write_lock_holder, WOLFSENTRY_THREAD_GET_ID);

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
        if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
#ifdef WOLFSENTRY_LOCK_DEBUGGING
            WOLFSENTRY_ATOMIC_STORE(ll_ent->thread_state, WOLFSENTRY_LOCK_HAVE_WRITE);
            WOLFSENTRY_ATOMIC_DECREMENT(lock->locker_list.incoherency_expected, 1);
#else
            ll_ent->thread_state = WOLFSENTRY_LOCK_HAVE_WRITE;
#endif
        }
#endif

        WOLFSENTRY_RETURN_OK;
    }

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
        wolfsentry_errcode_t ws_ret = _locker_list_insert_self(lock, WOLFSENTRY_LOCK_HAVE_WRITE, 0);
        if (ws_ret < 0) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else
                WOLFSENTRY_ERROR_RETURN_RECODED(ws_ret);
        }
    }
#endif

    lock->state = WOLFSENTRY_LOCK_EXCLUSIVE;
    lock->write_lock_holder = WOLFSENTRY_THREAD_GET_ID;

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    else
        WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_mutex_timed(struct wolfsentry_rwlock *lock, wolfsentry_time_t max_wait, wolfsentry_lock_flags_t flags) {
    wolfsentry_time_t now;
    struct timespec abs_timeout;
    wolfsentry_errcode_t ret;

    if (max_wait < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (max_wait > 0) {
        if ((ret = WOLFSENTRY_GET_TIME_1(lock->hpi->timecbs, &now)) < 0)
            return ret;
        if ((ret = WOLFSENTRY_TO_EPOCH_TIME_1(lock->hpi->timecbs, WOLFSENTRY_ADD_TIME_1(lock->hpi->timecbs, now,max_wait), &abs_timeout.tv_sec, &abs_timeout.tv_nsec)) < 0)
            return ret;
        return wolfsentry_lock_mutex_abstimed(lock, &abs_timeout, flags);
    } else
        return wolfsentry_lock_mutex_abstimed(lock, &timespec_deadline_now, flags);
}

wolfsentry_errcode_t wolfsentry_lock_mutex(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
    return wolfsentry_lock_mutex_abstimed(lock, NULL, flags);
}

wolfsentry_errcode_t wolfsentry_lock_mutex2shared(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    struct wolfsentry_locker_list_ent *ll_ent = NULL;
#endif
    if (WOLFSENTRY_ATOMIC_LOAD(lock->state) == WOLFSENTRY_LOCK_UNINITED)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((flags & WOLFSENTRY_LOCK_FLAG_RECURSIVE_SHARED) &&
        (! (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (lock->state == WOLFSENTRY_LOCK_SHARED)
        WOLFSENTRY_ERROR_RETURN(ALREADY);

    for (;;) {
        int ret = sem_wait(&lock->sem);
        if (ret == 0)
            break;
        else {
            if (errno != EINTR)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        }
    }

    SHARED_LOCKER_LIST_ASSERT_CONSISTENCY(lock);

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
        ll_ent = _locker_list_assoc_self(lock);
        if (! ll_ent) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else
                WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
        }
        LOCKER_LIST_ASSERT_ENT_CONSISTENCY(lock, ll_ent);
        if (ll_ent->thread_state != WOLFSENTRY_LOCK_HAVE_WRITE) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else
                WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
        }
    }
#endif

    if (lock->state != WOLFSENTRY_LOCK_EXCLUSIVE) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    if (lock->write_lock_holder != WOLFSENTRY_THREAD_GET_ID) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);
    }

    if ((lock->holder_count.write > 1) &&
        (! (flags & WOLFSENTRY_LOCK_FLAG_RECURSIVE_SHARED)))
    {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    if (flags & (WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO | WOLFSENTRY_LOCK_FLAG_TRY_RESERVATION_TOO)) {
        /* can't happen, but be sure. */
        if (lock->read2write_reserver_count > 0) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            WOLFSENTRY_ERROR_RETURN(BUSY);
        }
        ++lock->read2write_reserver_count;
        lock->read2write_reservation_holder = lock->write_lock_holder;
        /* note, not incrementing write_waiter_count, to allow shared lockers to get locks until the redemption phase. */
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
        if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
            ll_ent->thread_state = WOLFSENTRY_LOCK_HAVE_READ | WOLFSENTRY_LOCK_HAVE_READ2WRITE_RESERVED;
#endif
    } else {
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
        if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
            ll_ent->thread_state = WOLFSENTRY_LOCK_HAVE_READ;
#endif
    }

    lock->state = WOLFSENTRY_LOCK_SHARED;
    lock->write_lock_holder = WOLFSENTRY_THREAD_NO_ID;
    lock->promoted_at_count = 0;
    /* writer count becomes reader count. */

    if (flags & (WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO | WOLFSENTRY_LOCK_FLAG_TRY_RESERVATION_TOO)) {
        /* increment by one to suppress posts to sem_read2write_waiters until
         * wolfsentry_lock_shared2mutex_redeem() is entered.
         */
        ++lock->holder_count.read;
    }

    if ((lock->write_waiter_count == 0) &&
        (lock->read_waiter_count > 0))
    {
        int read_waiter_count = lock->read_waiter_count;
        lock->holder_count.read += lock->read_waiter_count;
        lock->read_waiter_count = 0;
#ifdef WOLFSENTRY_LOCK_DEBUGGING
        if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
            WOLFSENTRY_ATOMIC_INCREMENT(lock->locker_list.incoherency_expected, read_waiter_count);
#endif
        for (; read_waiter_count > 0; --read_waiter_count) {
            if (sem_post(&lock->sem_read_waiters) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        }
    }

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    WOLFSENTRY_RETURN_OK;
}

/* a shared lock holder can use wolfsentry_lock_shared2mutex_reserve() to
 * guarantee success of a subsequent lock promotion via
 * wolfsentry_lock_shared2mutex_redeem().
 * wolfsentry_lock_shared2mutex_reserve() will immediately fail if the promotion
 * cannot be reserved.
 */
wolfsentry_errcode_t wolfsentry_lock_shared2mutex_reserve(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    struct wolfsentry_locker_list_ent *ll_ent = NULL;
#endif

    (void)flags;

    if (WOLFSENTRY_ATOMIC_LOAD(lock->state) == WOLFSENTRY_LOCK_UNINITED)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (WOLFSENTRY_ATOMIC_LOAD(lock->state) == WOLFSENTRY_LOCK_EXCLUSIVE) {
        if (WOLFSENTRY_ATOMIC_LOAD(lock->write_lock_holder) == WOLFSENTRY_THREAD_GET_ID)
            WOLFSENTRY_ERROR_RETURN(ALREADY);
        else
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    for (;;) {
        int ret = sem_wait(&lock->sem);
        if (ret == 0)
            break;
        else {
            if (errno != EINTR)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        }
    }

    SHARED_LOCKER_LIST_ASSERT_CONSISTENCY(lock);

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
        ll_ent = _locker_list_assoc_self(lock);
        if (! ll_ent) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else
                WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
        }
        LOCKER_LIST_ASSERT_ENT_CONSISTENCY(lock, ll_ent);
        if (ll_ent->thread_state != WOLFSENTRY_LOCK_HAVE_READ) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else if (ll_ent->thread_state == WOLFSENTRY_LOCK_HAVE_WRITE)
                WOLFSENTRY_ERROR_RETURN(ALREADY);
            else
                WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
        }
    }
#endif

    if (lock->state != WOLFSENTRY_LOCK_SHARED) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    if (lock->read2write_reserver_count > 0) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(BUSY);
    }

    lock->read2write_reservation_holder = WOLFSENTRY_THREAD_GET_ID;
    ++lock->read2write_reserver_count;
    /* note, not incrementing write_waiter_count, to allow shared lockers to get locks until the redemption phase. */
    ++lock->holder_count.read; /* suppress posts to sem_read2write_waiters until wolfsentry_lock_shared2mutex_redeem() is entered. */

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
        ll_ent->thread_state |= WOLFSENTRY_LOCK_HAVE_READ2WRITE_RESERVED;
#endif

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
    return wolfsentry_lock_shared2mutex_redeem_abstimed(lock, NULL, flags);
}

/* if this returns BUSY or TIMED_OUT, the caller still owns a reservation, and must either retry the redemption, or abandon the reservation. */
wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem_abstimed(struct wolfsentry_rwlock *lock, const struct timespec *abs_timeout, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    struct wolfsentry_locker_list_ent *ll_ent = NULL;
#endif

    (void)flags;

    if (WOLFSENTRY_ATOMIC_LOAD(lock->state) == WOLFSENTRY_LOCK_UNINITED)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (WOLFSENTRY_ATOMIC_LOAD(lock->state) == WOLFSENTRY_LOCK_EXCLUSIVE) {
        if (WOLFSENTRY_ATOMIC_LOAD(lock->write_lock_holder) == WOLFSENTRY_THREAD_GET_ID)
            WOLFSENTRY_ERROR_RETURN(ALREADY);
        else
            WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);
    }

    if (abs_timeout == NULL) {
        for (;;) {
            ret = sem_wait(&lock->sem);
            if ((ret == 0) || (errno != EINTR))
                break;
        }
    } else if (abs_timeout == &timespec_deadline_now) {
        ret = sem_trywait(&lock->sem);
        if ((ret < 0) && (errno == EAGAIN))
            WOLFSENTRY_ERROR_RETURN(BUSY);
    } else {
        ret = sem_timedwait(&lock->sem, abs_timeout);
        if (ret < 0) {
            if (errno == ETIMEDOUT)
                WOLFSENTRY_ERROR_RETURN(TIMED_OUT);
            else if (errno == EINTR)
                WOLFSENTRY_ERROR_RETURN(INTERRUPTED);
        }
    }
    if (ret < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    SHARED_LOCKER_LIST_ASSERT_CONSISTENCY(lock);

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
        ll_ent = _locker_list_assoc_self(lock);
        if (! ll_ent) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else
                WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
        }
        LOCKER_LIST_ASSERT_ENT_CONSISTENCY(lock, ll_ent);
        if (ll_ent->thread_state != (WOLFSENTRY_LOCK_HAVE_READ | WOLFSENTRY_LOCK_HAVE_READ2WRITE_RESERVED)) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else if (ll_ent->thread_state == WOLFSENTRY_LOCK_HAVE_WRITE)
                WOLFSENTRY_ERROR_RETURN(ALREADY);
            else
                WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
        }
        if (ll_ent->held_lock_count != 1) {
            /* if we wanted to make this tricky and over-engineered, we could
             * subtract ll_ent->held_lock_count from holder_count.read to allow
             * promotion of recursive shared locks.  but that would be a core
             * dynamic that would depend on _SHARED_ERROR_CHECKING, which
             * doesn't make sense.  better to design the application to not need
             * to promote recursive shared locks at depth, i.e promotions only
             * happen in the outermost function or in a _FLAG_RECURSIVE_MUTEX
             * stack.
             */
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else
                WOLFSENTRY_ERROR_RETURN(DEADLOCK_AVERTED);
        }
    }
#endif

    if (lock->state != WOLFSENTRY_LOCK_SHARED) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    if (lock->read2write_reservation_holder == WOLFSENTRY_THREAD_NO_ID) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    if (lock->read2write_reservation_holder != WOLFSENTRY_THREAD_GET_ID) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);
    }

    if (lock->holder_count.read < 2) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    if (lock->holder_count.read == 2) {
        --lock->holder_count.read; /* remove extra count associated with the reservation. */
        lock->promoted_at_count = lock->holder_count.read;
        /* read count becomes write count. */
        lock->state = WOLFSENTRY_LOCK_EXCLUSIVE;
        lock->write_lock_holder = lock->read2write_reservation_holder;
        lock->read2write_reservation_holder = WOLFSENTRY_THREAD_NO_ID;
        --lock->read2write_reserver_count;
        --lock->write_waiter_count;

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
        if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
            ll_ent->thread_state = WOLFSENTRY_LOCK_HAVE_WRITE;
#endif

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

        WOLFSENTRY_RETURN_OK;
    }

    if (abs_timeout == &timespec_deadline_now) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(BUSY);
    }

    --lock->holder_count.read; /* reenable posts to sem_read2write_waiters by unlockers. */
    ++lock->write_waiter_count; /* and force shared lockers to wait. */

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    if (abs_timeout == NULL) {
        for (;;) {
            ret = sem_wait(&lock->sem_read2write_waiters);
            if (ret == 0)
                break;
            else {
                if (errno != EINTR)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            }
        }
    } else
        ret = sem_timedwait(&lock->sem_read2write_waiters, abs_timeout);
    if (ret < 0) {
        if (errno == ETIMEDOUT)
            ret = WOLFSENTRY_ERROR_ENCODE(TIMED_OUT);
        else if (errno == EINTR)
            ret = WOLFSENTRY_ERROR_ENCODE(INTERRUPTED);
        else
            ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);

        /* note, recovery from timeout/interruption requires untimed and uninterruptible wait on lock->sem. */
        for (;;) {
            int ret2 = sem_wait(&lock->sem);
            if (ret2 == 0)
                break;
            else {
                if (errno != EINTR)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            }
        }

        /*
         * now that we own lock->sem, we can retry lock->sem_read2write_waiters,
         * in case an unlock (and associated post to
         * lock->sem_read2write_waiters) occured after a sem_timedwait()
         * timeout but before this thread retook lock->sem.
         */
        if (sem_trywait(&lock->sem_read2write_waiters) == 0) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
            if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
#ifdef WOLFSENTRY_LOCK_DEBUGGING
                WOLFSENTRY_ATOMIC_STORE(ll_ent->thread_state, WOLFSENTRY_LOCK_HAVE_WRITE);
                WOLFSENTRY_ATOMIC_DECREMENT(lock->locker_list.incoherency_expected, 1);
#else
                ll_ent->thread_state = WOLFSENTRY_LOCK_HAVE_WRITE;
#endif
            }
#endif
            WOLFSENTRY_ATOMIC_STORE(lock->write_lock_holder, WOLFSENTRY_THREAD_GET_ID);
            WOLFSENTRY_RETURN_OK;
        }

        ++lock->holder_count.read; /* restore disabling posts to sem_read2write_waiters by unlockers. */
        --lock->write_waiter_count; /* and allow shared lockers again. */

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            return ret;
    }

    WOLFSENTRY_ATOMIC_STORE(lock->write_lock_holder, WOLFSENTRY_THREAD_GET_ID);

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
#ifdef WOLFSENTRY_LOCK_DEBUGGING
        WOLFSENTRY_ATOMIC_STORE(ll_ent->thread_state, WOLFSENTRY_LOCK_HAVE_WRITE);
        WOLFSENTRY_ATOMIC_DECREMENT(lock->locker_list.incoherency_expected, 1);
#else
        ll_ent->thread_state = WOLFSENTRY_LOCK_HAVE_WRITE;
#endif
    }
#endif

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem_timed(struct wolfsentry_rwlock *lock, wolfsentry_time_t max_wait, wolfsentry_lock_flags_t flags) {
    wolfsentry_time_t now;
    struct timespec abs_timeout;
    wolfsentry_errcode_t ret;

    if (max_wait < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (max_wait > 0) {
        if ((ret = WOLFSENTRY_GET_TIME_1(lock->hpi->timecbs, &now)) < 0)
            return ret;
        if ((ret = WOLFSENTRY_TO_EPOCH_TIME_1(lock->hpi->timecbs, WOLFSENTRY_ADD_TIME_1(lock->hpi->timecbs, now,max_wait), &abs_timeout.tv_sec, &abs_timeout.tv_nsec)) < 0)
            return ret;
        return wolfsentry_lock_shared2mutex_redeem_abstimed(lock, &abs_timeout, flags);
    } else
        return wolfsentry_lock_shared2mutex_redeem_abstimed(lock, &timespec_deadline_now, flags);
}

/* note caller still holds its shared lock after return. */
wolfsentry_errcode_t wolfsentry_lock_shared2mutex_abandon(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    struct wolfsentry_locker_list_ent *ll_ent = NULL;
#endif

    (void)flags;

    if (WOLFSENTRY_ATOMIC_LOAD(lock->state) == WOLFSENTRY_LOCK_UNINITED)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (lock->read2write_reservation_holder != WOLFSENTRY_THREAD_GET_ID) {
        if (lock->read2write_reservation_holder == WOLFSENTRY_THREAD_NO_ID)
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
        else
            WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);
    }

    for (;;) {
        int ret = sem_wait(&lock->sem);
        if (ret == 0)
            break;
        else {
            if (errno != EINTR)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        }
    }

    SHARED_LOCKER_LIST_ASSERT_CONSISTENCY(lock);

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
        ll_ent = _locker_list_assoc_self(lock);
        if (! ll_ent) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else
                WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
        }
        LOCKER_LIST_ASSERT_ENT_CONSISTENCY(lock, ll_ent);
        if (ll_ent->thread_state != (WOLFSENTRY_LOCK_HAVE_READ | WOLFSENTRY_LOCK_HAVE_READ2WRITE_RESERVED)) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else if (ll_ent->thread_state == WOLFSENTRY_LOCK_HAVE_WRITE)
                WOLFSENTRY_ERROR_RETURN(ALREADY);
            else
                WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
        }
    }
#endif

    if (lock->state != WOLFSENTRY_LOCK_SHARED) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    --lock->read2write_reserver_count;
    --lock->holder_count.read;
    lock->read2write_reservation_holder = WOLFSENTRY_THREAD_NO_ID;

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
        ll_ent->thread_state &= ~(unsigned int)WOLFSENTRY_LOCK_HAVE_READ2WRITE_RESERVED;
#endif

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_shared2mutex(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
    return wolfsentry_lock_shared2mutex_abstimed(lock, NULL, flags);
}

/* if another thread is already waiting for read2write, then this
 * returns BUSY, and the caller must _unlock() to resolve the
 * deadlock, then reattempt its transaction with a fresh lock (ideally
 * with a _lock_mutex() at the open).
 */
wolfsentry_errcode_t wolfsentry_lock_shared2mutex_abstimed(struct wolfsentry_rwlock *lock, const struct timespec *abs_timeout, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    struct wolfsentry_locker_list_ent *ll_ent = NULL;
#endif
    switch (WOLFSENTRY_ATOMIC_LOAD(lock->state)) {
    case WOLFSENTRY_LOCK_EXCLUSIVE:
        /* silently and cheaply tolerate repeat calls to _shared2mutex*(). */
        if (lock->write_lock_holder == WOLFSENTRY_THREAD_GET_ID)
            WOLFSENTRY_RETURN_OK;
        else
            WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);
    case WOLFSENTRY_LOCK_SHARED:
        if (lock->read2write_reservation_holder == WOLFSENTRY_THREAD_GET_ID)
            return wolfsentry_lock_shared2mutex_redeem_abstimed(lock, abs_timeout, flags);
        break;
    case WOLFSENTRY_LOCK_UNLOCKED:
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    case WOLFSENTRY_LOCK_UNINITED:
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

    if (abs_timeout == NULL) {
        for (;;) {
            ret = sem_wait(&lock->sem);
            if ((ret == 0) || (errno != EINTR))
                break;
        }
    } else if (abs_timeout == &timespec_deadline_now) {
        ret = sem_trywait(&lock->sem);
        if ((ret < 0) && (errno == EAGAIN))
            WOLFSENTRY_ERROR_RETURN(BUSY);
    } else {
        ret = sem_timedwait(&lock->sem, abs_timeout);
        if (ret < 0) {
            if (errno == ETIMEDOUT)
                WOLFSENTRY_ERROR_RETURN(TIMED_OUT);
            else if (errno == EINTR)
                WOLFSENTRY_ERROR_RETURN(INTERRUPTED);
            else if (errno == EINVAL)
                WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        }
    }
    if (ret < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    SHARED_LOCKER_LIST_ASSERT_CONSISTENCY(lock);

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
        ll_ent = _locker_list_assoc_self(lock);
        if (! ll_ent) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else
                WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
        }
        LOCKER_LIST_ASSERT_ENT_CONSISTENCY(lock, ll_ent);
        if (ll_ent->thread_state != WOLFSENTRY_LOCK_HAVE_READ) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else
                WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
        }
        if (ll_ent->held_lock_count != 1) {
            /* if we wanted to make this tricky and over-engineered, we could
             * subtract ll_ent->held_lock_count from holder_count.read to allow
             * promotion of recursive shared locks.  but that would be a core
             * dynamic that would depend on _SHARED_ERROR_CHECKING, which
             * doesn't make sense.  better to design the application to not need
             * to promote recursive shared locks at depth, i.e promotions only
             * happen in the outermost function or in a _FLAG_RECURSIVE_MUTEX
             * stack.
             */
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else
                WOLFSENTRY_ERROR_RETURN(DEADLOCK_AVERTED);
        }
    }
#endif

    if (lock->state != WOLFSENTRY_LOCK_SHARED) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    if (lock->read2write_reserver_count > 0) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(BUSY);
    }

    if (lock->holder_count.read == 1) {
        /* read count becomes write count. */
        lock->state = WOLFSENTRY_LOCK_EXCLUSIVE;
        lock->write_lock_holder = WOLFSENTRY_THREAD_GET_ID;

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
        if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
            ll_ent->thread_state = WOLFSENTRY_LOCK_HAVE_WRITE;
#endif

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_RETURN_OK;
    }

    if (abs_timeout == &timespec_deadline_now) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(BUSY);
    }

    ++lock->read2write_reserver_count;
    ++lock->write_waiter_count;

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    if (abs_timeout == NULL) {
        for (;;) {
            ret = sem_wait(&lock->sem_read2write_waiters);
            if (ret == 0)
                break;
            else {
                if (errno != EINTR)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            }
        }
    } else 
        ret = sem_timedwait(&lock->sem_read2write_waiters, abs_timeout);

    if (ret < 0) {
        if (errno == ETIMEDOUT)
            ret = WOLFSENTRY_ERROR_ENCODE(TIMED_OUT);
        else if (errno == EINTR)
            ret = WOLFSENTRY_ERROR_ENCODE(INTERRUPTED);
        else
            ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);

        for (;;) {
            int ret2 = sem_wait(&lock->sem);
            if (ret2 == 0)
                break;
            else {
                if (errno != EINTR)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            }
        }

        /*
         * now that we own lock->sem, we can retry lock->sem_read2write_waiters,
         * in case an unlock (and associated post to
         * lock->sem_read2write_waiters) occured after a sem_timedwait()
         * timeout but before this thread retook lock->sem.
         */
        if (sem_trywait(&lock->sem_read2write_waiters) == 0) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            lock->write_lock_holder = WOLFSENTRY_THREAD_GET_ID;
            WOLFSENTRY_RETURN_OK;
        }

        --lock->read2write_reserver_count;
        --lock->write_waiter_count;

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
        if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
            ll_ent->thread_state = WOLFSENTRY_LOCK_HAVE_WRITE;
#endif

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_RETURN_OK;
    }

    lock->write_lock_holder = WOLFSENTRY_THREAD_GET_ID;

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
#ifdef WOLFSENTRY_LOCK_DEBUGGING
        WOLFSENTRY_ATOMIC_STORE(ll_ent->thread_state, WOLFSENTRY_LOCK_HAVE_WRITE);
        WOLFSENTRY_ATOMIC_DECREMENT(lock->locker_list.incoherency_expected, 1);
#else
        ll_ent->thread_state = WOLFSENTRY_LOCK_HAVE_WRITE;
#endif
    }
#endif

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_shared2mutex_timed(struct wolfsentry_rwlock *lock, wolfsentry_time_t max_wait, wolfsentry_lock_flags_t flags) {
    wolfsentry_time_t now;
    struct timespec abs_timeout;
    wolfsentry_errcode_t ret;

    if (max_wait < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (max_wait > 0) {
        if ((ret = WOLFSENTRY_GET_TIME_1(lock->hpi->timecbs, &now)) < 0)
            return ret;
        if ((ret = WOLFSENTRY_TO_EPOCH_TIME_1(lock->hpi->timecbs, WOLFSENTRY_ADD_TIME_1(lock->hpi->timecbs, now,max_wait), &abs_timeout.tv_sec, &abs_timeout.tv_nsec)) < 0)
            return ret;
        return wolfsentry_lock_shared2mutex_abstimed(lock, &abs_timeout, flags);
    } else
        return wolfsentry_lock_shared2mutex_abstimed(lock, &timespec_deadline_now, flags);
}

/* note, if caller has a shared2mutex reservation, it must
 * _shared2mutex_abandon() it first, before _unlock()ing.
 */
wolfsentry_errcode_t wolfsentry_lock_unlock(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    struct wolfsentry_locker_list_ent *ll_ent = NULL;
#endif

    if (WOLFSENTRY_ATOMIC_LOAD(lock->state) == WOLFSENTRY_LOCK_UNINITED)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    /* unlocking a recursive mutex, like recursively locking one, can be done lock-free. */
    if ((WOLFSENTRY_ATOMIC_LOAD(lock->write_lock_holder) == WOLFSENTRY_THREAD_GET_ID) &&
        (lock->holder_count.write > 1))
    {
        --lock->holder_count.write;
        WOLFSENTRY_RETURN_OK;
    }

    /* trap and retry for EINTR to avoid unnecessary failures. */
    do {
        ret = sem_wait(&lock->sem);
    } while ((ret < 0) && (errno == EINTR));
    if (ret < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    SHARED_LOCKER_LIST_ASSERT_CONSISTENCY(lock);

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
        if ((ll_ent = _locker_list_assoc_self(lock)) == NULL) {
            if (lock->state != WOLFSENTRY_LOCK_UNLOCKED)
                ret = WOLFSENTRY_ERROR_ENCODE(NOT_PERMITTED);
            else
                ret = WOLFSENTRY_ERROR_ENCODE(INCOMPATIBLE_STATE);
            if (sem_post(&lock->sem_read2write_waiters) < 0)
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
            return ret;
        }
        LOCKER_LIST_ASSERT_ENT_CONSISTENCY(lock, ll_ent);
    }
#endif

    if (lock->state == WOLFSENTRY_LOCK_SHARED) {
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
        if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
            if (ll_ent->thread_state != WOLFSENTRY_LOCK_HAVE_READ) {
                ret = WOLFSENTRY_ERROR_ENCODE(NOT_PERMITTED);
                goto out;
            }
        }
#endif

        /* opportunistically error-check that the caller didn't inadvertently do
         * an outermost unlock while still holding a promotion reservation.
         */
        if ((! (flags & WOLFSENTRY_LOCK_FLAG_ABANDON_RESERVATION_TOO)) &&
            (lock->holder_count.read == 2) &&
            (lock->read2write_reservation_holder != WOLFSENTRY_THREAD_NO_ID))
        {
            if (lock->read2write_reservation_holder == WOLFSENTRY_THREAD_GET_ID)
                ret = WOLFSENTRY_ERROR_ENCODE(INCOMPATIBLE_STATE);
            else
                ret = WOLFSENTRY_ERROR_ENCODE(INTERNAL_CHECK_FATAL);
            goto out;
        }

        if ((flags & WOLFSENTRY_LOCK_FLAG_ABANDON_RESERVATION_TOO) &&
            (lock->read2write_reservation_holder == WOLFSENTRY_THREAD_GET_ID))
        {
            --lock->read2write_reserver_count;
            --lock->holder_count.read;
            lock->read2write_reservation_holder = WOLFSENTRY_THREAD_NO_ID;
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
            if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
                ll_ent->thread_state &= ~(unsigned int)WOLFSENTRY_LOCK_HAVE_READ2WRITE_RESERVED;
#endif
        }

        if (--lock->holder_count.read == 0)
            lock->state = WOLFSENTRY_LOCK_UNLOCKED;
        else if ((lock->holder_count.read == 1) && (lock->read2write_reserver_count > 0)) {
            lock->promoted_at_count = lock->holder_count.read;
            /* read count becomes write count. */
            --lock->read2write_reserver_count;
            --lock->write_waiter_count;
            lock->state = WOLFSENTRY_LOCK_EXCLUSIVE;
#ifdef WOLFSENTRY_LOCK_DEBUGGING
            if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
                WOLFSENTRY_ATOMIC_INCREMENT(lock->locker_list.incoherency_expected, 1);
#endif
            if (sem_post(&lock->sem_read2write_waiters) < 0)
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
            else {
                ret = WOLFSENTRY_ERROR_ENCODE(OK);
            }
            goto out;
        }
    } else if (lock->state == WOLFSENTRY_LOCK_EXCLUSIVE) {
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
        if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
            if (ll_ent->thread_state != WOLFSENTRY_LOCK_HAVE_WRITE) {
                ret = WOLFSENTRY_ERROR_ENCODE(NOT_PERMITTED);
                goto out;
            }
        }
#endif

        if (lock->write_lock_holder != WOLFSENTRY_THREAD_GET_ID) {
            ret = WOLFSENTRY_ERROR_ENCODE(NOT_PERMITTED);
            goto out;
        }

        --lock->holder_count.write;
        if (lock->holder_count.write < 0) {
            ret = WOLFSENTRY_ERROR_ENCODE(INTERNAL_CHECK_FATAL);
            goto out;
        }
        if (lock->holder_count.write == 0) {
            lock->state = WOLFSENTRY_LOCK_UNLOCKED;
            lock->write_lock_holder = WOLFSENTRY_THREAD_NO_ID;
            lock->promoted_at_count = 0;
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
            lock->write_locker_list_ent = NULL;
#endif
            /* fall through to waiter notification phase. */
        } else {
#ifdef WOLFSENTRY_LOCK_DEBUGGING
            if (! (flags & WOLFSENTRY_LOCK_FLAG_RECURSIVE_MUTEX))
                WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
#endif
            if (lock->promoted_at_count == lock->holder_count.write) {
                lock->state = WOLFSENTRY_LOCK_SHARED;
                lock->promoted_at_count = 0;
                if (flags & WOLFSENTRY_LOCK_FLAG_TRY_RESERVATION_TOO) {
                    lock->read2write_reservation_holder = WOLFSENTRY_THREAD_GET_ID;
                    ++lock->read2write_reserver_count;
                    /* note, not incrementing write_waiter_count, to allow shared lockers to get locks until the redemption phase. */
                    ++lock->holder_count.read; /* suppress posts to sem_read2write_waiters until wolfsentry_lock_shared2mutex_redeem() is entered. */
                }
                /* fall through to waiter notification phase. */
            } else {
                ret = WOLFSENTRY_ERROR_ENCODE(OK);
                goto out;
            }
        }
    } else {
        WOLFSENTRY_WARN("wolfsentry_lock_unlock with state=%d\n", lock->state);
        ret = WOLFSENTRY_ERROR_ENCODE(INCOMPATIBLE_STATE);
        goto out;
    }

    if (lock->write_waiter_count > 0)  {
        if (lock->state == WOLFSENTRY_LOCK_UNLOCKED) {
            --lock->write_waiter_count;
            lock->state = WOLFSENTRY_LOCK_EXCLUSIVE;
            lock->holder_count.write = 1;
#ifdef WOLFSENTRY_LOCK_DEBUGGING
            if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
                WOLFSENTRY_ATOMIC_INCREMENT(lock->locker_list.incoherency_expected, 1);
#endif
            if (sem_post(&lock->sem_write_waiters) < 0) {
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
                goto out;
            }
        }
    } else if (lock->read_waiter_count > 0) {
        int i;
        lock->holder_count.read += lock->read_waiter_count;
        lock->read_waiter_count = 0;
        lock->state = WOLFSENTRY_LOCK_SHARED;
#ifdef WOLFSENTRY_LOCK_DEBUGGING
        if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING)
            WOLFSENTRY_ATOMIC_INCREMENT(lock->locker_list.incoherency_expected, lock->holder_count.read);
#endif
        for (i = 0; i < lock->holder_count.read; ++i) {
            if (sem_post(&lock->sem_read_waiters) < 0) {
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
                goto out;
            }
        }
    }

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING) {
        if (WOLFSENTRY_ERROR_CODE_IS(ret, OK))
            _locker_list_delete(lock, ll_ent);
    }
#endif

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    return ret;
}

wolfsentry_errcode_t wolfsentry_lock_have_shared(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
    enumint_t lock_state = WOLFSENTRY_ATOMIC_LOAD(lock->state);
    (void)flags;
    if (lock_state != WOLFSENTRY_LOCK_SHARED) {
        if (lock_state == WOLFSENTRY_LOCK_UNINITED)
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        else
            WOLFSENTRY_ERROR_RETURN(NOT_OK);
    } else
#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    if (! (lock->flags & WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING))
#endif
        WOLFSENTRY_RETURN_OK; /* this is garbage information that tells the
                               * caller that someone, maybe the caller, had a
                               * shared lock around the time of the call.
                               */

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
    for (;;) {
        int ret = sem_wait(&lock->sem);
        if (ret == 0)
            break;
        else {
            if (errno != EINTR)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        }
    }

    SHARED_LOCKER_LIST_ASSERT_CONSISTENCY(lock);

    {
        struct wolfsentry_locker_list_ent *ll_ent = _locker_list_assoc_self(lock);
        wolfsentry_errcode_t ret;
        if (ll_ent)
            LOCKER_LIST_ASSERT_ENT_CONSISTENCY(lock, ll_ent);
        if ((! ll_ent) || (! (ll_ent->thread_state & WOLFSENTRY_LOCK_HAVE_READ))) {
            if ((lock->state != WOLFSENTRY_LOCK_UNLOCKED) && (! (ll_ent->thread_state & WOLFSENTRY_LOCK_HAVE_WRITE)))
                ret = WOLFSENTRY_ERROR_ENCODE(NOT_PERMITTED);
            else
                ret = WOLFSENTRY_ERROR_ENCODE(NOT_OK);
        } else
            ret = WOLFSENTRY_ERROR_ENCODE(OK);
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            return ret;
    }
#else
    WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
#endif /* WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING */
}

wolfsentry_errcode_t wolfsentry_lock_have_mutex(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
    enumint_t lock_state = WOLFSENTRY_ATOMIC_LOAD(lock->state);
    (void)flags;
    if (lock_state == WOLFSENTRY_LOCK_EXCLUSIVE) {
        if (WOLFSENTRY_ATOMIC_LOAD(lock->write_lock_holder) == WOLFSENTRY_THREAD_GET_ID)
            WOLFSENTRY_RETURN_OK;
        else
            WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);
    } else {
        if (lock_state == WOLFSENTRY_LOCK_UNINITED)
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        else
            WOLFSENTRY_ERROR_RETURN(NOT_OK);
    }
}

wolfsentry_errcode_t wolfsentry_lock_have_either(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;
    ret = wolfsentry_lock_have_mutex(lock, flags);
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, NOT_OK))
        return ret;
    return wolfsentry_lock_have_shared(lock, flags);
}

wolfsentry_errcode_t wolfsentry_lock_have_shared2mutex_reservation(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
    (void)flags;
    if (WOLFSENTRY_ATOMIC_LOAD(lock->state) == WOLFSENTRY_LOCK_UNINITED)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (WOLFSENTRY_ATOMIC_LOAD(lock->read2write_reservation_holder) == WOLFSENTRY_THREAD_GET_ID)
        WOLFSENTRY_RETURN_OK;
    else
        WOLFSENTRY_ERROR_RETURN(NOT_OK);
}

wolfsentry_errcode_t wolfsentry_lock_get_flags(struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t *flags) {
    if (WOLFSENTRY_ATOMIC_LOAD(lock->state) == WOLFSENTRY_LOCK_UNINITED)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    *flags = lock->flags;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_context_lock_mutex(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_mutex(&wolfsentry->lock, WOLFSENTRY_LOCK_FLAG_NONE);
}

wolfsentry_errcode_t wolfsentry_context_lock_mutex_abstimed(
    struct wolfsentry_context *wolfsentry,
    const struct timespec *abs_timeout) {
    return wolfsentry_lock_mutex_abstimed(&wolfsentry->lock, abs_timeout, WOLFSENTRY_LOCK_FLAG_NONE);
}

wolfsentry_errcode_t wolfsentry_context_lock_mutex_timed(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_time_t max_wait) {
    return wolfsentry_lock_mutex_timed(&wolfsentry->lock, max_wait, WOLFSENTRY_LOCK_FLAG_NONE);
}

wolfsentry_errcode_t wolfsentry_context_unlock(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_unlock(&wolfsentry->lock, WOLFSENTRY_LOCK_FLAG_NONE);
}

#endif /* WOLFSENTRY_THREADSAFE */

#ifdef WOLFSENTRY_CLOCK_BUILTINS

#ifdef FREERTOS

#include <FreeRTOS.h>
#include <task.h>

/* Note: NANOSECONDS_PER_SECOND % configTICK_RATE_HZ should equal 0 or this
 * won't work well */

static wolfsentry_errcode_t wolfsentry_builtin_get_time(void *context, wolfsentry_time_t *now) {
    TimeOut_t xCurrentTime = { 0 };
    uint64_t ullTickCount = 0;
    vTaskSetTimeOutState(&xCurrentTime);
    ullTickCount = (uint64_t)(xCurrentTime.xOverflowCount) << (sizeof(TickType_t) * 8);
    ullTickCount += xCurrentTime.xTimeOnEntering;
    *now = ullTickCount * FREERTOS_NANOSECONDS_PER_TICK;
    WOLFSENTRY_RETURN_OK;
}
#else

#include <time.h>

static wolfsentry_errcode_t wolfsentry_builtin_get_time(void *context, wolfsentry_time_t *now) {
    struct timespec ts;
    (void)context;
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    *now = ((wolfsentry_time_t)ts.tv_sec * (wolfsentry_time_t)1000000) + ((wolfsentry_time_t)ts.tv_nsec / (wolfsentry_time_t)1000);
    WOLFSENTRY_RETURN_OK;
}

#endif /* FREERTOS */

static wolfsentry_time_t wolfsentry_builtin_diff_time(wolfsentry_time_t later, wolfsentry_time_t earlier) {
    WOLFSENTRY_RETURN_VALUE(later - earlier);
}

static wolfsentry_time_t wolfsentry_builtin_add_time(wolfsentry_time_t start_time, wolfsentry_time_t time_interval) {
    WOLFSENTRY_RETURN_VALUE(start_time + time_interval);
}

static wolfsentry_errcode_t wolfsentry_builtin_to_epoch_time(wolfsentry_time_t when, time_t *epoch_secs, long *epoch_nsecs) {
    if (when / (wolfsentry_time_t)1000000 > MAX_SINT_OF(*epoch_secs))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    *epoch_secs = (time_t)(when / (wolfsentry_time_t)1000000);
    *epoch_nsecs = (long)((when % (wolfsentry_time_t)1000000) * (wolfsentry_time_t)1000);
    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_builtin_from_epoch_time(time_t epoch_secs, long epoch_nsecs, wolfsentry_time_t *when) {
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
    wolfsentry_builtin_to_epoch_time,
    wolfsentry_builtin_from_epoch_time,
    wolfsentry_builtin_to_epoch_time,
    wolfsentry_builtin_from_epoch_time
#endif
};

#endif /* WOLFSENTRY_CLOCK_BUILTINS */

wolfsentry_errcode_t wolfsentry_time_now_plus_delta(struct wolfsentry_context *wolfsentry, wolfsentry_time_t td, wolfsentry_time_t *res) {
    wolfsentry_errcode_t ret = WOLFSENTRY_GET_TIME(res);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    *res = WOLFSENTRY_ADD_TIME(*res, td);
    WOLFSENTRY_RETURN_OK;
}

#ifdef WOLFSENTRY_THREADSAFE
wolfsentry_errcode_t wolfsentry_time_to_timespec(struct wolfsentry_context *wolfsentry, wolfsentry_time_t t, struct timespec *ts) {
    time_t epoch_secs;
    long int epoch_nsecs;
    WOLFSENTRY_TO_EPOCH_TIME(t, &epoch_secs, &epoch_nsecs);
    ts->tv_sec = epoch_secs;
    ts->tv_nsec = epoch_nsecs;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_time_now_plus_delta_timespec(struct wolfsentry_context *wolfsentry, wolfsentry_time_t td, struct timespec *ts) {
    wolfsentry_time_t now;
    time_t epoch_secs;
    long int epoch_nsecs;
    wolfsentry_errcode_t ret = WOLFSENTRY_GET_TIME(&now);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    WOLFSENTRY_TO_EPOCH_TIME(WOLFSENTRY_ADD_TIME(now, td), &epoch_secs, &epoch_nsecs);
    ts->tv_sec = epoch_secs;
    ts->tv_nsec = epoch_nsecs;
    WOLFSENTRY_RETURN_OK;
}
#endif /* WOLFSENTRY_THREADSAFE */

void *wolfsentry_malloc(struct wolfsentry_context *wolfsentry, size_t size) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->hpi.allocator.malloc(wolfsentry->hpi.allocator.context, size));
}
void wolfsentry_free(struct wolfsentry_context *wolfsentry, void *ptr) {
    wolfsentry->hpi.allocator.free(wolfsentry->hpi.allocator.context, ptr);
}
void *wolfsentry_realloc(struct wolfsentry_context *wolfsentry, void *ptr, size_t size) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->hpi.allocator.realloc(wolfsentry->hpi.allocator.context, ptr, size));
}
void *wolfsentry_memalign(struct wolfsentry_context *wolfsentry, size_t alignment, size_t size) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->hpi.allocator.memalign ? wolfsentry->hpi.allocator.memalign(wolfsentry->hpi.allocator.context, alignment, size) : NULL);
}
void wolfsentry_free_aligned(struct wolfsentry_context *wolfsentry, void *ptr) {
    if (ptr && wolfsentry->hpi.allocator.free_aligned)
        wolfsentry->hpi.allocator.free_aligned(wolfsentry->hpi.allocator.context, ptr);
}

wolfsentry_errcode_t wolfsentry_get_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t *time_p) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->hpi.timecbs.get_time(wolfsentry->hpi.timecbs.context, time_p));
}
wolfsentry_time_t wolfsentry_diff_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t later, wolfsentry_time_t earlier) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->hpi.timecbs.diff_time(later, earlier));
}
wolfsentry_time_t wolfsentry_add_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t start_time, wolfsentry_time_t time_interval) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->hpi.timecbs.add_time(start_time, time_interval));
}
wolfsentry_errcode_t wolfsentry_to_epoch_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t when, time_t *epoch_secs, long *epoch_nsecs) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->timecbs.to_epoch_time(when, epoch_secs, epoch_nsecs));
}
wolfsentry_errcode_t wolfsentry_from_epoch_time(struct wolfsentry_context *wolfsentry, time_t epoch_secs, long epoch_nsecs, wolfsentry_time_t *when) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->timecbs.from_epoch_time(epoch_secs, epoch_nsecs, when));
}
wolfsentry_errcode_t wolfsentry_interval_to_seconds(struct wolfsentry_context *wolfsentry, wolfsentry_time_t howlong, time_t *howlong_secs, long *howlong_nsecs) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->timecbs.interval_to_seconds(howlong, howlong_secs, howlong_nsecs));
}
wolfsentry_errcode_t wolfsentry_interval_from_seconds(struct wolfsentry_context *wolfsentry, time_t howlong_secs, long howlong_nsecs, wolfsentry_time_t *howlong) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->timecbs.interval_from_seconds(howlong_secs, howlong_nsecs, howlong));
}

wolfsentry_ent_id_t wolfsentry_get_object_id(const void *object) {
    WOLFSENTRY_RETURN_VALUE(((const struct wolfsentry_table_ent_header *)object)->id);
}

wolfsentry_errcode_t wolfsentry_object_checkout(void *object) {
    wolfsentry_errcode_t ret;
    WOLFSENTRY_REFCOUNT_INCREMENT(((struct wolfsentry_table_ent_header *)object)->refcount, ret);
    WOLFSENTRY_ERROR_RERETURN(ret);
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
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_eventconfig_get_1(&wolfsentry->config, config));
}

wolfsentry_errcode_t wolfsentry_defaultconfig_update(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_eventconfig *config)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_eventconfig_update_1(config, &wolfsentry->config));
}

struct wolfsentry_allocator *wolfsentry_get_allocator(struct wolfsentry_context *wolfsentry) {
    WOLFSENTRY_RETURN_VALUE(&wolfsentry->allocator);
}

WOLFSENTRY_API struct wolfsentry_timecbs *wolfsentry_get_timecbs(struct wolfsentry_context *wolfsentry) {
    WOLFSENTRY_RETURN_VALUE(&wolfsentry->timecbs);
}

static void wolfsentry_context_free_1(
    struct wolfsentry_context **wolfsentry)
{
    if ((*wolfsentry)->routes != NULL)
        wolfsentry_route_table_free(*wolfsentry, &(*wolfsentry)->routes);
    if ((*wolfsentry)->events != NULL)
        WOLFSENTRY_FREE_1((*wolfsentry)->hpi.allocator, (*wolfsentry)->events);
    if ((*wolfsentry)->actions != NULL)
        WOLFSENTRY_FREE_1((*wolfsentry)->hpi.allocator, (*wolfsentry)->actions);
    if ((*wolfsentry)->user_values != NULL)
        WOLFSENTRY_FREE_1((*wolfsentry)->hpi.allocator, (*wolfsentry)->user_values);
    if ((*wolfsentry)->addr_families_bynumber != NULL)
        WOLFSENTRY_FREE_1((*wolfsentry)->hpi.allocator, (*wolfsentry)->addr_families_bynumber);
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    if ((*wolfsentry)->addr_families_byname != NULL)
        WOLFSENTRY_FREE_1((*wolfsentry)->hpi.allocator, (*wolfsentry)->addr_families_byname);
#endif
    WOLFSENTRY_FREE_1((*wolfsentry)->hpi.allocator, *wolfsentry);
    *wolfsentry = NULL;
    WOLFSENTRY_RETURN_VOID;
}

static wolfsentry_errcode_t wolfsentry_context_init_1(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_lock_flags_t lock_flags)
{
    wolfsentry_errcode_t ret;
    if ((ret = wolfsentry_event_table_init(wolfsentry->events)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    if ((ret = wolfsentry_action_table_init(wolfsentry->actions)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    if ((ret = wolfsentry_route_table_init(wolfsentry->routes)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    if ((ret = wolfsentry_kv_table_init(wolfsentry->user_values)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    if ((ret = wolfsentry_addr_family_bynumber_table_init(wolfsentry->addr_families_bynumber)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    if ((ret = wolfsentry_addr_family_byname_table_init(wolfsentry->addr_families_byname)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
#endif
#ifdef WOLFSENTRY_THREADSAFE
    if ((ret = wolfsentry_lock_init(&wolfsentry->hpi, &wolfsentry->lock, lock_flags)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
#else
    (void)lock_flags;
#endif

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_context_alloc_1(
    const struct wolfsentry_host_platform_interface *hpi,
    struct wolfsentry_context **wolfsentry,
    wolfsentry_lock_flags_t lock_flags)
{
    wolfsentry_errcode_t ret;
    if ((*wolfsentry = (struct wolfsentry_context *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof **wolfsentry)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);

    memset(*wolfsentry, 0, sizeof **wolfsentry);

    (*wolfsentry)->hpi = *hpi;

    if ((((*wolfsentry)->events = (struct wolfsentry_event_table *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof *(*wolfsentry)->events)) == NULL) ||
        (((*wolfsentry)->actions = (struct wolfsentry_action_table *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof *(*wolfsentry)->actions)) == NULL) ||
        (((*wolfsentry)->routes = (struct wolfsentry_route_table *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof *(*wolfsentry)->routes_static)) == NULL) ||
        (((*wolfsentry)->user_values = (struct wolfsentry_kv_table *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof *(*wolfsentry)->user_values)) == NULL) ||
        (((*wolfsentry)->addr_families_bynumber = (struct wolfsentry_addr_family_bynumber_table *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof *(*wolfsentry)->addr_families_bynumber)) == NULL)
#ifdef WOLFSENTRY_PROTOCOL_NAMES
        || (((*wolfsentry)->addr_families_byname = (struct wolfsentry_addr_family_byname_table *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof *(*wolfsentry)->addr_families_byname)) == NULL)
#endif
        )
    {
        wolfsentry_context_free_1(wolfsentry);
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    }

    memset((*wolfsentry)->events, 0, sizeof *(*wolfsentry)->events);
    memset((*wolfsentry)->actions, 0, sizeof *(*wolfsentry)->actions);
    memset((*wolfsentry)->routes, 0, sizeof *(*wolfsentry)->routes);
    memset((*wolfsentry)->user_values, 0, sizeof *(*wolfsentry)->user_values);
    memset((*wolfsentry)->addr_families_bynumber, 0, sizeof *(*wolfsentry)->addr_families_bynumber);
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    memset((*wolfsentry)->addr_families_byname, 0, sizeof *(*wolfsentry)->addr_families_byname);
    if ((ret = wolfsentry_addr_family_table_pair(*wolfsentry, (*wolfsentry)->addr_families_bynumber, (*wolfsentry)->addr_families_byname)) < 0) {
        wolfsentry_context_free_1(wolfsentry);
        WOLFSENTRY_ERROR_RERETURN(ret);
    }
#endif

    if ((ret = wolfsentry_context_init_1(*wolfsentry, lock_flags)) < 0) {
        wolfsentry_context_free_1(wolfsentry);
        WOLFSENTRY_ERROR_RERETURN(ret);
    }

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_init_ex(
    const struct wolfsentry_host_platform_interface *user_hpi,
    const struct wolfsentry_eventconfig *config,
    struct wolfsentry_context **wolfsentry,
    wolfsentry_init_flags_t flags)
{
    struct wolfsentry_host_platform_interface hpi;
    wolfsentry_lock_flags_t lock_flags = WOLFSENTRY_LOCK_FLAG_NONE;
    wolfsentry_errcode_t ret = wolfsentry_eventconfig_check(config);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    if ((user_hpi == NULL) || (user_hpi->allocator.malloc == NULL)) {
#ifndef WOLFSENTRY_MALLOC_BUILTINS
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
#else
        hpi.allocator = default_allocator;
#endif
    } else
        hpi.allocator = user_hpi->allocator;

    if ((hpi.allocator.malloc == NULL) ||
        (hpi.allocator.free == NULL) ||
        (hpi.allocator.realloc == NULL))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((hpi.allocator.memalign == NULL) ^
        (hpi.allocator.free_aligned == NULL))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((user_hpi == NULL) || (user_hpi->timecbs.get_time == NULL)) {
#ifndef WOLFSENTRY_CLOCK_BUILTINS
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
#else
        hpi.timecbs = default_timecbs;
#endif
    } else
        hpi.timecbs = user_hpi->timecbs;

    if ((hpi.timecbs.get_time == NULL) ||
        (hpi.timecbs.diff_time == NULL) ||
        (hpi.timecbs.add_time == NULL) ||
        (hpi.timecbs.to_epoch_time == NULL) ||
        (hpi.timecbs.from_epoch_time == NULL) ||
        (hpi.timecbs.interval_to_seconds == NULL) ||
        (hpi.timecbs.interval_from_seconds == NULL))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((hpi.allocator.memalign == NULL) && config && (config->route_private_data_alignment > 0))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (flags & WOLFSENTRY_INIT_FLAG_LOCK_SHARED_ERROR_CHECKING)
        lock_flags |= WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING;

    if ((ret = wolfsentry_context_alloc_1(&hpi, wolfsentry, lock_flags)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    if ((ret = wolfsentry_eventconfig_load(config, &(*wolfsentry)->config)) < 0)
        goto out;

    /* config->penaltybox_duration is passed to wolfsentry_init_ex() in seconds,
     * because wolfsentry_interval_from_seconds() needs a valid
     * wolfsentry_context (circular dependency).  fix it now that we can.
     */
    timecbs->interval_from_seconds((long int)(*wolfsentry)->config.config.penaltybox_duration, 0 /* howlong_nsecs */, &((*wolfsentry)->config.config.penaltybox_duration));

    (*wolfsentry)->config_at_creation = (*wolfsentry)->config;

    if ((ret = wolfsentry_route_table_fallthrough_route_alloc(*wolfsentry, (*wolfsentry)->routes)) < 0)
        goto out;

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    if (ret < 0) {
        (void)wolfsentry_lock_destroy(&(*wolfsentry)->lock, WOLFSENTRY_LOCK_FLAG_NONE);
        wolfsentry_context_free_1(wolfsentry);
    }
    WOLFSENTRY_ERROR_RERETURN(ret);
}

wolfsentry_errcode_t wolfsentry_init(
    const struct wolfsentry_host_platform_interface *hpi,
    const struct wolfsentry_eventconfig *config,
    struct wolfsentry_context **wolfsentry)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_init_ex(hpi, config, wolfsentry, WOLFSENTRY_INIT_FLAG_NONE));
}

wolfsentry_errcode_t wolfsentry_context_flush(WOLFSENTRY_CONTEXT_ARGS_IN) {
    wolfsentry_errcode_t ret;
    wolfsentry_action_res_t action_results;

    action_results = WOLFSENTRY_ACTION_RES_NONE;
    if ((ret = wolfsentry_route_flush_table(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->routes, &action_results)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    if ((ret = wolfsentry_table_free_ents(wolfsentry, &wolfsentry->events->header)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    if ((ret = wolfsentry_table_free_ents(wolfsentry, &wolfsentry->user_values->header)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_context_free(struct wolfsentry_context **wolfsentry) {
    wolfsentry_errcode_t ret;

    if ((ret = wolfsentry_lock_destroy(&(*wolfsentry)->lock, WOLFSENTRY_LOCK_FLAG_NONE)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    if ((*wolfsentry)->routes != NULL) {
        if ((ret = wolfsentry_table_free_ents(*wolfsentry, &(*wolfsentry)->routes->header)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
    }
    if ((*wolfsentry)->actions != NULL) {
        if ((ret = wolfsentry_table_free_ents(*wolfsentry, &(*wolfsentry)->actions->header)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
    }
    if ((*wolfsentry)->events != NULL) {
        if ((ret = wolfsentry_table_free_ents(*wolfsentry, &(*wolfsentry)->events->header)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
    }
    if ((*wolfsentry)->user_values != NULL) {
        if ((ret = wolfsentry_table_free_ents(*wolfsentry, &(*wolfsentry)->user_values->header)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
    }
    if ((*wolfsentry)->addr_families_bynumber != NULL) {
        if ((ret = wolfsentry_table_free_ents(*wolfsentry, &(*wolfsentry)->addr_families_bynumber->header)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
    }
    /* freeing ents in addr_families_byname is implicit to freeing the
     * corresponding ents in addr_families_bynumber.
     */

    wolfsentry_context_free_1(wolfsentry);

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_shutdown(struct wolfsentry_context **wolfsentry) {
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_context_free(wolfsentry));
}

wolfsentry_errcode_t wolfsentry_context_inhibit_actions(struct wolfsentry_context *wolfsentry) {
    wolfsentry_eventconfig_flags_t flags_before, flags_after;
    WOLFSENTRY_ATOMIC_UPDATE_FLAGS(
        wolfsentry->config.config.flags,
        (wolfsentry_eventconfig_flags_t)WOLFSENTRY_EVENTCONFIG_FLAG_INHIBIT_ACTIONS,
        (wolfsentry_eventconfig_flags_t)WOLFSENTRY_EVENTCONFIG_FLAG_NONE,
        &flags_before,
        &flags_after);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_context_enable_actions(struct wolfsentry_context *wolfsentry) {
    wolfsentry_eventconfig_flags_t flags_before, flags_after;
    WOLFSENTRY_ATOMIC_UPDATE_FLAGS(
        wolfsentry->config.config.flags,
        (wolfsentry_eventconfig_flags_t)WOLFSENTRY_EVENTCONFIG_FLAG_NONE,
        (wolfsentry_eventconfig_flags_t)WOLFSENTRY_EVENTCONFIG_FLAG_INHIBIT_ACTIONS,
        &flags_before,
        &flags_after);
    WOLFSENTRY_RETURN_OK;
}

/* caller must have read lock and read2write reservation on context, and hold
 * onto it until either redeeming the reservation and exchanging in the cloned
 * context, or abandoning the reservation and the clone.
 */
wolfsentry_errcode_t wolfsentry_context_clone(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_context **clone,
    wolfsentry_clone_flags_t flags)
{
    wolfsentry_errcode_t ret;

#ifdef WOLFSENTRY_THREADSAFE
    if ((ret = wolfsentry_context_alloc_1(&wolfsentry->hpi, clone, wolfsentry->lock.flags)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
#else
    if ((ret = wolfsentry_context_alloc_1(&wolfsentry->hpi, clone, WOLFSENTRY_LOCK_FLAG_NONE)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
#endif

    (*clone)->hpi = wolfsentry->hpi;
    /* note that the ID generation state is copied verbatim.  in the
     * wolfsentry_table_clone() operations below, objects are copied with their
     * IDs intact.
     */
    (*clone)->mk_id_cb = wolfsentry->mk_id_cb;
    (*clone)->mk_id_cb_state = wolfsentry->mk_id_cb_state;

    if (WOLFSENTRY_CHECK_BITS(flags, WOLFSENTRY_CLONE_FLAG_AS_AT_CREATION))
        (*clone)->config = (*clone)->config_at_creation = wolfsentry->config_at_creation;
    else {
        (*clone)->config = wolfsentry->config;
        (*clone)->config_at_creation = wolfsentry->config_at_creation;
    }

    WOLFSENTRY_TABLE_HEADER_RESET((*clone)->ents_by_id);

    if ((ret = wolfsentry_table_clone(wolfsentry, &wolfsentry->actions->header, *clone, &(*clone)->actions->header, flags)) < 0)
        goto out;

#ifdef WOLFSENTRY_PROTOCOL_NAMES
    if ((ret = wolfsentry_coupled_table_clone(
             wolfsentry,
             &wolfsentry->addr_families_bynumber->header,
             &wolfsentry->addr_families_byname->header,
             *clone,
             &(*clone)->addr_families_bynumber->header,
             &(*clone)->addr_families_byname->header,
             flags)) < 0)
        goto out;
#else
    if ((ret = wolfsentry_table_clone(wolfsentry, &wolfsentry->addr_families_bynumber->header, *clone, &(*clone)->addr_families_bynumber->header, flags)) < 0)
        goto out;
#endif

    if (WOLFSENTRY_CHECK_BITS(flags, WOLFSENTRY_CLONE_FLAG_AS_AT_CREATION)) {
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        goto out;
    }

    if ((ret = wolfsentry_table_clone(wolfsentry, &wolfsentry->events->header, *clone, &(*clone)->events->header, flags)) < 0)
        goto out;
    if ((ret = wolfsentry_table_clone(wolfsentry, &wolfsentry->routes->header, *clone, &(*clone)->routes->header, flags)) < 0)
        goto out;
    if ((ret = wolfsentry_table_clone(wolfsentry, &wolfsentry->user_values->header, *clone, &(*clone)->user_values->header, flags)) < 0)
        goto out;

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    if ((ret < 0) && (*clone != NULL))
        (void)wolfsentry_context_free(clone);

    WOLFSENTRY_ERROR_RERETURN(ret);
}

wolfsentry_errcode_t wolfsentry_context_exchange(struct wolfsentry_context *wolfsentry1, struct wolfsentry_context *wolfsentry2) {
    struct wolfsentry_context scratch;

    if ((memcmp(&wolfsentry1->hpi, &wolfsentry2->hpi, sizeof wolfsentry1->hpi)) ||
        (wolfsentry1->mk_id_cb != wolfsentry2->mk_id_cb))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    scratch = *wolfsentry1;

    wolfsentry1->mk_id_cb_state = wolfsentry2->mk_id_cb_state;
    wolfsentry1->config = wolfsentry2->config;
    wolfsentry1->config_at_creation = wolfsentry2->config_at_creation;
    wolfsentry1->events = wolfsentry2->events;
    wolfsentry1->actions = wolfsentry2->actions;
    wolfsentry1->routes =  wolfsentry2->routes;
    wolfsentry1->user_values = wolfsentry2->user_values;
    wolfsentry1->addr_families_bynumber = wolfsentry2->addr_families_bynumber;
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    wolfsentry1->addr_families_byname = wolfsentry2->addr_families_byname;
#endif
    wolfsentry1->ents_by_id = wolfsentry2->ents_by_id;

    wolfsentry2->mk_id_cb_state = scratch.mk_id_cb_state;
    wolfsentry2->config = scratch.config;
    wolfsentry2->config_at_creation = scratch.config_at_creation;
    wolfsentry2->events = scratch.events;
    wolfsentry2->actions = scratch.actions;
    wolfsentry2->routes = scratch.routes;
    wolfsentry2->user_values = scratch.user_values;
    wolfsentry2->addr_families_bynumber = scratch.addr_families_bynumber;
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    wolfsentry2->addr_families_byname = scratch.addr_families_byname;
#endif

    wolfsentry2->ents_by_id = scratch.ents_by_id;

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_hitcount_t wolfsentry_table_n_inserts(struct wolfsentry_table_header *table) {
    WOLFSENTRY_RETURN_VALUE(table->n_inserts);
}

wolfsentry_hitcount_t wolfsentry_table_n_deletes(struct wolfsentry_table_header *table) {
    WOLFSENTRY_RETURN_VALUE(table->n_deletes);
}

static const char base64_inv_lut[0x100] =
    /* ^@-\x1f */ "||||||||||||||||||||||||||||||||"
    /* \ -* */ "|||||||||||"
    /* + */ "\x3e"
    /* ,-. */ "|||"
    /* / */ "\x3f"
    /* 0-9 */ "\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d"
    /* :-< */ "|||"
    /* = */ "@"
    /* >-@ */ "|||"
    /* A-P */ "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    /* Q-Z */ "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
    /* [-` */ "||||||"
    /* a-p */ "\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29"
    /* q-z */ "\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33"
    /* {-DEL */ "|||||"
    /* 0x80- */
    "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
    "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||";

wolfsentry_errcode_t wolfsentry_base64_decode(const char *src, size_t src_len, byte *dest, size_t *dest_spc, int ignore_junk_p) {
    uint32_t decoded = 0;
    uint32_t decoded_bits = 0;
    uint32_t pad_chars = 0;
    const char *src_end = src + src_len;
    size_t dest_len = 0;

    if (*dest_spc < ((src_len + 3) / 4) * 3)
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);

    for (; src < src_end; ++src) {
        uint32_t this_char = (uint32_t)base64_inv_lut[*(unsigned char *)src];
        if (this_char == (uint32_t)'|') {
            if (ignore_junk_p)
                continue;
            else
                WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        } else if (this_char == (uint32_t)'@') {
            if ((src + 1 < src_end) && (base64_inv_lut[*((unsigned char *)src + 1)] != '@'))
                WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
            ++pad_chars;
            decoded <<= 6U;
            continue;
        }

        decoded <<= 6U;
        decoded |= this_char;
        decoded_bits += 6U;

        if (decoded_bits == 24U) {
            *dest++ = (byte)(decoded >> 16U);
            *dest++ = (byte)(decoded >> 8U);
            *dest++ = (byte)(decoded);
            decoded = 0;
            decoded_bits = 0;
            dest_len += 3;
        }
    }

    if (decoded_bits && (pad_chars == 0)) {
        if (decoded_bits < 8U)
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        pad_chars = (28U - decoded_bits) >> 3U;
        decoded <<= 24U - decoded_bits;
        decoded_bits = 24U;
    }

    switch (pad_chars) {
    case 0:
        break;
    case 1:
        *dest++ = (byte)(decoded >> 16U);
        *dest++ = (byte)(decoded >> 8U);
        dest_len += 2;
        break;
        /* fall through */
    case 2:
        *dest++ = (byte)(decoded >> 16U);
        ++dest_len;
        break;
    default:
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

    *dest_spc = dest_len;

    WOLFSENTRY_RETURN_OK;
}
