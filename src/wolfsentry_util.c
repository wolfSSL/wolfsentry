/*
 * wolfsentry_util.c
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

#define WOLFSENTRY_DEFINE_BUILD_SETTINGS
#include "wolfsentry_internal.h"

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_WOLFSENTRY_UTIL_C

#ifdef WOLFSENTRY_ERROR_STRINGS

static const char *user_defined_sources[WOLFSENTRY_SOURCE_ID_MAX - WOLFSENTRY_SOURCE_ID_USER_BASE + 1] = {0};

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_source_string_set(enum wolfsentry_source_id wolfsentry_source_id, const char *source_string) {
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
WOLFSENTRY_API const char *wolfsentry_errcode_source_string(wolfsentry_errcode_t e)
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
    case WOLFSENTRY_SOURCE_ID_WOLFSENTRY_UTIL_C:
        return "wolfsentry_util.c";
    case WOLFSENTRY_SOURCE_ID_KV_C:
        return "kv.c";
    case WOLFSENTRY_SOURCE_ID_ADDR_FAMILIES_C:
        return "addr_families.c";
    case WOLFSENTRY_SOURCE_ID_JSON_LOAD_CONFIG_C:
        return "json/load_config.c";
    case WOLFSENTRY_SOURCE_ID_JSON_JSON_UTIL_C:
        return "json/json_util.c";
    case WOLFSENTRY_SOURCE_ID_LWIP_PACKET_FILTER_GLUE_C:
        return "lwip/packet_filter_glue.c";
    case WOLFSENTRY_SOURCE_ID_ACTION_BUILTINS_C:
        return "action_builtins.c";

    case WOLFSENTRY_SOURCE_ID_USER_BASE:
        break;
    }
    if (i >= WOLFSENTRY_SOURCE_ID_USER_BASE) {
        if (user_defined_sources[i - WOLFSENTRY_SOURCE_ID_USER_BASE])
            return user_defined_sources[i - WOLFSENTRY_SOURCE_ID_USER_BASE];
        else
            return "unknown user defined source";
    } else
        return "unknown source";
}

static const char *user_defined_errors[WOLFSENTRY_ERROR_ID_MAX - WOLFSENTRY_ERROR_ID_USER_BASE + 1] = {0};
static const char *user_defined_successes[WOLFSENTRY_ERROR_ID_MAX + WOLFSENTRY_SUCCESS_ID_USER_BASE + 1] = {0};

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_error_string_set(enum wolfsentry_error_id wolfsentry_error_id, const char *message_string) {
    if (wolfsentry_error_id < 0) {
        if ((wolfsentry_error_id > WOLFSENTRY_ERROR_ID_USER_BASE) || (wolfsentry_error_id < -WOLFSENTRY_ERROR_ID_MAX))
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        else if (user_defined_errors[-(wolfsentry_error_id - WOLFSENTRY_ERROR_ID_USER_BASE)] != NULL)
            WOLFSENTRY_ERROR_RETURN(ITEM_ALREADY_PRESENT);
        else {
            user_defined_errors[-(wolfsentry_error_id - WOLFSENTRY_ERROR_ID_USER_BASE)] = message_string;
            WOLFSENTRY_RETURN_OK;
        }
    } else {
        if ((wolfsentry_error_id < WOLFSENTRY_SUCCESS_ID_USER_BASE) || (wolfsentry_error_id > WOLFSENTRY_ERROR_ID_MAX))
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        else if (user_defined_successes[wolfsentry_error_id - WOLFSENTRY_SUCCESS_ID_USER_BASE] != NULL)
            WOLFSENTRY_ERROR_RETURN(ITEM_ALREADY_PRESENT);
        else {
            user_defined_successes[wolfsentry_error_id - WOLFSENTRY_SUCCESS_ID_USER_BASE] = message_string;
            WOLFSENTRY_RETURN_OK;
        }
    }
}

/* note, returns not instrumented, to avoid noise when debugging. */
WOLFSENTRY_API const char *wolfsentry_errcode_error_string(wolfsentry_errcode_t e)
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
        return "A prerequisite condition was unmet because a resource was busy";
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
        return "Configuration clause in wrong sequence or missing dependency";
    case WOLFSENTRY_ERROR_ID_CONFIG_UNEXPECTED:
        return "Configuration has unexpected or invalid structure";
    case WOLFSENTRY_ERROR_ID_CONFIG_MISPLACED_KEY:
        return "Configuration uses a key in the wrong context or combination";
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
    case WOLFSENTRY_ERROR_ID_LACKING_MUTEX:
        return "Caller lacks exclusive lock";
    case WOLFSENTRY_ERROR_ID_LACKING_READ_LOCK:
        return "Caller lacks shared read lock";
    case WOLFSENTRY_ERROR_ID_LIB_MISMATCH:
        return "Library or plugin version mismatch";
    case WOLFSENTRY_ERROR_ID_LIBCONFIG_MISMATCH:
        return "Library built configuration is incompatible with caller";
    case WOLFSENTRY_ERROR_ID_IO_FAILED:
        return "Input/output failure";
    case WOLFSENTRY_ERROR_ID_WRONG_ATTRIBUTES:
        return "Attributes of item preclude the requested operation";

    case WOLFSENTRY_SUCCESS_ID_LOCK_OK_AND_GOT_RESV:
        return "Lock request succeeded and reserved promotion";
    case WOLFSENTRY_SUCCESS_ID_HAVE_MUTEX:
        return "Caller owns a mutex on the designated lock";
    case WOLFSENTRY_SUCCESS_ID_HAVE_READ_LOCK:
        return "Caller shares the designated lock";
    case WOLFSENTRY_SUCCESS_ID_USED_FALLBACK:
        return "Operation succeeded by fallback strategy";
    case WOLFSENTRY_SUCCESS_ID_YES:
        return "Result was Yes";
    case WOLFSENTRY_SUCCESS_ID_NO:
        return "Result was No";
    case WOLFSENTRY_SUCCESS_ID_ALREADY_OK:
        return "Operation skipped due to idempotency";
    case WOLFSENTRY_SUCCESS_ID_DEFERRED:
        return "Operation deferred awaiting state change";
    case WOLFSENTRY_ERROR_ID_USER_BASE:
    case WOLFSENTRY_SUCCESS_ID_USER_BASE:
        break;
    }
    if (i <= WOLFSENTRY_ERROR_ID_USER_BASE) {
        if (user_defined_errors[-(i - WOLFSENTRY_ERROR_ID_USER_BASE)])
            return user_defined_errors[-(i - WOLFSENTRY_ERROR_ID_USER_BASE)];
        else
            return "unknown user defined error code";
    } else if (i >= WOLFSENTRY_SUCCESS_ID_USER_BASE) {
        if (user_defined_successes[i - WOLFSENTRY_SUCCESS_ID_USER_BASE])
            return user_defined_errors[i - WOLFSENTRY_SUCCESS_ID_USER_BASE];
        else
            return "unknown user defined success code";
    } else if (i >= 0)
        return "unknown success code";
    else
        return "unknown error code";
}

/* note, returns not instrumented, to avoid noise when debugging. */
WOLFSENTRY_API const char *wolfsentry_errcode_error_name(wolfsentry_errcode_t e)
{
    enum wolfsentry_error_id i = (enum wolfsentry_error_id)WOLFSENTRY_ERROR_DECODE_ERROR_CODE(e);
    switch(i) {
#define _ERRNAME_TO_STRING(x) case WOLFSENTRY_ERROR_ID_ ## x: return #x
    _ERRNAME_TO_STRING(OK);
    _ERRNAME_TO_STRING(NOT_OK);
    _ERRNAME_TO_STRING(INTERNAL_CHECK_FATAL);
    _ERRNAME_TO_STRING(SYS_OP_FATAL);
    _ERRNAME_TO_STRING(SYS_OP_FAILED);
    _ERRNAME_TO_STRING(SYS_RESOURCE_FAILED);
    _ERRNAME_TO_STRING(INCOMPATIBLE_STATE);
    _ERRNAME_TO_STRING(TIMED_OUT);
    _ERRNAME_TO_STRING(INVALID_ARG);
    _ERRNAME_TO_STRING(BUSY);
    _ERRNAME_TO_STRING(INTERRUPTED);
    _ERRNAME_TO_STRING(NUMERIC_ARG_TOO_BIG);
    _ERRNAME_TO_STRING(NUMERIC_ARG_TOO_SMALL);
    _ERRNAME_TO_STRING(STRING_ARG_TOO_LONG);
    _ERRNAME_TO_STRING(BUFFER_TOO_SMALL);
    _ERRNAME_TO_STRING(IMPLEMENTATION_MISSING);
    _ERRNAME_TO_STRING(ITEM_NOT_FOUND);
    _ERRNAME_TO_STRING(ITEM_ALREADY_PRESENT);
    _ERRNAME_TO_STRING(ALREADY_STOPPED);
    _ERRNAME_TO_STRING(WRONG_OBJECT);
    _ERRNAME_TO_STRING(DATA_MISSING);
    _ERRNAME_TO_STRING(NOT_PERMITTED);
    _ERRNAME_TO_STRING(ALREADY);
    _ERRNAME_TO_STRING(CONFIG_INVALID_KEY);
    _ERRNAME_TO_STRING(CONFIG_INVALID_VALUE);
    _ERRNAME_TO_STRING(CONFIG_OUT_OF_SEQUENCE);
    _ERRNAME_TO_STRING(CONFIG_UNEXPECTED);
    _ERRNAME_TO_STRING(CONFIG_MISPLACED_KEY);
    _ERRNAME_TO_STRING(CONFIG_PARSER);
    _ERRNAME_TO_STRING(CONFIG_MISSING_HANDLER);
    _ERRNAME_TO_STRING(CONFIG_JSON_VALUE_SIZE);
    _ERRNAME_TO_STRING(OP_NOT_SUPP_FOR_PROTO);
    _ERRNAME_TO_STRING(WRONG_TYPE);
    _ERRNAME_TO_STRING(BAD_VALUE);
    _ERRNAME_TO_STRING(DEADLOCK_AVERTED);
    _ERRNAME_TO_STRING(OVERFLOW_AVERTED);
    _ERRNAME_TO_STRING(LACKING_MUTEX);
    _ERRNAME_TO_STRING(LACKING_READ_LOCK);
    _ERRNAME_TO_STRING(LIB_MISMATCH);
    _ERRNAME_TO_STRING(LIBCONFIG_MISMATCH);
    _ERRNAME_TO_STRING(WRONG_ATTRIBUTES);
    _ERRNAME_TO_STRING(IO_FAILED);
#undef _ERRNAME_TO_STRING

#define _SUCNAME_TO_STRING(x) case WOLFSENTRY_SUCCESS_ID_ ## x: return #x
    _SUCNAME_TO_STRING(LOCK_OK_AND_GOT_RESV);
    _SUCNAME_TO_STRING(HAVE_MUTEX);
    _SUCNAME_TO_STRING(HAVE_READ_LOCK);
    _SUCNAME_TO_STRING(USED_FALLBACK);
    _SUCNAME_TO_STRING(YES);
    _SUCNAME_TO_STRING(NO);
    _SUCNAME_TO_STRING(ALREADY_OK);
    _SUCNAME_TO_STRING(DEFERRED);
#undef _SUCNAME_TO_STRING

    case WOLFSENTRY_SUCCESS_ID_USER_BASE:
    case WOLFSENTRY_ERROR_ID_USER_BASE:
        break;
    }
    return wolfsentry_errcode_error_string(e);
}

#if defined(WOLFSENTRY_DEBUG_CALL_TRACE) && defined(__GNUC__) && !defined(__STRICT_ANSI__)
_Pragma("GCC diagnostic push");
_Pragma("GCC diagnostic ignored \"-Wframe-address\"");

#ifdef WOLFSENTRY_CALL_DEPTH_RETURNS_STRING
WOLFSENTRY_API const char *_wolfsentry_call_depth(void)
#else
WOLFSENTRY_API unsigned int _wolfsentry_call_depth(void)
#endif
{
    unsigned int i;
    void *p = __builtin_frame_address(0);
#ifdef WOLFSENTRY_CALL_DEPTH_RETURNS_STRING
    static const char spaces[] = "                ";
    wolfsentry_static_assert2(sizeof spaces == 17, "spaces for WOLFSENTRY_CALL_DEPTH_RETURNS_STRING must be 16 characters plus the terminating null.")
#endif
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
#ifdef WOLFSENTRY_CALL_DEPTH_RETURNS_STRING
    return spaces + sizeof spaces - i;
#else
    return i - 1;
#endif
}
_Pragma("GCC diagnostic pop");

#endif /* WOLFSENTRY_DEBUG_CALL_TRACE __GNUC__ && !__STRICT_ANSI__ */

#endif /* WOLFSENTRY_ERROR_STRINGS */

#if defined(WOLFSENTRY_PROTOCOL_NAMES) || !defined(WOLFSENTRY_NO_JSON)

static const struct {
    wolfsentry_action_res_t res;
    const char *desc;
} action_res_bit_map[] = {
    { WOLFSENTRY_ACTION_RES_NONE, "none" },
    { WOLFSENTRY_ACTION_RES_ACCEPT, "accept" },
    { WOLFSENTRY_ACTION_RES_REJECT, "reject" },
    { WOLFSENTRY_ACTION_RES_CONNECT, "connect" },
    { WOLFSENTRY_ACTION_RES_DISCONNECT, "disconnect" },
    { WOLFSENTRY_ACTION_RES_DEROGATORY, "derogatory" },
    { WOLFSENTRY_ACTION_RES_COMMENDABLE, "commendable" },
    { WOLFSENTRY_ACTION_RES_STOP, "stop" },
    { WOLFSENTRY_ACTION_RES_DEALLOCATED, "deallocated" },
    { WOLFSENTRY_ACTION_RES_INSERTED, "inserted" },
    { WOLFSENTRY_ACTION_RES_ERROR, "error" },
    { WOLFSENTRY_ACTION_RES_FALLTHROUGH, "fallthrough" },
    { WOLFSENTRY_ACTION_RES_UPDATE, "update" },
    { WOLFSENTRY_ACTION_RES_PORT_RESET, "port-reset" },
    { WOLFSENTRY_ACTION_RES_SENDING, "sending" },
    { WOLFSENTRY_ACTION_RES_RECEIVED, "received" },
    { WOLFSENTRY_ACTION_RES_BINDING, "binding" },
    { WOLFSENTRY_ACTION_RES_LISTENING, "listening" },
    { WOLFSENTRY_ACTION_RES_STOPPED_LISTENING, "stopped-listening" },
    { WOLFSENTRY_ACTION_RES_CONNECTING_OUT, "connecting-out" },
    { WOLFSENTRY_ACTION_RES_CLOSED, "closed" },
    { WOLFSENTRY_ACTION_RES_UNREACHABLE, "unreachable" },
    { WOLFSENTRY_ACTION_RES_SOCK_ERROR, "sock-error" },
    { WOLFSENTRY_ACTION_RES_CLOSE_WAIT, "close-wait" },
    { WOLFSENTRY_ACTION_RES_RESERVED23, "reserved-23" },
    { WOLFSENTRY_ACTION_RES_USER0, "user+0" },
    { WOLFSENTRY_ACTION_RES_USER1, "user+1" },
    { WOLFSENTRY_ACTION_RES_USER2, "user+2" },
    { WOLFSENTRY_ACTION_RES_USER3, "user+3" },
    { WOLFSENTRY_ACTION_RES_USER4, "user+4" },
    { WOLFSENTRY_ACTION_RES_USER5, "user+5" },
    { WOLFSENTRY_ACTION_RES_USER6, "user+6" },
    { WOLFSENTRY_ACTION_RES_USER7, "user+7" }
};

wolfsentry_static_assert(length_of_array(action_res_bit_map) == 1U + sizeof(wolfsentry_action_res_t) * BITS_PER_BYTE)

WOLFSENTRY_API const char *wolfsentry_action_res_assoc_by_flag(wolfsentry_action_res_t res, unsigned int bit) {
    if (bit > 31)
        return "(out-of-range)";
    if (res & (1U << bit)) {
        unsigned int i;
        for (i = 0; i < length_of_array(action_res_bit_map); ++i) {
            if (action_res_bit_map[i].res == (1U << bit))
                return action_res_bit_map[i].desc;
        }
        return "(?)";
    } else
        return NULL;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_res_assoc_by_name(const char *bit_name, int bit_name_len, wolfsentry_action_res_t *res) {
    unsigned int i;
    if (bit_name_len < 0)
        bit_name_len = (int)strlen(bit_name);
    for (i = 0; i < length_of_array(action_res_bit_map); ++i) {
        if ((strncmp(action_res_bit_map[i].desc, bit_name, (size_t)bit_name_len) == 0) &&
            (strlen(action_res_bit_map[i].desc) == (size_t)bit_name_len))
        {
            *res = action_res_bit_map[i].res;
            WOLFSENTRY_RETURN_OK;
        }
    }
    WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
}

#endif /* WOLFSENTRY_PROTOCOL_NAMES || !WOLFSENTRY_NO_JSON */

WOLFSENTRY_API struct wolfsentry_build_settings wolfsentry_get_build_settings(void) {
    return wolfsentry_build_settings;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_build_settings_compatible(struct wolfsentry_build_settings caller_build_settings) {
    if (caller_build_settings.version == 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (caller_build_settings.version != WOLFSENTRY_VERSION)
        WOLFSENTRY_ERROR_RETURN(LIB_MISMATCH);
    if (~((WOLFSENTRY_CONFIG_FLAG_MAX << 1UL) - 1UL) & caller_build_settings.config)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
#ifdef WOLFSENTRY_SHORT_ENUMS
    if ((sizeof(wolfsentry_init_flags_t) < sizeof(int)) ^ WOLFSENTRY_SHORT_ENUMS)
        WOLFSENTRY_ERROR_RETURN(LIBCONFIG_MISMATCH);
#endif

#define CHECK_CONFIG_MATCHES(x) if (! ((caller_build_settings.config & WOLFSENTRY_CONFIG_FLAG_ ## x) == (wolfsentry_build_settings.config & WOLFSENTRY_CONFIG_FLAG_ ## x))) WOLFSENTRY_ERROR_RETURN(LIBCONFIG_MISMATCH)

    /* flags that affect struct layout must match. */

    CHECK_CONFIG_MATCHES(USER_DEFINED_TYPES);
    CHECK_CONFIG_MATCHES(THREADSAFE);
    CHECK_CONFIG_MATCHES(PROTOCOL_NAMES);
    CHECK_CONFIG_MATCHES(HAVE_JSON_DOM);
    CHECK_CONFIG_MATCHES(SHORT_ENUMS);
#undef CHECK_CONFIG_MATCHES
    WOLFSENTRY_RETURN_OK;
}

#ifdef WOLFSENTRY_MALLOC_BUILTINS

#ifdef WOLFSENTRY_MALLOC_DEBUG

static volatile int n_mallocs = 0;

WOLFSENTRY_API int _wolfsentry_get_n_mallocs(void) {
    return n_mallocs;
}

#endif /* WOLFSENTRY_MALLOC_DEBUG */

#ifdef FREERTOS

#if (configSUPPORT_DYNAMIC_ALLOCATION != 1)
#error need configSUPPORT_DYNAMIC_ALLOCATION to use WOLFSENTRY_MALLOC_BUILTINS on FreeRTOS.
#endif

static void *wolfsentry_builtin_malloc(
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), size_t size)
{
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
#ifdef WOLFSENTRY_MALLOC_DEBUG
    {
        void *ret = pvPortMalloc(size);
        if (ret != NULL)
            WOLFSENTRY_ATOMIC_INCREMENT(n_mallocs, 1);
        return ret;
    }
#else
    WOLFSENTRY_RETURN_VALUE(pvPortMalloc(size));
#endif
}

static void wolfsentry_builtin_free(
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), void *ptr)
{
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    vPortFree(ptr);
#ifdef WOLFSENTRY_MALLOC_DEBUG
    if (ptr != NULL)
        WOLFSENTRY_ATOMIC_DECREMENT(n_mallocs, 1);
#endif
    WOLFSENTRY_RETURN_VOID;
}

/* this implementation of realloc() only works with FreeRTOS heap_{4,5}.c, which
 * is checked at build time by forcing the linker to resolve vPortGetHeapStats().
 */

/* Assumes 8bit bytes! */
#define heapBITS_PER_BYTE         ( ( size_t ) 8 )

/* MSB of the xBlockSize member of an BlockLink_t structure is used to track
 * the allocation status of a block.  When MSB of the xBlockSize member of
 * an BlockLink_t structure is set then the block belongs to the application.
 * When the bit is free the block is still part of the free heap space. */
#define heapBLOCK_ALLOCATED_BITMASK    ( ( ( size_t ) 1 ) << ( ( sizeof( size_t ) * heapBITS_PER_BYTE ) - 1 ) )
#define heapBLOCK_IS_ALLOCATED( pxBlock )        ( ( ( pxBlock->xBlockSize ) & heapBLOCK_ALLOCATED_BITMASK ) != 0 )

/* Define the linked list structure.  This is used to link free blocks in order
 * of their memory address. */
typedef struct A_BLOCK_LINK {
    struct A_BLOCK_LINK * pxNextFreeBlock; /*<< The next free block in the list. */
    size_t xBlockSize;                     /*<< The size of the free block. */
} BlockLink_t;

static const size_t xHeapStructSize = ( sizeof( BlockLink_t ) + ( ( size_t ) ( portBYTE_ALIGNMENT - 1 ) ) ) & ~( ( size_t ) portBYTE_ALIGNMENT_MASK );

static void *wolfsentry_builtin_realloc(
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), void *ptr,
    size_t size)
{
    static int checked_heap_flavor = 0;
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;

    if (checked_heap_flavor == 0) {
        /* force use of vPortGetHeapStats() to confirm use of heap_4 or heap_5. */
        HeapStats_t pxHeapStats;
        vPortGetHeapStats(&pxHeapStats);
        checked_heap_flavor = 1;
    }

    if (size == 0) {
        wolfsentry_builtin_free(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(context), ptr);
        WOLFSENTRY_RETURN_VALUE(NULL);
    } else if (ptr == NULL) {
        WOLFSENTRY_RETURN_VALUE(wolfsentry_builtin_malloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(context), size));
    } else {
        void *pvReturn = NULL;
        BlockLink_t *pxLink = (BlockLink_t *)(void *)((char*)ptr - xHeapStructSize);
        if (heapBLOCK_IS_ALLOCATED(pxLink)) {
            uint32_t blockSize = pxLink->xBlockSize & ~heapBLOCK_ALLOCATED_BITMASK;
            blockSize -= xHeapStructSize;
            if (blockSize >= size)
                WOLFSENTRY_RETURN_VALUE(ptr);
            pvReturn = pvPortMalloc(size);
            if (pvReturn) {
                memcpy(pvReturn, ptr, blockSize);
                vPortFree(ptr);
            }
        }
        WOLFSENTRY_RETURN_VALUE(pvReturn);
    }
}

static void *wolfsentry_builtin_memalign(
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), size_t alignment,
    size_t size)
{
    void *ptr = NULL;
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;

    if (alignment && size) {
        uint32_t hdr_size = sizeof(uint16_t) + (alignment - 1);
        void *p = pvPortMalloc(size + hdr_size);
        if (p) {
#ifdef WOLFSENTRY_MALLOC_DEBUG
            WOLFSENTRY_ATOMIC_INCREMENT(n_mallocs, 1);
#endif
            /* Align to powers of two */
            ptr = (void *) ((((uintptr_t)p + sizeof(uint16_t)) + (alignment - 1)) & ~(alignment - 1));
            *((uint16_t *)ptr - 1) = (uint16_t)((uintptr_t)ptr - (uintptr_t)p);
        }
    }
    WOLFSENTRY_RETURN_VALUE(ptr);
}

static void wolfsentry_builtin_free_aligned(
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), void *ptr)
{
    uint16_t offset = *((uint16_t *)ptr - 1);
    void *p = (void *)((uint8_t *)ptr - offset);

    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;

    vPortFree(p);
#ifdef WOLFSENTRY_MALLOC_DEBUG
    WOLFSENTRY_ATOMIC_DECREMENT(n_mallocs, 1);
#endif
    WOLFSENTRY_RETURN_VOID;
}

#else

#include <stdlib.h>
#ifndef WOLFSENTRY_NO_POSIX_MEMALIGN
#ifdef WOLFSENTRY_NO_ERRNO_H
#error POSIX memalign requires errno.h
#else
#include <errno.h>
#endif
#endif

static void *wolfsentry_builtin_malloc(
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), size_t size)
{
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
#ifdef WOLFSENTRY_MALLOC_DEBUG
    {
        ret = malloc(size);
        if (ret != NULL)
            WOLFSENTRY_ATOMIC_INCREMENT(n_mallocs, 1);
        WOLFSENTRY_RETURN_VALUE(ret);
    }
#else
    WOLFSENTRY_RETURN_VALUE(malloc(size));
#endif
}

static void wolfsentry_builtin_free(
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), void *ptr)
{
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    free(ptr);
#ifdef WOLFSENTRY_MALLOC_DEBUG
    if (ptr != NULL)
        WOLFSENTRY_ATOMIC_DECREMENT(n_mallocs, 1);
#endif
    WOLFSENTRY_RETURN_VOID;
}

static void *wolfsentry_builtin_realloc(
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), void *ptr,
    size_t size)
{
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
#ifdef WOLFSENTRY_MALLOC_DEBUG
    {
        void *ret = realloc(ptr, size);
        if ((ptr == null) && (ret != NULL))
            WOLFSENTRY_ATOMIC_INCREMENT(n_mallocs, 1);
        else if ((ptr != null) && (ret == NULL))
            WOLFSENTRY_ATOMIC_DECREMENT(n_mallocs, 1);
        return ret;
    }
#else
    WOLFSENTRY_RETURN_VALUE(realloc(ptr, size));
#endif
}

static void *wolfsentry_builtin_memalign(
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), size_t alignment,
    size_t size)
{
#ifdef WOLFSENTRY_NO_POSIX_MEMALIGN
    void *ptr = NULL;
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    if (alignment && size) {
        size_t hdr_size = sizeof(uint16_t) + (alignment - 1);
        void *p = malloc(size + hdr_size);
        if (p) {
            /* Align to powers of two */
            ptr = (void *) ((((uintptr_t)p + sizeof(uint16_t)) + (alignment - 1)) & ~(alignment - 1));
            *((uint16_t *)ptr - 1) = (uint16_t)((uintptr_t)ptr - (uintptr_t)p);
        }
        /* cppcheck-suppress memleak
         */
    }
#ifdef WOLFSENTRY_MALLOC_DEBUG
    if (ptr != NULL)
        WOLFSENTRY_ATOMIC_INCREMENT(n_mallocs, 1);
#endif
    WOLFSENTRY_RETURN_VALUE(ptr);
#else
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    if (alignment <= sizeof(void *)) {
        void *ret = malloc(size);
#ifdef WOLFSENTRY_MALLOC_DEBUG
        if (ret != NULL)
            WOLFSENTRY_ATOMIC_INCREMENT(n_mallocs, 1);
#endif
        WOLFSENTRY_RETURN_VALUE(ret);
    } else {
        void *ret = 0;
        int eret = posix_memalign(&ret, alignment, size);
        if (eret != 0) {
            errno = eret;
            WOLFSENTRY_RETURN_VALUE(NULL);
        }
#ifdef WOLFSENTRY_MALLOC_DEBUG
        WOLFSENTRY_ATOMIC_INCREMENT(n_mallocs, 1);
#endif
        WOLFSENTRY_RETURN_VALUE(ret);
    }
#endif
}

static void wolfsentry_builtin_free_aligned(
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), void *ptr)
{
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
#ifdef WOLFSENTRY_NO_POSIX_MEMALIGN
    {
        uint16_t offset = *((uint16_t *)ptr - 1);
        void *p = (void *)((uint8_t *)ptr - offset);
        free(p);
    }
#else
    free(ptr);
#endif
#ifdef WOLFSENTRY_MALLOC_DEBUG
    WOLFSENTRY_ATOMIC_DECREMENT(n_mallocs, 1);
#endif
    WOLFSENTRY_RETURN_VOID;
}

#endif

static const struct wolfsentry_allocator default_allocator = {
#ifdef WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
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

#if defined(FREERTOS) && (defined(WOLFSENTRY_THREADSAFE) || defined(WOLFSENTRY_CLOCK_BUILTINS))

#include <task.h>

static void freertos_now(struct timespec *now) {
    TimeOut_t xCurrentTime = { 0 };
    uint64_t ullTickCount = 0;

    vTaskSetTimeOutState(&xCurrentTime);
    ullTickCount = (uint64_t)(xCurrentTime.xOverflowCount) << (sizeof(TickType_t) * 8);
    ullTickCount += xCurrentTime.xTimeOnEntering;

    now->tv_sec = (time_t)(ullTickCount / configTICK_RATE_HZ);
    now->tv_nsec = (long int)(((ullTickCount % configTICK_RATE_HZ) * FREERTOS_NANOSECONDS_PER_SECOND) / configTICK_RATE_HZ);
}

#endif /* FREERTOS && (WOLFSENTRY_THREADSAFE || WOLFSENTRY_CLOCK_BUILTINS) */

#ifdef WOLFSENTRY_THREADSAFE

#ifdef WOLFSENTRY_NO_ERRNO_H
#error WOLFSENTRY_THREADSAFE requires errno.h
#else
#include <errno.h>
#endif

static wolfsentry_thread_id_t fallback_thread_id_counter = WOLFSENTRY_THREAD_NO_ID;

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_init_thread_context(struct wolfsentry_thread_context *thread_context, wolfsentry_thread_flags_t init_thread_flags, void *user_context) {
    memset(thread_context, 0, sizeof *thread_context);
    thread_context->user_context = user_context;
    thread_context->deadline.tv_sec = WOLFSENTRY_DEADLINE_NEVER;
    thread_context->deadline.tv_nsec = WOLFSENTRY_DEADLINE_NEVER;
    thread_context->current_thread_flags = init_thread_flags;
    thread_context->id = WOLFSENTRY_THREAD_GET_ID_HANDLER();
    if (thread_context->id == WOLFSENTRY_THREAD_NO_ID) {
        thread_context->id = WOLFSENTRY_ATOMIC_DECREMENT(fallback_thread_id_counter, 1);
        /* run in a loop of 2^24 to try to avoid overlap with host-generated
         * thread IDs.  the expectation is that contexts need to be
         * orthogonalized from each other and from other tasks, by fallback if
         * necessary, but that fallback will occur only for short-lived
         * (non-task) contexts (mainly interrupt handlers).  with this, a
         * trylock call is safe from an interrupt handler, and if it succeeds,
         * the held lock can be safely locked recursively from within the
         * interrupt context.
         */
        if (thread_context->id == (wolfsentry_thread_id_t)((uintptr_t)WOLFSENTRY_THREAD_NO_ID - 0xffffff))
            WOLFSENTRY_ATOMIC_INCREMENT(fallback_thread_id_counter, 0xffffff);
        WOLFSENTRY_SUCCESS_RETURN(USED_FALLBACK);
    } else
        WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_alloc_thread_context(struct wolfsentry_host_platform_interface *hpi, struct wolfsentry_thread_context **thread_context, wolfsentry_thread_flags_t init_thread_flags, void *user_context) {
    wolfsentry_errcode_t ret;
    if ((*thread_context = (struct wolfsentry_thread_context *)hpi->allocator.malloc(hpi->allocator.context, NULL /* thread */, sizeof **thread_context)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    ret = wolfsentry_init_thread_context(*thread_context, init_thread_flags, user_context);
    if (ret < 0) {
        int ret2 = wolfsentry_free_thread_context(hpi, thread_context, init_thread_flags);
        if (ret2 < 0)
            ret = ret2;
    }
    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_get_thread_id(struct wolfsentry_thread_context *thread, wolfsentry_thread_id_t *id) {
    WOLFSENTRY_THREAD_ASSERT_INITED(thread);
    if (id == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    *id = WOLFSENTRY_THREAD_GET_ID;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_get_thread_user_context(struct wolfsentry_thread_context *thread, void **user_context) {
    WOLFSENTRY_THREAD_ASSERT_INITED(thread);
    if (user_context == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (thread->user_context == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    *user_context = thread->user_context;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_get_thread_deadline(struct wolfsentry_thread_context *thread, struct timespec *deadline) {
    WOLFSENTRY_THREAD_ASSERT_INITED(thread);
    if (deadline == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (! (thread->current_thread_flags & WOLFSENTRY_THREAD_FLAG_DEADLINE)) {
        deadline->tv_sec = WOLFSENTRY_DEADLINE_NEVER;
        deadline->tv_nsec = WOLFSENTRY_DEADLINE_NEVER;
    } else
        *deadline = thread->deadline;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_get_thread_flags(struct wolfsentry_thread_context *thread, wolfsentry_thread_flags_t *thread_flags) {
    WOLFSENTRY_THREAD_ASSERT_INITED(thread);
    if (thread_flags == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    *thread_flags = thread->current_thread_flags;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_destroy_thread_context(struct wolfsentry_thread_context *thread, wolfsentry_thread_flags_t thread_flags) {
    (void)thread_flags;
    WOLFSENTRY_THREAD_ASSERT_INITED(thread);
    if (thread->shared_count > 0)
        WOLFSENTRY_ERROR_RETURN(BUSY);
    else if (thread->shared_count < 0)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if (thread->mutex_and_reservation_count > 0)
        WOLFSENTRY_ERROR_RETURN(BUSY);
    else if (thread->mutex_and_reservation_count < 0)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if (thread->recursion_of_tracked_lock)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if (thread->tracked_shared_lock != NULL)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);

    /* if this thread was allocated by fallback, and is exiting before another
     * fallback allocation, try to reclaim the ID.
     */
    if (thread->id == fallback_thread_id_counter)
        (void)WOLFSENTRY_ATOMIC_TEST_AND_SET(fallback_thread_id_counter, thread->id, (wolfsentry_thread_id_t)((uintptr_t)thread->id + 1));

    memset(thread, 0, sizeof *thread);
    thread->id = WOLFSENTRY_THREAD_NO_ID;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_free_thread_context(struct wolfsentry_host_platform_interface *hpi, struct wolfsentry_thread_context **thread_context, wolfsentry_thread_flags_t thread_flags) {
    wolfsentry_errcode_t ret;
    if ((! thread_context) || (! *thread_context))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    ret = wolfsentry_destroy_thread_context(*thread_context, thread_flags);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    hpi->allocator.free(hpi->allocator.context, NULL /* thread */, *thread_context);
    *thread_context = NULL;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_set_deadline_rel_usecs(WOLFSENTRY_CONTEXT_ARGS_IN, int usecs) {
    wolfsentry_time_t now;
    wolfsentry_errcode_t ret;

    WOLFSENTRY_THREAD_ASSERT_INITED(thread);

    if (usecs < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (usecs > 0) {
        if ((ret = WOLFSENTRY_GET_TIME(&now)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
        ret = WOLFSENTRY_TO_EPOCH_TIME(WOLFSENTRY_ADD_TIME(now, usecs), &thread->deadline.tv_sec, &thread->deadline.tv_nsec);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        thread->current_thread_flags |= WOLFSENTRY_THREAD_FLAG_DEADLINE;
        WOLFSENTRY_RETURN_OK;
    } else {
        thread->deadline.tv_sec = WOLFSENTRY_DEADLINE_NOW;
        thread->deadline.tv_nsec = WOLFSENTRY_DEADLINE_NOW;
        thread->current_thread_flags |= WOLFSENTRY_THREAD_FLAG_DEADLINE;
        WOLFSENTRY_RETURN_OK;
    }
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_set_deadline_abs(WOLFSENTRY_CONTEXT_ARGS_IN, time_t epoch_secs, long epoch_nsecs) {
    (void)wolfsentry;

    WOLFSENTRY_THREAD_ASSERT_INITED(thread);

    if ((epoch_nsecs < 0) || (epoch_nsecs >= 1000000000))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if ((epoch_secs == WOLFSENTRY_DEADLINE_NEVER) ||
        (epoch_secs == WOLFSENTRY_DEADLINE_NOW))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    thread->deadline.tv_sec = epoch_secs;
    thread->deadline.tv_nsec = epoch_nsecs;
    thread->current_thread_flags |= WOLFSENTRY_THREAD_FLAG_DEADLINE;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_clear_deadline(WOLFSENTRY_CONTEXT_ARGS_IN) {
    (void)wolfsentry;

    WOLFSENTRY_THREAD_ASSERT_INITED(thread);

    thread->deadline.tv_sec = WOLFSENTRY_DEADLINE_NEVER;
    thread->deadline.tv_nsec = WOLFSENTRY_DEADLINE_NEVER;
    WOLFSENTRY_CLEAR_BITS(thread->current_thread_flags, WOLFSENTRY_THREAD_FLAG_DEADLINE);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_set_thread_readonly(struct wolfsentry_thread_context *thread) {
    WOLFSENTRY_THREAD_ASSERT_INITED(thread);

    if (thread->mutex_and_reservation_count > 0)
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    thread->current_thread_flags |= WOLFSENTRY_THREAD_FLAG_READONLY;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_set_thread_readwrite(struct wolfsentry_thread_context *thread) {
    WOLFSENTRY_THREAD_ASSERT_INITED(thread);

    if (thread->shared_count > thread->recursion_of_tracked_lock)
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    WOLFSENTRY_CLEAR_BITS(thread->current_thread_flags, WOLFSENTRY_THREAD_FLAG_READONLY);
    WOLFSENTRY_RETURN_OK;
}

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

#ifdef WOLFSENTRY_SEM_BUILTINS

#ifdef WOLFSENTRY_USE_NONPOSIX_SEMAPHORES

#ifdef __MACH__

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

static int darwin_sem_timedwait(sem_t *sem, const struct timespec *abs_timeout) {
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
    (void)pshared;

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
            iStatus = 1;
        }
        else if( iCompareResult == 0 )
        {
            /* if times are the same WOLFSENTRY_RETURN_VALUE(zero */
            pxResult->tv_sec = 0;
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
    int xReturn = 0;

    if( pxTimespec != NULL )
    {
        /* Verify 0 <= tv_nsec < 1000000000. */
        if( ( pxTimespec->tv_nsec >= 0 ) &&
            ( pxTimespec->tv_nsec < FREERTOS_NANOSECONDS_PER_SECOND ) )
        {
            xReturn = 1;
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
                if( llTotalTicks > (int64_t)MAX_UINT_OF(*pxResult) )
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

            freertos_now(&xCurrentTime);
            iStatus = UTILS_AbsoluteTimespecToDeltaTicks( abstime, &xCurrentTime, &xDelay );

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

#error Semaphore builtins not implemented for target -- build wolfSentry with -DWOLFSENTRY_NO_SEM_BUILTIN, and supply semaphore implementation with struct wolfsentry_host_platform_interface argument to wolfsentry_init().

#endif

#endif /* WOLFSENTRY_USE_NONPOSIX_SEMAPHORES */

#endif /* WOLFSENTRY_SEM_BUILTINS */

static const struct timespec timespec_deadline_now = {WOLFSENTRY_DEADLINE_NOW, WOLFSENTRY_DEADLINE_NOW};

#ifdef WOLFSENTRY_SEM_BUILTINS
static const struct wolfsentry_semcbs builtin_sem_methods =
{
    sem_init,
    sem_post,
    sem_wait,
    sem_timedwait,
    sem_trywait,
    sem_destroy
};
#endif /* WOLFSENTRY_SEM_BUILTINS */

#undef sem_init
#undef sem_post
#undef sem_wait
#undef sem_timedwait
#undef sem_trywait
#undef sem_destroy

#ifdef WOLFSENTRY_SEM_BUILTINS

#define sem_init (hpi->semcbs.sem_init ? hpi->semcbs.sem_init : builtin_sem_methods.sem_init)
#define sem_post (hpi->semcbs.sem_post ? hpi->semcbs.sem_post : builtin_sem_methods.sem_post)
#define sem_wait (hpi->emcbs->sem_wait ? hpi->emcbs->sem_wait : builtin_sem_methods.sem_wait)
#define sem_timedwait (hpi->semcbs.sem_timedwait ? hpi->semcbs.sem_timedwait : builtin_sem_methods.sem_timedwait)
#define sem_trywait (hpi->semcbs.sem_trywait ? hpi->semcbs.sem_trywait : builtin_sem_methods.sem_trywait)
#define sem_destroy (hpi->semcbs.sem_destroy ? hpi->semcbs.sem_destroy : builtin_sem_methods.sem_destroy)

#else

#define sem_init (hpi->semcbs.sem_init)
#define sem_post (hpi->semcbs.sem_post)
#define sem_wait (hpi->emcbs->sem_wait)
#define sem_timedwait (hpi->semcbs.sem_timedwait)
#define sem_trywait (hpi->semcbs.sem_trywait)
#define sem_destroy (hpi->semcbs.sem_destroy)

#endif

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_init(struct wolfsentry_host_platform_interface *hpi, struct wolfsentry_thread_context *thread, struct wolfsentry_rwlock *lock, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;

    if (lock == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    WOLFSENTRY_THREAD_ASSERT_NULL_OR_INITED(thread);

    if (flags & (WOLFSENTRY_LOCK_FLAG_RETAIN_SEMAPHORE |
                 WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO |
                 WOLFSENTRY_LOCK_FLAG_TRY_RESERVATION_TOO |
                 WOLFSENTRY_LOCK_FLAG_ABANDON_RESERVATION_TOO))
    {
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

    memset(lock,0,sizeof *lock);

    lock->flags = flags;
    lock->write_lock_holder = WOLFSENTRY_THREAD_NO_ID;
    lock->read2write_reservation_holder = WOLFSENTRY_THREAD_NO_ID;
    lock->hpi = hpi;

    if (sem_init(&lock->sem, (flags & WOLFSENTRY_LOCK_FLAG_PSHARED) != 0, 0 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (sem_init(&lock->sem_read_waiters, (flags & WOLFSENTRY_LOCK_FLAG_PSHARED) != 0, 0 /* value */) < 0) {
        ret = WOLFSENTRY_ERROR_ENCODE(SYS_RESOURCE_FAILED);
        goto free_sem;
    }
    if (sem_init(&lock->sem_write_waiters, (flags & WOLFSENTRY_LOCK_FLAG_PSHARED) != 0, 0 /* value */) < 0) {
        ret = WOLFSENTRY_ERROR_ENCODE(SYS_RESOURCE_FAILED);
        goto free_read_waiters;
    }
    if (sem_init(&lock->sem_read2write_waiters, (flags & WOLFSENTRY_LOCK_FLAG_PSHARED) != 0, 0 /* value */) < 0) {
        ret = WOLFSENTRY_ERROR_ENCODE(SYS_RESOURCE_FAILED);
        goto free_write_waiters;
    }

    ret = WOLFSENTRY_ERROR_ENCODE(OK);
    lock->state = WOLFSENTRY_LOCK_UNLOCKED;
    goto out;

  free_write_waiters:
    if (sem_init(&lock->sem_write_waiters, (flags & WOLFSENTRY_LOCK_FLAG_PSHARED) != 0, 0 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
  free_read_waiters:
    if (sem_init(&lock->sem_read_waiters, (flags & WOLFSENTRY_LOCK_FLAG_PSHARED) != 0, 0 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
  free_sem:
    if (sem_init(&lock->sem, (flags & WOLFSENTRY_LOCK_FLAG_PSHARED) != 0, 1 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);

  out:

    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API size_t wolfsentry_lock_size(void) {
    return sizeof(struct wolfsentry_rwlock);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_alloc(struct wolfsentry_host_platform_interface *hpi, struct wolfsentry_thread_context *thread, struct wolfsentry_rwlock **lock, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;

    if (lock == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    /* for pshared, the caller will need to handle the shared memory allocation
     * and call wolfsentry_lock_init() directly.
     */
    if (flags & WOLFSENTRY_LOCK_FLAG_PSHARED)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);

    WOLFSENTRY_THREAD_ASSERT_NULL_OR_INITED(thread);

    if ((*lock = (struct wolfsentry_rwlock *)hpi->allocator.malloc(hpi->allocator.context, thread, sizeof **lock)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if ((ret = wolfsentry_lock_init(hpi, thread, *lock, flags)) < 0) {
        WOLFSENTRY_FREE_1(hpi->allocator, *lock);
        *lock = NULL;
        WOLFSENTRY_ERROR_RERETURN(ret);
    }
    WOLFSENTRY_RETURN_OK;
}

#undef sem_init
#undef sem_post
#undef sem_wait
#undef sem_timedwait
#undef sem_trywait
#undef sem_destroy

#ifdef WOLFSENTRY_SEM_BUILTINS

#define sem_init (lock->hpi->semcbs.sem_init ? lock->hpi->semcbs.sem_init : builtin_sem_methods.sem_init)
#define sem_post (lock->hpi->semcbs.sem_post ? lock->hpi->semcbs.sem_post : builtin_sem_methods.sem_post)
#define sem_wait (lock->hpi->semcbs.sem_wait ? lock->hpi->semcbs.sem_wait : builtin_sem_methods.sem_wait)
#define sem_timedwait (lock->hpi->semcbs.sem_timedwait ? lock->hpi->semcbs.sem_timedwait : builtin_sem_methods.sem_timedwait)
#define sem_trywait (lock->hpi->semcbs.sem_trywait ? lock->hpi->semcbs.sem_trywait : builtin_sem_methods.sem_trywait)
#define sem_destroy (lock->hpi->semcbs.sem_destroy ? lock->hpi->semcbs.sem_destroy : builtin_sem_methods.sem_destroy)

#else

#define sem_init (lock->hpi->semcbs.sem_init)
#define sem_post (lock->hpi->semcbs.sem_post)
#define sem_wait (lock->hpi->semcbs.sem_wait)
#define sem_timedwait (lock->hpi->semcbs.sem_timedwait)
#define sem_trywait (lock->hpi->semcbs.sem_trywait)
#define sem_destroy (lock->hpi->semcbs.sem_destroy)

#endif

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_destroy(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    int ret;

    if (lock == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    (void)thread;
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
    if (lock->state != WOLFSENTRY_LOCK_UNLOCKED) {
        WOLFSENTRY_WARN("attempt to destroy used lock {%u,%d,%d,%d,%d,%d,%d}\n", (unsigned int)lock->state, lock->holder_count.read, lock->read_waiter_count, lock->write_waiter_count, lock->read2write_waiter_read_count, lock->read2write_reservation_holder != WOLFSENTRY_THREAD_NO_ID, lock->promoted_at_count);
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    if ((lock->write_lock_holder != WOLFSENTRY_THREAD_NO_ID) ||
        (lock->read2write_reservation_holder != WOLFSENTRY_THREAD_NO_ID) ||
        (lock->holder_count.read != 0) ||
        (lock->read_waiter_count != 0) ||
        (lock->write_waiter_count != 0) ||
        (lock->read2write_waiter_read_count != 0) ||
        (lock->read2write_reservation_holder != WOLFSENTRY_THREAD_NO_ID) ||
        (lock->promoted_at_count != 0))
    {
        WOLFSENTRY_WARN("attempt to destroy lock with corrupted state {%u,%d,%d,%d,%d,%d,%d}\n", (unsigned int)lock->state, lock->holder_count.read, lock->read_waiter_count, lock->write_waiter_count, lock->read2write_waiter_read_count, lock->read2write_reservation_holder != WOLFSENTRY_THREAD_NO_ID, lock->promoted_at_count);
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    }

    if ((sem_trywait(&lock->sem) == 0) ||
        (sem_trywait(&lock->sem_read_waiters) == 0) ||
        (sem_trywait(&lock->sem_write_waiters) == 0) ||
        (sem_trywait(&lock->sem_read2write_waiters) == 0))
    {
        WOLFSENTRY_WARN("%s", "attempt to destroy lock with nonzero semaphore count(s) (internal inconsistency)\n");
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    }

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

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_free(struct wolfsentry_rwlock **lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;

    if ((lock == NULL) || (*lock == NULL))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((*lock)->state != WOLFSENTRY_LOCK_UNINITED) {
        if ((ret = wolfsentry_lock_destroy(*lock, thread, flags)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
    }
    WOLFSENTRY_FREE_1((*lock)->hpi->allocator, *lock);
    *lock = NULL;
    WOLFSENTRY_RETURN_OK;
}

#ifndef SHARED_LOCKER_LIST_ASSERT_CONSISTENCY
#define SHARED_LOCKER_LIST_ASSERT_CONSISTENCY(lock) DO_NOTHING
#endif

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared_abstimed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, const struct timespec *abs_timeout, wolfsentry_lock_flags_t flags) {
    int ret;

    WOLFSENTRY_LOCK_ASSERT_INITED(lock);

    WOLFSENTRY_THREAD_ASSERT_INITED(thread);

    if (WOLFSENTRY_ATOMIC_LOAD(lock->write_lock_holder) == WOLFSENTRY_THREAD_GET_ID)
        WOLFSENTRY_ERROR_RERETURN(wolfsentry_lock_mutex_abstimed(lock, thread, abs_timeout, flags));

    if ((thread->current_thread_flags & WOLFSENTRY_THREAD_FLAG_READONLY) &&
        (flags & WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO))
    {
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    /* opportunistic error checking. */
    if ((flags & WOLFSENTRY_LOCK_FLAG_NONRECURSIVE_SHARED) && (thread->tracked_shared_lock == lock))
        WOLFSENTRY_ERROR_RETURN(ALREADY);

    if ((abs_timeout == NULL) &&
        (thread->current_thread_flags & WOLFSENTRY_THREAD_FLAG_DEADLINE))
    {
        abs_timeout = &thread->deadline;
    }

    /* if shared lock recursion is enabled, and the caller already holds some
     * other lock in shared mode, it must first be promoted.
     */
    if (thread->tracked_shared_lock &&
        (thread->tracked_shared_lock != lock) &&
        (! (flags & WOLFSENTRY_LOCK_FLAG_NONRECURSIVE_SHARED)) &&
        (! (thread->current_thread_flags & WOLFSENTRY_THREAD_FLAG_READONLY)))
    {
        ret = wolfsentry_lock_shared2mutex_abstimed(thread->tracked_shared_lock, thread, abs_timeout, flags);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
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

    /* note, recursive shared locking bypasses the check on
     * lock->write_waiter_count, otherwise we'd need to return DEADLOCK_AVERTED
     * and the caller would have to unwind its transaction.
     */
    if ((lock->state == WOLFSENTRY_LOCK_EXCLUSIVE) || ((lock->write_waiter_count > 0) && (thread->tracked_shared_lock != lock))) {
        if (abs_timeout == &timespec_deadline_now) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else
                WOLFSENTRY_ERROR_RETURN(BUSY);
        }

        ++lock->read_waiter_count;

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
                if (sem_wait(&lock->sem) == 0)
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
                WOLFSENTRY_RETURN_OK;
            }

            --lock->read_waiter_count;

            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

            WOLFSENTRY_ERROR_RERETURN(ret);
        }

        ++thread->shared_count;
        if (! thread->tracked_shared_lock) {
            thread->tracked_shared_lock = lock;
            thread->recursion_of_tracked_lock = 1;
        }
        else if (thread->tracked_shared_lock == lock)
            ++thread->recursion_of_tracked_lock;

        if ((flags & (WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO | WOLFSENTRY_LOCK_FLAG_TRY_RESERVATION_TOO)) &&
            (! (thread->current_thread_flags & WOLFSENTRY_THREAD_FLAG_READONLY)))
        {
            if (WOLFSENTRY_ATOMIC_LOAD(lock->read2write_reservation_holder) != WOLFSENTRY_THREAD_NO_ID) {
                if (flags & WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO) {
                    ret = wolfsentry_lock_unlock(lock, thread, flags);
                    if (ret < 0)
                        WOLFSENTRY_ERROR_RERETURN(ret);
                    else
                        WOLFSENTRY_ERROR_RETURN(BUSY);
                }
                else
                    WOLFSENTRY_RETURN_OK;
            }
            ret = wolfsentry_lock_shared2mutex_reserve(lock, thread, flags);
            if (ret < 0) {
                if (WOLFSENTRY_ERROR_CODE_IS(ret, BUSY)) {
                    if (flags & WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO) {
                        ret = wolfsentry_lock_unlock(lock, thread, flags);
                        if (ret < 0)
                            WOLFSENTRY_ERROR_RERETURN(ret);
                        else
                            WOLFSENTRY_ERROR_RETURN(BUSY);
                    }
                    else
                        WOLFSENTRY_RETURN_OK;
                } else
                    WOLFSENTRY_ERROR_RERETURN(ret);
            } else
                WOLFSENTRY_SUCCESS_RETURN(LOCK_OK_AND_GOT_RESV);
        }

        WOLFSENTRY_RETURN_OK;
    }
    else if ((lock->state == WOLFSENTRY_LOCK_UNLOCKED) ||
               (lock->state == WOLFSENTRY_LOCK_SHARED))
    {
        int store_reservation = 0;

        if ((flags & (WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO | WOLFSENTRY_LOCK_FLAG_TRY_RESERVATION_TOO)) &&
            (! (thread->current_thread_flags & WOLFSENTRY_THREAD_FLAG_READONLY)))
        {
            if (lock->read2write_reservation_holder != WOLFSENTRY_THREAD_NO_ID) {
                if (lock->read2write_reservation_holder == WOLFSENTRY_THREAD_GET_ID) {
                    /* lock->read2write_waiter_read_count is incremented below, in the !store_reservation path. */
                    ret = 0;
                } else if (flags & WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO)
                    ret = WOLFSENTRY_ERROR_ENCODE(BUSY);
                else
                    ret = 0;
                if (ret < 0) {
                    if (sem_post(&lock->sem) < 0)
                        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
                    WOLFSENTRY_ERROR_RERETURN(ret);
                }
            } else
                store_reservation = 1;
        }

        if (lock->state == WOLFSENTRY_LOCK_UNLOCKED)
            WOLFSENTRY_ATOMIC_STORE(lock->state, WOLFSENTRY_LOCK_SHARED);

        ++thread->shared_count;
        if (! thread->tracked_shared_lock) {
            thread->tracked_shared_lock = lock;
            thread->recursion_of_tracked_lock = 1;
        }
        else if (thread->tracked_shared_lock == lock)
            ++thread->recursion_of_tracked_lock;

        if (store_reservation) {
            WOLFSENTRY_ATOMIC_STORE(lock->read2write_reservation_holder, WOLFSENTRY_THREAD_GET_ID);
            lock->holder_count.read += 2; /* suppress posts to sem_read2write_waiters until wolfsentry_lock_shared2mutex_redeem() is entered. */
            lock->read2write_waiter_read_count = thread->recursion_of_tracked_lock;
            ++thread->mutex_and_reservation_count;
        } else {
            ++lock->holder_count.read;
            if (lock->read2write_reservation_holder == WOLFSENTRY_THREAD_GET_ID)
                ++lock->read2write_waiter_read_count;
        }
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

        if (store_reservation)
            WOLFSENTRY_SUCCESS_RETURN(LOCK_OK_AND_GOT_RESV);
        else
            WOLFSENTRY_RETURN_OK;
    } else
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared_timed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_time_t max_wait, wolfsentry_lock_flags_t flags) {
    wolfsentry_time_t now;
    struct timespec abs_timeout;
    wolfsentry_errcode_t ret;

    if (max_wait < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (max_wait > 0) {
        if ((ret = WOLFSENTRY_GET_TIME_1(lock->hpi->timecbs, &now)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
        if ((ret = WOLFSENTRY_TO_EPOCH_TIME_1(lock->hpi->timecbs, WOLFSENTRY_ADD_TIME_1(lock->hpi->timecbs, now,max_wait), &abs_timeout.tv_sec, &abs_timeout.tv_nsec)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
        return wolfsentry_lock_shared_abstimed(lock, thread, &abs_timeout, flags);
    } else
        return wolfsentry_lock_shared_abstimed(lock, thread, &timespec_deadline_now, flags);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    return wolfsentry_lock_shared_abstimed(lock, thread, NULL, flags);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_mutex_abstimed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, const struct timespec *abs_timeout, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;

    if (lock == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (thread) {
        if (thread->id == WOLFSENTRY_THREAD_NO_ID)
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        if (thread->current_thread_flags & WOLFSENTRY_THREAD_FLAG_READONLY)
            WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);
    }

    switch (WOLFSENTRY_ATOMIC_LOAD(lock->state)) {
    case WOLFSENTRY_LOCK_EXCLUSIVE:
        if (WOLFSENTRY_ATOMIC_LOAD(lock->write_lock_holder) == WOLFSENTRY_THREAD_GET_ID) {
            if (! (flags & WOLFSENTRY_LOCK_FLAG_NONRECURSIVE_MUTEX)) {
                /* recursively locking while holding write is effectively uncontended. */
                ++lock->holder_count.write;
                if (thread)
                    ++thread->mutex_and_reservation_count;
                WOLFSENTRY_RETURN_OK;
            } else {
                WOLFSENTRY_ERROR_RETURN(ALREADY);
            }
        } else
            break; /* regular semantics */
    case WOLFSENTRY_LOCK_SHARED: {
        wolfsentry_thread_id_t read2write_reservation_holder = WOLFSENTRY_ATOMIC_LOAD(lock->read2write_reservation_holder);
        if (read2write_reservation_holder == WOLFSENTRY_THREAD_GET_ID) {
            if (flags & WOLFSENTRY_LOCK_FLAG_NONRECURSIVE_MUTEX)
                WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
            else {
                ret = wolfsentry_lock_shared2mutex_redeem_abstimed(lock, thread, abs_timeout, flags);
                WOLFSENTRY_RERETURN_IF_ERROR(ret);
                ++lock->holder_count.write;
                if (thread)
                    ++thread->mutex_and_reservation_count;
                WOLFSENTRY_RETURN_OK;
            }
        }
        else if (thread && (thread->tracked_shared_lock == lock)) {
            ret = wolfsentry_lock_shared2mutex_abstimed(lock, thread, abs_timeout, flags);
            WOLFSENTRY_RERETURN_IF_ERROR(ret);
            ++lock->holder_count.write;
            if (thread)
                ++thread->mutex_and_reservation_count;
            WOLFSENTRY_RETURN_OK;
        }
        else
            break; /* regular semantics (wait in line). */
    }
    case WOLFSENTRY_LOCK_UNLOCKED:
        break; /* regular semantics */
    case WOLFSENTRY_LOCK_UNINITED:
    case WOLFSENTRY_LOCK_MAX:
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

    /* _RETAIN_SEMAPHORE is for use by interrupt handlers, which never wait, so
     * wouldn't be able to wait at unlock time for the semaphore either.
     */
    if ((flags & WOLFSENTRY_LOCK_FLAG_RETAIN_SEMAPHORE) &&
        (abs_timeout != &timespec_deadline_now))
    {
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

    if ((abs_timeout == NULL) &&
        thread &&
        (thread->current_thread_flags & WOLFSENTRY_THREAD_FLAG_DEADLINE))
    {
        abs_timeout = &thread->deadline;
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
        if (abs_timeout == &timespec_deadline_now) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            WOLFSENTRY_ERROR_RETURN(BUSY);
        }

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
                if (sem_wait(&lock->sem) == 0)
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
                if (thread)
                    ++thread->mutex_and_reservation_count;
                WOLFSENTRY_RETURN_OK;
            }

            --lock->write_waiter_count;

            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

            WOLFSENTRY_ERROR_RERETURN(ret);
        }

        WOLFSENTRY_ATOMIC_STORE(lock->write_lock_holder, WOLFSENTRY_THREAD_GET_ID);
        if (thread)
            ++thread->mutex_and_reservation_count;

        WOLFSENTRY_RETURN_OK;
    }

    WOLFSENTRY_ATOMIC_STORE(lock->state, WOLFSENTRY_LOCK_EXCLUSIVE);
    WOLFSENTRY_ATOMIC_STORE(lock->write_lock_holder, WOLFSENTRY_THREAD_GET_ID);
    if (lock->holder_count.write != 0)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    lock->holder_count.write = 1;
    if (thread)
        ++thread->mutex_and_reservation_count;

    if (flags & WOLFSENTRY_LOCK_FLAG_RETAIN_SEMAPHORE) {
        lock->flags |= WOLFSENTRY_LOCK_FLAG_RETAIN_SEMAPHORE;
        WOLFSENTRY_RETURN_OK;
    }

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    else
        WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_mutex_timed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_time_t max_wait, wolfsentry_lock_flags_t flags) {
    wolfsentry_time_t now;
    struct timespec abs_timeout;
    wolfsentry_errcode_t ret;

    if (max_wait < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (max_wait > 0) {
        if ((ret = WOLFSENTRY_GET_TIME_1(lock->hpi->timecbs, &now)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
        if ((ret = WOLFSENTRY_TO_EPOCH_TIME_1(lock->hpi->timecbs, WOLFSENTRY_ADD_TIME_1(lock->hpi->timecbs, now,max_wait), &abs_timeout.tv_sec, &abs_timeout.tv_nsec)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
        return wolfsentry_lock_mutex_abstimed(lock, thread, &abs_timeout, flags);
    } else
        return wolfsentry_lock_mutex_abstimed(lock, thread, &timespec_deadline_now, flags);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_mutex(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    return wolfsentry_lock_mutex_abstimed(lock, thread, NULL, flags);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_mutex2shared(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    WOLFSENTRY_LOCK_ASSERT_INITED(lock);

    WOLFSENTRY_THREAD_ASSERT_INITED(thread);

    if (lock->state == WOLFSENTRY_LOCK_SHARED)
        WOLFSENTRY_ERROR_RETURN(ALREADY);

    if (thread->tracked_shared_lock)
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);

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
        (flags & WOLFSENTRY_LOCK_FLAG_NONRECURSIVE_SHARED))
    {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    if (flags & (WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO | WOLFSENTRY_LOCK_FLAG_TRY_RESERVATION_TOO)) {
        /* can't happen, but be sure. */
        if (lock->read2write_reservation_holder != WOLFSENTRY_THREAD_NO_ID) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
        }
        WOLFSENTRY_ATOMIC_STORE(lock->read2write_reservation_holder, lock->write_lock_holder);
        ++thread->mutex_and_reservation_count;
        lock->read2write_waiter_read_count = lock->holder_count.write;
        /* note, not incrementing write_waiter_count, to allow shared lockers to get locks until the redemption phase. */
    }

    WOLFSENTRY_ATOMIC_STORE(lock->state, WOLFSENTRY_LOCK_SHARED);
    WOLFSENTRY_ATOMIC_STORE(lock->write_lock_holder, WOLFSENTRY_THREAD_NO_ID);
    lock->promoted_at_count = 0;

    /* writer count becomes reader count. */

    thread->mutex_and_reservation_count -= lock->holder_count.write;
    thread->shared_count += lock->holder_count.read;
    thread->recursion_of_tracked_lock = lock->holder_count.read;
    thread->tracked_shared_lock = lock;

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
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_reserve(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    (void)flags;

    WOLFSENTRY_LOCK_ASSERT_INITED(lock);

    WOLFSENTRY_THREAD_ASSERT_INITED(thread);

    if (thread->current_thread_flags & WOLFSENTRY_THREAD_FLAG_READONLY)
        WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);

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

    if (lock->state != WOLFSENTRY_LOCK_SHARED) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    if (lock->read2write_reservation_holder != WOLFSENTRY_THREAD_NO_ID) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(BUSY);
    }

    WOLFSENTRY_ATOMIC_STORE(lock->read2write_reservation_holder, WOLFSENTRY_THREAD_GET_ID);
    ++thread->mutex_and_reservation_count;
    /* note, not incrementing write_waiter_count, to allow shared lockers to get locks until the redemption phase. */
    ++lock->holder_count.read; /* suppress posts to sem_read2write_waiters until wolfsentry_lock_shared2mutex_redeem() is entered. */
    lock->read2write_waiter_read_count = thread->recursion_of_tracked_lock;

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    WOLFSENTRY_RETURN_OK;
}

/* if this returns BUSY or TIMED_OUT, the caller still owns a reservation, and must either retry the redemption, or abandon the reservation. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem_abstimed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, const struct timespec *abs_timeout, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;

    (void)flags;

    WOLFSENTRY_LOCK_ASSERT_INITED(lock);

    WOLFSENTRY_THREAD_ASSERT_INITED(thread);

    if (WOLFSENTRY_ATOMIC_LOAD(lock->state) == WOLFSENTRY_LOCK_EXCLUSIVE) {
        if (WOLFSENTRY_ATOMIC_LOAD(lock->write_lock_holder) == WOLFSENTRY_THREAD_GET_ID)
            WOLFSENTRY_ERROR_RETURN(ALREADY);
        else
            WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);
    }

    if ((abs_timeout == NULL) &&
        (thread->current_thread_flags & WOLFSENTRY_THREAD_FLAG_DEADLINE))
    {
        abs_timeout = &thread->deadline;
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

    if (lock->holder_count.read == lock->read2write_waiter_read_count + 1) {
        --lock->holder_count.read; /* remove extra count associated with the reservation. */
        lock->promoted_at_count = lock->holder_count.read;
        /* read count becomes write count. */
        WOLFSENTRY_ATOMIC_STORE(lock->state, WOLFSENTRY_LOCK_EXCLUSIVE);
        WOLFSENTRY_ATOMIC_STORE(lock->write_lock_holder, lock->read2write_reservation_holder);
        WOLFSENTRY_ATOMIC_STORE(lock->read2write_reservation_holder, WOLFSENTRY_THREAD_NO_ID);
        thread->mutex_and_reservation_count += lock->read2write_waiter_read_count - 1; /* -1 for the reservation */
        thread->shared_count -= lock->read2write_waiter_read_count;
        if (thread->tracked_shared_lock == lock) {
            thread->recursion_of_tracked_lock = 0;
            thread->tracked_shared_lock = NULL;
        }
        lock->read2write_waiter_read_count = 0;

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
    if (thread->tracked_shared_lock == lock)
        lock->read2write_waiter_read_count = thread->recursion_of_tracked_lock;
    else
        lock->read2write_waiter_read_count = 1;

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
            if (sem_wait(&lock->sem) == 0)
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
            WOLFSENTRY_ATOMIC_STORE(lock->write_lock_holder, WOLFSENTRY_THREAD_GET_ID);
            WOLFSENTRY_RETURN_OK;
        }

        ++lock->holder_count.read; /* restore disabling posts to sem_read2write_waiters by unlockers. */
        --lock->write_waiter_count; /* and allow shared lockers again. */

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RERETURN(ret);
    }

    WOLFSENTRY_ATOMIC_STORE(lock->write_lock_holder, WOLFSENTRY_THREAD_GET_ID);
    WOLFSENTRY_ATOMIC_STORE(lock->read2write_reservation_holder, WOLFSENTRY_THREAD_NO_ID);

    if (thread->tracked_shared_lock == lock) {
        thread->mutex_and_reservation_count += thread->recursion_of_tracked_lock - 1; /* -1 for the reservation */
        thread->shared_count -= thread->recursion_of_tracked_lock;
        thread->recursion_of_tracked_lock = 0;
        thread->tracked_shared_lock = NULL;
    } else {
        /* no change to mutex_and_reservation_count on promotion of an
         * untracked lock -- the reservation becomes the mutex.
         */
        --thread->shared_count;
    }

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem_timed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_time_t max_wait, wolfsentry_lock_flags_t flags) {
    wolfsentry_time_t now;
    struct timespec abs_timeout;
    wolfsentry_errcode_t ret;

    if (max_wait < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (max_wait > 0) {
        if ((ret = WOLFSENTRY_GET_TIME_1(lock->hpi->timecbs, &now)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
        if ((ret = WOLFSENTRY_TO_EPOCH_TIME_1(lock->hpi->timecbs, WOLFSENTRY_ADD_TIME_1(lock->hpi->timecbs, now,max_wait), &abs_timeout.tv_sec, &abs_timeout.tv_nsec)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
        return wolfsentry_lock_shared2mutex_redeem_abstimed(lock, thread, &abs_timeout, flags);
    } else
        return wolfsentry_lock_shared2mutex_redeem_abstimed(lock, thread, &timespec_deadline_now, flags);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    return wolfsentry_lock_shared2mutex_redeem_abstimed(lock, thread, NULL, flags);
}

/* note caller still holds its shared lock after return. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_abandon(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    (void)flags;

    WOLFSENTRY_LOCK_ASSERT_INITED(lock);

    WOLFSENTRY_THREAD_ASSERT_INITED(thread);

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

    if (lock->state != WOLFSENTRY_LOCK_SHARED) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    --lock->holder_count.read;
    lock->read2write_waiter_read_count = 0;
    WOLFSENTRY_ATOMIC_STORE(lock->read2write_reservation_holder, WOLFSENTRY_THREAD_NO_ID);
    --thread->mutex_and_reservation_count;

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    WOLFSENTRY_RETURN_OK;
}

/* if another thread is already waiting for read2write, then this
 * returns BUSY, and the caller must _unlock() to resolve the
 * deadlock, then reattempt its transaction with a fresh lock (ideally
 * with a _lock_mutex() at the open).
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_abstimed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, const struct timespec *abs_timeout, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;

    if (lock == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    WOLFSENTRY_THREAD_ASSERT_INITED(thread);

    if (thread->current_thread_flags & WOLFSENTRY_THREAD_FLAG_READONLY)
        WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);

    switch (WOLFSENTRY_ATOMIC_LOAD(lock->state)) {
    case WOLFSENTRY_LOCK_EXCLUSIVE:
        /* silently and cheaply tolerate repeat calls to _shared2mutex*(). */
        if (WOLFSENTRY_ATOMIC_LOAD(lock->write_lock_holder) == WOLFSENTRY_THREAD_GET_ID)
            WOLFSENTRY_RETURN_OK;
        else
            WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);
    case WOLFSENTRY_LOCK_SHARED:
        if (WOLFSENTRY_ATOMIC_LOAD(lock->read2write_reservation_holder) == WOLFSENTRY_THREAD_GET_ID)
            return wolfsentry_lock_shared2mutex_redeem_abstimed(lock, thread, abs_timeout, flags);
        break;
    case WOLFSENTRY_LOCK_UNLOCKED:
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    case WOLFSENTRY_LOCK_UNINITED:
    default:
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

    if ((abs_timeout == NULL) &&
        (thread->current_thread_flags & WOLFSENTRY_THREAD_FLAG_DEADLINE))
    {
        abs_timeout = &thread->deadline;
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

    if (lock->state != WOLFSENTRY_LOCK_SHARED) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    if (lock->read2write_reservation_holder != WOLFSENTRY_THREAD_NO_ID) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(BUSY);
    }

    if ((lock->holder_count.read == 1)
        || ((thread->tracked_shared_lock == lock)
            && (lock->holder_count.read == thread->recursion_of_tracked_lock)))
    {
        /* read count becomes write count. */
        WOLFSENTRY_ATOMIC_STORE(lock->state, WOLFSENTRY_LOCK_EXCLUSIVE);
        WOLFSENTRY_ATOMIC_STORE(lock->write_lock_holder, WOLFSENTRY_THREAD_GET_ID);

        ret = sem_post(&lock->sem);
        if (thread->tracked_shared_lock == lock) {
            thread->mutex_and_reservation_count += thread->recursion_of_tracked_lock;
            thread->shared_count -= thread->recursion_of_tracked_lock;
            thread->recursion_of_tracked_lock = 0;
            thread->tracked_shared_lock = NULL;
        } else {
            ++thread->mutex_and_reservation_count;
            --thread->shared_count;
        }
        if (ret < 0)
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

    WOLFSENTRY_ATOMIC_STORE(lock->read2write_reservation_holder, WOLFSENTRY_THREAD_GET_ID);
    ++thread->mutex_and_reservation_count;
    if (thread->tracked_shared_lock == lock)
        lock->read2write_waiter_read_count = thread->recursion_of_tracked_lock;
    else
        lock->read2write_waiter_read_count = 1;
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
            if (sem_wait(&lock->sem) == 0)
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
            WOLFSENTRY_ATOMIC_STORE(lock->write_lock_holder, WOLFSENTRY_THREAD_GET_ID);
            if (thread->tracked_shared_lock == lock) {
                thread->mutex_and_reservation_count += thread->recursion_of_tracked_lock - 1; /* -1 for reservation */
                thread->shared_count -= thread->recursion_of_tracked_lock;
                thread->recursion_of_tracked_lock = 0;
                thread->tracked_shared_lock = NULL;
            } else {
                /* reservation count stays in thread->recursion_of_tracked_lock */
                --thread->shared_count;
            }
            WOLFSENTRY_RETURN_OK;
        }

        WOLFSENTRY_ATOMIC_STORE(lock->read2write_reservation_holder, WOLFSENTRY_THREAD_NO_ID);
        --lock->write_waiter_count;
        --thread->mutex_and_reservation_count;

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RERETURN(ret);
    }

    WOLFSENTRY_ATOMIC_STORE(lock->write_lock_holder, lock->read2write_reservation_holder);
    WOLFSENTRY_ATOMIC_STORE(lock->read2write_reservation_holder, WOLFSENTRY_THREAD_NO_ID);

    if (thread->tracked_shared_lock == lock) {
        thread->mutex_and_reservation_count += thread->recursion_of_tracked_lock - 1; /* -1 for reservation */
        thread->shared_count -= thread->recursion_of_tracked_lock;
        thread->recursion_of_tracked_lock = 0;
        thread->tracked_shared_lock = NULL;
    } else {
        /* reservation count stays in thread->recursion_of_tracked_lock */
        --thread->shared_count;
    }

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_timed(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_time_t max_wait, wolfsentry_lock_flags_t flags) {
    wolfsentry_time_t now;
    struct timespec abs_timeout;
    wolfsentry_errcode_t ret;

    if (max_wait < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (max_wait > 0) {
        if ((ret = WOLFSENTRY_GET_TIME_1(lock->hpi->timecbs, &now)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
        if ((ret = WOLFSENTRY_TO_EPOCH_TIME_1(lock->hpi->timecbs, WOLFSENTRY_ADD_TIME_1(lock->hpi->timecbs, now,max_wait), &abs_timeout.tv_sec, &abs_timeout.tv_nsec)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
        return wolfsentry_lock_shared2mutex_abstimed(lock, thread, &abs_timeout, flags);
    } else
        return wolfsentry_lock_shared2mutex_abstimed(lock, thread, &timespec_deadline_now, flags);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    return wolfsentry_lock_shared2mutex_abstimed(lock, thread, NULL, flags);
}

/* note, if caller has a shared2mutex reservation, it must
 * _shared2mutex_abandon() it first, before _unlock()ing,
 * unless flags & WOLFSENTRY_LOCK_FLAG_ABANDON_RESERVATION_TOO.
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_unlock(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;

    WOLFSENTRY_LOCK_ASSERT_INITED(lock);

    if ((thread == NULL) && (flags & WOLFSENTRY_LOCK_FLAG_AUTO_DOWNGRADE))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    WOLFSENTRY_THREAD_ASSERT_NULL_OR_INITED(thread);

    /* unlocking a recursive mutex, like recursively locking one, can be done lock-free. */
    if ((WOLFSENTRY_ATOMIC_LOAD(lock->write_lock_holder) == WOLFSENTRY_THREAD_GET_ID) &&
        (lock->holder_count.write > 1))
    {
        --lock->holder_count.write;
        if (thread)
            --thread->mutex_and_reservation_count;
        WOLFSENTRY_RETURN_OK;
    }

    if (lock->flags & WOLFSENTRY_LOCK_FLAG_RETAIN_SEMAPHORE)
        WOLFSENTRY_CLEAR_BITS(lock->flags, WOLFSENTRY_LOCK_FLAG_RETAIN_SEMAPHORE);
    else {
        /* trap and retry for EINTR to avoid unnecessary failures. */
        do {
            ret = sem_wait(&lock->sem);
        } while ((ret < 0) && (errno == EINTR));
        if (ret < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    }

    SHARED_LOCKER_LIST_ASSERT_CONSISTENCY(lock);

    if (lock->state == WOLFSENTRY_LOCK_SHARED) {
        if (thread == NULL) {
            ret = WOLFSENTRY_ERROR_ENCODE(INVALID_ARG);
            goto out;
        }

        /* opportunistically error-check that the caller didn't inadvertently do
         * an outermost unlock while still holding a promotion reservation.
         *
         * note that if reserver is already in redemption phase, then the extra
         * holder_count.read has moved to write_waiter_count.
         */
        if ((! (flags & WOLFSENTRY_LOCK_FLAG_ABANDON_RESERVATION_TOO)) &&
            (lock->read2write_reservation_holder != WOLFSENTRY_THREAD_NO_ID) &&
            (lock->holder_count.read + lock->write_waiter_count == 2))
        {
            if (lock->read2write_reservation_holder == WOLFSENTRY_THREAD_GET_ID)
                flags |= WOLFSENTRY_LOCK_FLAG_ABANDON_RESERVATION_TOO;
            else {
                ret = WOLFSENTRY_ERROR_ENCODE(INTERNAL_CHECK_FATAL);
                goto out;
            }
        }

        if ((flags & WOLFSENTRY_LOCK_FLAG_ABANDON_RESERVATION_TOO) &&
            (lock->read2write_reservation_holder == WOLFSENTRY_THREAD_GET_ID))
        {
            --lock->holder_count.read;
            lock->read2write_waiter_read_count = 0;
            WOLFSENTRY_ATOMIC_STORE(lock->read2write_reservation_holder, WOLFSENTRY_THREAD_NO_ID);
            --thread->mutex_and_reservation_count;
        }

        --thread->shared_count;
        if (thread->tracked_shared_lock == lock) {
            --thread->recursion_of_tracked_lock;
            if (thread->recursion_of_tracked_lock == 0)
                thread->tracked_shared_lock = NULL;
        }

        if (--lock->holder_count.read == 0)
            WOLFSENTRY_ATOMIC_STORE(lock->state, WOLFSENTRY_LOCK_UNLOCKED);
        else if ((lock->holder_count.read == lock->read2write_waiter_read_count)
                 && (lock->read2write_reservation_holder != WOLFSENTRY_THREAD_NO_ID)
                 && (lock->read2write_reservation_holder != WOLFSENTRY_THREAD_GET_ID))
        {
            lock->promoted_at_count = lock->holder_count.read;
            /* read count becomes write count. */
            --lock->write_waiter_count;
            lock->read2write_waiter_read_count = 0;
            WOLFSENTRY_ATOMIC_STORE(lock->state, WOLFSENTRY_LOCK_EXCLUSIVE);
            WOLFSENTRY_ATOMIC_STORE(lock->write_lock_holder, lock->read2write_reservation_holder);
            if (sem_post(&lock->sem_read2write_waiters) < 0)
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
            else {
                ret = WOLFSENTRY_ERROR_ENCODE(OK);
            }
            goto out;
        }
        else if (lock->read2write_reservation_holder == WOLFSENTRY_THREAD_GET_ID) {
            --lock->read2write_waiter_read_count;
        }
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
    } else if (lock->state == WOLFSENTRY_LOCK_EXCLUSIVE) {
        if (lock->write_lock_holder != WOLFSENTRY_THREAD_GET_ID) {
            ret = WOLFSENTRY_ERROR_ENCODE(NOT_PERMITTED);
            goto out;
        }

        --lock->holder_count.write;
        if (thread)
            --thread->mutex_and_reservation_count;
        if (lock->holder_count.write < 0) {
            ret = WOLFSENTRY_ERROR_ENCODE(INTERNAL_CHECK_FATAL);
            goto out;
        }
        if (lock->holder_count.write == 0) {
            WOLFSENTRY_ATOMIC_STORE(lock->state, WOLFSENTRY_LOCK_UNLOCKED);
            WOLFSENTRY_ATOMIC_STORE(lock->write_lock_holder, WOLFSENTRY_THREAD_NO_ID);
            lock->promoted_at_count = 0;
            ret = WOLFSENTRY_ERROR_ENCODE(OK);
            /* fall through to waiter notification phase. */
        } else {
            if (lock->promoted_at_count == lock->holder_count.write) {
                lock->promoted_at_count = 0;
                if ((flags & WOLFSENTRY_LOCK_FLAG_AUTO_DOWNGRADE) && (! thread->tracked_shared_lock)) {
                    WOLFSENTRY_ATOMIC_STORE(lock->state, WOLFSENTRY_LOCK_SHARED);
                    if (flags & (WOLFSENTRY_LOCK_FLAG_TRY_RESERVATION_TOO | WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO)) {
                        WOLFSENTRY_ATOMIC_STORE(lock->read2write_reservation_holder, WOLFSENTRY_THREAD_GET_ID);
                        /* note, not incrementing write_waiter_count, to allow shared lockers to get locks until the redemption phase. */
                        lock->read2write_waiter_read_count = lock->holder_count.read;
                        ++lock->holder_count.read; /* suppress posts to sem_read2write_waiters until wolfsentry_lock_shared2mutex_redeem() is entered. */
                        thread->mutex_and_reservation_count -= lock->holder_count.write - 1; /* -1 for the reservation */
                        thread->shared_count += lock->holder_count.read;
                        thread->tracked_shared_lock = lock;
                        thread->recursion_of_tracked_lock = lock->holder_count.read;
                        ret = WOLFSENTRY_SUCCESS_ENCODE(LOCK_OK_AND_GOT_RESV);
                    } else
                        ret = WOLFSENTRY_ERROR_ENCODE(OK);
                    /* fall through to waiter notification phase. */
                } else {
                    ret = WOLFSENTRY_ERROR_ENCODE(OK);
                    goto out;
                }
            } else {
                ret = WOLFSENTRY_ERROR_ENCODE(OK);
                goto out;
            }
        }
    } else {
        WOLFSENTRY_WARN("wolfsentry_lock_unlock with state=%u\n", (unsigned int)lock->state);
        ret = WOLFSENTRY_ERROR_ENCODE(INCOMPATIBLE_STATE);
        goto out;
    }

    if (lock->write_waiter_count > 0)  {
        if (lock->state == WOLFSENTRY_LOCK_UNLOCKED) {
            --lock->write_waiter_count;
            WOLFSENTRY_ATOMIC_STORE(lock->state, WOLFSENTRY_LOCK_EXCLUSIVE);
            lock->holder_count.write = 1;
            if (sem_post(&lock->sem_write_waiters) < 0) {
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
                goto out;
            }
        }
    } else if (lock->read_waiter_count > 0) {
        int i;
        lock->holder_count.read += lock->read_waiter_count;
        lock->read_waiter_count = 0;
        WOLFSENTRY_ATOMIC_STORE(lock->state, WOLFSENTRY_LOCK_SHARED);
        for (i = 0; i < lock->holder_count.read; ++i) {
            if (sem_post(&lock->sem_read_waiters) < 0) {
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
                goto out;
            }
        }
    }

  out:

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_have_shared(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    uint32_t lock_state;

    if (lock == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    WOLFSENTRY_THREAD_ASSERT_INITED(thread);

    (void)flags;

    lock_state = WOLFSENTRY_ATOMIC_LOAD(lock->state);

    if (lock_state != WOLFSENTRY_LOCK_SHARED) {
        if (lock_state == WOLFSENTRY_LOCK_UNINITED)
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        else
            WOLFSENTRY_ERROR_RETURN(LACKING_READ_LOCK);
    } else {
        if (thread->current_thread_flags & WOLFSENTRY_THREAD_FLAG_READONLY) {
            if (thread->tracked_shared_lock == lock)
                WOLFSENTRY_SUCCESS_RETURN(HAVE_READ_LOCK);
            else if (thread->shared_count > 0)
                WOLFSENTRY_RETURN_OK; /* this is garbage information that tells the
                                       * caller that someone, maybe the caller, had a
                                       * shared lock around the time of the call.
                                       */
            else
                WOLFSENTRY_ERROR_RETURN(LACKING_READ_LOCK);
        } else {
            if (thread->tracked_shared_lock == lock)
                WOLFSENTRY_SUCCESS_RETURN(HAVE_READ_LOCK);
            else
                WOLFSENTRY_ERROR_RETURN(LACKING_READ_LOCK);
        }
    }
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_have_mutex(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    uint32_t lock_state;

    if (lock == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    lock_state = WOLFSENTRY_ATOMIC_LOAD(lock->state);

    WOLFSENTRY_THREAD_ASSERT_NULL_OR_INITED(thread);

    (void)flags;

    if (lock_state == WOLFSENTRY_LOCK_EXCLUSIVE) {
        if (WOLFSENTRY_ATOMIC_LOAD(lock->write_lock_holder) == WOLFSENTRY_THREAD_GET_ID)
            WOLFSENTRY_SUCCESS_RETURN(HAVE_MUTEX);
        else
            WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);
    } else {
        if (lock_state == WOLFSENTRY_LOCK_UNINITED)
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        else
            WOLFSENTRY_ERROR_RETURN(LACKING_MUTEX);
    }
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_have_either(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    wolfsentry_errcode_t ret;
    if (thread) {
        ret = wolfsentry_lock_have_shared(lock, thread, flags);
        if (! WOLFSENTRY_ERROR_CODE_IS(ret, LACKING_READ_LOCK))
            WOLFSENTRY_ERROR_RERETURN(ret);
    }
    ret = wolfsentry_lock_have_mutex(lock, thread, flags);
    if (WOLFSENTRY_ERROR_CODE_IS(ret, NOT_PERMITTED) ||
        WOLFSENTRY_ERROR_CODE_IS(ret, LACKING_MUTEX))
    {
        WOLFSENTRY_ERROR_RETURN(LACKING_READ_LOCK);
    } else
        WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_have_shared2mutex_reservation(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    (void)flags;
    WOLFSENTRY_LOCK_ASSERT_INITED(lock);
    WOLFSENTRY_THREAD_ASSERT_INITED(thread);
    if (WOLFSENTRY_ATOMIC_LOAD(lock->read2write_reservation_holder) == WOLFSENTRY_THREAD_GET_ID)
        WOLFSENTRY_RETURN_OK;
    else
        WOLFSENTRY_ERROR_RETURN(NOT_OK);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_shared2mutex_is_reserved(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t flags) {
    (void)flags;
    WOLFSENTRY_LOCK_ASSERT_INITED(lock);
    WOLFSENTRY_THREAD_ASSERT_INITED(thread);
    if (WOLFSENTRY_ATOMIC_LOAD(lock->read2write_reservation_holder) == WOLFSENTRY_THREAD_NO_ID)
        WOLFSENTRY_SUCCESS_RETURN(NO);
    else
        WOLFSENTRY_SUCCESS_RETURN(YES);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_lock_get_flags(struct wolfsentry_rwlock *lock, struct wolfsentry_thread_context *thread, wolfsentry_lock_flags_t *flags) {
    (void)thread;
    WOLFSENTRY_LOCK_ASSERT_INITED(lock);
    if (flags == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    *flags = lock->flags;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex(WOLFSENTRY_CONTEXT_ARGS_IN) {
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_lock_mutex(&wolfsentry->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex_abstimed(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct timespec *abs_timeout)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_lock_mutex_abstimed(&wolfsentry->lock, thread, abs_timeout, WOLFSENTRY_LOCK_FLAG_NONE));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex_abstimed_ex(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct timespec *abs_timeout,
    wolfsentry_lock_flags_t flags)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_lock_mutex_abstimed(&wolfsentry->lock, thread, abs_timeout, flags));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex_timed(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_time_t max_wait)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_lock_mutex_timed(&wolfsentry->lock, thread, max_wait, WOLFSENTRY_LOCK_FLAG_NONE));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_mutex_timed_ex(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_time_t max_wait,
    wolfsentry_lock_flags_t flags)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_lock_mutex_timed(&wolfsentry->lock, thread, max_wait, flags));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared(
    WOLFSENTRY_CONTEXT_ARGS_IN)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_lock_shared(&wolfsentry->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared_abstimed(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct timespec *abs_timeout)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_lock_shared_abstimed(&wolfsentry->lock, thread, abs_timeout, WOLFSENTRY_LOCK_FLAG_NONE));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared_with_reservation_abstimed(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct timespec *abs_timeout)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_lock_shared_abstimed(&wolfsentry->lock, thread, abs_timeout, WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared_timed(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_time_t max_wait)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_lock_shared_timed(&wolfsentry->lock, thread, max_wait, WOLFSENTRY_LOCK_FLAG_NONE));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_lock_shared_with_reservation_timed(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_time_t max_wait)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_lock_shared_timed(&wolfsentry->lock, thread, max_wait, WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_IN) {
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_lock_unlock(&wolfsentry->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_unlock_and_abandon_reservation(
    WOLFSENTRY_CONTEXT_ARGS_IN)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_lock_unlock(&wolfsentry->lock, thread, WOLFSENTRY_LOCK_FLAG_ABANDON_RESERVATION_TOO));
}


#endif /* WOLFSENTRY_THREADSAFE */

#ifdef WOLFSENTRY_CLOCK_BUILTINS

#ifdef FREERTOS

static wolfsentry_errcode_t wolfsentry_builtin_get_time(void *context, wolfsentry_time_t *now) {
    struct timespec ts;
    (void)context;
    freertos_now(&ts);
    *now = ((wolfsentry_time_t)ts.tv_sec * (wolfsentry_time_t)1000000) + ((wolfsentry_time_t)ts.tv_nsec / (wolfsentry_time_t)1000);
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
#ifdef WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
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

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_time_now_plus_delta(struct wolfsentry_context *wolfsentry, wolfsentry_time_t td, wolfsentry_time_t *res) {
    wolfsentry_errcode_t ret = WOLFSENTRY_GET_TIME(res);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    *res = WOLFSENTRY_ADD_TIME(*res, td);
    WOLFSENTRY_RETURN_OK;
}

#ifdef WOLFSENTRY_THREADSAFE
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_time_to_timespec(struct wolfsentry_context *wolfsentry, wolfsentry_time_t t, struct timespec *ts) {
    time_t epoch_secs;
    long int epoch_nsecs;
    WOLFSENTRY_TO_EPOCH_TIME(t, &epoch_secs, &epoch_nsecs);
    ts->tv_sec = epoch_secs;
    ts->tv_nsec = epoch_nsecs;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_time_now_plus_delta_timespec(struct wolfsentry_context *wolfsentry, wolfsentry_time_t td, struct timespec *ts) {
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

WOLFSENTRY_API void *wolfsentry_malloc(WOLFSENTRY_CONTEXT_ARGS_IN, size_t size) {
    WOLFSENTRY_RETURN_VALUE(
        wolfsentry->hpi.allocator.malloc(
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry->hpi.allocator.context),
            size));
}
WOLFSENTRY_API_VOID wolfsentry_free(WOLFSENTRY_CONTEXT_ARGS_IN, void *ptr) {
    wolfsentry->hpi.allocator.free(
        wolfsentry->hpi.allocator.context,
#ifdef WOLFSENTRY_THREADSAFE
        thread,
#endif
        ptr);
}
WOLFSENTRY_API void *wolfsentry_realloc(WOLFSENTRY_CONTEXT_ARGS_IN, void *ptr, size_t size) {
    WOLFSENTRY_RETURN_VALUE(
        wolfsentry->hpi.allocator.realloc(
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry->hpi.allocator.context),
            ptr,
            size));
}
WOLFSENTRY_API void *wolfsentry_memalign(WOLFSENTRY_CONTEXT_ARGS_IN, size_t alignment, size_t size) {
    WOLFSENTRY_RETURN_VALUE(
        wolfsentry->hpi.allocator.memalign ?
        wolfsentry->hpi.allocator.memalign(
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry->hpi.allocator.context),
            alignment,
            size)
        : NULL);
}
WOLFSENTRY_API_VOID wolfsentry_free_aligned(WOLFSENTRY_CONTEXT_ARGS_IN, void *ptr) {
    if (ptr && wolfsentry->hpi.allocator.free_aligned)
        wolfsentry->hpi.allocator.free_aligned(
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry->hpi.allocator.context),
            ptr);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_get_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t *time_p) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->hpi.timecbs.get_time(wolfsentry->hpi.timecbs.context, time_p));
}
WOLFSENTRY_API wolfsentry_time_t wolfsentry_diff_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t later, wolfsentry_time_t earlier) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->hpi.timecbs.diff_time(later, earlier));
}
WOLFSENTRY_API wolfsentry_time_t wolfsentry_add_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t start_time, wolfsentry_time_t time_interval) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->hpi.timecbs.add_time(start_time, time_interval));
}
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_to_epoch_time(struct wolfsentry_context *wolfsentry, wolfsentry_time_t when, time_t *epoch_secs, long *epoch_nsecs) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->hpi.timecbs.to_epoch_time(when, epoch_secs, epoch_nsecs));
}
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_from_epoch_time(struct wolfsentry_context *wolfsentry, time_t epoch_secs, long epoch_nsecs, wolfsentry_time_t *when) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->hpi.timecbs.from_epoch_time(epoch_secs, epoch_nsecs, when));
}
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_interval_to_seconds(struct wolfsentry_context *wolfsentry, wolfsentry_time_t howlong, time_t *howlong_secs, long *howlong_nsecs) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->hpi.timecbs.interval_to_seconds(howlong, howlong_secs, howlong_nsecs));
}
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_interval_from_seconds(struct wolfsentry_context *wolfsentry, time_t howlong_secs, long howlong_nsecs, wolfsentry_time_t *howlong) {
    WOLFSENTRY_RETURN_VALUE(wolfsentry->hpi.timecbs.interval_from_seconds(howlong_secs, howlong_nsecs, howlong));
}

WOLFSENTRY_API wolfsentry_object_type_t wolfsentry_get_object_type(const void *object) {
    if ((object == NULL) || (((const struct wolfsentry_table_ent_header *)object)->parent_table == NULL))
        WOLFSENTRY_RETURN_VALUE(WOLFSENTRY_OBJECT_TYPE_UNINITED);
    WOLFSENTRY_RETURN_VALUE(((const struct wolfsentry_table_ent_header *)object)->parent_table->ent_type);
}

WOLFSENTRY_API wolfsentry_ent_id_t wolfsentry_get_object_id(const void *object) {
    if (object == NULL)
        WOLFSENTRY_RETURN_VALUE(WOLFSENTRY_OBJECT_TYPE_UNINITED);
    WOLFSENTRY_RETURN_VALUE(((const struct wolfsentry_table_ent_header *)object)->id);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_object_checkout(WOLFSENTRY_CONTEXT_ARGS_IN, void *object) {
    wolfsentry_errcode_t ret;
    if (object == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
    WOLFSENTRY_REFCOUNT_INCREMENT(((struct wolfsentry_table_ent_header *)object)->refcount, ret);
    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_object_release(WOLFSENTRY_CONTEXT_ARGS_IN, void *object, wolfsentry_action_res_t *action_results) {
    if (object == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    WOLFSENTRY_ERROR_RERETURN(((struct wolfsentry_table_ent_header *)object)->parent_table->free_fn(WOLFSENTRY_CONTEXT_ARGS_OUT, (struct wolfsentry_table_ent_header *)object, action_results));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_eventconfig_init(
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

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_eventconfig_check(
    const struct wolfsentry_eventconfig *config)
{
    wolfsentry_errcode_t ret;

    if (config == NULL)
        WOLFSENTRY_RETURN_OK;

    if (config->route_flags_to_add_on_insert & config->route_flags_to_clear_on_insert)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (config->action_res_filter_bits_set & config->action_res_filter_bits_unset)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (config->action_res_bits_to_add & config->action_res_bits_to_clear)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (config->derogatory_threshold_for_penaltybox > MAX_UINT_OF(instance_of_field(struct wolfsentry_route, meta.derogatory_count)))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    ret = wolfsentry_route_check_flags_sensical(config->route_flags_to_add_on_insert);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    if (config->route_private_data_size == 0) {
        if (config->route_private_data_alignment != 0)
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    } else {
        if ((config->route_private_data_alignment != 0) &&
            ((config->route_private_data_alignment < sizeof(void *)) ||
             ((config->route_private_data_alignment & (config->route_private_data_alignment - 1)) != 0) ||
             (config->route_private_data_alignment > config->route_private_data_size)))
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

    if (config->route_private_data_alignment > 0) {
        size_t private_data_slop = offsetof(struct wolfsentry_route, data) % config->route_private_data_alignment;
        if (private_data_slop > 0) {
            if (config->route_private_data_size + (config->route_private_data_alignment - private_data_slop) > MAX_UINT_OF(((struct wolfsentry_route *)0)->data_addr_offset))
                WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
        }
    }

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_eventconfig_load(
    const struct wolfsentry_eventconfig *supplied,
    struct wolfsentry_eventconfig_internal *internal)
{
    wolfsentry_errcode_t ret;
    if (internal == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (supplied == NULL)
        WOLFSENTRY_RETURN_OK;

    ret = wolfsentry_eventconfig_check(supplied);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    memset(internal, 0, sizeof *internal);
    memcpy(&internal->config, supplied, sizeof internal->config);
    if (internal->config.route_private_data_alignment > 0) {
        size_t private_data_slop = offsetof(struct wolfsentry_route, data) % internal->config.route_private_data_alignment;
        if (private_data_slop > 0) {
            internal->route_private_data_padding = internal->config.route_private_data_alignment - private_data_slop;
            internal->config.route_private_data_size += internal->route_private_data_padding;
        }
    }

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_eventconfig_update_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_eventconfig *supplied,
    struct wolfsentry_eventconfig_internal *internal)
{
    wolfsentry_errcode_t ret;
    if (supplied == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (internal == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    WOLFSENTRY_HAVE_MUTEX_OR_RETURN();

    ret = wolfsentry_eventconfig_check(supplied);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    internal->config.max_connection_count = supplied->max_connection_count;
    internal->config.derogatory_threshold_for_penaltybox = supplied->derogatory_threshold_for_penaltybox;
    internal->config.penaltybox_duration = supplied->penaltybox_duration;
    internal->config.route_idle_time_for_purge = supplied->route_idle_time_for_purge;
    internal->config.flags = supplied->flags;
    internal->config.route_flags_to_add_on_insert = supplied->route_flags_to_add_on_insert;
    internal->config.route_flags_to_clear_on_insert = supplied->route_flags_to_clear_on_insert;
    internal->config.action_res_filter_bits_set = supplied->action_res_filter_bits_set;
    internal->config.action_res_filter_bits_unset = supplied->action_res_filter_bits_unset;
    internal->config.action_res_bits_to_add = supplied->action_res_bits_to_add;
    internal->config.action_res_bits_to_clear = supplied->action_res_bits_to_clear;

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_eventconfig_get_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_eventconfig_internal *internal,
    struct wolfsentry_eventconfig *exported)
{
    if (internal == NULL)
        WOLFSENTRY_ERROR_RETURN(DATA_MISSING);
    if (exported == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();

    *exported = internal->config;
    exported->route_private_data_size -= internal->route_private_data_padding;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_defaultconfig_get(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_eventconfig *config)
{
    wolfsentry_errcode_t ret;
    WOLFSENTRY_SHARED_OR_RETURN();
    ret = wolfsentry_eventconfig_get_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &wolfsentry->config, config);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_defaultconfig_update(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_eventconfig *config)
{
    wolfsentry_errcode_t ret;
    WOLFSENTRY_MUTEX_OR_RETURN();
    ret = wolfsentry_eventconfig_update_1(WOLFSENTRY_CONTEXT_ARGS_OUT, config, &wolfsentry->config);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API struct wolfsentry_host_platform_interface *wolfsentry_get_hpi(struct wolfsentry_context *wolfsentry) {
    WOLFSENTRY_RETURN_VALUE(&wolfsentry->hpi);
}

WOLFSENTRY_API struct wolfsentry_allocator *wolfsentry_get_allocator(struct wolfsentry_context *wolfsentry) {
    WOLFSENTRY_RETURN_VALUE(&wolfsentry->hpi.allocator);
}

WOLFSENTRY_API struct wolfsentry_timecbs *wolfsentry_get_timecbs(struct wolfsentry_context *wolfsentry) {
    WOLFSENTRY_RETURN_VALUE(&wolfsentry->hpi.timecbs);
}

static wolfsentry_errcode_t wolfsentry_context_free_1(
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_context **wolfsentry)
    )
{
#ifdef WOLFSENTRY_THREADSAFE
    wolfsentry_errcode_t ret = wolfsentry_lock_have_mutex(&(*wolfsentry)->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
#endif

    if ((*wolfsentry)->routes != NULL)
        wolfsentry_route_table_free(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*wolfsentry), &(*wolfsentry)->routes);
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

#ifdef WOLFSENTRY_THREADSAFE
    ret = wolfsentry_lock_unlock(&(*wolfsentry)->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    ret = wolfsentry_lock_destroy(&(*wolfsentry)->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
#endif

    WOLFSENTRY_FREE_1((*wolfsentry)->hpi.allocator, *wolfsentry);
    *wolfsentry = NULL;
    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_context_init_1(
    struct wolfsentry_context *wolfsentry
#ifdef WOLFSENTRY_THREADSAFE
    ,
    struct wolfsentry_thread_context *thread,
    wolfsentry_lock_flags_t lock_flags
#endif
    )
{
    wolfsentry_errcode_t ret;

#ifdef WOLFSENTRY_THREADSAFE
    if ((ret = wolfsentry_lock_init(&wolfsentry->hpi, thread, &wolfsentry->lock, lock_flags)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
#endif

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

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_context_alloc_1(
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(const struct wolfsentry_host_platform_interface *hpi),
    struct wolfsentry_context **wolfsentry
#ifdef WOLFSENTRY_THREADSAFE
    , wolfsentry_lock_flags_t lock_flags
#endif
    )
{
    wolfsentry_errcode_t ret;
    if ((*wolfsentry = (struct wolfsentry_context *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof **wolfsentry)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);

    memset(*wolfsentry, 0, sizeof **wolfsentry);

    (*wolfsentry)->hpi = *hpi;

    if ((((*wolfsentry)->events = (struct wolfsentry_event_table *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof *(*wolfsentry)->events)) == NULL) ||
        (((*wolfsentry)->actions = (struct wolfsentry_action_table *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof *(*wolfsentry)->actions)) == NULL) ||
        (((*wolfsentry)->routes = (struct wolfsentry_route_table *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof *(*wolfsentry)->routes)) == NULL) ||
        (((*wolfsentry)->user_values = (struct wolfsentry_kv_table *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof *(*wolfsentry)->user_values)) == NULL) ||
        (((*wolfsentry)->addr_families_bynumber = (struct wolfsentry_addr_family_bynumber_table *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof *(*wolfsentry)->addr_families_bynumber)) == NULL)
#ifdef WOLFSENTRY_PROTOCOL_NAMES
        || (((*wolfsentry)->addr_families_byname = (struct wolfsentry_addr_family_byname_table *)WOLFSENTRY_MALLOC_1(hpi->allocator, sizeof *(*wolfsentry)->addr_families_byname)) == NULL)
#endif
        )
    {
        (void)wolfsentry_context_free_1(WOLFSENTRY_CONTEXT_ARGS_OUT);
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    }

    memset((*wolfsentry)->events, 0, sizeof *(*wolfsentry)->events);
    memset((*wolfsentry)->actions, 0, sizeof *(*wolfsentry)->actions);
    memset((*wolfsentry)->routes, 0, sizeof *(*wolfsentry)->routes);
    memset((*wolfsentry)->user_values, 0, sizeof *(*wolfsentry)->user_values);
    memset((*wolfsentry)->addr_families_bynumber, 0, sizeof *(*wolfsentry)->addr_families_bynumber);
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    memset((*wolfsentry)->addr_families_byname, 0, sizeof *(*wolfsentry)->addr_families_byname);
    if ((ret = wolfsentry_addr_family_table_pair(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*wolfsentry), (*wolfsentry)->addr_families_bynumber, (*wolfsentry)->addr_families_byname)) < 0) {
        (void)wolfsentry_context_free_1(WOLFSENTRY_CONTEXT_ARGS_OUT);
        WOLFSENTRY_ERROR_RERETURN(ret);
    }
#endif

    if ((ret = wolfsentry_context_init_1(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*wolfsentry)
#ifdef WOLFSENTRY_THREADSAFE
                                         , lock_flags
#endif
             )) < 0) {
        (void)wolfsentry_context_free_1(WOLFSENTRY_CONTEXT_ARGS_OUT);
        WOLFSENTRY_ERROR_RERETURN(ret);
    }

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_init_ex(
    struct wolfsentry_build_settings caller_build_settings,
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(const struct wolfsentry_host_platform_interface *user_hpi),
    const struct wolfsentry_eventconfig *config,
    struct wolfsentry_context **wolfsentry,
    wolfsentry_init_flags_t flags)
{
    struct wolfsentry_host_platform_interface hpi;
#ifdef WOLFSENTRY_THREADSAFE
    wolfsentry_lock_flags_t lock_flags = WOLFSENTRY_LOCK_FLAG_NONE;
#endif
    wolfsentry_errcode_t ret;

    ret = wolfsentry_build_settings_compatible(caller_build_settings);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    if (user_hpi &&
        ((user_hpi->caller_build_settings.version != 0) ||
         (user_hpi->caller_build_settings.config != 0)) &&
        ((user_hpi->caller_build_settings.version != caller_build_settings.version) ||
         (user_hpi->caller_build_settings.config != caller_build_settings.config)))
    {
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

    ret = wolfsentry_eventconfig_check(config);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    memset(&hpi, 0, sizeof hpi);

    hpi.caller_build_settings = caller_build_settings;

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

#ifdef WOLFSENTRY_THREADSAFE
    if (flags & WOLFSENTRY_INIT_FLAG_LOCK_SHARED_ERROR_CHECKING)
        lock_flags |= WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING;
    if ((ret = wolfsentry_context_alloc_1(&hpi, thread, wolfsentry, lock_flags)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
#else
    (void)flags;
    if ((ret = wolfsentry_context_alloc_1(&hpi, wolfsentry)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
#endif

    if ((ret = wolfsentry_eventconfig_load(config, &(*wolfsentry)->config)) < 0)
        goto out;

    /* times in config are passed to wolfsentry_init_ex() in seconds,
     * because wolfsentry_interval_from_seconds() needs a valid
     * wolfsentry_context (circular dependency).  fix it now that we can.
     */
    hpi.timecbs.interval_from_seconds((long int)(*wolfsentry)->config.config.penaltybox_duration, 0 /* howlong_nsecs */, &((*wolfsentry)->config.config.penaltybox_duration));
    hpi.timecbs.interval_from_seconds((long int)(*wolfsentry)->config.config.route_idle_time_for_purge, 0 /* howlong_nsecs */, &((*wolfsentry)->config.config.route_idle_time_for_purge));

    (*wolfsentry)->config_at_creation = (*wolfsentry)->config;

    if ((ret = wolfsentry_route_table_fallthrough_route_alloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*wolfsentry), (*wolfsentry)->routes)) < 0)
        goto out;

    if ((ret = wolfsentry_action_insert_builtins(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*wolfsentry))) < 0)
        goto out;

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    if (ret < 0) {
        (void)wolfsentry_context_free_1(WOLFSENTRY_CONTEXT_ARGS_OUT);
    }
    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_init(
    struct wolfsentry_build_settings caller_build_settings,
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(const struct wolfsentry_host_platform_interface *hpi),
    const struct wolfsentry_eventconfig *config,
    struct wolfsentry_context **wolfsentry)
{
    WOLFSENTRY_ERROR_RERETURN(
        wolfsentry_init_ex(
            caller_build_settings,
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(hpi),
            config,
            wolfsentry,
            WOLFSENTRY_INIT_FLAG_NONE));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_cleanup_push(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_cleanup_callback_t handler,
    void *arg)
{
    struct wolfsentry_cleanup_hook_ent *i = NULL; /* without initing, compiler gripes with maybe-uninitialized in no-inline builds. */

    WOLFSENTRY_MUTEX_OR_RETURN();

    wolfsentry_list_ent_get_first(&wolfsentry->cleanup_hooks, (struct wolfsentry_list_ent_header **)&i);
    while (i) {
        if ((i->handler == handler) && (i->arg == arg))
            WOLFSENTRY_SUCCESS_UNLOCK_AND_RETURN(ALREADY_OK);
        wolfsentry_list_ent_get_next(&wolfsentry->cleanup_hooks, (struct wolfsentry_list_ent_header **)&i);
    }

    i = WOLFSENTRY_MALLOC(sizeof *i);
    if (i == NULL)
        WOLFSENTRY_ERROR_UNLOCK_AND_RETURN(SYS_RESOURCE_FAILED);
    i->handler = handler;
    i->arg = arg;
    wolfsentry_list_ent_prepend(&wolfsentry->cleanup_hooks, (struct wolfsentry_list_ent_header *)i);
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_cleanup_pop(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    int execute_p)
{
    struct wolfsentry_cleanup_hook_ent *i = NULL; /* without initing, compiler gripes with maybe-uninitialized in no-inline builds. */

    WOLFSENTRY_MUTEX_OR_RETURN();

    wolfsentry_list_ent_get_first(&wolfsentry->cleanup_hooks, (struct wolfsentry_list_ent_header **)&i);
    if (i == NULL)
        WOLFSENTRY_ERROR_UNLOCK_AND_RETURN(ITEM_NOT_FOUND);
    if (execute_p)
        i->handler(WOLFSENTRY_CONTEXT_ARGS_OUT, i->arg);
    wolfsentry_list_ent_delete(&wolfsentry->cleanup_hooks, (struct wolfsentry_list_ent_header *)i);
    WOLFSENTRY_FREE(i);
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_cleanup_all(
    WOLFSENTRY_CONTEXT_ARGS_IN)
{
    wolfsentry_errcode_t ret;
    WOLFSENTRY_MUTEX_OR_RETURN();

    for (;;) {
        ret = wolfsentry_cleanup_pop(WOLFSENTRY_CONTEXT_ARGS_OUT, 1);
        if (ret < 0)
            break;
    }
    if (WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND))
        WOLFSENTRY_UNLOCK_AND_RETURN_OK;
    else
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_flush(WOLFSENTRY_CONTEXT_ARGS_IN) {
    wolfsentry_errcode_t ret;
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;

    WOLFSENTRY_MUTEX_OR_RETURN();

    if ((ret = wolfsentry_route_flush_table(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->routes, &action_results)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);

    ret = wolfsentry_event_flush_all(WOLFSENTRY_CONTEXT_ARGS_OUT);
    WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_table_free_ents(WOLFSENTRY_CONTEXT_ARGS_OUT, &wolfsentry->user_values->header);

    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_free(WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_context **wolfsentry)) {
    wolfsentry_errcode_t ret;
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;

#ifdef WOLFSENTRY_THREADSAFE
    WOLFSENTRY_HAVE_MUTEX_OR_RETURN_EX(*wolfsentry);
    if ((*wolfsentry)->lock.holder_count.write != 1)
        WOLFSENTRY_ERROR_UNLOCK_AND_RETURN_EX(*wolfsentry, BUSY);
    if ((*wolfsentry)->lock.read_waiter_count != 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RETURN_EX(*wolfsentry, BUSY);
    if ((*wolfsentry)->lock.write_waiter_count != 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RETURN_EX(*wolfsentry, BUSY);
#endif

    ret = wolfsentry_cleanup_all(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*wolfsentry));
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_route_flush_table(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*wolfsentry), (*wolfsentry)->routes, &action_results);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    ret = wolfsentry_action_flush_all(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*wolfsentry));
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    ret = wolfsentry_event_flush_all(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*wolfsentry));
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    ret = wolfsentry_table_free_ents(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*wolfsentry), &(*wolfsentry)->user_values->header);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    ret = wolfsentry_table_free_ents(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*wolfsentry), &(*wolfsentry)->addr_families_bynumber->header);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    /* freeing ents in addr_families_byname is implicit to freeing the
     * corresponding ents in addr_families_bynumber.
     */

    WOLFSENTRY_ERROR_RERETURN(wolfsentry_context_free_1(WOLFSENTRY_CONTEXT_ARGS_OUT));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_context **wolfsentry)) {
    wolfsentry_errcode_t ret;
#ifdef WOLFSENTRY_THREADSAFE
    ret = WOLFSENTRY_MUTEX_EX(*wolfsentry);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
#endif
    ret = wolfsentry_context_free(WOLFSENTRY_CONTEXT_ARGS_OUT);
#ifdef WOLFSENTRY_THREADSAFE
    if (WOLFSENTRY_ERROR_CODE_IS(ret, BUSY))
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_context_unlock(*wolfsentry, thread));
#endif
    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_inhibit_actions(WOLFSENTRY_CONTEXT_ARGS_IN) {
    wolfsentry_eventconfig_flags_t flags_before, flags_after;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    WOLFSENTRY_ATOMIC_UPDATE_FLAGS(
        wolfsentry->config.config.flags,
        (wolfsentry_eventconfig_flags_t)WOLFSENTRY_EVENTCONFIG_FLAG_INHIBIT_ACTIONS,
        (wolfsentry_eventconfig_flags_t)WOLFSENTRY_EVENTCONFIG_FLAG_NONE,
        &flags_before,
        &flags_after);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_enable_actions(WOLFSENTRY_CONTEXT_ARGS_IN) {
    wolfsentry_eventconfig_flags_t flags_before, flags_after;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
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
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_clone(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_context **clone,
    wolfsentry_clone_flags_t flags)
{
    wolfsentry_errcode_t ret;

#ifdef WOLFSENTRY_THREADSAFE
    WOLFSENTRY_SHARED_OR_RETURN();

    if ((ret = wolfsentry_context_alloc_1(&wolfsentry->hpi, thread, clone, wolfsentry->lock.flags)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);

    if ((ret = wolfsentry_context_lock_mutex_abstimed(*clone, thread, NULL)) < 0)
        goto out;
#else
    if ((ret = wolfsentry_context_alloc_1(&wolfsentry->hpi, clone)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
#endif

    /* note that wolfsentry->lock and wolfsentry->cleanup_hooks are not copied
     * to the clone.  these follow the context pointer itself, which is
     * necessarily invariant once allocated by wolfsentry_init(), until final
     * deallocation by wolfsentry_shutdown().
     */

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

    if ((ret = wolfsentry_table_clone(WOLFSENTRY_CONTEXT_ARGS_OUT, &wolfsentry->actions->header, *clone, &(*clone)->actions->header, flags)) < 0)
        goto out;

#ifdef WOLFSENTRY_PROTOCOL_NAMES
    if ((ret = wolfsentry_coupled_table_clone(
             WOLFSENTRY_CONTEXT_ARGS_OUT,
             &wolfsentry->addr_families_bynumber->header,
             &wolfsentry->addr_families_byname->header,
             *clone,
             &(*clone)->addr_families_bynumber->header,
             &(*clone)->addr_families_byname->header,
             flags)) < 0)
        goto out;
#else
    if ((ret = wolfsentry_table_clone(WOLFSENTRY_CONTEXT_ARGS_OUT, &wolfsentry->addr_families_bynumber->header, *clone, &(*clone)->addr_families_bynumber->header, flags)) < 0)
        goto out;
#endif

    if (WOLFSENTRY_CHECK_BITS(flags, WOLFSENTRY_CLONE_FLAG_AS_AT_CREATION)) {
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        goto out;
    }

    if ((ret = wolfsentry_table_clone(WOLFSENTRY_CONTEXT_ARGS_OUT, &wolfsentry->events->header, *clone, &(*clone)->events->header, flags)) < 0)
        goto out;

    /* if WOLFSENTRY_CLONE_FLAG_NO_ROUTES, wolfsentry_table_clone() for the
     * routes will return immediately after
     * wolfsentry_route_table_clone_header(), without copying any routes.
     */
    if ((ret = wolfsentry_table_clone(WOLFSENTRY_CONTEXT_ARGS_OUT, &wolfsentry->routes->header, *clone, &(*clone)->routes->header, flags)) < 0)
        goto out;

    if ((ret = wolfsentry_table_clone(WOLFSENTRY_CONTEXT_ARGS_OUT, &wolfsentry->user_values->header, *clone, &(*clone)->user_values->header, flags)) < 0)
        goto out;

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    if ((ret < 0) && (*clone != NULL))
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_context_free(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(clone)));

    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_context_exchange(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_context *wolfsentry2) {
    struct wolfsentry_context scratch;
    wolfsentry_errcode_t ret;

    if ((memcmp(&wolfsentry->hpi, &wolfsentry2->hpi, sizeof wolfsentry->hpi)) ||
        (wolfsentry->mk_id_cb != wolfsentry2->mk_id_cb))
    {
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

#ifdef WOLFSENTRY_THREADSAFE
    {
        ret = wolfsentry_context_lock_mutex_abstimed(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        ret = wolfsentry_context_lock_mutex_abstimed(wolfsentry2, thread, NULL);
        WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);
    }
#endif

    /* now that we have a mutex on both contexts, coherently copy the route
     * metadata from the current context to the new one to be swapped in.
     */
    ret = wolfsentry_route_copy_metadata(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        wolfsentry->routes,
        wolfsentry2,
        wolfsentry2->routes);
    if (ret < 0)
        goto out;

    scratch = *wolfsentry;

    wolfsentry->mk_id_cb_state = wolfsentry2->mk_id_cb_state;
    wolfsentry->config = wolfsentry2->config;
    wolfsentry->config_at_creation = wolfsentry2->config_at_creation;
    wolfsentry->events = wolfsentry2->events;
    wolfsentry->actions = wolfsentry2->actions;
    wolfsentry->routes =  wolfsentry2->routes;
    wolfsentry->user_values = wolfsentry2->user_values;
    wolfsentry->addr_families_bynumber = wolfsentry2->addr_families_bynumber;
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    wolfsentry->addr_families_byname = wolfsentry2->addr_families_byname;
#endif
    wolfsentry->ents_by_id = wolfsentry2->ents_by_id;

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

    /* note that wolfsentry->lock and wolfsentry->cleanup_hooks are not copied.
     * both of these follow the context pointer itself, which is necessarily
     * invariant once allocated by wolfsentry_init(), until final deallocation
     * by wolfsentry_shutdown().
     */

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

out:

#ifdef WOLFSENTRY_THREADSAFE
    {
        wolfsentry_errcode_t ret1, ret2;
        ret1 = wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT);
        ret2 = wolfsentry_context_unlock(wolfsentry2, thread);
        WOLFSENTRY_RERETURN_IF_ERROR(ret1);
        WOLFSENTRY_RERETURN_IF_ERROR(ret2);
    }
#endif

    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_hitcount_t wolfsentry_table_n_inserts(struct wolfsentry_table_header *table) {
    WOLFSENTRY_RETURN_VALUE(table->n_inserts);
}

WOLFSENTRY_API wolfsentry_hitcount_t wolfsentry_table_n_deletes(struct wolfsentry_table_header *table) {
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

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_base64_decode(const char *src, size_t src_len, byte *dest, size_t *dest_spc, int ignore_junk_p) {
    uint32_t decoded = 0;
    uint32_t decoded_bits = 0;
    uint32_t pad_chars = 0;
    const char *src_end = src + src_len;
    size_t dest_len = 0;

    if (WOLFSENTRY_BASE64_DECODED_BUFSPC(src, src_len) > *dest_spc)
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
        /* decoded_bits = 24U; */ /* commented out to silence analyzer */
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
