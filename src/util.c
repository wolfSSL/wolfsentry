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
    case WOLFSENTRY_SOURCE_ID_JSON_LOAD_CONFIG_C:
        return "json/load_config.c";
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
    case WOLFSENTRY_ERROR_ID_CONFIG_OUT_OF_SEQUENCE:
        return "Configuration clause is not in the correct sequence";
    case WOLFSENTRY_ERROR_ID_CONFIG_UNEXPECTED:
        return "Configuration has unexpected or invalid structure";
    case WOLFSENTRY_ERROR_ID_CONFIG_PARSER:
        return "Configuration parsing failed";
    case WOLFSENTRY_ERROR_ID_OP_NOT_SUPP_FOR_PROTO:
        return "Operation not supported for protocol";
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
        return malloc(size);
#else
    else {
        void *ret = 0;
        if (posix_memalign(&ret, alignment, size) < 0)
            return NULL;
        return ret;
    }
#endif
}

static void wolfsentry_builtin_free_aligned(void *context, void *ptr) {
    (void)context;
    free(ptr);
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

wolfsentry_ent_id_t wolfsentry_get_table_id(const void *table) {
    return ((const struct wolfsentry_table_header *)table)->id;
}

wolfsentry_ent_id_t wolfsentry_get_object_id(const void *object) {
    return ((const struct wolfsentry_table_ent_header *)object)->id;
}

#ifdef WOLFSENTRY_THREADSAFE

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
        return -1;
    }
    if (value != 0) {
        /* note, dispatch_release() fails hard, with Trace/BPT trap signal, if
         * the sem's internal count is less than the value passed in with
         * dispatch_semaphore_create().  force init with zero count to prevent
         * this from happening.
         */
        errno = EINVAL;
        return -1;
    }
    new_sem = dispatch_semaphore_create(value);
    if (new_sem == NULL) {
        errno = ENOMEM;
        return -1;
    }
    *sem = new_sem;
    return 0;
}
#define sem_init darwin_sem_init

static int darwin_sem_post(sem_t *sem)
{
    if (dispatch_semaphore_signal(*sem) < 0) {
        errno = EINVAL;
        return -1;
    } else
        return 0;
}
#define sem_post darwin_sem_post

static int darwin_sem_wait(sem_t *sem)
{
    if (dispatch_semaphore_wait(*sem, DISPATCH_TIME_FOREVER) == 0)
        return 0;
    else {
        errno = EINVAL;
        return -1;
    }
}
#define sem_wait darwin_sem_wait

static int darwin_sem_timedwait(sem_t *sem, struct timespec *abs_timeout) {
    if (dispatch_semaphore_wait(*sem, dispatch_walltime(abs_timeout, 0)) == 0)
        return 0;
    else {
        errno = ETIMEDOUT;
        return -1;
    }
}
#define sem_timedwait darwin_sem_timedwait

static int darwin_sem_trywait(sem_t *sem) {
    if (dispatch_semaphore_wait(*sem, DISPATCH_TIME_NOW) == 0)
        return 0;
    else {
        errno = EAGAIN;
        return -1;
    }
}
#define sem_trywait darwin_sem_trywait

static int darwin_sem_destroy(sem_t *sem)
{
    if (*sem == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* note, dispatch_release() fails hard, with Trace/BPT trap signal, if the
     * sem's internal count is less than the value passed in with
     * dispatch_semaphore_create().  but this can't happen if the sem is inited
     * with value 0, hence forcing that value in darwin_sem_init() above.
     */
    dispatch_release(*sem);
    *sem = NULL;
    return 0;
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
        return -1;
    }

    /* Create the FreeRTOS semaphore.
     * This is only used to queue threads when no semaphore is available.
     * Initializing with semaphore initial count zero.
     * This call will not fail because the memory for the semaphore has already been allocated.
     */
    ( void ) xSemaphoreCreateCountingStatic( SEM_VALUE_MAX, value, sem );

    return 0;
}

#define sem_init freertos_sem_init

static int freertos_sem_post( sem_t * sem )
{
    /* Give the semaphore using the FreeRTOS API. */
    ( void ) xSemaphoreGive(sem);

    return 0;
}

#define sem_post freertos_sem_post


static void UTILS_NanosecondsToTimespec( int64_t llSource,
        struct timespec * const pxDestination )
{
	long lCarrySec = 0;

	/* Convert to timespec. */
	pxDestination->tv_sec = ( time_t ) ( llSource / FREERTOS_SEM_NANOSECONDS_PER_SECOND );
	pxDestination->tv_nsec = ( long ) ( llSource % FREERTOS_SEM_NANOSECONDS_PER_SECOND );

	/* Subtract from tv_sec if tv_nsec < 0. */
	if( pxDestination->tv_nsec < 0L )
	{
		/* Compute the number of seconds to carry. */
		lCarrySec = ( pxDestination->tv_nsec / ( long ) FREERTOS_SEM_NANOSECONDS_PER_SECOND ) + 1L;

		pxDestination->tv_sec -= ( time_t ) ( lCarrySec );
		pxDestination->tv_nsec += lCarrySec * ( long ) FREERTOS_SEM_NANOSECONDS_PER_SECOND;
	}
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

    return iStatus;
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

        /* if x < y then result would be negative, return 1 */
        if( iCompareResult == -1 )
        {
            iStatus = 1;
        }
        else if( iCompareResult == 0 )
        {
            /* if times are the same return zero */
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
                pxResult->tv_nsec += ( long ) FREERTOS_SEM_NANOSECONDS_PER_SECOND;
            }

            /* if nano second is negative after borrow, it is an overflow error */
            if( pxResult->tv_nsec < 0 )
            {
                iStatus = -1;
            }
        }
    }

    return iStatus;
}

static int UTILS_ValidateTimespec( const struct timespec * const pxTimespec )
{
    int xReturn = 0;

    if( pxTimespec != NULL )
    {
        /* Verify 0 <= tv_nsec < 1000000000. */
        if( ( pxTimespec->tv_nsec >= 0 ) &&
            ( pxTimespec->tv_nsec < FREERTOS_SEM_NANOSECONDS_PER_SECOND ) )
        {
            xReturn = 1;
        }
    }

    return xReturn;
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
         * FREERTOS_SEM_NANOSECONDS_PER_TICK > 1. */
        lNanoseconds = pxTimespec->tv_nsec / ( long ) FREERTOS_SEM_NANOSECONDS_PER_TICK + /* Whole nanoseconds. */
                       ( long ) ( pxTimespec->tv_nsec % ( long ) FREERTOS_SEM_NANOSECONDS_PER_TICK != 0 ); /* Add 1 to round up if needed. */

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

    return iStatus;
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

    return iStatus;
}


static int freertos_clock_gettime( clockid_t clock_id,
                   struct timespec * tp )
{
    TimeOut_t xCurrentTime = { 0 };

    /* Intermediate variable used to convert TimeOut_t to struct timespec.
     * Also used to detect overflow issues. It must be unsigned because the
     * behavior of signed integer overflow is undefined. */
    uint64_t ullTickCount = 0ULL;

    /* Silence warnings about unused parameters. */
    ( void ) clock_id;

    /* Get the current tick count and overflow count. vTaskSetTimeOutState()
     * is used to get these values because they are both static in tasks.c. */
    vTaskSetTimeOutState( &xCurrentTime );

    /* Adjust the tick count for the number of times a TickType_t has overflowed.
     * portMAX_DELAY should be the maximum value of a TickType_t. */
    ullTickCount = ( uint64_t ) ( xCurrentTime.xOverflowCount ) << ( sizeof( TickType_t ) * 8 );

    /* Add the current tick count. */
    ullTickCount += xCurrentTime.xTimeOnEntering;

    /* Convert ullTickCount to timespec. */
    UTILS_NanosecondsToTimespec( ( int64_t ) ullTickCount * FREERTOS_SEM_NANOSECONDS_PER_TICK, tp );

    return 0;
}

#define clock_gettime freertos_clock_gettime

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

    return iStatus;
}

#define sem_timedwait freertos_sem_timedwait

static int freertos_sem_wait( sem_t * sem )
{
    return freertos_sem_timedwait( sem, NULL );
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

    return iStatus;
}

#define sem_trywait freertos_sem_trywait

static int freertos_sem_destroy( sem_t * sem )
{
    /* Free the resources in use by the semaphore. */
    vSemaphoreDelete( sem );

    return 0;
}

#define sem_destroy freertos_sem_destroy


#else

#error semaphore shim set missing for target

#endif

#endif /* WOLFSENTRY_USE_NONPOSIX_SEMAPHORES */

wolfsentry_errcode_t wolfsentry_lock_init(struct wolfsentry_rwlock *lock, int pshared) {
    wolfsentry_errcode_t ret;

    memset(lock,0,sizeof *lock);

    if (sem_init(&lock->sem, pshared, 0 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (sem_init(&lock->sem_read_waiters, pshared, 0 /* value */) < 0) {
        ret = WOLFSENTRY_ERROR_ENCODE(SYS_RESOURCE_FAILED);
        goto free_sem;
    }
    if (sem_init(&lock->sem_write_waiters, pshared, 0 /* value */) < 0) {
        ret = WOLFSENTRY_ERROR_ENCODE(SYS_RESOURCE_FAILED);
        goto free_read_waiters;
    }
    if (sem_init(&lock->sem_read2write_waiters, pshared, 0 /* value */) < 0) {
        ret = WOLFSENTRY_ERROR_ENCODE(SYS_RESOURCE_FAILED);
        goto free_write_waiters;
    }

    ret = WOLFSENTRY_ERROR_ENCODE(OK);
    goto out;

  free_write_waiters:
    if (sem_init(&lock->sem_write_waiters, pshared, 0 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
  free_read_waiters:
    if (sem_init(&lock->sem_read_waiters, pshared, 0 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
  free_sem:
    if (sem_init(&lock->sem, pshared, 1 /* value */) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);

  out:

    return ret;
}

wolfsentry_errcode_t wolfsentry_lock_alloc(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock **lock, int pshared) {
    wolfsentry_errcode_t ret;
    if ((*lock = (struct wolfsentry_rwlock *)WOLFSENTRY_MALLOC(sizeof **lock)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if ((ret = wolfsentry_lock_init(*lock, pshared)) < 0) {
        WOLFSENTRY_FREE(*lock);
        *lock = NULL;
        return ret;
    }
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_destroy(struct wolfsentry_rwlock *lock) {
    int ret;
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

    if (sem_destroy(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (sem_destroy(&lock->sem_read_waiters) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (sem_destroy(&lock->sem_write_waiters) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    if (sem_destroy(&lock->sem_read2write_waiters) < 0)
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
    for (;;) {
        int ret = sem_wait(&lock->sem);
        if (ret == 0)
            break;
        else {
            if (errno != EINTR)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        }
    }

    if ((lock->state == WOLFSENTRY_LOCK_EXCLUSIVE) || (lock->write_waiter_count > 0)) {

        ++lock->read_waiter_count;

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

        for (;;) {
            int ret = sem_wait(&lock->sem_read_waiters);
            if (ret == 0)
                break;
            else {
                if (errno != EINTR)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            }
        }

        WOLFSENTRY_RETURN_OK;
    }

    if (lock->state == WOLFSENTRY_LOCK_UNLOCKED)
        lock->state = WOLFSENTRY_LOCK_SHARED;
    else if (lock->state != WOLFSENTRY_LOCK_SHARED)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);

    ++lock->shared_count;

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    else
        WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_shared_abstimed(struct wolfsentry_rwlock *lock, struct timespec *abs_timeout) {
    int ret;

    if (abs_timeout == NULL) {
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

    if ((lock->state == WOLFSENTRY_LOCK_EXCLUSIVE) || (lock->write_waiter_count > 0)) {

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
                WOLFSENTRY_RETURN_OK;
            }

            --lock->read_waiter_count;

            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

            return ret;
        }
        WOLFSENTRY_RETURN_OK;
    }

    if (lock->state == WOLFSENTRY_LOCK_UNLOCKED)
        lock->state = WOLFSENTRY_LOCK_SHARED;
    else if (lock->state != WOLFSENTRY_LOCK_SHARED)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);

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
        return wolfsentry_lock_shared_abstimed(lock, &abs_timeout);
    } else
        return wolfsentry_lock_shared_abstimed(lock, NULL);
}

wolfsentry_errcode_t wolfsentry_lock_shared_and_reserve_shared2mutex(struct wolfsentry_rwlock *lock) {
    for (;;) {
        int ret = sem_wait(&lock->sem);
        if (ret == 0)
            break;
        else {
            if (errno != EINTR)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        }
    }

    if (lock->read2write_waiter_count > 0) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(BUSY);
    }

    ++lock->read2write_waiter_count;

    if ((lock->state == WOLFSENTRY_LOCK_EXCLUSIVE) || (lock->write_waiter_count > 0)) {

        lock->read_waiter_count += 2; /* suppress posts to sem_read2write_waiters until wolfsentry_lock_shared2mutex_redeem() is entered. */

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

        for (;;) {
            int ret = sem_wait(&lock->sem_read_waiters);
            if (ret == 0)
                break;
            else {
                if (errno != EINTR)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            }
        }
        /* again, for the second count, now reflected in lock->shared_count. */
        for (;;) {
            int ret = sem_wait(&lock->sem_read_waiters);
            if (ret == 0)
                break;
            else {
                if (errno != EINTR)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            }
        }

        WOLFSENTRY_RETURN_OK;
    }

    if (lock->state == WOLFSENTRY_LOCK_UNLOCKED)
        lock->state = WOLFSENTRY_LOCK_SHARED;
    else if (lock->state != WOLFSENTRY_LOCK_SHARED)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);

    lock->shared_count += 2; /* suppress posts to sem_read2write_waiters until wolfsentry_lock_shared2mutex_redeem() is entered. */

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    else
        WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_shared_abstimed_and_reserve_shared2mutex(struct wolfsentry_rwlock *lock, struct timespec *abs_timeout) {
    int ret;

    if (abs_timeout == NULL) {
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

    if (lock->read2write_waiter_count > 0) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(BUSY);
    }

    ++lock->read2write_waiter_count;

    if ((lock->state == WOLFSENTRY_LOCK_EXCLUSIVE) || (lock->write_waiter_count > 0)) {

        if (abs_timeout == NULL) {
            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            else
                WOLFSENTRY_ERROR_RETURN(BUSY);
        }

        lock->read_waiter_count += 2; /* suppress posts to sem_read2write_waiters until wolfsentry_lock_shared2mutex_redeem() is entered. */

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

        if (sem_timedwait(&lock->sem_read_waiters, abs_timeout) < 0) {
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
                goto get_second_count;
            }

            lock->read_waiter_count -= 2;
            --lock->read2write_waiter_count;

            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

            return ret;
        }

      get_second_count:

        /* again, untimed, for the second count, now reflected in lock->shared_count. */
        for (;;) {
            ret = sem_wait(&lock->sem_read_waiters);
            if (ret == 0)
                break;
            else {
                if (errno != EINTR)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            }
        }

        WOLFSENTRY_RETURN_OK;
    }

    if (lock->state == WOLFSENTRY_LOCK_UNLOCKED)
        lock->state = WOLFSENTRY_LOCK_SHARED;
    else if (lock->state != WOLFSENTRY_LOCK_SHARED)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);

    lock->shared_count += 2; /* suppress posts to sem_read2write_waiters until wolfsentry_lock_shared2mutex_redeem() is entered. */

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    else
        WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_shared_timed_and_reserve_shared2mutex(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock *lock, wolfsentry_time_t max_wait) {
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
        return wolfsentry_lock_shared_abstimed_and_reserve_shared2mutex(lock, &abs_timeout);
    } else
        return wolfsentry_lock_shared_abstimed_and_reserve_shared2mutex(lock, NULL);
}

wolfsentry_errcode_t wolfsentry_lock_mutex(struct wolfsentry_rwlock *lock) {
    for (;;) {
        int ret = sem_wait(&lock->sem);
        if (ret == 0)
            break;
        else {
            if (errno != EINTR)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        }
    }

    if (lock->state != WOLFSENTRY_LOCK_UNLOCKED) {

        ++lock->write_waiter_count;

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

        for (;;) {
            int ret = sem_wait(&lock->sem_write_waiters);
            if (ret == 0)
                break;
            else {
                if (errno != EINTR)
                    WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
            }
        }

        WOLFSENTRY_RETURN_OK;
    }

    lock->state = WOLFSENTRY_LOCK_EXCLUSIVE;

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
    else
        WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_mutex_abstimed(struct wolfsentry_rwlock *lock, struct timespec *abs_timeout) {
    wolfsentry_errcode_t ret;

    if (abs_timeout == NULL) {
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
                WOLFSENTRY_RETURN_OK;
            }

            --lock->write_waiter_count;

            if (sem_post(&lock->sem) < 0)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

            return ret;
        }

        WOLFSENTRY_RETURN_OK;
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
        return wolfsentry_lock_mutex_abstimed(lock, &abs_timeout);
    } else
        return wolfsentry_lock_mutex_abstimed(lock, NULL);
}

wolfsentry_errcode_t wolfsentry_lock_mutex2shared(struct wolfsentry_rwlock *lock) {
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

    if (lock->state != WOLFSENTRY_LOCK_EXCLUSIVE) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    lock->state = WOLFSENTRY_LOCK_SHARED;
    lock->shared_count = 1;

    if ((lock->write_waiter_count == 0) &&
        (lock->read_waiter_count > 0)) {
        int read_waiter_count = lock->read_waiter_count;
        lock->shared_count += lock->read_waiter_count;
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

wolfsentry_errcode_t wolfsentry_lock_mutex2shared_and_reserve_shared2mutex(struct wolfsentry_rwlock *lock) {
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

    if (lock->state != WOLFSENTRY_LOCK_EXCLUSIVE) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    /* wolfsentry_lock_shared_*and_reserve_shared2mutex() may have already
     * reserved rd2wr, in which case the caller just keeps its write lock.
     */
    if (lock->read2write_waiter_count > 0) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(BUSY);
    }

    lock->state = WOLFSENTRY_LOCK_SHARED;
    lock->shared_count = 2; /* suppress posts to sem_read2write_waiters until wolfsentry_lock_shared2mutex_redeem() is entered. */
    ++lock->read2write_waiter_count;
    /* note, not incrementing write_waiter_count, to allow shared lockers to get locks until the redemption phase. */

    if ((lock->write_waiter_count == 0) &&
        (lock->read_waiter_count > 0)) {
        int read_waiter_count = lock->read_waiter_count;
        lock->shared_count += lock->read_waiter_count;
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

/* if another thread is already waiting for read2write, then this
 * returns BUSY, and the caller must _unlock() to resolve the
 * deadlock, then reattempt its transaction with a fresh lock (ideally
 * with a _lock_mutex() at the open).
 */
wolfsentry_errcode_t wolfsentry_lock_shared2mutex(struct wolfsentry_rwlock *lock) {
    if (lock->state == WOLFSENTRY_LOCK_EXCLUSIVE)
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
    ++lock->write_waiter_count; /* force shared lockers to wait. */

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    for (;;) {
        int ret = sem_wait(&lock->sem_read2write_waiters);
        if (ret == 0)
            break;
        else {
            if (errno != EINTR)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        }
    }

    WOLFSENTRY_RETURN_OK;
}

/* a shared lock holder can use wolfsentry_lock_shared2mutex_reserve() to
 * guarantee success of a subsequent lock promotion via
 * wolfsentry_lock_shared2mutex_redeem().
 * wolfsentry_lock_shared2mutex_reserve() will immediately fail if the promotion
 * cannot be reserved.
 */
wolfsentry_errcode_t wolfsentry_lock_shared2mutex_reserve(struct wolfsentry_rwlock *lock) {
    if (lock->state == WOLFSENTRY_LOCK_EXCLUSIVE)
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

    ++lock->read2write_waiter_count;
    /* note, not incrementing write_waiter_count, to allow shared lockers to get locks until the redemption phase. */
    ++lock->shared_count; /* suppress posts to sem_read2write_waiters until wolfsentry_lock_shared2mutex_redeem() is entered. */

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem(struct wolfsentry_rwlock *lock) {
    if (lock->state == WOLFSENTRY_LOCK_EXCLUSIVE)
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

    if (lock->state != WOLFSENTRY_LOCK_SHARED) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    --lock->shared_count; /* reenable posts to sem_read2write_waiters by unlockers. */
    ++lock->write_waiter_count; /* and force shared lockers to wait. */

    if (lock->shared_count == 1) {

        lock->state = WOLFSENTRY_LOCK_EXCLUSIVE;
        lock->shared_count = 0;
        --lock->read2write_waiter_count;
        --lock->write_waiter_count;

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

        WOLFSENTRY_RETURN_OK;
    }

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    for (;;) {
        int ret = sem_wait(&lock->sem_read2write_waiters);
        if (ret == 0)
            break;
        else {
            if (errno != EINTR)
                WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        }
    }

    WOLFSENTRY_RETURN_OK;
}

/* if this returns BUSY or TIMED_OUT, the caller still owns a reservation, and must either retry the redemption, or abandon the reservation. */
wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem_abstimed(struct wolfsentry_rwlock *lock, struct timespec *abs_timeout) {
    wolfsentry_errcode_t ret;

    if (lock->state != WOLFSENTRY_LOCK_SHARED)
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);

    if (abs_timeout == NULL) {
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

    if (lock->state != WOLFSENTRY_LOCK_SHARED) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    if (lock->shared_count < 2) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    if (lock->shared_count == 2) {

        lock->state = WOLFSENTRY_LOCK_EXCLUSIVE;
        lock->shared_count = 0;
        --lock->read2write_waiter_count;

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

        WOLFSENTRY_RETURN_OK;
    }

    if (abs_timeout == NULL) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(BUSY);
    }

    --lock->shared_count; /* reenable posts to sem_read2write_waiters by unlockers. */
    ++lock->write_waiter_count; /* and force shared lockers to wait. */

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    if (sem_timedwait(&lock->sem_read2write_waiters, abs_timeout) < 0) {
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
            WOLFSENTRY_RETURN_OK;
        }

        ++lock->shared_count; /* restore disabling posts to sem_read2write_waiters by unlockers. */
        --lock->write_waiter_count; /* and allow shared lockers again. */

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            return ret;
    }

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_shared2mutex_redeem_timed(struct wolfsentry_context *wolfsentry, struct wolfsentry_rwlock *lock, wolfsentry_time_t max_wait) {
    wolfsentry_time_t now;
    struct timespec abs_timeout;
    wolfsentry_errcode_t ret;

    if (lock->state != WOLFSENTRY_LOCK_SHARED)
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);

    if (max_wait < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (max_wait > 0) {
        if ((ret = WOLFSENTRY_GET_TIME(&now)) < 0)
            return ret;
        if ((ret = WOLFSENTRY_TO_EPOCH_TIME(WOLFSENTRY_ADD_TIME(now,max_wait), &abs_timeout.tv_sec, &abs_timeout.tv_nsec)) < 0)
            return ret;
        return wolfsentry_lock_shared2mutex_redeem_abstimed(lock, &abs_timeout);
    } else
        return wolfsentry_lock_shared2mutex_redeem_abstimed(lock, NULL);
}

/* note caller still holds its shared lock after return. */
wolfsentry_errcode_t wolfsentry_lock_shared2mutex_abandon(struct wolfsentry_rwlock *lock) {
    if (lock->state == WOLFSENTRY_LOCK_EXCLUSIVE)
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

    if (lock->state != WOLFSENTRY_LOCK_SHARED) {
        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    }

    --lock->read2write_waiter_count;
    --lock->shared_count;

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_lock_shared2mutex_abstimed(struct wolfsentry_rwlock *lock, struct timespec *abs_timeout) {
    wolfsentry_errcode_t ret;

    /* silently and cheaply tolerate repeat calls to _shared2mutex*(). */
    if (lock->state == WOLFSENTRY_LOCK_EXCLUSIVE)
        WOLFSENTRY_RETURN_OK;

    if (abs_timeout == NULL) {
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
    ++lock->write_waiter_count;

    if (sem_post(&lock->sem) < 0)
        WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);

    if (sem_timedwait(&lock->sem_read2write_waiters, abs_timeout) < 0) {
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
            WOLFSENTRY_RETURN_OK;
        }

        --lock->read2write_waiter_count;
        --lock->write_waiter_count;

        if (sem_post(&lock->sem) < 0)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FATAL);
        else
            WOLFSENTRY_RETURN_OK;
    }

    WOLFSENTRY_RETURN_OK;
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
        return wolfsentry_lock_shared2mutex_abstimed(lock, &abs_timeout);
    } else
        return wolfsentry_lock_shared2mutex_abstimed(lock, NULL);
}

wolfsentry_errcode_t wolfsentry_lock_have_shared(struct wolfsentry_rwlock *lock) {
    /* when error-checking, return NOT_PERMITTED when lock is held but not by caller. */

    if (lock->state == WOLFSENTRY_LOCK_SHARED)
        WOLFSENTRY_RETURN_OK;
    else
        WOLFSENTRY_ERROR_RETURN(NOT_OK);
}

wolfsentry_errcode_t wolfsentry_lock_have_mutex(struct wolfsentry_rwlock *lock) {
    /* when error-checking, return NOT_PERMITTED when lock is held but not by caller. */

    if (lock->state == WOLFSENTRY_LOCK_EXCLUSIVE)
        WOLFSENTRY_RETURN_OK;
    else
        WOLFSENTRY_ERROR_RETURN(NOT_OK);
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
        else if ((lock->shared_count == 1) && (lock->read2write_waiter_count > 0)) {
            lock->shared_count = 0;
            --lock->read2write_waiter_count;
            --lock->write_waiter_count;
            lock->state = WOLFSENTRY_LOCK_EXCLUSIVE;
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
            lock->state = WOLFSENTRY_LOCK_EXCLUSIVE;
            if (sem_post(&lock->sem_write_waiters) < 0) {
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
                goto out;
            }
        }
    } else if (lock->read_waiter_count > 0) {
        int i;
        lock->shared_count = lock->read_waiter_count;
        lock->read_waiter_count = 0;
        lock->state = WOLFSENTRY_LOCK_SHARED;
        for (i = 0; i < lock->shared_count; ++i) {
            if (sem_post(&lock->sem_read_waiters) < 0) {
                ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
                goto out;
            }
        }
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
    return wolfsentry_lock_shared_abstimed(&wolfsentry->lock, abs_timeout);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared_timed(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_time_t max_wait) {
    return wolfsentry_lock_shared_timed(wolfsentry, &wolfsentry->lock, max_wait);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared_and_reserve_shared2mutex(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_shared_and_reserve_shared2mutex(&wolfsentry->lock);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared_abstimed_and_reserve_shared2mutex(
    struct wolfsentry_context *wolfsentry,
    struct timespec *abs_timeout) {
    return wolfsentry_lock_shared_abstimed_and_reserve_shared2mutex(&wolfsentry->lock, abs_timeout);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared_timed_and_reserve_shared2mutex(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_time_t max_wait) {
    return wolfsentry_lock_shared_timed_and_reserve_shared2mutex(wolfsentry, &wolfsentry->lock, max_wait);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_shared2mutex(&wolfsentry->lock);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_abstimed(
    struct wolfsentry_context *wolfsentry,
    struct timespec *abs_timeout) {
    return wolfsentry_lock_shared2mutex_abstimed(&wolfsentry->lock, abs_timeout);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_timed(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_time_t max_wait) {
    return wolfsentry_lock_shared2mutex_timed(wolfsentry, &wolfsentry->lock, max_wait);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_reserve(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_shared2mutex_reserve(&wolfsentry->lock);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_redeem(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_shared2mutex_redeem(&wolfsentry->lock);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_redeem_abstimed(
    struct wolfsentry_context *wolfsentry,
    struct timespec *abs_timeout) {
    return wolfsentry_lock_shared2mutex_redeem_abstimed(&wolfsentry->lock, abs_timeout);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_redeem_timed(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_time_t max_wait) {
    return wolfsentry_lock_shared2mutex_redeem_timed(wolfsentry, &wolfsentry->lock, max_wait);
}

wolfsentry_errcode_t wolfsentry_context_lock_shared2mutex_abandon(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_shared2mutex_abandon(&wolfsentry->lock);
}

wolfsentry_errcode_t wolfsentry_context_lock_mutex(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_mutex(&wolfsentry->lock);
}

wolfsentry_errcode_t wolfsentry_context_lock_mutex_abstimed(
    struct wolfsentry_context *wolfsentry,
    struct timespec *abs_timeout) {
    return wolfsentry_lock_mutex_abstimed(&wolfsentry->lock, abs_timeout);
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

wolfsentry_errcode_t wolfsentry_context_lock_mutex2shared_and_reserve_shared2mutex(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_mutex2shared_and_reserve_shared2mutex(&wolfsentry->lock);
}

wolfsentry_errcode_t wolfsentry_context_unlock(
    struct wolfsentry_context *wolfsentry) {
    return wolfsentry_lock_unlock(&wolfsentry->lock);
}

#endif /* WOLFSENTRY_THREADSAFE */

#ifdef WOLFSENTRY_CLOCK_BUILTINS

#ifdef FREERTOS

#include <FreeRTOS.h>
#include <task.h>

static wolfsentry_errcode_t wolfsentry_builtin_get_time(void *context, wolfsentry_time_t *now) {
    TimeOut_t xCurrentTime = { 0 };
    uint64_t ullTickCount = 0;
    vTaskSetTimeOutState(&xCurrentTime);
    ullTickCount = (uint64_t)(xCurrentTime.xOverflowCount) << (sizeof(TickType_t) * 8);
    ullTickCount += xCurrentTime.xTimeOnEntering;
    *now = ullTickCount * (1000000000LL / configTICK_RATE_HZ);
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
void wolfsentry_free_aligned(struct wolfsentry_context *wolfsentry, void *ptr) {
    if (ptr && wolfsentry->allocator.free_aligned)
        wolfsentry->allocator.free_aligned(wolfsentry->allocator.context, ptr);
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

    if ((allocator->memalign == NULL) ^
        (allocator->free_aligned == NULL))
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

    if ((ret = wolfsentry_lock_init(&(*wolfsentry)->lock, 0 /* pshared */)) < 0)
        goto out;

    (*wolfsentry)->allocator = *allocator;
    (*wolfsentry)->timecbs = *timecbs;

    if ((ret = wolfsentry_eventconfig_load(config, &(*wolfsentry)->config)) < 0)
        goto out;

    (*wolfsentry)->config_at_creation = (*wolfsentry)->config;

    (*wolfsentry)->events.header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_event_key_cmp;
    (*wolfsentry)->events.header.free_fn = (wolfsentry_ent_free_fn_t)wolfsentry_event_drop_reference;
    (*wolfsentry)->events.header.ent_type = WOLFSENTRY_OBJECT_TYPE_EVENT;
    if ((ret = wolfsentry_id_generate(*wolfsentry, WOLFSENTRY_OBJECT_TYPE_TABLE, &(*wolfsentry)->events.header.id)) < 0)
        goto out;
    (*wolfsentry)->actions.header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_action_key_cmp;
    (*wolfsentry)->actions.header.free_fn = (wolfsentry_ent_free_fn_t)wolfsentry_action_drop_reference;
    (*wolfsentry)->actions.header.ent_type = WOLFSENTRY_OBJECT_TYPE_ACTION;
    if ((ret = wolfsentry_id_generate(*wolfsentry, WOLFSENTRY_OBJECT_TYPE_TABLE, &(*wolfsentry)->actions.header.id)) < 0)
        goto out;
    (*wolfsentry)->routes_static.header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_route_key_cmp;
    (*wolfsentry)->routes_dynamic.header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_route_key_cmp;
    (*wolfsentry)->routes_static.header.free_fn = (wolfsentry_ent_free_fn_t)wolfsentry_route_drop_reference;
    (*wolfsentry)->routes_dynamic.header.free_fn = (wolfsentry_ent_free_fn_t)wolfsentry_route_drop_reference;
    (*wolfsentry)->routes_static.header.ent_type = WOLFSENTRY_OBJECT_TYPE_ROUTE;
    (*wolfsentry)->routes_dynamic.header.ent_type = WOLFSENTRY_OBJECT_TYPE_ROUTE;
    if ((ret = wolfsentry_id_generate(*wolfsentry, WOLFSENTRY_OBJECT_TYPE_TABLE, &(*wolfsentry)->routes_static.header.id)) < 0)
        goto out;
    if ((ret = wolfsentry_id_generate(*wolfsentry, WOLFSENTRY_OBJECT_TYPE_TABLE, &(*wolfsentry)->routes_dynamic.header.id)) < 0)
        goto out;

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    if (ret < 0)
        allocator->free(allocator->context, *wolfsentry);

    return ret;
}

wolfsentry_errcode_t wolfsentry_context_flush(struct wolfsentry_context *wolfsentry) {
    wolfsentry_errcode_t ret;

    if ((ret = wolfsentry_route_flush_table(wolfsentry, &wolfsentry->routes_static)) < 0)
        return ret;

    if ((ret = wolfsentry_route_flush_table(wolfsentry, &wolfsentry->routes_dynamic)) < 0)
        return ret;

    if ((ret = wolfsentry_table_free_ents(wolfsentry, &wolfsentry->events.header)) < 0)
        return ret;

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_context_free(struct wolfsentry_context **wolfsentry) {
    wolfsentry_free_cb_t free_cb = (*wolfsentry)->allocator.free;
    wolfsentry_errcode_t ret;
    if ((ret = wolfsentry_table_free_ents(*wolfsentry, &(*wolfsentry)->routes_static.header)) < 0)
        return ret;
    if ((ret = wolfsentry_table_free_ents(*wolfsentry, &(*wolfsentry)->routes_dynamic.header)) < 0)
        return ret;
    if ((ret = wolfsentry_table_free_ents(*wolfsentry, &(*wolfsentry)->actions.header)) < 0)
        return ret;
    if ((ret = wolfsentry_table_free_ents(*wolfsentry, &(*wolfsentry)->events.header)) < 0)
        return ret;

    if ((ret = wolfsentry_lock_destroy(&(*wolfsentry)->lock)) < 0)
        return ret;

    free_cb((*wolfsentry)->allocator.context, *wolfsentry);
    *wolfsentry = NULL;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_shutdown(struct wolfsentry_context **wolfsentry) {
    return wolfsentry_context_free(wolfsentry);
}

wolfsentry_errcode_t wolfsentry_context_inhibit_actions(struct wolfsentry_context *wolfsentry) {
    wolfsentry_eventconfig_flags_t flags_before, flags_after;
    WOLFSENTRY_ATOMIC_UPDATE(
        wolfsentry->config.config.flags,
        (wolfsentry_eventconfig_flags_t)WOLFSENTRY_EVENTCONFIG_FLAG_INHIBIT_ACTIONS,
        (wolfsentry_eventconfig_flags_t)WOLFSENTRY_EVENTCONFIG_FLAG_NONE,
        &flags_before,
        &flags_after);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_context_enable_actions(struct wolfsentry_context *wolfsentry) {
    wolfsentry_eventconfig_flags_t flags_before, flags_after;
    WOLFSENTRY_ATOMIC_UPDATE(
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

    if ((*clone = (struct wolfsentry_context *)WOLFSENTRY_MALLOC(sizeof **clone)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    memset(*clone, 0, sizeof **clone);

    **clone = *wolfsentry;

    if ((ret = wolfsentry_lock_init(&wolfsentry->lock, 0 /* pshared */)) < 0)
        goto out;

    if (WOLFSENTRY_CHECK_BITS(flags, WOLFSENTRY_CLONE_FLAG_AS_AT_CREATION))
        (*clone)->config = (*clone)->config_at_creation = wolfsentry->config_at_creation;
    else {
        (*clone)->config = wolfsentry->config;
        (*clone)->config_at_creation = wolfsentry->config_at_creation;
    }

    WOLFSENTRY_TABLE_HEADER_RESET((*clone)->events.header);
    WOLFSENTRY_TABLE_HEADER_RESET((*clone)->routes_static.header); /* xxx default_event */
    WOLFSENTRY_TABLE_HEADER_RESET((*clone)->routes_dynamic.header); /* xxx default_event */
    WOLFSENTRY_TABLE_HEADER_RESET((*clone)->ents_by_id);

    if ((ret = wolfsentry_table_clone(wolfsentry, &wolfsentry->actions.header, *clone, &(*clone)->actions.header, wolfsentry_action_clone, flags)) < 0)
        goto out;

    if (WOLFSENTRY_CHECK_BITS(flags, WOLFSENTRY_CLONE_FLAG_AS_AT_CREATION)) {
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        goto out;
    }

    /* event cloning is tricky because events refer to other events by pointer, so a second pass through the table is needed. */
    if ((ret = wolfsentry_table_clone(wolfsentry, &wolfsentry->events.header, *clone, &(*clone)->events.header, wolfsentry_event_clone_bare, flags)) < 0)
        goto out;
    if ((ret = wolfsentry_table_clone_map(wolfsentry, &wolfsentry->events.header, *clone, &(*clone)->events.header, wolfsentry_event_clone_resolve, flags)) < 0)
        goto out;

    if ((ret = wolfsentry_table_clone(wolfsentry, &wolfsentry->routes_static.header, *clone, &(*clone)->routes_static.header, wolfsentry_route_clone, flags)) < 0)
        goto out;
    if ((ret = wolfsentry_table_clone(wolfsentry, &wolfsentry->routes_dynamic.header, *clone, &(*clone)->routes_dynamic.header, wolfsentry_route_clone, flags)) < 0)
        goto out;

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    if ((ret < 0) && (*clone != NULL)) {
        WOLFSENTRY_FREE(*clone);
    }

    return ret;
}

wolfsentry_errcode_t wolfsentry_context_exchange(struct wolfsentry_context *wolfsentry1, struct wolfsentry_context *wolfsentry2) {
    struct wolfsentry_context scratch;

    if ((memcmp(&wolfsentry1->allocator, &wolfsentry2->allocator, sizeof wolfsentry1->allocator)) ||
        (wolfsentry1->mk_id_cb != wolfsentry2->mk_id_cb))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    scratch = *wolfsentry1;

    wolfsentry1->timecbs = wolfsentry2->timecbs;
    wolfsentry1->mk_id_cb_state = wolfsentry2->mk_id_cb_state;
    wolfsentry1->config = wolfsentry2->config;
    wolfsentry1->config_at_creation = wolfsentry2->config_at_creation;
    wolfsentry1->events = wolfsentry2->events;
    wolfsentry1->actions = wolfsentry2->actions;
    wolfsentry1->routes_static = wolfsentry2->routes_static;
    wolfsentry1->routes_dynamic = wolfsentry2->routes_dynamic;
    wolfsentry1->ents_by_id = wolfsentry2->ents_by_id;

    wolfsentry2->timecbs = scratch.timecbs;
    wolfsentry2->mk_id_cb_state = scratch.mk_id_cb_state;
    wolfsentry2->config = scratch.config;
    wolfsentry2->config_at_creation = scratch.config_at_creation;
    wolfsentry2->events = scratch.events;
    wolfsentry2->actions = scratch.actions;
    wolfsentry2->routes_static = scratch.routes_static;
    wolfsentry2->routes_dynamic = scratch.routes_dynamic;
    wolfsentry2->ents_by_id = scratch.ents_by_id;

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_hitcount_t wolfsentry_table_n_inserts(struct wolfsentry_table_header *table) {
    return table->n_inserts;
}

wolfsentry_hitcount_t wolfsentry_table_n_deletes(struct wolfsentry_table_header *table) {
    return table->n_deletes;
}
