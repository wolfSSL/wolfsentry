/*
 * unittests.c
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

#define _GNU_SOURCE

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_USER_BASE
#define WOLFSENTRY_ERROR_ID_UNIT_TEST_FAILURE WOLFSENTRY_ERROR_ID_USER_BASE
#define UNIT_TEST_FAILURE_MSG "failure within unit test"

#ifndef PRIVATE_DATA_SIZE
#define PRIVATE_DATA_SIZE 32
#endif
#ifndef PRIVATE_DATA_ALIGNMENT
#define PRIVATE_DATA_ALIGNMENT 16
#endif

#include "src/wolfsentry_internal.h"

#if (defined(_POSIX_C_SOURCE) || defined(__MACH__)) && !defined(FREERTOS)
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>
#endif

#ifdef WOLFSENTRY_LWIP

#ifndef TEST_LWIP

#define iovec iovec /* inhibit lwIP's definition of struct iovec */
#include "lwip/sockets.h"
#undef iovec

/* supply libc-based implementations of lwip_inet_{ntop,pton}, since we're not
 * currently building/linking any lwIP objects for the unit tests.
 */
#undef inet_ntop
const char *inet_ntop(int af, const void *src,
                             char *dst, socklen_t size);
const char *lwip_inet_ntop(int af, const void *src,
                             char *dst, socklen_t size) {
    return inet_ntop(af, src, dst, size);
}
#undef inet_pton
int inet_pton(int af, const char *src, void *dst);
int lwip_inet_pton(int af, const char *src, void *dst) {
    return inet_pton(af, src, dst);
}

#endif /* !TEST_LWIP */

#elif defined(WOLFSENTRY_NETXDUO)

#include "nxd_bsd.h"
/* undef OK this conflicts with the _OK macros in wolfsentry_errcodes.h */
#undef OK


#else /* !WOLFSENTRY_LWIP */

#include <sys/socket.h>
#include <netinet/in.h>

#endif /* WOLFSENTRY_LWIP */

#include <stdlib.h>
#include <unistd.h>

#ifdef WOLFSENTRY_NO_STDIO
#define printf(...)
#endif

#ifdef WOLFSENTRY_UNITTEST_BENCHMARKS
static inline uint64_t get_intel_cycles(void)
{
    unsigned int lo_c, hi_c;
    __asm__ __volatile__ (
        "cpuid\n\t"
        "rdtsc"
        : "=a"(lo_c), "=d"(hi_c)   /* out */
        : "a"(0)                   /* in */
        : "%ebx", "%ecx");         /* clobber */
    return ((uint64_t)lo_c) | (((uint64_t)hi_c) << 32UL);
}
#endif

#ifdef WOLFSENTRY_THREADSAFE

#include <unistd.h>
#include <pthread.h>

#define WOLFSENTRY_EXIT_ON_FAILURE(...) do { wolfsentry_errcode_t _retval = (__VA_ARGS__); if (_retval < 0) { WOLFSENTRY_WARN("%s: " WOLFSENTRY_ERROR_FMT "\n", #__VA_ARGS__, WOLFSENTRY_ERROR_FMT_ARGS(_retval)); exit(1); }} while(0)
#define WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(expected, ...) do { wolfsentry_errcode_t _retval = (__VA_ARGS__); if (! WOLFSENTRY_ERROR_CODE_IS(_retval, expected)) { WOLFSENTRY_WARN("%s: expected %s but got: " WOLFSENTRY_ERROR_FMT "\n", #__VA_ARGS__, #expected, WOLFSENTRY_ERROR_FMT_ARGS(_retval)); exit(1); }} while(0)
#define WOLFSENTRY_EXIT_UNLESS_EXPECTED_SUCCESS(expected, ...) do { wolfsentry_errcode_t _retval = (__VA_ARGS__); if (! WOLFSENTRY_SUCCESS_CODE_IS(_retval, expected)) { WOLFSENTRY_WARN("%s: expected %s but got: " WOLFSENTRY_ERROR_FMT "\n", #__VA_ARGS__, #expected, WOLFSENTRY_ERROR_FMT_ARGS(_retval)); exit(1); }} while(0)
#define WOLFSENTRY_EXIT_ON_SYSFAILURE(...) do { int _retval = (__VA_ARGS__); if (_retval < 0) { perror(#__VA_ARGS__); exit(1); }} while(0)
#define WOLFSENTRY_EXIT_ON_SYSFALSE(...) do { if (! (__VA_ARGS__)) { perror(#__VA_ARGS__); exit(1); }} while(0)
#define WOLFSENTRY_EXIT_ON_SUCCESS(...) do { if ((__VA_ARGS__) >= 0) { WOLFSENTRY_WARN("%s should have failed, but succeeded.\n", #__VA_ARGS__); exit(1); }} while(0)
#define WOLFSENTRY_EXIT_ON_FALSE(...) do { if (! (__VA_ARGS__)) { WOLFSENTRY_WARN("%s should have been true, but was false.\n", #__VA_ARGS__); exit(1); }} while(0)
#define WOLFSENTRY_EXIT_ON_TRUE(...) do { if (__VA_ARGS__) { WOLFSENTRY_WARN("%s should have been false, but was true.\n", #__VA_ARGS__); exit(1); }} while(0)
#define WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(...) do { int _pthread_ret; if ((_pthread_ret = (__VA_ARGS__)) != 0) { WOLFSENTRY_WARN("%s: %s\n", #__VA_ARGS__, strerror(_pthread_ret)); exit(1); }} while(0)

#else /* !WOLFSENTRY_THREADSAFE */

#define WOLFSENTRY_EXIT_ON_FAILURE(...) do { wolfsentry_errcode_t _retval = (__VA_ARGS__); if (_retval < 0) { WOLFSENTRY_WARN("%s: " WOLFSENTRY_ERROR_FMT "\n", #__VA_ARGS__, WOLFSENTRY_ERROR_FMT_ARGS(_retval)); return 1; }} while(0)
#define WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(expected, ...) do { wolfsentry_errcode_t _retval = (__VA_ARGS__); if (! WOLFSENTRY_ERROR_CODE_IS(_retval, expected)) { WOLFSENTRY_WARN("%s: expected %s but got: " WOLFSENTRY_ERROR_FMT "\n", #expected, #__VA_ARGS__, WOLFSENTRY_ERROR_FMT_ARGS(_retval)); return 1; }} while(0)
#define WOLFSENTRY_EXIT_UNLESS_EXPECTED_SUCCESS(expected, ...) do { wolfsentry_errcode_t _retval = (__VA_ARGS__); if (! WOLFSENTRY_SUCCESS_CODE_IS(_retval, expected)) { WOLFSENTRY_WARN("%s: expected %s but got: " WOLFSENTRY_ERROR_FMT "\n", #expected, #__VA_ARGS__, WOLFSENTRY_ERROR_FMT_ARGS(_retval)); return 1; }} while(0)
#define WOLFSENTRY_EXIT_ON_SYSFAILURE(...) do { int _retval = (__VA_ARGS__); if (_retval < 0) { perror(#__VA_ARGS__); exit(1); }} while(0)
#define WOLFSENTRY_EXIT_ON_SYSFALSE(...) do { if (! (__VA_ARGS__)) { perror(#__VA_ARGS__); exit(1); }} while(0)
#define WOLFSENTRY_EXIT_ON_SUCCESS(...) do { if ((__VA_ARGS__) >= 0) { WOLFSENTRY_WARN("%s should have failed, but succeeded.\n", #__VA_ARGS__); return 1; }} while(0)
#define WOLFSENTRY_EXIT_ON_FALSE(...) do { if (! (__VA_ARGS__)) { WOLFSENTRY_WARN("%s should have been true, but was false.\n", #__VA_ARGS__); return 1; }} while(0)
#define WOLFSENTRY_EXIT_ON_TRUE(...) do { if (__VA_ARGS__) { WOLFSENTRY_WARN("%s should have been false, but was true.\n", #__VA_ARGS__); return 1; }} while(0)

#endif /* WOLFSENTRY_THREADSAFE */

/* If not defined use default allocators */
#ifdef WOLFSENTRY_TEST_HPI

extern struct wolfsentry_host_platform_interface* WOLFSENTRY_TEST_HPI;

#elif defined(WOLFSENTRY_TEST_HPI_POSIX_VANILLA)

static void *my_malloc(WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), size_t size) {
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    return malloc(size);
}
static void my_free(WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), void *ptr) {
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    free(ptr);
    WOLFSENTRY_RETURN_VOID;
}
static void *my_realloc(WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), void *ptr, size_t size) {
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    return realloc(ptr, size);
}
static void *my_memalign(WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), size_t alignment, size_t size) {
    void *ret = 0;
    int eret;
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    eret = posix_memalign(&ret, alignment, size);
    if (eret != 0) {
        errno = eret;
        WOLFSENTRY_RETURN_VALUE(NULL);
    }
    WOLFSENTRY_RETURN_VALUE(ret);
}
static void my_free_aligned(
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(void *context), void *ptr)
{
    (void)context;
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    free(ptr);
    WOLFSENTRY_RETURN_VOID;
}

static const struct wolfsentry_host_platform_interface vanilla_posix_hpi = {
    .caller_build_settings = {
        .version = WOLFSENTRY_VERSION,
        .config = WOLFSENTRY_CONFIG_SIGNATURE
    },
    .allocator = {
        .context = NULL,
        .malloc = my_malloc,
        .free = my_free,
        .realloc = my_realloc,
        .memalign = my_memalign,
        .free_aligned = my_free_aligned
    }
    /* not bothering to test timecbs. */
#ifdef WOLFSENTRY_THREADSAFE
    ,
    .semcbs = {
        .sem_init = sem_init,
        .sem_post = sem_post,
        .sem_wait = sem_wait,
        .sem_timedwait = sem_timedwait,
        .sem_trywait = sem_trywait,
        .sem_destroy = sem_destroy
    }
#endif
};

#define WOLFSENTRY_TEST_HPI (&vanilla_posix_hpi)

#else
#define WOLFSENTRY_TEST_HPI NULL
#endif

#define TEST_SKIP(name) static int name (void) { printf("[  skipping " #name "  ]\n"); return 0; }


#ifdef TEST_INIT

static wolfsentry_errcode_t test_init(void) {
    struct wolfsentry_context *wolfsentry;
#ifdef WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
    struct wolfsentry_eventconfig config = {
        .route_private_data_size = PRIVATE_DATA_SIZE,
        .route_private_data_alignment = PRIVATE_DATA_ALIGNMENT,
        .max_connection_count = 10
    };
#else
    struct wolfsentry_eventconfig config = {
        32,
        0,
        10,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0
    };
#endif
    wolfsentry_errcode_t ret;
    WOLFSENTRY_THREAD_HEADER_CHECKED(WOLFSENTRY_THREAD_FLAG_NONE);

#ifdef WOLFSENTRY_ERROR_STRINGS
    {
        const char *src = wolfsentry_errcode_source_string(WOLFSENTRY_ERROR_ENCODE(UNIT_TEST_FAILURE));
        WOLFSENTRY_EXIT_ON_TRUE(src == NULL);
        WOLFSENTRY_EXIT_ON_FALSE(strcmp(src, __FILE__) == 0);
    }

    {
        const char *errmsg = wolfsentry_errcode_error_string(WOLFSENTRY_ERROR_ENCODE(UNIT_TEST_FAILURE));
        WOLFSENTRY_EXIT_ON_TRUE(errmsg == NULL);
        WOLFSENTRY_EXIT_ON_FALSE(strcmp(errmsg, UNIT_TEST_FAILURE_MSG) == 0);
    }
#endif

    ret = wolfsentry_init(wolfsentry_build_settings,
                          WOLFSENTRY_CONTEXT_ARGS_OUT_EX(WOLFSENTRY_TEST_HPI),
                          &config,
                          &wolfsentry);
    printf("wolfsentry_init() returns " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
    if (ret < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    ret = wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&wolfsentry));
    printf("wolfsentry_shutdown() returns " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));

    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE));

    WOLFSENTRY_ERROR_RERETURN(ret);
}

#endif /* TEST_INIT */

static __attribute_maybe_unused__ wolfsentry_errcode_t my_addr_family_parser(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *addr_text,
    const int addr_text_len,
    byte *addr_internal,
    wolfsentry_addr_bits_t *addr_internal_len)
{
    uint32_t a[3];
    char abuf[32];
    int n_octets, parsed_len = 0, i;

    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;

    if (snprintf(abuf,sizeof abuf,"%.*s",addr_text_len,addr_text) >= (int)sizeof abuf)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
    if ((n_octets = sscanf(abuf,"%o/%o/%o%n",(unsigned int *)&a[0],(unsigned int *)&a[1],(unsigned int *)&a[2],&parsed_len)) < 1)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    if (parsed_len != addr_text_len) {
        if ((n_octets = sscanf(abuf,"%o/%o/%n",(unsigned int *)&a[0],(unsigned int *)&a[1],&parsed_len)) < 1)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    }
    if (parsed_len != addr_text_len) {
        if ((n_octets = sscanf(abuf,"%o/%n",(unsigned int *)&a[0],&parsed_len)) < 1)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    }
    if (parsed_len != addr_text_len)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    for (i = 0; i < n_octets; ++i) {
        if (a[i] > MAX_UINT_OF(byte))
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        addr_internal[i] = (byte)a[i];
    }
    *addr_internal_len = (wolfsentry_addr_bits_t)(n_octets * 8);
    WOLFSENTRY_RETURN_OK;
}

static __attribute_maybe_unused__ wolfsentry_errcode_t my_addr_family_formatter(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const byte *addr_internal,
    const unsigned int addr_internal_len,
    char *addr_text,
    int *addr_text_len)
{
    int out_len;
    int ret;

    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;

    if (addr_internal_len <= 8)
        out_len = snprintf(addr_text, (size_t)*addr_text_len, "%03o/",(unsigned int)addr_internal[0]);
    else if (addr_internal_len <= 16)
        out_len = snprintf(addr_text, (size_t)*addr_text_len, "%03o/%03o/",(unsigned int)addr_internal[0],(unsigned int)addr_internal[1]);
    else
        out_len = snprintf(addr_text, (size_t)*addr_text_len, "%03o/%03o/%03o",(unsigned int)addr_internal[0],(unsigned int)addr_internal[1],(unsigned int)addr_internal[2]);
    if (out_len >= *addr_text_len)
        ret = WOLFSENTRY_ERROR_ENCODE(BUFFER_TOO_SMALL);
    else
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
    *addr_text_len = out_len;
    WOLFSENTRY_ERROR_RERETURN(ret);
}

#ifndef WOLFSENTRY_NO_JSON

#include <wolfsentry/wolfsentry_json.h>

static int test_action_enabled = 1;

static __attribute_maybe_unused__ wolfsentry_errcode_t test_action(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *target_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    const struct wolfsentry_event *parent_event;

    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;

    (void)handler_arg;
    (void)route_table;
    (void)action_results;

    if (! test_action_enabled)
        WOLFSENTRY_RETURN_OK;

    if (rule_route == NULL) {
        printf("null rule_route, target_route=%p\n", (void *)target_route);
        WOLFSENTRY_RETURN_OK;
    }

    parent_event = wolfsentry_route_parent_event(rule_route);
    printf("action callback: target_route=%p  a=\"%s\" parent_event=\"%s\" trigger=\"%s\" t=%u r_id=%u caller_arg=%p\n",
           (void *)target_route,
           wolfsentry_action_get_label(action),
           wolfsentry_event_get_label(parent_event),
           wolfsentry_event_get_label(trigger_event),
           (unsigned)action_type,
           (unsigned int)wolfsentry_get_object_id(rule_route),
           caller_arg);
    WOLFSENTRY_RETURN_OK;
}

static __attribute_maybe_unused__ wolfsentry_errcode_t load_test_action_handlers(WOLFSENTRY_CONTEXT_ARGS_IN) {
    wolfsentry_errcode_t ret;
    ret = wolfsentry_action_insert(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        "handle-insert",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        test_action,
        NULL,
        NULL);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_action_insert(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        "handle-delete",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        test_action,
        NULL,
        NULL);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_action_insert(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        "handle-match",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        test_action,
        NULL,
        NULL);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_action_insert(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        "handle-update",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        test_action,
        NULL,
        NULL);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_action_insert(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        "notify-on-decision",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        test_action,
        NULL,
        NULL);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_action_insert(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        "handle-connect",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        test_action,
        NULL,
        NULL);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_action_insert(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        "handle-connect2",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        test_action,
        NULL,
        NULL);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    WOLFSENTRY_RETURN_OK;
}

static __attribute_maybe_unused__ wolfsentry_errcode_t json_feed_file(WOLFSENTRY_CONTEXT_ARGS_IN, const char *fname, wolfsentry_config_load_flags_t flags, int verbose) {
    wolfsentry_errcode_t ret;
    struct wolfsentry_json_process_state *jps;
    FILE *f = NULL;
    unsigned char buf[512];
    char err_buf[512];
    int fini_ret;

    if (strcmp(fname,"-")) {
        f = fopen(fname, "r");
        if (! f) {
            (void)fprintf(stderr, "fopen(%s): %s\n",fname,strerror(errno));
            WOLFSENTRY_ERROR_RETURN(UNIT_TEST_FAILURE);
        }
    }

    ret = wolfsentry_config_json_init(WOLFSENTRY_CONTEXT_ARGS_OUT, flags, &jps);
    if (ret < 0)
        goto out;

    for (;;) {
        size_t n = fread(buf, 1, sizeof buf, f ? f : stdin);
        if ((n < sizeof buf) && ferror(f)) {
            (void)fprintf(stderr,"fread(%s): %s\n",fname, strerror(errno));
            ret = WOLFSENTRY_ERROR_ENCODE(UNIT_TEST_FAILURE);
            goto out;
        }

        ret = wolfsentry_config_json_feed(jps, buf, n, err_buf, sizeof err_buf);
        if (ret < 0) {
            if (verbose)
                (void)fprintf(stderr, "%.*s\n", (int)sizeof err_buf, err_buf);
            goto out;
        }
        if ((n < sizeof buf) && feof(f))
            break;
    }

  out:

    fini_ret = wolfsentry_config_json_fini(&jps, err_buf, sizeof err_buf);
    if (fini_ret < 0) {
        if (verbose)
            (void)fprintf(stderr, "%.*s\n", (int)sizeof err_buf, err_buf);
    }
    if (WOLFSENTRY_ERROR_CODE_IS(ret, OK))
        ret = fini_ret;
    if (WOLFSENTRY_ERROR_CODE_IS(ret, OK))
        ret = WOLFSENTRY_ERROR_ENCODE(OK);

    if (f)
        fclose(f);

    if ((ret < 0) && verbose)
        (void)fprintf(stderr,"error processing file %s\n",fname);

    WOLFSENTRY_ERROR_RERETURN(ret);
}

#endif /* !WOLFSENTRY_NO_JSON */


#ifdef TEST_LWIP

#ifndef WOLFSENTRY_LWIP
#error TEST_LWIP requires WOLFSENTRY_LWIP
#endif

/* note this code is substantially identical to the demo code in doc/freertos-lwip-app.md */

/* #define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_USER_BASE */
#define WOLFSENTRY_ERROR_ID_USER_APP_ERR0 (WOLFSENTRY_ERROR_ID_USER_BASE-1)

#include <wolfsentry/wolfsentry_json.h>
#include <wolfsentry/wolfsentry_lwip.h>

static struct wolfsentry_context *wolfsentry_lwip_ctx = NULL;

static const struct wolfsentry_eventconfig demo_config = {
#ifdef WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
        .route_private_data_size = 64,
        .route_private_data_alignment = 0,         /* default alignment -- same as sizeof(void *). */
        .max_connection_count = 10,                /* by default, don't allow more than 10 simultaneous connections that match the same route. */
        .derogatory_threshold_for_penaltybox = 4,  /* after 4 derogatory events matching the same route, put the route in penalty box status. */
        .penaltybox_duration = 300,                /* keep routes in penalty box status for 5 minutes.  denominated in seconds when passing to wolfsentry_init(). */
        .route_idle_time_for_purge = 0,            /* 0 to disable -- autopurge doesn't usually make much sense as a default config. */
        .flags = WOLFSENTRY_EVENTCONFIG_FLAG_COMMENDABLE_CLEARS_DEROGATORY, /* automatically clear derogatory count for a route when a commendable event matches the route. */
        .route_flags_to_add_on_insert = 0,
        .route_flags_to_clear_on_insert = 0,
        .action_res_filter_bits_set = 0,
        .action_res_filter_bits_unset = 0,
        .action_res_bits_to_add = 0,
        .action_res_bits_to_clear = 0
#else
        64,
        0,
        10,
        4,
        300,
        0,
        WOLFSENTRY_EVENTCONFIG_FLAG_COMMENDABLE_CLEARS_DEROGATORY,
        0,
        0,
        0,
        0,
        0,
        0
#endif
    };

/* This routine is to be called once by the application before any direct calls
 * to lwIP -- i.e., before lwip_init() or tcpip_init().
 */
static wolfsentry_errcode_t activate_wolfsentry_lwip(const char *json_config, int json_config_len)
{
    wolfsentry_errcode_t ret;
    char err_buf[512]; /* buffer for detailed error messages from
                        * wolfsentry_config_json_oneshot().
                        */

    /* Allocate a thread state struct on the stack.  Note that the final
     * semicolon is supplied by the macro definition, so that in single-threaded
     * application builds this expands to nothing at all.
     */
    WOLFSENTRY_THREAD_HEADER_DECLS

    if (wolfsentry_lwip_ctx != NULL) {
        printf("activate_wolfsentry_lwip() called multiple times.\n");
        WOLFSENTRY_ERROR_RETURN(ALREADY);
    }

#ifdef WOLFSENTRY_ERROR_STRINGS
#if 0
    /* Enable pretty-printing of the app source code filename for
     * WOLFSENTRY_ERROR_FMT/WOLFSENTRY_ERROR_FMT_ARGS().
     */
    ret = WOLFSENTRY_REGISTER_SOURCE();
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
#endif /* 0 */

    /* Enable pretty-printing of an app-specific error code. */
    ret = WOLFSENTRY_REGISTER_ERROR(USER_APP_ERR0, "failure in application code");
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
#endif

    /* Initialize the thread state struct -- this sets the thread ID. */
    WOLFSENTRY_THREAD_HEADER_INIT_CHECKED(WOLFSENTRY_THREAD_FLAG_NONE);

    /* Call the main wolfSentry initialization routine.
     *
     * WOLFSENTRY_CONTEXT_ARGS_OUT() is a macro that abstracts away
     * conditionally passing the thread struct pointer to APIs that need it.  If
     * this is a single-threaded build (!defined(WOLFSENTRY_THREADSAFE)), then
     * the thread arg is omitted entirely.
     *
     * WOLFSENTRY_CONTEXT_ARGS_OUT_EX() is a variant that allows the caller to
     * supply the first arg explicitly, when "wolfsentry" is not the correct arg
     * to pass.  This is used here to pass a null pointer for the host platform
     * interface ("hpi").
     */
    ret = wolfsentry_init(
        wolfsentry_build_settings,
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(NULL /* hpi */),
        &demo_config,
        &wolfsentry_lwip_ctx);
    if (ret < 0) {
        printf("wolfsentry_init() failed: " WOLFSENTRY_ERROR_FMT "\n",
               WOLFSENTRY_ERROR_FMT_ARGS(ret));
        goto out;
    }

    /* Insert user-defined actions here, if any. */
#if 0
    ret = wolfsentry_action_insert(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_lwip_ctx),
        "my-action",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        my_action_handler,
        NULL,
        NULL);
#else
    ret = load_test_action_handlers(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_lwip_ctx));
#endif
    if (ret < 0) {
        printf("wolfsentry_action_insert() failed: " WOLFSENTRY_ERROR_FMT "\n",
               WOLFSENTRY_ERROR_FMT_ARGS(ret));
        goto out;
    }

    if (json_config) {
        if (json_config_len < 0)
            json_config_len = (int)strlen(json_config);

        /* Do the initial load of the policy. */
        ret = wolfsentry_config_json_oneshot(
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_lwip_ctx),
            (unsigned char *)json_config,
            (size_t)json_config_len,
            WOLFSENTRY_CONFIG_LOAD_FLAG_NONE,
            err_buf,
            sizeof err_buf);
        if (ret < 0) {
            printf("wolfsentry_config_json_oneshot() failed: %s\n", err_buf);
            goto out;
        }
    } /* else the application will need to set up the policy programmatically,
       * or itself call wolfsentry_config_json_oneshot() or sibling APIs.
       */

    /* Install lwIP callbacks.  Once this call returns with success, all lwIP
     * traffic designated for filtration by the mask arguments shown below will
     * be subject to filtering (or other supplementary processing) according to
     * the policy loaded above.
     *
     * Note that if a given protocol is gated out of LWIP, its mask argument
     * must be passed as zero here, else the call will return
     * IMPLEMENTATION_MISSING error will occur.
     *
     * The callback installation also registers a cleanup routine that will be
     * called automatically by wolfsentry_shutdown().
     */

#define LWIP_ALL_EVENTS (                       \
        (1U << FILT_BINDING) |                  \
        (1U << FILT_DISSOCIATE) |               \
        (1U << FILT_LISTENING) |                \
        (1U << FILT_STOP_LISTENING) |           \
        (1U << FILT_CONNECTING) |               \
        (1U << FILT_ACCEPTING) |                \
        (1U << FILT_CLOSED) |                   \
        (1U << FILT_REMOTE_RESET) |             \
        (1U << FILT_RECEIVING) |                \
        (1U << FILT_SENDING) |                  \
        (1U << FILT_ADDR_UNREACHABLE) |         \
        (1U << FILT_PORT_UNREACHABLE) |         \
        (1U << FILT_INBOUND_ERR) |              \
        (1U << FILT_OUTBOUND_ERR))

    ret = wolfsentry_install_lwip_filter_callbacks(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_lwip_ctx),

#if LWIP_ARP || LWIP_ETHERNET
        LWIP_ALL_EVENTS, /* ethernet_mask */
#else
        0,
#endif
#if LWIP_IPV4 || LWIP_IPV6
        LWIP_ALL_EVENTS, /* ip_mask */
#else
        0,
#endif
#if LWIP_ICMP || LWIP_ICMP6
        LWIP_ALL_EVENTS, /* icmp_mask */
#else
        0,
#endif
#if LWIP_TCP
        LWIP_ALL_EVENTS, /* tcp_mask */
#else
        0,
#endif
#if LWIP_UDP
        LWIP_ALL_EVENTS /* udp_mask */
#else
        0
#endif
        );
    if (ret < 0) {
        printf("wolfsentry_install_lwip_filter_callbacks: " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
    }

out:
    if (ret < 0) {
        /* Clean up if initialization failed. */
        wolfsentry_errcode_t shutdown_ret = wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&wolfsentry_lwip_ctx));
        if (shutdown_ret < 0)
            printf("wolfsentry_shutdown: " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(shutdown_ret));
    }

    WOLFSENTRY_THREAD_TAILER_CHECKED(WOLFSENTRY_THREAD_FLAG_NONE);

    WOLFSENTRY_ERROR_RERETURN(ret);
}

/* to be called once by the application after any final calls to lwIP. */
static wolfsentry_errcode_t shutdown_wolfsentry_lwip(void)
{
    wolfsentry_errcode_t ret;
    if (wolfsentry_lwip_ctx == NULL) {
        printf("shutdown_wolfsentry_lwip() called before successful activation.\n");
        return -1;
    }

    /* after successful shutdown, wolfsentry_lwip_ctx will once again be a null
     * pointer as it was before init.
     */
    ret = wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(&wolfsentry_lwip_ctx, NULL));
    if (ret < 0) {
        printf("wolfsentry_shutdown: " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
    }

    return ret;
}

#ifdef FREERTOS

static int test_lwip(const char *json_path) {
    static const char *trivial_json = "{ \"wolfsentry-config-version\" : 1 }";

    (void)json_path;
    WOLFSENTRY_EXIT_ON_FAILURE(activate_wolfsentry_lwip(trivial_json, -1));
    WOLFSENTRY_EXIT_ON_FAILURE(shutdown_wolfsentry_lwip());
    return 0;
}

#else /* !FREERTOS */

static int test_lwip(const char *json_path) {
    if (json_path) {
        struct stat st;
        const char *json;
        int fd = open(json_path, O_RDONLY);
        if (fd < 0) {
            perror(json_path);
            exit(1);
        }
        if (fstat(fd, &st) < 0) {
            perror(json_path);
            exit(1);
        }
        json = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
        if (json == MAP_FAILED) {
            perror(json_path);
            exit(1);
        }
        (void)close(fd);
        WOLFSENTRY_EXIT_ON_FAILURE(activate_wolfsentry_lwip(json, (int)st.st_size));
        munmap((void *)json, (size_t)st.st_size);
    } else
        WOLFSENTRY_EXIT_ON_FAILURE(activate_wolfsentry_lwip(NULL, 0));
    WOLFSENTRY_EXIT_ON_FAILURE(shutdown_wolfsentry_lwip());
    return 0;
}

#endif /* !FREERTOS */

#endif /* TEST_LWIP */

#if defined(TEST_RWLOCKS)

#if defined(WOLFSENTRY_THREADSAFE)

#include <signal.h>

struct rwlock_args {
    struct wolfsentry_context *wolfsentry;
    volatile int *measured_sequence;
    volatile int *measured_sequence_i;
    int thread_id;
    struct wolfsentry_rwlock *lock;
    wolfsentry_time_t max_wait;
    pthread_mutex_t thread_phase_lock; /* need to wrap a mutex around thread_phase to blind the thread sanitizer to the spin locks on it. */
    volatile int thread_phase;
};

#define INCREMENT_PHASE(x) do { WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_mutex_lock(&(x)->thread_phase_lock)); ++(x)->thread_phase; WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_mutex_unlock(&(x)->thread_phase_lock)); } while(0)

static void *rd_routine(struct rwlock_args *args) {
    int i;
    WOLFSENTRY_THREAD_HEADER(WOLFSENTRY_THREAD_FLAG_NONE);
    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_GET_ERROR);
    INCREMENT_PHASE(args);
    if (args->max_wait >= 0)
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared_timed(args->lock, thread, args->max_wait, WOLFSENTRY_LOCK_FLAG_NONE));
    else
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared(args->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    INCREMENT_PHASE(args);
    i = WOLFSENTRY_ATOMIC_POSTINCREMENT(*args->measured_sequence_i,1);
    args->measured_sequence[i] = args->thread_id;
    usleep(10000);
    i = WOLFSENTRY_ATOMIC_POSTINCREMENT(*args->measured_sequence_i,1);
    args->measured_sequence[i] = args->thread_id + 4;
    INCREMENT_PHASE(args);
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(args->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    INCREMENT_PHASE(args);
    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE));
    return 0;
}

static void *wr_routine(struct rwlock_args *args) {
    int i;
    WOLFSENTRY_THREAD_HEADER(WOLFSENTRY_THREAD_FLAG_NONE);
    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_GET_ERROR);
    INCREMENT_PHASE(args);
    if (args->max_wait >= 0)
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex_timed(args->lock, thread, args->max_wait, WOLFSENTRY_LOCK_FLAG_NONE));
    else
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex(args->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    INCREMENT_PHASE(args);
    i = WOLFSENTRY_ATOMIC_POSTINCREMENT(*args->measured_sequence_i,1);
    args->measured_sequence[i] = args->thread_id;
    usleep(10000);
    i = WOLFSENTRY_ATOMIC_POSTINCREMENT(*args->measured_sequence_i,1);
    args->measured_sequence[i] = args->thread_id + 4;
    INCREMENT_PHASE(args);
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(args->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    INCREMENT_PHASE(args);
    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE));
    return 0;
}

static void *rd2wr_routine(struct rwlock_args *args) {
    int i;
    WOLFSENTRY_THREAD_HEADER(WOLFSENTRY_THREAD_FLAG_NONE);
    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_GET_ERROR);
    INCREMENT_PHASE(args);
    if (args->max_wait >= 0)
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared_timed(args->lock, thread, args->max_wait, WOLFSENTRY_LOCK_FLAG_NONE));
    else
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared(args->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    i = WOLFSENTRY_ATOMIC_POSTINCREMENT(*args->measured_sequence_i,1);
    args->measured_sequence[i] = args->thread_id;
    INCREMENT_PHASE(args);
    if (args->max_wait >= 0)
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared2mutex_timed(args->lock, thread, args->max_wait, WOLFSENTRY_LOCK_FLAG_NONE));
    else
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared2mutex(args->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    INCREMENT_PHASE(args);
    i = WOLFSENTRY_ATOMIC_POSTINCREMENT(*args->measured_sequence_i,1);
    args->measured_sequence[i] = args->thread_id + 4;
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(args->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    INCREMENT_PHASE(args);
    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE));
    return 0;
}

static void *rd2wr_reserved_routine(struct rwlock_args *args) {
    int i;
    WOLFSENTRY_THREAD_HEADER(WOLFSENTRY_THREAD_FLAG_NONE);
    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_GET_ERROR);
    INCREMENT_PHASE(args);
    if (args->max_wait >= 0)
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared_timed(args->lock, thread, args->max_wait, WOLFSENTRY_LOCK_FLAG_NONE));
    else
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared(args->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE)); // GCOV_EXCL_LINE
    i = WOLFSENTRY_ATOMIC_POSTINCREMENT(*args->measured_sequence_i,1);
    args->measured_sequence[i] = args->thread_id;

    INCREMENT_PHASE(args);
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared2mutex_reserve(args->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    INCREMENT_PHASE(args);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared2mutex_redeem(args->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));


    INCREMENT_PHASE(args);

    i = WOLFSENTRY_ATOMIC_POSTINCREMENT(*args->measured_sequence_i,1);
    args->measured_sequence[i] = args->thread_id + 4;
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(args->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    INCREMENT_PHASE(args);
    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE));
    return 0;
}

#define MAX_WAIT 100000
#define WAIT_FOR_PHASE(x, atleast) do { int cur_phase; WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_mutex_lock(&(x).thread_phase_lock)); cur_phase = (x).thread_phase; WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_mutex_unlock(&(x).thread_phase_lock)); if (cur_phase >= (atleast)) break; usleep(1000); } while(1)

static int test_rw_locks(void) {
    struct wolfsentry_context *wolfsentry;
    struct wolfsentry_rwlock *lock;
#ifdef WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
    struct wolfsentry_eventconfig config = { .route_private_data_size = PRIVATE_DATA_SIZE, .route_private_data_alignment = PRIVATE_DATA_ALIGNMENT, .max_connection_count = 10 };
#else
    struct wolfsentry_eventconfig config = { 32, 0, 10, 0, 0, 0, 0, 0, 0 };
#endif

    volatile int measured_sequence[8], measured_sequence_i = 0;
    int measured_sequence_transposed[8];

    pthread_t thread1, thread2, thread3, thread4;
    struct rwlock_args thread1_args, thread2_args, thread3_args, thread4_args;

    WOLFSENTRY_THREAD_HEADER_CHECKED(WOLFSENTRY_THREAD_FLAG_NONE);

    (void)alarm(1);

#ifdef WOLFSENTRY_LOCK_SHARED_ERROR_CHECKING
#define test_rw_locks_WOLFSENTRY_INIT_FLAGS WOLFSENTRY_INIT_FLAG_LOCK_SHARED_ERROR_CHECKING
#define test_rw_locks_WOLFSENTRY_LOCK_FLAGS WOLFSENTRY_LOCK_FLAG_SHARED_ERROR_CHECKING
#else
#define test_rw_locks_WOLFSENTRY_INIT_FLAGS WOLFSENTRY_INIT_FLAG_NONE
#define test_rw_locks_WOLFSENTRY_LOCK_FLAGS WOLFSENTRY_LOCK_FLAG_NONE
#endif

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_init_ex(wolfsentry_build_settings,
                                                  WOLFSENTRY_TEST_HPI,
                                                  thread,
                                                  &config,
                                                  &wolfsentry,
                                                  test_rw_locks_WOLFSENTRY_INIT_FLAGS
                                   ));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_alloc(wolfsentry_get_hpi(wolfsentry), thread, &lock,
                                                     test_rw_locks_WOLFSENTRY_LOCK_FLAGS
                                   ));

    {
        struct wolfsentry_thread_context_public uninited_thread_buffer =
            WOLFSENTRY_THREAD_CONTEXT_PUBLIC_INITIALIZER;
        struct wolfsentry_thread_context *uninited_thread =
            (struct wolfsentry_thread_context *)&uninited_thread_buffer;
        wolfsentry_thread_flags_t thread_flags;
        wolfsentry_thread_id_t thread_id;
        struct wolfsentry_thread_context *null_thread = NULL;
        struct wolfsentry_rwlock *null_lock = NULL;
        wolfsentry_lock_flags_t lock_flags;
#define TEST_INVALID_ARGS(x) WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(INVALID_ARG, x)
        TEST_INVALID_ARGS(wolfsentry_get_thread_id(NULL, NULL));
        TEST_INVALID_ARGS(wolfsentry_get_thread_id(uninited_thread, NULL));
        TEST_INVALID_ARGS(wolfsentry_get_thread_id(uninited_thread, &thread_id));
        TEST_INVALID_ARGS(wolfsentry_get_thread_id(thread, NULL));
        TEST_INVALID_ARGS(wolfsentry_get_thread_flags(null_thread, NULL));
        TEST_INVALID_ARGS(wolfsentry_get_thread_flags(uninited_thread, NULL));
        TEST_INVALID_ARGS(wolfsentry_get_thread_flags(uninited_thread, &thread_flags));
        TEST_INVALID_ARGS(wolfsentry_get_thread_flags(thread, NULL));
        TEST_INVALID_ARGS(wolfsentry_destroy_thread_context(null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_destroy_thread_context(uninited_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_free_thread_context(NULL, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_free_thread_context(NULL, &null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_free_thread_context(NULL, &uninited_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_set_deadline_rel(wolfsentry, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_set_deadline_rel(wolfsentry, uninited_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_set_deadline_rel_usecs(wolfsentry, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_set_deadline_rel_usecs(wolfsentry, uninited_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_set_deadline_abs(wolfsentry, null_thread, 0, 0));
        TEST_INVALID_ARGS(wolfsentry_set_deadline_abs(wolfsentry, uninited_thread, 0, 0));
        TEST_INVALID_ARGS(wolfsentry_get_deadline_rel(wolfsentry, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_get_deadline_rel(wolfsentry, uninited_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_get_deadline_rel_usecs(wolfsentry, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_get_deadline_rel_usecs(wolfsentry, uninited_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_clear_deadline(wolfsentry, null_thread));
        TEST_INVALID_ARGS(wolfsentry_clear_deadline(wolfsentry, uninited_thread));
        TEST_INVALID_ARGS(wolfsentry_set_thread_readonly(null_thread));
        TEST_INVALID_ARGS(wolfsentry_set_thread_readonly(uninited_thread));
        TEST_INVALID_ARGS(wolfsentry_set_thread_readwrite(null_thread));
        TEST_INVALID_ARGS(wolfsentry_set_thread_readwrite(uninited_thread));
        TEST_INVALID_ARGS(wolfsentry_lock_init(NULL, null_thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_init(NULL, uninited_thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_init(NULL, uninited_thread, lock, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_alloc(NULL, null_thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_alloc(NULL, uninited_thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_alloc(NULL, uninited_thread, &lock, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_destroy(NULL, thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_free(NULL, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_free(&null_lock, thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared_abstimed(null_lock, null_thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared_abstimed(lock, null_thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared_abstimed(null_lock, thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared_timed(null_lock, null_thread, 0, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared_timed(lock, null_thread, 0, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared_timed(null_lock, thread, 0, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared(null_lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared(lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared(null_lock, thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_mutex_abstimed(null_lock, null_thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_mutex_abstimed(null_lock, thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_mutex_timed(null_lock, null_thread, 0, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_mutex_timed(null_lock, thread, 0, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_mutex(null_lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_mutex(null_lock, thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_mutex2shared(null_lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_mutex2shared(lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_mutex2shared(null_lock, thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_reserve(null_lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_reserve(lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_reserve(null_lock, thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_redeem_abstimed(null_lock, null_thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_redeem_abstimed(lock, null_thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_redeem_abstimed(null_lock, thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_redeem_timed(null_lock, null_thread, 0, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_redeem_timed(lock, null_thread, 0, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_redeem_timed(null_lock, thread, 0, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_redeem(null_lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_redeem(lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_redeem(null_lock, thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_abandon(null_lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_abandon(lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_abandon(null_lock, thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_abstimed(null_lock, null_thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_abstimed(lock, null_thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_abstimed(null_lock, thread, NULL, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_timed(null_lock, null_thread, 0, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_timed(lock, null_thread, 0, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex_timed(null_lock, thread, 0, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex(null_lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex(lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_shared2mutex(null_lock, thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_unlock(null_lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_unlock(null_lock, thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_have_shared(null_lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_have_shared(lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_have_shared(null_lock, thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_have_mutex(null_lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_have_mutex(null_lock, thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_have_either(null_lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_have_either(null_lock, thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_have_shared2mutex_reservation(null_lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_have_shared2mutex_reservation(lock, null_thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_have_shared2mutex_reservation(null_lock, thread, 0));
        TEST_INVALID_ARGS(wolfsentry_lock_get_flags(null_lock, null_thread, &lock_flags));
        TEST_INVALID_ARGS(wolfsentry_lock_get_flags(null_lock, thread, &lock_flags));
        TEST_INVALID_ARGS(wolfsentry_lock_get_flags(lock, thread, NULL));
    }

    {
        long usecs = -1;
        wolfsentry_time_t t = (wolfsentry_time_t)(-1);
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_set_deadline_rel_usecs(WOLFSENTRY_CONTEXT_ARGS_OUT, 0));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_get_deadline_rel(WOLFSENTRY_CONTEXT_ARGS_OUT, &t));
        WOLFSENTRY_EXIT_ON_FALSE(t == 0);
        WOLFSENTRY_EXIT_UNLESS_EXPECTED_SUCCESS(NO_WAITING, wolfsentry_get_deadline_rel_usecs(WOLFSENTRY_CONTEXT_ARGS_OUT, &usecs));
        WOLFSENTRY_EXIT_ON_FALSE(usecs == 0);
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_clear_deadline(WOLFSENTRY_CONTEXT_ARGS_OUT));
        WOLFSENTRY_EXIT_UNLESS_EXPECTED_SUCCESS(NO_DEADLINE, wolfsentry_get_deadline_rel_usecs(WOLFSENTRY_CONTEXT_ARGS_OUT, &usecs));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_set_deadline_rel_usecs(WOLFSENTRY_CONTEXT_ARGS_OUT, 1000000));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_get_deadline_rel_usecs(WOLFSENTRY_CONTEXT_ARGS_OUT, &usecs));
        WOLFSENTRY_EXIT_ON_FALSE(usecs > 100000 && usecs <= 1000000);
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_clear_deadline(WOLFSENTRY_CONTEXT_ARGS_OUT));
    }

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_set_thread_readonly(thread));
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(NOT_PERMITTED, wolfsentry_lock_mutex_timed(lock, thread, 0, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_set_thread_readwrite(thread));

    memset(&thread1_args, 0, sizeof thread1_args);
    thread1_args.wolfsentry = wolfsentry;
    thread1_args.measured_sequence = measured_sequence;
    thread1_args.measured_sequence_i = &measured_sequence_i;
    thread1_args.lock = lock;
    thread1_args.max_wait = -1;
    thread2_args = thread3_args = thread4_args = thread1_args;

    thread1_args.thread_id = 1;
    thread2_args.thread_id = 2;
    thread3_args.thread_id = 3;
    thread4_args.thread_id = 4;

    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_mutex_init(&thread1_args.thread_phase_lock, NULL));
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_mutex_init(&thread2_args.thread_phase_lock, NULL));
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_mutex_init(&thread3_args.thread_phase_lock, NULL));
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_mutex_init(&thread4_args.thread_phase_lock, NULL));


    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex_timed(lock, thread, 0, WOLFSENTRY_LOCK_FLAG_NONE));

    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread1, 0 /* attr */, (void *(*)(void *))rd_routine, (void *)&thread1_args));
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread2, 0 /* attr */, (void *(*)(void *))rd_routine, (void *)&thread2_args));
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread3, 0 /* attr */, (void *(*)(void *))wr_routine, (void *)&thread3_args));

    /* go to a lot of trouble to make sure thread 3 has entered _lock_mutex() wait. */
    WAIT_FOR_PHASE(thread3_args, 1);
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_kill(thread3, 0));
    usleep(10000);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread1, 0 /* retval */));

    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread4, 0 /* attr */, (void *(*)(void *))wr_routine, (void *)&thread4_args));
usleep(10000);
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread4, 0 /* retval */));

    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread2, 0 /* retval */));
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread3, 0 /* retval */));

    /* the first write-locking thread must get the lock first after the parent unlocks,
     * because write lock requests have priority over read lock requests all else equal.
     * the second write-locking thread must get the lock last, because it is launched
     * after the first read lock thread has returned.  there is a race between the other read-locking thread
     * launching and the first write locking thread completing, but the usleep(10000) before the
     * parent unlock relaxes that race.  there is a second race between the first read-locking
     * thread returning and the other read-locking thread activating its read lock -- the second
     * write-locking thread can beat it by getting lock->sem first.  this race is relaxed with the
     * usleep(10000) in rd_routine().  the usleep(10000) in wr_routine() is just to catch lock
     * violations in the measured_sequence.
     *
     * the sequence of the two read-locking threads, sandwiched between the write-locking threads,
     * is undefined, and experimentally does vary.
     *
     */

    if ((measured_sequence[0] != 3) ||
        (measured_sequence[6] != 4) ||
        (measured_sequence[1] != 7) ||
        (measured_sequence[7] != 8)) {
    // GCOV_EXCL_START
        size_t i;
        (void)fprintf(stderr,"wrong sequence at L%d.  should be {3,7,1,2,5,6,4,8} (the middle 4 are safely permutable), but got {", __LINE__);
        for (i = 0; i < sizeof measured_sequence / sizeof measured_sequence[0]; ++i)
            (void)fprintf(stderr,"%d%s",measured_sequence[i], i == (sizeof measured_sequence / sizeof measured_sequence[0]) - 1 ? "}.\n" : ",");
        WOLFSENTRY_ERROR_RETURN(NOT_OK);
    // GCOV_EXCL_STOP
    }

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_destroy(lock, thread, test_rw_locks_WOLFSENTRY_LOCK_FLAGS));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_init(wolfsentry_get_hpi(wolfsentry), thread, lock,
                                                    test_rw_locks_WOLFSENTRY_LOCK_FLAGS));

    /* now a scenario with shared2mutex and mutex2shared in the mix: */

    thread1_args.thread_phase = thread2_args.thread_phase = thread3_args.thread_phase = thread4_args.thread_phase = 0;

    measured_sequence_i = 0;

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    thread1_args.max_wait = MAX_WAIT; /* builtin wolfsentry_time_t is microseconds, same as usleep(). */
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread1, 0 /* attr */, (void *(*)(void *))rd_routine, (void *)&thread1_args));

    WAIT_FOR_PHASE(thread1_args, 1);
    thread2_args.max_wait = MAX_WAIT;
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread2, 0 /* attr */, (void *(*)(void *))rd2wr_routine, (void *)&thread2_args));

    WAIT_FOR_PHASE(thread2_args, 1);

    /* this transition advances thread1 and thread2 to both hold shared locks.
     * non-negligible chance that thread2 goes into shared2mutex wait before
     * thread1 can get a shared lock.
     */
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex2shared(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    WAIT_FOR_PHASE(thread2_args, 2);

    /* this thread has to wait until thread2 is done with its shared2mutex sequence. */

/* constraint: thread2 must unlock (6) before thread3 locks (3) */
/* constraint: thread3 lock-unlock (3, 7) must be adjacent */
    thread3_args.max_wait = MAX_WAIT;
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread3, 0 /* attr */, (void *(*)(void *))wr_routine, (void *)&thread3_args));

    WAIT_FOR_PHASE(thread3_args, 1);

    while (WOLFSENTRY_SUCCESS_CODE_IS(wolfsentry_lock_shared2mutex_is_reserved(lock, thread, 0), NO))
        usleep(10000);

    /* this one must fail, because at this point thread2 must be in shared2mutex wait. */
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(BUSY, wolfsentry_lock_shared2mutex(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    /* take the opportunity to test expected failures of the _timed() variants. */
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(BUSY, wolfsentry_lock_mutex_timed(lock, thread, 0, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(BUSY, wolfsentry_lock_mutex_timed(lock, thread, 1000, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(TIMED_OUT, wolfsentry_lock_mutex_timed(lock, NULL /* thread */, 1000, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(INVALID_ARG, wolfsentry_lock_shared_timed(lock, NULL /* thread */, 0, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(ALREADY, wolfsentry_lock_shared_timed(lock, thread, 0, WOLFSENTRY_LOCK_FLAG_NONRECURSIVE_SHARED));
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(ALREADY, wolfsentry_lock_shared_timed(lock, thread, 1000, WOLFSENTRY_LOCK_FLAG_NONRECURSIVE_SHARED));

    /* this unlock allows thread2 to finally get its mutex. */
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread1, 0 /* retval */));

/* constraint: thread2 must unlock (6) before thread4 locks (4) */
/* constraint: thread4 lock-unlock (4, 8) must be adjacent */
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread4, 0 /* attr */, (void *(*)(void *))wr_routine, (void *)&thread4_args));
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread4, 0 /* retval */));

    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread2, 0 /* retval */));
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread3, 0 /* retval */));

    {
        int i;
        for (i=0; i<8; ++i)
            measured_sequence_transposed[measured_sequence[i] - 1] = i + 1;
    }
#define SEQ(x) measured_sequence_transposed[(x)-1]
    if ((SEQ(6) > SEQ(3)) ||
        (SEQ(7) - SEQ(3) != 1) ||
        (SEQ(6) > SEQ(4)) ||
        (SEQ(8) - SEQ(4) != 1)) {
    // GCOV_EXCL_START
        size_t i;
        (void)fprintf(stderr,"wrong sequence at L%d.  got {", __LINE__);
        for (i = 0; i < sizeof measured_sequence / sizeof measured_sequence[0]; ++i)
            (void)fprintf(stderr,"%d%s",measured_sequence[i], i == (sizeof measured_sequence / sizeof measured_sequence[0]) - 1 ? "}.\n" : ",");
        WOLFSENTRY_ERROR_RETURN(NOT_OK);
    // GCOV_EXCL_STOP
    }


    /* again, using shared2mutex reservation: */

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_destroy(lock, thread, test_rw_locks_WOLFSENTRY_LOCK_FLAGS));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_init(wolfsentry_get_hpi(wolfsentry), thread, lock,
                                                    test_rw_locks_WOLFSENTRY_LOCK_FLAGS));

    thread1_args.thread_phase = thread2_args.thread_phase = thread3_args.thread_phase = thread4_args.thread_phase = 0;

    measured_sequence_i = 0;

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared2mutex(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(ALREADY, wolfsentry_lock_shared2mutex_reserve(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(ALREADY, wolfsentry_lock_shared2mutex_redeem(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(INCOMPATIBLE_STATE, wolfsentry_lock_shared2mutex_abandon(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    thread1_args.max_wait = MAX_WAIT; /* builtin wolfsentry_time_t is microseconds, same as usleep(). */
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread1, 0 /* attr */, (void *(*)(void *))rd_routine, (void *)&thread1_args));

    WAIT_FOR_PHASE(thread1_args, 1);

    thread2_args.max_wait = MAX_WAIT;
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread2, 0 /* attr */, (void *(*)(void *))rd2wr_reserved_routine, (void *)&thread2_args));

    WAIT_FOR_PHASE(thread2_args, 1);

    /* this transition advances thread1 and thread2 to both hold shared locks.
     * non-negligible chance that thread2 goes into shared2mutex wait before
     * thread1 can get a shared lock.
     */
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex2shared(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    WAIT_FOR_PHASE(thread2_args, 3);

    /* this thread has to wait until thread2 is done with its shared2mutex sequence. */

/* constraint: thread2 must unlock (6) before thread3 locks (3) */
/* constraint: thread3 lock-unlock (3, 7) must be adjacent */
    thread3_args.max_wait = MAX_WAIT;
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread3, 0 /* attr */, (void *(*)(void *))wr_routine, (void *)&thread3_args));

    WAIT_FOR_PHASE(thread3_args, 1);

    /* this one must fail, because at this point thread2 must be in shared2mutex wait. */
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(BUSY, wolfsentry_lock_shared2mutex(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    /* take the opportunity to test expected failures of the _timed() variants. */
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(BUSY, wolfsentry_lock_mutex_timed(lock, thread, 0, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(BUSY, wolfsentry_lock_mutex_timed(lock, thread, 1000, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(TIMED_OUT, wolfsentry_lock_mutex_timed(lock, NULL /* thread */, 1000, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(ALREADY, wolfsentry_lock_shared_timed(lock, thread, 0, WOLFSENTRY_LOCK_FLAG_NONRECURSIVE_SHARED));
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(ALREADY, wolfsentry_lock_shared_timed(lock, thread, 1000, WOLFSENTRY_LOCK_FLAG_NONRECURSIVE_SHARED));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_have_shared(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(LACKING_MUTEX, wolfsentry_lock_have_mutex(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    /* this unlock allows thread2 to finally get its mutex. */
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread1, 0 /* retval */));

/* constraint: thread2 must unlock (6) before thread4 locks (4) */
/* constraint: thread4 lock-unlock (4, 8) must be adjacent */
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread4, 0 /* attr */, (void *(*)(void *))wr_routine, (void *)&thread4_args));
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread4, 0 /* retval */));

    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread2, 0 /* retval */));
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread3, 0 /* retval */));

    {
        int i;
        for (i=0; i<8; ++i)
            measured_sequence_transposed[measured_sequence[i] - 1] = i + 1;
    }
#define SEQ(x) measured_sequence_transposed[(x)-1]
    if ((SEQ(6) > SEQ(3)) ||
        (SEQ(7) - SEQ(3) != 1) ||
        (SEQ(6) > SEQ(4)) ||
        (SEQ(8) - SEQ(4) != 1)) {
    // GCOV_EXCL_START
        size_t i;
        (void)fprintf(stderr,"wrong sequence at L%d.  got {", __LINE__);
        for (i = 0; i < sizeof measured_sequence / sizeof measured_sequence[0]; ++i)
            (void)fprintf(stderr,"%d%s",measured_sequence[i], i == (sizeof measured_sequence / sizeof measured_sequence[0]) - 1 ? "}.\n" : ",");
        WOLFSENTRY_ERROR_RETURN(NOT_OK);
    // GCOV_EXCL_STOP
    }

    /* cursory exercise of compound reservation calls. */

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_destroy(lock, thread, test_rw_locks_WOLFSENTRY_LOCK_FLAGS));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_init(wolfsentry_get_hpi(wolfsentry), thread, lock,
                                                    test_rw_locks_WOLFSENTRY_LOCK_FLAGS));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex2shared(lock, thread, WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared2mutex_redeem(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared(lock, thread, WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared2mutex_redeem(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared_timed(lock, thread, 1000, WOLFSENTRY_LOCK_FLAG_GET_RESERVATION_TOO));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared2mutex_redeem_timed(lock, thread, 1000, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    /* cursory exercise of null thread calls. */
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_destroy(lock, NULL /* thread */, test_rw_locks_WOLFSENTRY_LOCK_FLAGS));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_init(wolfsentry_get_hpi(wolfsentry), NULL /* thread */, lock,
                                                    test_rw_locks_WOLFSENTRY_LOCK_FLAGS));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex(lock, NULL /* thread */, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(lock, NULL /* thread */, WOLFSENTRY_LOCK_FLAG_NONE));

    /* exercise interrupt-handler-style lock cycle. */
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex_timed(lock, thread, 0, WOLFSENTRY_LOCK_FLAG_RETAIN_SEMAPHORE));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex_timed(lock, thread, 0, WOLFSENTRY_LOCK_FLAG_RETAIN_SEMAPHORE));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_free(&lock, thread, WOLFSENTRY_LOCK_FLAG_NONE));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_shutdown(&wolfsentry, thread));

    (void)alarm(0);

    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE));

    WOLFSENTRY_RETURN_OK;
}

#else

TEST_SKIP(test_rw_locks)

#endif /* WOLFSENTRY_THREADSAFE */

#endif /* TEST_RWLOCKS */

#ifdef TEST_STATIC_ROUTES

static wolfsentry_errcode_t replace_rule_transactionally(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *event_label,
    int event_label_len,
    const struct wolfsentry_sockaddr *del_remote,
    const struct wolfsentry_sockaddr *del_local,
    wolfsentry_route_flags_t del_flags,
    const struct wolfsentry_sockaddr *ins_remote,
    const struct wolfsentry_sockaddr *ins_local,
    wolfsentry_route_flags_t ins_flags,
    wolfsentry_ent_id_t *ins_id,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_context *new_wolfsentry_ctx = NULL;
    int n_deleted;

    WOLFSENTRY_PROMOTABLE_OR_RETURN();

    ret = wolfsentry_context_clone(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        &new_wolfsentry_ctx,
        WOLFSENTRY_CLONE_FLAG_NONE);
    if (ret < 0)
        goto out;

    ret = wolfsentry_route_delete(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(new_wolfsentry_ctx),
        NULL /* caller_arg */,
        del_remote,
        del_local,
        del_flags,
        event_label,
        event_label_len,
        action_results,
        &n_deleted);
    if (ret < 0)
        goto out;

    ret = wolfsentry_route_insert(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(new_wolfsentry_ctx),
        NULL /* caller_arg */,
        ins_remote,
        ins_local,
        ins_flags,
        event_label,
        event_label_len,
        ins_id,
        action_results);
    if (ret < 0)
        goto out;

    ret = wolfsentry_context_exchange(WOLFSENTRY_CONTEXT_ARGS_OUT, new_wolfsentry_ctx);

out:

    if (new_wolfsentry_ctx != NULL) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_context_free(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&new_wolfsentry_ctx)));
    }


    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

static int test_static_routes(void) {

    struct wolfsentry_context *wolfsentry;
    wolfsentry_action_res_t action_results;
    int n_deleted;
    wolfsentry_ent_id_t id;
    wolfsentry_route_flags_t inexact_matches;

    struct {
        struct wolfsentry_sockaddr sa;
        byte addr_buf[4];
    } remote, local, remote_wildcard, local_wildcard;

    struct wolfsentry_eventconfig config = {
#ifdef WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
        .route_private_data_size = PRIVATE_DATA_SIZE,
        .route_private_data_alignment = PRIVATE_DATA_ALIGNMENT,
        .max_connection_count = 10,
        .derogatory_threshold_for_penaltybox = 4,
        .penaltybox_duration = 1, /* denominated in seconds when passing to wolfsentry_init(). */
        .route_idle_time_for_purge = 0,
        .flags = WOLFSENTRY_EVENTCONFIG_FLAG_NONE
#else
        PRIVATE_DATA_SIZE,
        PRIVATE_DATA_ALIGNMENT,
        10,
        4,
        1, /* denominated in seconds when passing to wolfsentry_init(). */
        0,
        WOLFSENTRY_EVENTCONFIG_FLAG_NONE,
        0,
        0,
        0,
        0,
        0,
        0
#endif
    };

    wolfsentry_route_flags_t flags = WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS, flags_wildcard;

    struct wolfsentry_route_table *main_routes;
    struct wolfsentry_route *route_ref;
    wolfsentry_ent_id_t route_id;
    int prefixlen;
    byte *private_data;
    size_t private_data_size;

    WOLFSENTRY_THREAD_HEADER_CHECKED(WOLFSENTRY_THREAD_FLAG_NONE);

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_init_ex(
            wolfsentry_build_settings,
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(WOLFSENTRY_TEST_HPI),
            &config,
            &wolfsentry,
            WOLFSENTRY_INIT_FLAG_NONE));

    remote.sa.sa_family = local.sa.sa_family = AF_INET;
    remote.sa.sa_proto = local.sa.sa_proto = IPPROTO_TCP;
    remote.sa.sa_port = 12345;
    local.sa.sa_port = 443;
    remote.sa.addr_len = local.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;
    remote.sa.interface = local.sa.interface = 1;
    memcpy(remote.sa.addr,"\0\1\2\3",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\377\376\375\374",sizeof local.addr_buf);

    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);


    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_default_policy_set(WOLFSENTRY_CONTEXT_ARGS_OUT, WOLFSENTRY_ACTION_RES_ACCEPT));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
    WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_FALLTHROUGH));


    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_default_policy_set(WOLFSENTRY_CONTEXT_ARGS_OUT, WOLFSENTRY_ACTION_RES_REJECT));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

    WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_FALLTHROUGH));


#ifdef WOLFSENTRY_UNITTEST_BENCHMARKS
    {
        struct timespec start_at, end_at;
	uint64_t start_at_cycles, end_at_cycles;
        int i;
	double ns_per_call, cycles_per_call;

        WOLFSENTRY_EXIT_ON_SYSFAILURE(clock_gettime(CLOCK_MONOTONIC, &start_at));
	start_at_cycles = get_intel_cycles();
        for (i=0; i<1000000; ++i) {
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                                       &route_id, &inexact_matches, &action_results));
        }
	end_at_cycles = get_intel_cycles();
        WOLFSENTRY_EXIT_ON_SYSFAILURE(clock_gettime(CLOCK_MONOTONIC, &end_at));
	ns_per_call = ((double)(end_at.tv_sec - start_at.tv_sec) * 1000000000.0 + (double)(end_at.tv_nsec - start_at.tv_nsec)) / (double)i;
	cycles_per_call = (double)(end_at_cycles - start_at_cycles) / (double)i;
        printf("benchmark wolfsentry_route_event_dispatch() with empty route table: %.2f ns/call %.2f cycles/call\n", ns_per_call, cycles_per_call);
#ifdef WOLFSENTRY_MAX_CYCLES_PER_CALL_EMPTY_TABLE
	if (cycles_per_call > (double)WOLFSENTRY_MAX_CYCLES_PER_CALL_EMPTY_TABLE) {
            (void)fprintf(stderr, "benchmark wolfsentry_route_event_dispatch() with empty route table: measured %.2f cycles/call exceeds max %.2f\n", cycles_per_call, (double)WOLFSENTRY_MAX_CYCLES_PER_CALL_EMPTY_TABLE);
            WOLFSENTRY_EXIT_ON_TRUE(cycles_per_call > (double)WOLFSENTRY_MAX_CYCLES_PER_CALL_EMPTY_TABLE);
        }
#endif
    }
#endif /* WOLFSENTRY_UNITTEST_BENCHMARKS */


    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_default_policy_set(WOLFSENTRY_CONTEXT_ARGS_OUT, WOLFSENTRY_ACTION_RES_NONE));


    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    memcpy(remote.sa.addr,"\4\5\6\7",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);

    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

#if 0
    puts("table after first 2 inserts:");
    for (struct wolfsentry_route *i = (struct wolfsentry_route *)wolfsentry->routes.header.head;
         i;
         i = (struct wolfsentry_route *)(i->header.next))
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_render(i, stdout));
    putchar('\n');
#endif

    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);

    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));

    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);

    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));

    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_GREENLISTED);
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED);
    memcpy(remote.sa.addr,"\3\4\5\6",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_GREENLISTED);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED);
    memcpy(remote.sa.addr,"\2\3\4\5",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);


    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT, &main_routes));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_get_reference(
                                 WOLFSENTRY_CONTEXT_ARGS_OUT,
                                 main_routes,
                                 &remote.sa,
                                 &local.sa,
                                 flags,
                                 0 /* event_label_len */,
                                 0 /* event_label */,
                                 1 /* exact_p */,
                                 &inexact_matches,
                                 &route_ref));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));

    WOLFSENTRY_EXIT_ON_FALSE(wolfsentry_get_object_type(route_ref) == WOLFSENTRY_OBJECT_TYPE_ROUTE);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_get_private_data(
                                 WOLFSENTRY_CONTEXT_ARGS_OUT,
                                 route_ref,
                                 (void **)&private_data,
                                 &private_data_size));

    if (private_data_size < PRIVATE_DATA_SIZE) {
        printf("private_data_size is " SIZET_FMT " but expected %d.\n",private_data_size,PRIVATE_DATA_SIZE);
        WOLFSENTRY_ERROR_RETURN(NOT_OK);
    }
    if ((PRIVATE_DATA_ALIGNMENT > 0) && ((uintptr_t)private_data % (uintptr_t)PRIVATE_DATA_ALIGNMENT)) {
        printf("private_data (%p) is not aligned to %d.\n", private_data, PRIVATE_DATA_ALIGNMENT);
        WOLFSENTRY_ERROR_RETURN(NOT_OK);
    }

    {
        byte *i;
        const byte *i_end;
        for (i = private_data, i_end = (private_data + private_data_size); i < i_end; ++i)
            *i = 'x';
    }

#if 0
    puts("table after deleting 4.5.6.7 and inserting 3 more:");
    for (struct wolfsentry_route *i = (struct wolfsentry_route *)wolfsentry->routes.header.head;
         i;
         i = (struct wolfsentry_route *)(i->header.next))
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_render(i, stdout));
#endif

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, route_ref, &action_results));
    WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_DEALLOCATED));

    /* now test basic eventless dispatch using exact-match ents in the static table. */

    WOLFSENTRY_CLEAR_ALL_BITS(action_results);

    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);
    memcpy(remote.sa.addr,"\3\4\5\6",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
    WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
    WOLFSENTRY_EXIT_ON_FALSE(inexact_matches == 0);

    flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);

    WOLFSENTRY_EXIT_ON_FALSE(
        WOLFSENTRY_SUCCESS_CODE_IS(
            wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                            &route_id, &inexact_matches, &action_results),
            USED_FALLBACK));
    WOLFSENTRY_EXIT_ON_FALSE(inexact_matches == (WOLFSENTRY_ROUTE_WILDCARD_FLAGS | WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD));

    memcpy(remote.sa.addr,"\2\3\4\5",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
    WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
    WOLFSENTRY_EXIT_ON_FALSE(inexact_matches == 0);

    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
    WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
    WOLFSENTRY_EXIT_ON_FALSE(inexact_matches == 0);

    memcpy(remote.sa.addr,"\0\1\2\3",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\377\376\375\374",sizeof local.addr_buf);
    WOLFSENTRY_EXIT_ON_FALSE(
        WOLFSENTRY_SUCCESS_CODE_IS(
            wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                            &route_id, &inexact_matches, &action_results),
            USED_FALLBACK));
    WOLFSENTRY_EXIT_ON_FALSE(inexact_matches == (WOLFSENTRY_ROUTE_WILDCARD_FLAGS | WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD));

    flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

    WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
    WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
    WOLFSENTRY_EXIT_ON_FALSE(inexact_matches == 0);


    /* now test eventless dispatch using wildcard/prefix matches in the static table. */


    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_GREENLISTED);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED);
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);
    memcpy(remote.sa.addr,"\4\5\6\7",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);

    for (prefixlen = sizeof remote.addr_buf * BITS_PER_BYTE;
         prefixlen >= 8;
         --prefixlen) {
        remote.sa.addr_len = (wolfsentry_addr_bits_t)prefixlen;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

        remote.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
        WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
        WOLFSENTRY_EXIT_ON_TRUE(prefixlen < (int)(sizeof remote.addr_buf * BITS_PER_BYTE) ? ! WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD) : WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD));

        remote.sa.addr_len = (wolfsentry_addr_bits_t)prefixlen;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
        WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


        local.sa.addr_len = (wolfsentry_addr_bits_t)prefixlen;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

        local.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
        WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
        WOLFSENTRY_EXIT_ON_TRUE(prefixlen < (int)(sizeof local.addr_buf * BITS_PER_BYTE) ? ! WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD) : WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD));

        local.sa.addr_len = (wolfsentry_addr_bits_t)prefixlen;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
        WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);

    }


    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    remote_wildcard.sa.sa_port = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD);

    {
        struct wolfsentry_route *new_route = NULL;

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_and_check_out(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &new_route, &action_results));

        id = wolfsentry_get_object_id(new_route);
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, new_route, &action_results));

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                                   &route_id, &inexact_matches, &action_results));
        WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    }

    local.sa.sa_port = 8765;
    WOLFSENTRY_EXIT_ON_FALSE(
        WOLFSENTRY_SUCCESS_CODE_IS(
            wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                            &route_id, &inexact_matches, &action_results),
            USED_FALLBACK));
    WOLFSENTRY_EXIT_ON_FALSE(inexact_matches == (WOLFSENTRY_ROUTE_WILDCARD_FLAGS | WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD));

    local.sa.sa_port = local_wildcard.sa.sa_port;

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_by_id(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, route_id, NULL /* event_label */, 0 /* event_label_len */, &action_results));

    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_DEALLOCATED));

    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    local_wildcard.sa.sa_port = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD));

    /* make sure the fixup (clamp_wildcard_fields_to_zero()) works as expected. */
    local_wildcard.sa.sa_port = 123;

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    remote_wildcard.sa.sa_port = local_wildcard.sa.sa_port = 0;
    remote_wildcard.sa.sa_proto = local_wildcard.sa.sa_proto = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD);
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD);
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD));
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD));
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    local_wildcard.sa.addr_len = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


    /* retest with explicit wildcard bit cleared, but addr_len still 0. */
    WOLFSENTRY_CLEAR_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD);
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    remote_wildcard.sa.sa_port = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD);
    local_wildcard.sa.addr_len = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD));
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    remote_wildcard.sa.addr_len = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    local_wildcard.sa.interface = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    remote_wildcard.sa.interface = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


    local.sa.interface = 2;
    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD);
    local_wildcard.sa.sa_family = remote_wildcard.sa.sa_family = 0;
    local_wildcard.sa.addr_len = remote_wildcard.sa.addr_len = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD);
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD);
    remote_wildcard.sa.sa_port = local_wildcard.sa.sa_port = 0;
    remote_wildcard.sa.sa_proto = local_wildcard.sa.sa_proto = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD);
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD);
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD));
    WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);
    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));


#ifndef WOLFSENTRY_NO_STDIO
    {
        wolfsentry_errcode_t ret;
        struct wolfsentry_cursor *cursor;
        struct wolfsentry_route *route;
        struct wolfsentry_route_exports route_exports;
        wolfsentry_hitcount_t n_seen = 0;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_table_iterate_start(WOLFSENTRY_CONTEXT_ARGS_OUT, main_routes, &cursor));
        for (ret = wolfsentry_route_table_iterate_current(main_routes, cursor, &route);
             ret >= 0;
             ret = wolfsentry_route_table_iterate_next(main_routes, cursor, &route)) {
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_export(WOLFSENTRY_CONTEXT_ARGS_OUT, route, &route_exports));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_exports_render(WOLFSENTRY_CONTEXT_ARGS_OUT, &route_exports, stdout));
            ++n_seen;
        }
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_table_iterate_end(WOLFSENTRY_CONTEXT_ARGS_OUT, main_routes, &cursor));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));
        WOLFSENTRY_EXIT_ON_FALSE(n_seen == wolfsentry->routes->header.n_ents);
    }
#endif

    remote.sa.sa_family = local.sa.sa_family = AF_INET;
    remote.sa.sa_proto = local.sa.sa_proto = IPPROTO_TCP;
    remote.sa.sa_port = 12345;
    local.sa.sa_port = 443;
    remote.sa.addr_len = local.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;
    remote.sa.interface = local.sa.interface = 1;
    memcpy(remote.sa.addr,"\0\1\2\3",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\377\376\375\374",sizeof local.addr_buf);

    WOLFSENTRY_CLEAR_ALL_BITS(flags);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS|WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);
    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));

    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_GREENLISTED);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED);
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);
    memcpy(remote.sa.addr,"\2\3\4\5",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);
    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));

    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);
    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));

    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_GREENLISTED);
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED);
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);
    memcpy(remote.sa.addr,"\3\4\5\6",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);
    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));

    WOLFSENTRY_EXIT_ON_FALSE(wolfsentry->routes->header.n_ents == 0);


    /* finally, test config.derogatory_threshold_for_penaltybox */

    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_GREENLISTED);
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED);
    memcpy(remote.sa.addr,"\3\4\5\6",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    {
        unsigned int i;
        for (i=1; i <= (unsigned int)config.derogatory_threshold_for_penaltybox + 1; ++i) {
            WOLFSENTRY_CLEAR_ALL_BITS(action_results);
            WOLFSENTRY_SET_BITS(action_results, WOLFSENTRY_ACTION_RES_DEROGATORY);
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch_with_inited_result(WOLFSENTRY_CONTEXT_ARGS_OUT, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                                                          &route_id, &inexact_matches, &action_results));
            if (i == config.derogatory_threshold_for_penaltybox) {
                WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
                WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
                printf("sleeping for %ld seconds to test penaltybox timeout...", (long int)(config.penaltybox_duration + 1));
                fflush(stdout);
                sleep((unsigned int)config.penaltybox_duration + 1);
                printf(" done.\n");
                fflush(stdout);
            } else {
                WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
                WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
            }
        }
    }



    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_get_reference(
                                 WOLFSENTRY_CONTEXT_ARGS_OUT,
                                 main_routes,
                                 &remote.sa,
                                 &local.sa,
                                 flags,
                                 0 /* event_label_len */,
                                 0 /* event_label */,
                                 1 /* exact_p */,
                                 &inexact_matches,
                                 &route_ref));


    {
        int old_derogatory_count;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_reset_derogatory_count(
                                       WOLFSENTRY_CONTEXT_ARGS_OUT,
                                       route_ref,
                                       &old_derogatory_count));
        /* 1 left from final iteration above. */
        WOLFSENTRY_EXIT_ON_FALSE(old_derogatory_count == 1);
    }

    {
        int new_derogatory_count;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_increment_derogatory_count(
                                       WOLFSENTRY_CONTEXT_ARGS_OUT,
                                       route_ref,
                                       123,
                                       &new_derogatory_count));
        WOLFSENTRY_EXIT_ON_FALSE(new_derogatory_count == 123);
    }

    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
        OVERFLOW_AVERTED,
        wolfsentry_route_increment_derogatory_count(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            route_ref,
            -124,
            NULL));

    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
        OVERFLOW_AVERTED,
        wolfsentry_route_increment_derogatory_count(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            route_ref,
            65536 - 123,
            NULL));

    {
        int new_derogatory_count;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_increment_derogatory_count(
                                       WOLFSENTRY_CONTEXT_ARGS_OUT,
                                       route_ref,
                                       1,
                                       &new_derogatory_count));
        WOLFSENTRY_EXIT_ON_FALSE(new_derogatory_count == 124);
    }

    {
        int old_commendable_count;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_reset_commendable_count(
                                       WOLFSENTRY_CONTEXT_ARGS_OUT,
                                       route_ref,
                                       &old_commendable_count));
        WOLFSENTRY_EXIT_ON_FALSE(old_commendable_count == 0);
    }

    {
        int new_commendable_count;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_increment_commendable_count(
                                       WOLFSENTRY_CONTEXT_ARGS_OUT,
                                       route_ref,
                                       123,
                                       &new_commendable_count));
        WOLFSENTRY_EXIT_ON_FALSE(new_commendable_count == 123);
    }

    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
        OVERFLOW_AVERTED,
        wolfsentry_route_increment_commendable_count(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            route_ref,
            -124,
            NULL));

    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
        OVERFLOW_AVERTED,
        wolfsentry_route_increment_commendable_count(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            route_ref,
            65536 - 123,
            NULL));

    {
        int new_commendable_count;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_increment_commendable_count(
                                       WOLFSENTRY_CONTEXT_ARGS_OUT,
                                       route_ref,
                                       1,
                                       &new_commendable_count));
        WOLFSENTRY_EXIT_ON_FALSE(new_commendable_count == 124);
    }

    /* test the generic object checkout/drop interface. */
#ifdef WOLFSENTRY_THREADSAFE
    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
        LACKING_READ_LOCK,
        wolfsentry_object_checkout(WOLFSENTRY_CONTEXT_ARGS_OUT, route_ref));
#endif

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_object_checkout(WOLFSENTRY_CONTEXT_ARGS_OUT, route_ref));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_object_release(WOLFSENTRY_CONTEXT_ARGS_OUT, route_ref, NULL /* action_results */));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_object_release(WOLFSENTRY_CONTEXT_ARGS_OUT, route_ref, NULL /* action_results */));

    /* leave the route in the table, to be cleaned up by wolfsentry_shutdown(). */

    {
        struct {
            struct wolfsentry_sockaddr sa;
            byte addr_buf[4];
        } alt_remote, alt_local;
        wolfsentry_route_flags_t alt_flags = WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS;
        wolfsentry_ent_id_t ins_id;

        memcpy(&alt_remote, &remote, sizeof alt_remote);
        memcpy(alt_remote.sa.addr,"\4\5\6\7",sizeof remote.addr_buf);
        memcpy(&alt_local, &local, sizeof alt_local);
        alt_flags = flags;
        WOLFSENTRY_SET_BITS(alt_flags, WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED);
        WOLFSENTRY_CLEAR_BITS(alt_flags, WOLFSENTRY_ROUTE_FLAG_GREENLISTED);

        WOLFSENTRY_EXIT_ON_FAILURE(
            replace_rule_transactionally(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                NULL /* event_label */,
                0 /* event_label_len */,
                &remote.sa,
                &local.sa,
                flags,
                &alt_remote.sa,
                &alt_local.sa,
                alt_flags,
                &ins_id,
                &action_results));

        WOLFSENTRY_EXIT_ON_FAILURE(
            replace_rule_transactionally(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                NULL /* event_label */,
                0 /* event_label_len */,
                &alt_remote.sa,
                &alt_local.sa,
                alt_flags,
                &remote.sa,
                &local.sa,
                flags,
                &ins_id,
                &action_results));

        WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
            ITEM_NOT_FOUND,
            replace_rule_transactionally(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                NULL /* event_label */,
                0 /* event_label_len */,
                &alt_remote.sa,
                &alt_local.sa,
                alt_flags,
                &remote.sa,
                &local.sa,
                flags,
                &ins_id,
                &action_results));

        WOLFSENTRY_EXIT_ON_FAILURE(
            replace_rule_transactionally(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                NULL /* event_label */,
                0 /* event_label_len */,
                &remote.sa,
                &local.sa,
                flags,
                &alt_remote.sa,
                &alt_local.sa,
                alt_flags,
                &ins_id,
                &action_results));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_route_delete(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                NULL /* caller_arg */,
                &alt_remote.sa,
                &alt_local.sa,
                alt_flags,
                NULL /* event_label */,
                0 /* event_label_len */,
                &action_results,
                &n_deleted));

        WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
            ITEM_NOT_FOUND,
            wolfsentry_route_delete(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                NULL /* caller_arg */,
                &remote.sa,
                &local.sa,
                flags,
                NULL /* event_label */,
                0 /* event_label_len */,
                &action_results,
                &n_deleted));
    }

    printf("all subtests succeeded -- %u distinct ents inserted and deleted.\n",wolfsentry->mk_id_cb_state.id_counter);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&wolfsentry)));

    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE));

    WOLFSENTRY_RETURN_OK;
}

#endif /* TEST_STATIC_ROUTES */

#ifdef TEST_DYNAMIC_RULES

static wolfsentry_errcode_t wolfsentry_action_dummy_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_action *action,
    void *handler_context,
    void *caller_arg,
    const struct wolfsentry_event *event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *target_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    (void)action;
    (void)handler_context;
    (void)caller_arg;
    (void)event;
    (void)action_type;
    (void)target_route;
    (void)route_table;
    (void)rule_route;
    (void)action_results;

    WOLFSENTRY_RETURN_OK;
}


static int test_dynamic_rules(void) {

    struct wolfsentry_context *wolfsentry;
#if 0
    wolfsentry_action_res_t action_results;
    int n_deleted;
    int ret;
    struct {
        struct wolfsentry_sockaddr sa;
        byte addr_buf[4];
    } src, dst;
#endif

    wolfsentry_ent_id_t id;

#ifdef WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
    static const struct wolfsentry_eventconfig config = { .route_private_data_size = PRIVATE_DATA_SIZE, .route_private_data_alignment = PRIVATE_DATA_ALIGNMENT, .max_connection_count = 10 };
    static const struct wolfsentry_eventconfig config2 = { .route_private_data_size = PRIVATE_DATA_SIZE * 2, .route_private_data_alignment = PRIVATE_DATA_ALIGNMENT * 2, .max_connection_count = 15 };
#else
    static const struct wolfsentry_eventconfig config = { PRIVATE_DATA_SIZE, PRIVATE_DATA_ALIGNMENT, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    static const struct wolfsentry_eventconfig config2 = { PRIVATE_DATA_SIZE * 2, PRIVATE_DATA_ALIGNMENT * 2, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
#endif

    WOLFSENTRY_THREAD_HEADER_CHECKED(WOLFSENTRY_THREAD_FLAG_NONE);

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_init_ex(
            wolfsentry_build_settings,
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(WOLFSENTRY_TEST_HPI),
            &config,
            &wolfsentry,
            WOLFSENTRY_INIT_FLAG_NONE));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "connect",
            -1 /* label_len */,
            10,
            NULL /* config */,
            WOLFSENTRY_EVENT_FLAG_NONE,
            &id));

    WOLFSENTRY_EXIT_ON_FALSE(
        WOLFSENTRY_ERROR_CODE_IS(
            wolfsentry_event_insert(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                WOLFSENTRY_BUILTIN_LABEL_PREFIX "connect",
                -1 /* label_len */,
                10,
                NULL /* config */,
                WOLFSENTRY_EVENT_FLAG_NONE,
                &id),
            NOT_PERMITTED));

    /* track port scanning */
    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "connection_refused",
            -1 /* label_len */,
            10,
            NULL /* config */,
            WOLFSENTRY_EVENT_FLAG_NONE,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "disconnect",
            -1 /* label_len */,
            10,
            NULL /* config */,
            WOLFSENTRY_EVENT_FLAG_NONE,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "authentication_succeeded",
            -1 /* label_len */,
            10,
            NULL /* config */,
            WOLFSENTRY_EVENT_FLAG_NONE,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "negotiation_abandoned",
            -1 /* label_len */,
            10,
            NULL /* config */,
            WOLFSENTRY_EVENT_FLAG_NONE,
            &id));

    {
        wolfsentry_ent_id_t auth_failed_id;
        struct wolfsentry_event *auth_failed_event;
        const struct wolfsentry_event *insertion_side_effect_demo_event;
        const char *insertion_side_effect_demo_label;

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_event_insert(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "authentication_failed",
                -1 /* label_len */,
                10,
                NULL /* config */,
                WOLFSENTRY_EVENT_FLAG_NONE,
                &id));

        auth_failed_id = id;

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_event_insert(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "insertion_side_effect_demo",
                -1 /* label_len */,
                10,
                NULL /* config */,
                WOLFSENTRY_EVENT_FLAG_NONE,
                &id));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_event_set_aux_event(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "authentication_failed",
                -1,
                "insertion_side_effect_demo",
                -1));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_event_get_reference(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "authentication_failed",
                -1,
                &auth_failed_event));

        WOLFSENTRY_EXIT_ON_FALSE(auth_failed_id == wolfsentry_get_object_id(auth_failed_event));

        WOLFSENTRY_EXIT_ON_FALSE(
            insertion_side_effect_demo_event = wolfsentry_event_get_aux_event(auth_failed_event)
            );

        WOLFSENTRY_EXIT_ON_FALSE(
            insertion_side_effect_demo_label = wolfsentry_event_get_label(insertion_side_effect_demo_event)
            );

        WOLFSENTRY_EXIT_ON_FALSE(strcmp(insertion_side_effect_demo_label, "insertion_side_effect_demo") == 0);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_event_drop_reference(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                auth_failed_event,
                NULL /* action_results */));
    }

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "match_side_effect_demo",
            -1 /* label_len */,
            10,
            NULL /* config */,
            WOLFSENTRY_EVENT_FLAG_NONE,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "deletion_side_effect_demo",
            -1 /* label_len */,
            10,
            &config2,
            WOLFSENTRY_EVENT_FLAG_NONE,
            &id));

    {
        struct wolfsentry_eventconfig eventconfig;

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_event_get_config(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "deletion_side_effect_demo",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &eventconfig));

        WOLFSENTRY_EXIT_ON_FALSE((eventconfig.route_private_data_size == config2.route_private_data_size) &&
                                 (eventconfig.route_private_data_alignment == config2.route_private_data_alignment) &&
                                 (eventconfig.max_connection_count == config2.max_connection_count));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_event_update_config(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "deletion_side_effect_demo",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &config));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_event_get_config(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "deletion_side_effect_demo",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &eventconfig));

        WOLFSENTRY_EXIT_ON_FALSE((eventconfig.route_private_data_size == config.route_private_data_size) &&
                                 (eventconfig.route_private_data_alignment == config.route_private_data_alignment) &&
                                 (eventconfig.max_connection_count == config.max_connection_count));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_event_delete(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "deletion_side_effect_demo",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                NULL /* action_results */));

        WOLFSENTRY_EXIT_ON_SUCCESS(
            wolfsentry_event_delete(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "deletion_side_effect_demo",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                NULL /* action_results */));
    }

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "insert_always",
            -1 /* label_len */,
            WOLFSENTRY_ACTION_FLAG_NONE,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    WOLFSENTRY_EXIT_ON_FALSE(
        WOLFSENTRY_ERROR_CODE_IS(
            wolfsentry_action_insert(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                WOLFSENTRY_BUILTIN_LABEL_PREFIX "insert_always",
                -1 /* label_len */,
                WOLFSENTRY_ACTION_FLAG_NONE,
                wolfsentry_action_dummy_callback,
                NULL /* handler_context */,
                &id),
            NOT_PERMITTED));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "insert_alway",
            -1 /* label_len */,
            WOLFSENTRY_ACTION_FLAG_NONE,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    {
        static char too_long_label[WOLFSENTRY_MAX_LABEL_BYTES + 2];
        memset(too_long_label, 'x', sizeof too_long_label - 1);

        too_long_label[sizeof too_long_label - 1] = 0;

        WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
            STRING_ARG_TOO_LONG,
            wolfsentry_action_insert(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                too_long_label,
                -1 /* label_len */,
                WOLFSENTRY_ACTION_FLAG_NONE,
                wolfsentry_action_dummy_callback,
                NULL /* handler_context */,
                &id));

        WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
            STRING_ARG_TOO_LONG,
            wolfsentry_action_insert(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                too_long_label,
                sizeof too_long_label - 1,
                WOLFSENTRY_ACTION_FLAG_NONE,
                wolfsentry_action_dummy_callback,
                NULL /* handler_context */,
                &id));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_action_insert(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                too_long_label,
                sizeof too_long_label - 2,
                WOLFSENTRY_ACTION_FLAG_NONE,
                wolfsentry_action_dummy_callback,
                NULL /* handler_context */,
                &id));

        WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
            STRING_ARG_TOO_LONG,
            wolfsentry_action_delete(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                too_long_label,
                sizeof too_long_label - 1,
                NULL /* action_results */));

        WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
            STRING_ARG_TOO_LONG,
            wolfsentry_action_delete(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                too_long_label,
                -1,
                NULL /* action_results */));

        WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
            INVALID_ARG,
            wolfsentry_action_delete(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                NULL,
                -1,
                NULL /* action_results */));

        too_long_label[sizeof too_long_label - 2] = 0;

        WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
            ITEM_ALREADY_PRESENT,
            wolfsentry_action_insert(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                too_long_label,
                -1 /* label_len */,
                WOLFSENTRY_ACTION_FLAG_NONE,
                wolfsentry_action_dummy_callback,
                NULL /* handler_context */,
                &id));

        WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
            INVALID_ARG,
            wolfsentry_action_insert(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                NULL,
                -1 /* label_len */,
                WOLFSENTRY_ACTION_FLAG_NONE,
                wolfsentry_action_dummy_callback,
                NULL /* handler_context */,
                &id));

        WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
            INVALID_ARG,
            wolfsentry_action_insert(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                too_long_label,
                0 /* label_len */,
                WOLFSENTRY_ACTION_FLAG_NONE,
                wolfsentry_action_dummy_callback,
                NULL /* handler_context */,
                &id));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_action_delete(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                too_long_label,
                -1 /* label_len */,
                NULL /* action_results */));
    }

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "set_connect_wildcards",
            -1 /* label_len */,
            WOLFSENTRY_ACTION_FLAG_NONE,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "set_connectionreset_wildcards",
            -1 /* label_len */,
            WOLFSENTRY_ACTION_FLAG_NONE,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "increment_derogatory",
            -1 /* label_len */,
            WOLFSENTRY_ACTION_FLAG_NONE,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "increment_commendable",
            -1 /* label_len */,
            WOLFSENTRY_ACTION_FLAG_NONE,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "check_counts",
            -1 /* label_len */,
            WOLFSENTRY_ACTION_FLAG_NONE,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    {
        struct wolfsentry_action *action;
        wolfsentry_action_flags_t flags;

        WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
            ITEM_NOT_FOUND,
            wolfsentry_action_get_reference(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "checXXXounts",
                -1 /* label_len */,
                &action));

        WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
            INVALID_ARG,
            wolfsentry_action_get_reference(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "checXXXounts",
                0 /* label_len */,
                &action));

        WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
            STRING_ARG_TOO_LONG,
            wolfsentry_action_get_reference(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "checXXXounts",
                WOLFSENTRY_MAX_LABEL_BYTES + 1 /* label_len */,
                &action));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_action_get_reference(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "check_counts",
                -1 /* label_len */,
                &action));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_action_get_flags(
                action,
                &flags));
        WOLFSENTRY_EXIT_ON_FALSE(flags == WOLFSENTRY_ACTION_FLAG_NONE);

        {
            wolfsentry_action_flags_t flags_before, flags_after;
            WOLFSENTRY_EXIT_ON_FAILURE(
                wolfsentry_action_update_flags(
                    action,
                    WOLFSENTRY_ACTION_FLAG_DISABLED,
                    WOLFSENTRY_ACTION_FLAG_NONE,
                    &flags_before,
                    &flags_after));
            WOLFSENTRY_EXIT_ON_FALSE(flags_before == WOLFSENTRY_ACTION_FLAG_NONE);
            WOLFSENTRY_EXIT_ON_FALSE(flags_after == WOLFSENTRY_ACTION_FLAG_DISABLED);
        }

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_action_get_flags(
                action,
                &flags));
        WOLFSENTRY_EXIT_ON_FALSE(flags == WOLFSENTRY_ACTION_FLAG_DISABLED);

        {
            wolfsentry_action_flags_t flags_before, flags_after;
            WOLFSENTRY_EXIT_ON_FAILURE(
                wolfsentry_action_update_flags(
                    action,
                    WOLFSENTRY_ACTION_FLAG_NONE,
                    WOLFSENTRY_ACTION_FLAG_DISABLED,
                    &flags_before,
                    &flags_after));
            WOLFSENTRY_EXIT_ON_FALSE(flags_before == WOLFSENTRY_ACTION_FLAG_DISABLED);
            WOLFSENTRY_EXIT_ON_FALSE(flags_after == WOLFSENTRY_ACTION_FLAG_NONE);
        }

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_action_get_flags(
                action,
                &flags));
        WOLFSENTRY_EXIT_ON_FALSE(flags == WOLFSENTRY_ACTION_FLAG_NONE);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_action_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, action, NULL));
    }

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "add_to_greenlist",
            -1 /* label_len */,
            WOLFSENTRY_ACTION_FLAG_NONE,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "del_from_greenlist",
            -1 /* label_len */,
            WOLFSENTRY_ACTION_FLAG_NONE,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_action_append(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "match_side_effect_demo",
            -1,
            WOLFSENTRY_ACTION_TYPE_MATCH,
            "del_from_greenlist",
            -1));

    WOLFSENTRY_EXIT_ON_SUCCESS(
        wolfsentry_event_action_prepend(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "match_side_effect_demo",
            -1,
            WOLFSENTRY_ACTION_TYPE_MATCH,
            "del_from_greenlist",
            -1));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_action_prepend(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "match_side_effect_demo",
            -1,
            WOLFSENTRY_ACTION_TYPE_MATCH,
            "add_to_greenlist",
            -1));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_action_insert_after(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "match_side_effect_demo",
            -1,
            WOLFSENTRY_ACTION_TYPE_MATCH,
            "check_counts",
            -1,
            "add_to_greenlist",
            -1));

    {
        struct wolfsentry_action_list_ent *cursor;
        const char *action_label;
        int action_label_len;
        static const char *labels[] = { "add_to_greenlist", "check_counts", "del_from_greenlist" };
        int label_i = 0;

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_event_action_list_start(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "match_side_effect_demo",
                -1,
                WOLFSENTRY_ACTION_TYPE_MATCH,
                &cursor));

        while (wolfsentry_event_action_list_next(
                   WOLFSENTRY_CONTEXT_ARGS_OUT,
                   &cursor,
                   &action_label,
                   &action_label_len) >= 0) {
            WOLFSENTRY_EXIT_ON_TRUE((size_t)label_i >= sizeof labels / sizeof labels[0]);
            WOLFSENTRY_EXIT_ON_FALSE(strcmp(action_label, labels[label_i++]) == 0);
        }

        WOLFSENTRY_EXIT_ON_FALSE(label_i == sizeof labels / sizeof labels[0]);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_event_action_list_done(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &cursor));

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));
    }

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_action_delete(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "match_side_effect_demo",
            -1,
            WOLFSENTRY_ACTION_TYPE_MATCH,
            "del_from_greenlist",
            -1));


    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&wolfsentry)));

    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE));

    WOLFSENTRY_RETURN_OK;
}

#endif /* TEST_DYNAMIC_RULES */

#ifdef TEST_USER_VALUES

#include <math.h>

static wolfsentry_errcode_t test_kv_validator(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_pair *kv)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    switch (WOLFSENTRY_KV_TYPE(kv)) {
    case WOLFSENTRY_KV_NONE:
    case WOLFSENTRY_KV_NULL:
    case WOLFSENTRY_KV_TRUE:
    case WOLFSENTRY_KV_FALSE:
        WOLFSENTRY_RETURN_OK;
    case WOLFSENTRY_KV_UINT:
        if (WOLFSENTRY_KV_V_UINT(kv) == 12345678UL)
            WOLFSENTRY_ERROR_RETURN(BAD_VALUE);
        else
            WOLFSENTRY_RETURN_OK;
    case WOLFSENTRY_KV_SINT:
        if (WOLFSENTRY_KV_V_SINT(kv) == -12345678L)
            WOLFSENTRY_ERROR_RETURN(BAD_VALUE);
        else
            WOLFSENTRY_RETURN_OK;
    case WOLFSENTRY_KV_FLOAT:
        if (WOLFSENTRY_KV_V_FLOAT(kv) > 100.0)
            WOLFSENTRY_ERROR_RETURN(BAD_VALUE);
        else
            WOLFSENTRY_RETURN_OK;
    case WOLFSENTRY_KV_STRING:
        if (WOLFSENTRY_KV_V_STRING_LEN(kv) != 8)
            WOLFSENTRY_RETURN_OK;
        if (strncmp(WOLFSENTRY_KV_V_STRING(kv), "deadbeef", WOLFSENTRY_KV_V_STRING_LEN(kv)) == 0)
            WOLFSENTRY_ERROR_RETURN(BAD_VALUE);
        else
            WOLFSENTRY_RETURN_OK;
    case WOLFSENTRY_KV_BYTES:
        if (WOLFSENTRY_KV_V_BYTES_LEN(kv) != 10)
            WOLFSENTRY_RETURN_OK;
        if (memcmp(WOLFSENTRY_KV_V_STRING(kv), "abcdefghij", WOLFSENTRY_KV_V_BYTES_LEN(kv)) == 0)
            WOLFSENTRY_ERROR_RETURN(BAD_VALUE);
        else
            WOLFSENTRY_RETURN_OK;
    default:
        break;
    }
    WOLFSENTRY_ERROR_RETURN(WRONG_TYPE);
}

static int test_user_values(void) {
    struct wolfsentry_context *wolfsentry;
    wolfsentry_action_res_t action_results;

    wolfsentry_kv_type_t kv_type;
    struct wolfsentry_kv_pair_internal *kv_ref;

    WOLFSENTRY_THREAD_HEADER_CHECKED(WOLFSENTRY_THREAD_FLAG_NONE);

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_init_ex(
            wolfsentry_build_settings,
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(WOLFSENTRY_TEST_HPI),
            NULL /* config */,
            &wolfsentry,
            WOLFSENTRY_INIT_FLAG_NONE));

    action_results = WOLFSENTRY_ACTION_RES_NONE;
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_user_value_set_validator(WOLFSENTRY_CONTEXT_ARGS_OUT, test_kv_validator, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(action_results == WOLFSENTRY_ACTION_RES_NONE);

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_user_value_store_null(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "test_null",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            0));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_user_value_store_bool(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "test_bool",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            WOLFSENTRY_KV_TRUE,
            0));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_user_value_get_bool(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "test_bool",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            &kv_type));

    WOLFSENTRY_EXIT_ON_FALSE(kv_type == WOLFSENTRY_KV_TRUE);

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_user_value_store_bool(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "test_bool",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            WOLFSENTRY_KV_FALSE,
            1));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_user_value_get_bool(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "test_bool",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            &kv_type));

    WOLFSENTRY_EXIT_ON_FALSE(kv_type == WOLFSENTRY_KV_FALSE);

    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
        WRONG_TYPE,
        wolfsentry_user_value_store_bool(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "test_bool",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            WOLFSENTRY_KV_NONE,
            1));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_user_value_get_type(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "test_bool",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            &kv_type));

    WOLFSENTRY_EXIT_ON_FALSE(kv_type == WOLFSENTRY_KV_FALSE);

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_user_value_get_type(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "test_bool",
            strlen("test_bool"),
            &kv_type));

    WOLFSENTRY_EXIT_ON_FALSE(kv_type == WOLFSENTRY_KV_FALSE);

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_user_value_delete(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "test_bool",
            WOLFSENTRY_LENGTH_NULL_TERMINATED));

    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
        ITEM_NOT_FOUND,
        wolfsentry_user_value_get_type(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "test_bool",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            &kv_type));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_user_value_store_uint(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "test_uint",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            123UL,
            0));

    {
        uint64_t value = 0;
        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_get_uint(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "test_uint",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &value));

        WOLFSENTRY_EXIT_ON_FALSE(value == 123UL);
    }

    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
        BAD_VALUE,
        wolfsentry_user_value_store_uint(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "bad_uint",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            12345678UL,
            0));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_user_value_store_sint(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "test_sint",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            -123L,
            0));

    {
        int64_t value = 0;
        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_get_sint(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "test_sint",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &value));

        WOLFSENTRY_EXIT_ON_FALSE(value == -123L);
    }

    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
        BAD_VALUE,
        wolfsentry_user_value_store_sint(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "bad_sint",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            -12345678L,
            0));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_user_value_store_double(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "test_float",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            1.234,
            0));

    {
        double value = 0.0;
        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_get_float(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "test_float",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &value));

        WOLFSENTRY_EXIT_ON_FALSE(fabs(value - 1.234) < 0.000001);
    }

    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
        BAD_VALUE,
        wolfsentry_user_value_store_double(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "bad_float",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            123.45678,
            0));

    {
        static const char test_string[] = "abc123";
        const char *value = NULL;
        int value_len = -1;
        int mutable = -1;
        wolfsentry_errcode_t ret;

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_store_string(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "test_string",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                test_string,
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                0));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_get_mutability(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "test_string",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &mutable));

        WOLFSENTRY_EXIT_ON_FALSE(mutable == 1);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_set_mutability(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "test_string",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                0));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_get_mutability(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "test_string",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &mutable));

        WOLFSENTRY_EXIT_ON_FALSE(mutable == 0);

        WOLFSENTRY_EXIT_ON_SUCCESS(
            ret = wolfsentry_user_value_delete(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "test_string",
                WOLFSENTRY_LENGTH_NULL_TERMINATED));

        WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(NOT_PERMITTED, ret);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_get_string(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "test_string",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &value,
                &value_len,
                &kv_ref));

        WOLFSENTRY_EXIT_ON_FALSE(value_len == (int)strlen(test_string));
        WOLFSENTRY_EXIT_ON_FALSE(strcmp(value, test_string) == 0);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_release_record(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &kv_ref));

    }

    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
        BAD_VALUE,
        wolfsentry_user_value_store_string(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "bad_string",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            "deadbeef",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            0));

    {
        static const byte test_bytes[] = { 0, 1, 2, 3, 4 };
        const byte *value = NULL;
        int value_len = -1;

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_store_bytes(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "test_bytes",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                test_bytes,
                sizeof test_bytes,
                0));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_get_bytes(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "test_bytes",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &value,
                &value_len,
                &kv_ref));

        WOLFSENTRY_EXIT_ON_FALSE(value_len == (int)sizeof test_bytes);
        WOLFSENTRY_EXIT_ON_FALSE(memcmp(value, test_bytes, (size_t)value_len) == 0);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_release_record(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &kv_ref));
    }

    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
        BAD_VALUE,
        wolfsentry_user_value_store_bytes(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "bad_bytes",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            (const byte *)"abcdefghij",
            10,
            0));

#ifndef WOLFSENTRY_NO_STDIO
    {
        wolfsentry_errcode_t ret;
        struct wolfsentry_cursor *cursor;
        const struct wolfsentry_kv_pair *kv_exports;
        const char *val_type;
        char val_buf[256];
        int val_buf_space;
        wolfsentry_hitcount_t n_seen = 0;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_user_values_iterate_start(WOLFSENTRY_CONTEXT_ARGS_OUT, &cursor));
        for (ret = wolfsentry_user_values_iterate_current(WOLFSENTRY_CONTEXT_ARGS_OUT, cursor, &kv_ref);
             ret >= 0;
             ret = wolfsentry_user_values_iterate_next(WOLFSENTRY_CONTEXT_ARGS_OUT, cursor, &kv_ref)) {
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_kv_pair_export(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_ref, &kv_exports));
            val_buf_space = sizeof val_buf;
            if (wolfsentry_kv_type_to_string(WOLFSENTRY_KV_TYPE(kv_exports), &val_type) < 0)
                val_type = "?";
            if (wolfsentry_kv_render_value(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_exports, val_buf, &val_buf_space) < 0)
                strcpy(val_buf,"?");
            printf("{ \"%.*s\" : { \"%s\" : %s } }\n",
                   (int)WOLFSENTRY_KV_KEY_LEN(kv_exports),
                   WOLFSENTRY_KV_KEY(kv_exports),
                   val_type,
                   val_buf);
            ++n_seen;
        }
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_user_values_iterate_end(WOLFSENTRY_CONTEXT_ARGS_OUT, &cursor));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));
        WOLFSENTRY_EXIT_ON_FALSE(n_seen == wolfsentry->user_values->header.n_ents);
        WOLFSENTRY_EXIT_ON_FALSE(n_seen == 6);
    }
#endif

    {
        static const struct {
            const char *q;
            const char *a;
        } base64_qna[] = {
            { "", "" },
            { "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu", "Many hands make light work." },
            { "bGlnaHQgd29yay4=", "light work." },
            { "bGlnaHQgd29yay4", "light work." },
            { "bGlnaHQgd29yaw==", "light work" },
            { "bGlnaHQgd29yaw", "light work" },
            { "bGlnaHQgd29y", "light wor" },
            { "bGlnaHQgd28=", "light wo" },
            { "bGlnaHQgdw==", "light w" },
            { "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV"
                "1hZWjAxMjM0NTY3ODkhQCMkJV4mKigpXy0rPXxcYH5bXXt9OzonIiw8Lj4vPw==",
              "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                                          "!@#$%^&*()_-+=|\\`~[]{};:'\",<.>/?" },
            { "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+",
              "\x69\xb7\x1d\x79\xf8\x21\x8a\x39\x25\x9a\x7a\x29\xaa\xbb\x2d\xba"
              "\xfc\x31\xcb\x30\x01\x08\x31\x05\x18\x72\x09\x28\xb3\x0d\x38\xf4"
              "\x11\x49\x35\x15\x59\x76\x19\xd3\x5d\xb7\xe3\x9e\xbb\xf3\xdf\xfe"
            }
        };

        int i;
        byte outbuf[256];
        size_t outbuf_spc;

        for (i=0; i < (int)(sizeof base64_qna / sizeof base64_qna[0]); ++i) {
            outbuf_spc = sizeof outbuf;
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_base64_decode(base64_qna[i].q, strlen(base64_qna[i].q), outbuf, &outbuf_spc, 0 /* ignore_junk_p */));
            WOLFSENTRY_EXIT_ON_FALSE((outbuf_spc == strlen(base64_qna[i].a)) && (memcmp(outbuf, base64_qna[i].a, outbuf_spc) == 0));
        }
    }

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&wolfsentry)));

    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE));

    WOLFSENTRY_RETURN_OK;
}

#endif /* TEST_USER_VALUES */

#ifdef TEST_USER_ADDR_FAMILIES

static int test_user_addr_families(void) {

    struct wolfsentry_context *wolfsentry;
    wolfsentry_action_res_t action_results;

    WOLFSENTRY_THREAD_HEADER_CHECKED(WOLFSENTRY_THREAD_FLAG_NONE);

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_init_ex(
            wolfsentry_build_settings,
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(WOLFSENTRY_TEST_HPI),
            NULL /* config */,
            &wolfsentry,
            WOLFSENTRY_INIT_FLAG_NONE));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_addr_family_handler_install(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            WOLFSENTRY_AF_USER_OFFSET,
            "my_AF",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            my_addr_family_parser,
            my_addr_family_formatter,
            24 /* max_addr_bits */));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_addr_family_handler_remove_bynumber(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            WOLFSENTRY_AF_USER_OFFSET,
            &action_results));

    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_DEALLOCATED));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_addr_family_handler_install(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            WOLFSENTRY_AF_USER_OFFSET,
            "my_AF",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            my_addr_family_parser,
            my_addr_family_formatter,
            24 /* max_addr_bits */));

    action_results = 0;

    /* exercise the plugins to disambiguate failures in the plugins from
     * JSON-specific failures.
     */
    {
        byte addr_internal[3];
        wolfsentry_addr_bits_t addr_internal_len;
        char addr_text[13];
        int addr_text_len;

        addr_internal_len = (wolfsentry_addr_bits_t)(sizeof addr_internal * 8);
        WOLFSENTRY_EXIT_ON_FAILURE(
            my_addr_family_parser(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "377/377/377",
                strlen("377/377/377"),
                addr_internal,
                &addr_internal_len));
        WOLFSENTRY_EXIT_ON_FALSE(addr_internal_len == (wolfsentry_addr_bits_t)(sizeof addr_internal * 8));
        WOLFSENTRY_EXIT_ON_FALSE(memcmp(addr_internal, "\377\377\377", sizeof addr_internal) == 0);

        addr_text_len = (int)sizeof addr_text;
        WOLFSENTRY_EXIT_ON_FAILURE(
            my_addr_family_formatter(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                addr_internal,
                (int)(sizeof addr_internal * 8),
                addr_text,
                &addr_text_len));
        WOLFSENTRY_EXIT_ON_FALSE(addr_text_len == strlen("377/377/377"));
        WOLFSENTRY_EXIT_ON_FALSE(strcmp(addr_text, "377/377/377") == 0);

        addr_internal_len = (wolfsentry_addr_bits_t)(sizeof addr_internal * 8);
        WOLFSENTRY_EXIT_ON_FAILURE(
            my_addr_family_parser(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "0/0/0",
                strlen("0/0/0"),
                addr_internal,
                &addr_internal_len));
        WOLFSENTRY_EXIT_ON_FALSE(addr_internal_len == (wolfsentry_addr_bits_t)(sizeof addr_internal * 8));
        WOLFSENTRY_EXIT_ON_FALSE(memcmp(addr_internal, "\0\0\0", sizeof addr_internal) == 0);

        addr_internal_len = (wolfsentry_addr_bits_t)(sizeof addr_internal * 8);
        WOLFSENTRY_EXIT_ON_FAILURE(
            my_addr_family_parser(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "377/377/",
                strlen("377/377/"),
                addr_internal,
                &addr_internal_len));
        WOLFSENTRY_EXIT_ON_FALSE(addr_internal_len == 16);
        WOLFSENTRY_EXIT_ON_FALSE(memcmp(addr_internal, "\377\377", 2) == 0);

        addr_text_len = (int)sizeof addr_text;
        WOLFSENTRY_EXIT_ON_FAILURE(
            my_addr_family_formatter(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                addr_internal,
                16,
                addr_text,
                &addr_text_len));
        WOLFSENTRY_EXIT_ON_FALSE(addr_text_len == strlen("377/377/"));
        WOLFSENTRY_EXIT_ON_FALSE(strcmp(addr_text, "377/377/") == 0);

        addr_internal_len = (wolfsentry_addr_bits_t)(sizeof addr_internal * 8);
        WOLFSENTRY_EXIT_ON_FAILURE(
            my_addr_family_parser(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "377/",
                strlen("377/"),
                addr_internal,
                &addr_internal_len));
        WOLFSENTRY_EXIT_ON_FALSE(addr_internal_len == 8);
        WOLFSENTRY_EXIT_ON_FALSE(memcmp(addr_internal, "\377", 1) == 0);

        addr_text_len = (int)sizeof addr_text;
        WOLFSENTRY_EXIT_ON_FAILURE(
            my_addr_family_formatter(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                addr_internal,
                8,
                addr_text,
                &addr_text_len));
        WOLFSENTRY_EXIT_ON_FALSE(addr_text_len == strlen("377/"));
        WOLFSENTRY_EXIT_ON_FALSE(strcmp(addr_text, "377/") == 0);
    }

#ifdef WOLFSENTRY_PROTOCOL_NAMES

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_addr_family_handler_remove_byname(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "my_AF",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            &action_results));

    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_DEALLOCATED));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_addr_family_handler_install(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            WOLFSENTRY_AF_USER_OFFSET,
            "my_AF",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            my_addr_family_parser,
            my_addr_family_formatter,
            24 /* max_addr_bits */));

    {
        wolfsentry_addr_family_t family_number;

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_addr_family_pton(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "my_AF",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            &family_number));
    WOLFSENTRY_EXIT_ON_FALSE(family_number == WOLFSENTRY_AF_USER_OFFSET);

    WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(
        ITEM_NOT_FOUND,
        wolfsentry_addr_family_pton(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            "no_such_AF",
            WOLFSENTRY_LENGTH_NULL_TERMINATED, &family_number));
    }

    {
        struct wolfsentry_addr_family_bynumber *addr_family = NULL;
        const char *family_name;

        WOLFSENTRY_EXIT_ON_FAILURE(
            (wolfsentry_addr_family_ntop(
                  WOLFSENTRY_CONTEXT_ARGS_OUT,
                  WOLFSENTRY_AF_USER_OFFSET,
                  &addr_family,
                  &family_name)));
        WOLFSENTRY_EXIT_ON_FALSE((family_name != NULL) &&
                                 (! strcmp(family_name,"my_AF")));

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_addr_family_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, addr_family, &action_results));
        WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_DEALLOCATED));
    }

#endif /* WOLFSENTRY_PROTOCOL_NAMES */

    {
        wolfsentry_addr_family_parser_t parser;
        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_addr_family_get_parser(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                WOLFSENTRY_AF_USER_OFFSET,
                &parser));
        WOLFSENTRY_EXIT_ON_FALSE(parser == my_addr_family_parser);
    }
    {
        wolfsentry_addr_family_formatter_t formatter;
        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_addr_family_get_formatter(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                WOLFSENTRY_AF_USER_OFFSET,
                &formatter));
        WOLFSENTRY_EXIT_ON_FALSE(formatter == my_addr_family_formatter);
    }

#ifdef WOLFSENTRY_PROTOCOL_NAMES
    {
        wolfsentry_addr_family_t family_number;
        wolfsentry_addr_bits_t bits;
        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_addr_family_pton(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "inet",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &family_number));
        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_addr_family_max_addr_bits(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                family_number,
                &bits));
        WOLFSENTRY_EXIT_ON_FALSE(bits == 32);
        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_addr_family_pton(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "inet6",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &family_number));
        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_addr_family_max_addr_bits(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                family_number,
                &bits));
        WOLFSENTRY_EXIT_ON_FALSE(bits == 128);
        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_addr_family_pton(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "link",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &family_number));
        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_addr_family_max_addr_bits(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                family_number,
                &bits));
        WOLFSENTRY_EXIT_ON_FALSE(bits == 48);
    }
#endif /* WOLFSENTRY_PROTOCOL_NAMES */

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&wolfsentry)));

    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE));

    WOLFSENTRY_RETURN_OK;
}

#endif /* TEST_USER_ADDR_FAMILIES */

#ifdef TEST_JSON

#include "wolfsentry/wolfsentry_json.h"
#ifdef WOLFSENTRY_HAVE_JSON_DOM
#include <wolfsentry/centijson_dom.h>
#endif

static int test_json(const char *fname, const char *extra_fname) {
    wolfsentry_errcode_t ret;
    struct wolfsentry_context *wolfsentry;
    wolfsentry_ent_id_t id;

#ifdef WOLFSENTRY_HAVE_DESIGNATED_INITIALIZERS
    struct wolfsentry_eventconfig config = { .route_private_data_size = PRIVATE_DATA_SIZE, .route_private_data_alignment = PRIVATE_DATA_ALIGNMENT };
#else
    struct wolfsentry_eventconfig config = { PRIVATE_DATA_SIZE, PRIVATE_DATA_ALIGNMENT, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
#endif

    WOLFSENTRY_THREAD_HEADER_CHECKED(WOLFSENTRY_THREAD_FLAG_NONE);

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_init_ex(
            wolfsentry_build_settings,
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(WOLFSENTRY_TEST_HPI),
            &config,
            &wolfsentry,
            WOLFSENTRY_INIT_FLAG_NONE));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_addr_family_handler_install(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            WOLFSENTRY_AF_USER_OFFSET,
            "my_AF",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            my_addr_family_parser,
            my_addr_family_formatter,
            24 /* max_addr_bits */));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_addr_family_handler_install(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            WOLFSENTRY_AF_USER_OFFSET + 1,
            "my_AF2",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            my_addr_family_parser,
            my_addr_family_formatter,
            24 /* max_addr_bits */));

    WOLFSENTRY_EXIT_ON_FAILURE(json_feed_file(WOLFSENTRY_CONTEXT_ARGS_OUT, fname, WOLFSENTRY_CONFIG_LOAD_FLAG_NO_ROUTES_OR_EVENTS, 1));

    {
        static const char test_string[] = "hello";
        const char *value = NULL;
        int value_len = -1;
        struct wolfsentry_kv_pair_internal *kv_ref;

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_get_string(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "user-string",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &value,
                &value_len,
                &kv_ref));

        WOLFSENTRY_EXIT_ON_FALSE(value_len == (int)strlen(test_string));
        WOLFSENTRY_EXIT_ON_FALSE(strcmp(value, test_string) == 0);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_release_record(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &kv_ref));
    }

    {
        static const char user_cert_string[] =
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDnzCCAyWgAwIBAgICEAEwCgYIKoZIzj0EAwMwgZcxCzAJBgNVBAYTAlVTMRMw\n"
            "EQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0dGxlMRAwDgYDVQQKDAd3\n"
            "b2xmU1NMMRQwEgYDVQQLDAtEZXZlbG9wbWVudDEYMBYGA1UEAwwPd3d3LndvbGZz\n"
            "c2wuY29tMR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdvbGZzc2wuY29tMCAXDTIyMDIx\n"
            "NTEyNTAyNFoYDzIwNTIwMjA4MTI1MDI0WjCBlTELMAkGA1UEBhMCVVMxEzARBgNV\n"
            "BAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxEDAOBgNVBAoMB0VsaXB0\n"
            "aWMxEjAQBgNVBAsMCUVDQzM4NFNydjEYMBYGA1UEAwwPd3d3LndvbGZzc2wuY29t\n"
            "MR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdvbGZzc2wuY29tMHYwEAYHKoZIzj0CAQYF\n"
            "K4EEACIDYgAE6s+TTywJuzkUD1Zkw0C03w5jruVxSwDMBJf/4ek4lrtfkbJqzLU5\n"
            "X49wWfEB9lorAWxoC89VJa9tmEgKqHTJqRegDMP70yNo/gQ8Y1CIO7lPfGc09zup\n"
            "c+cbw1FeIhjso4IBQDCCATwwCQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMCBkAw\n"
            "HQYDVR0OBBYEFII78mUv87QAxrwG/XlCdUtl0c68MIHXBgNVHSMEgc8wgcyAFKvg\n"
            "wyZMGNRyu9KEjJwKBZKAElNSoYGdpIGaMIGXMQswCQYDVQQGEwJVUzETMBEGA1UE\n"
            "CAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEQMA4GA1UECgwHd29sZlNT\n"
            "TDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxGDAWBgNVBAMMD3d3dy53b2xmc3NsLmNv\n"
            "bTEfMB0GCSqGSIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbYIUaiYbTQIaM//CRxT5\n"
            "51VgWi5/ESkwDgYDVR0PAQH/BAQDAgOoMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAoG\n"
            "CCqGSM49BAMDA2gAMGUCMQCEPZBU/y/EetTYGOKzLbtCN0CmHwmD3rwEeoLcVRdC\n"
            "XBeqB0LcyPZQzRS3Bhk5HyQCMBNiS5/JoIzSac8WToa9nik4ROlKOmOgZjiV4n3j\n"
            "F+yUIbg9aV7K5ISc2mF9G1G/0Q==\n"
            "-----END CERTIFICATE-----\n";
        const char *value = NULL;
        int value_len = -1;
        struct wolfsentry_kv_pair_internal *kv_ref;

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_get_string(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "user-cert-string",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &value,
                &value_len,
                &kv_ref));

        WOLFSENTRY_EXIT_ON_FALSE(value_len == (int)strlen(user_cert_string));
        WOLFSENTRY_EXIT_ON_FALSE(strcmp(value, user_cert_string) == 0);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_release_record(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &kv_ref));
    }

    WOLFSENTRY_EXIT_ON_FAILURE(load_test_action_handlers(WOLFSENTRY_CONTEXT_ARGS_OUT));

    WOLFSENTRY_EXIT_ON_FAILURE(json_feed_file(WOLFSENTRY_CONTEXT_ARGS_OUT, fname, WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN, 1));

    WOLFSENTRY_EXIT_ON_FAILURE(json_feed_file(WOLFSENTRY_CONTEXT_ARGS_OUT, fname, WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT, 1));

    WOLFSENTRY_EXIT_ON_SUCCESS(json_feed_file(WOLFSENTRY_CONTEXT_ARGS_OUT, fname, WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH | WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT, 0));

    {
        static const char *bad_json[] = {
            "{ \"wolfsentry-config-version\" : 1, \"user-values\" : { \"user-string\" : \"should collide\" } }",
            "{ \"wolfsentry-config-version\" : 2, \"user-values\" : { \"ok-user-string\" : \"shouldn't collide\" } }",
            "{ \"wolfsentry-config-version\" : 1, \"not-user-values\" : { \"ok-user-string\" : \"shouldn't collide\" } }",
            "{ \"wolfsentry-config-version\" : 1, \"user-values\" : { \"too-long-user-string-123456789-abcdefghi\" : \"x\" } }",
        };
        const char **bad_json_i;
        for (bad_json_i = bad_json; bad_json_i < &bad_json[length_of_array(bad_json)]; ++bad_json_i) {
            WOLFSENTRY_EXIT_ON_SUCCESS(
                wolfsentry_config_json_oneshot(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    (const unsigned char *)*bad_json_i,
                    strlen(*bad_json_i),
                    WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH | WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT,
                    NULL,
                    0));
        }
    }

    {
        struct wolfsentry_route_table *main_routes, main_routes_copy;
        const char *value = NULL;
        int value_len = -1;
        struct wolfsentry_kv_pair_internal *kv_ref;
        struct {
            struct wolfsentry_sockaddr sa;
            byte addr_buf[4];
        } remote, local;
        wolfsentry_ent_id_t route_id;
        wolfsentry_route_flags_t inexact_matches;
        wolfsentry_action_res_t action_results;

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT, &main_routes));
        main_routes_copy = *main_routes;

        if (extra_fname) {
            remote.sa.sa_family = local.sa.sa_family = AF_INET;
            remote.sa.sa_proto = local.sa.sa_proto = IPPROTO_TCP;
            remote.sa.sa_port = 12345;
            local.sa.sa_port = 13579;
            remote.sa.addr_len = local.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;
            remote.sa.interface = local.sa.interface = 1;

            memcpy(remote.sa.addr,"\12\24\36\50",sizeof remote.addr_buf);
            memcpy(local.sa.addr,"\62\74\106\120",sizeof local.addr_buf);

            WOLFSENTRY_EXIT_ON_FAILURE(
                wolfsentry_route_event_dispatch(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    &remote.sa,
                    &local.sa,
                    WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                    NULL /* event_label */,
                    0 /* event_label_len */,
                    NULL /* caller_arg */,
                    &route_id,
                    &inexact_matches,
                    &action_results));
            WOLFSENTRY_EXIT_ON_FALSE(route_id == WOLFSENTRY_ENT_ID_NONE);
            WOLFSENTRY_EXIT_ON_FALSE(action_results == (WOLFSENTRY_ACTION_RES_REJECT | WOLFSENTRY_ACTION_RES_FALLTHROUGH));

            WOLFSENTRY_EXIT_ON_FAILURE(json_feed_file(WOLFSENTRY_CONTEXT_ARGS_OUT, extra_fname, WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH | WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT, 1));

            WOLFSENTRY_EXIT_ON_FAILURE(
                wolfsentry_route_event_dispatch(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    &remote.sa,
                    &local.sa,
                    WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                    NULL /* event_label */,
                    0 /* event_label_len */,
                    NULL /* caller_arg */,
                    &route_id,
                    &inexact_matches,
                    &action_results));
            WOLFSENTRY_EXIT_ON_TRUE(route_id == WOLFSENTRY_ENT_ID_NONE);
            WOLFSENTRY_EXIT_ON_FALSE(action_results == WOLFSENTRY_ACTION_RES_ACCEPT);

            memcpy(remote.sa.addr,"\13\24\36\50",sizeof remote.addr_buf);

            WOLFSENTRY_EXIT_ON_FAILURE(
                wolfsentry_route_event_dispatch(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    &remote.sa,
                    &local.sa,
                    WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                    NULL /* event_label */,
                    0 /* event_label_len */,
                    NULL /* caller_arg */,
                    &route_id,
                    &inexact_matches,
                    &action_results));
            WOLFSENTRY_EXIT_ON_FALSE(route_id == WOLFSENTRY_ENT_ID_NONE);
            WOLFSENTRY_EXIT_ON_FALSE(action_results == (WOLFSENTRY_ACTION_RES_REJECT | WOLFSENTRY_ACTION_RES_FALLTHROUGH));
        } else {
            static const char *trivial_test_json = "{ \"wolfsentry-config-version\" : 1, \"user-values\" : { \"extra-user-string\" : \"extra hello\" } }";
            WOLFSENTRY_EXIT_ON_FAILURE(
                wolfsentry_config_json_oneshot(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    (const unsigned char *)trivial_test_json,
                    strlen(trivial_test_json),
                    WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH | WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT,
                    NULL,
                    0));
        }

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT, &main_routes));

        WOLFSENTRY_EXIT_ON_FALSE((main_routes->max_purgeable_routes == main_routes_copy.max_purgeable_routes) &&
                                 (main_routes->default_policy == main_routes_copy.default_policy));

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_get_string(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "user-string",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &value,
                &value_len,
                &kv_ref));

        WOLFSENTRY_EXIT_ON_FALSE(value_len == (int)strlen("hello"));
        WOLFSENTRY_EXIT_ON_FALSE(strcmp(value, "hello") == 0);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_release_record(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &kv_ref));


        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_get_string(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                "extra-user-string",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                &value,
                &value_len,
                &kv_ref));

        WOLFSENTRY_EXIT_ON_FALSE(value_len == (int)strlen("extra hello"));
        WOLFSENTRY_EXIT_ON_FALSE(strcmp(value, "extra hello") == 0);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_user_value_release_record(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &kv_ref));
    }

    WOLFSENTRY_EXIT_ON_FAILURE(json_feed_file(WOLFSENTRY_CONTEXT_ARGS_OUT, fname, WOLFSENTRY_CONFIG_LOAD_FLAG_NONE, 1));

    {
        struct wolfsentry_route_table *main_routes, main_routes_copy;
        struct wolfsentry_cursor *cursor;
        WOLFSENTRY_BYTE_STREAM_DECLARE_STACK(json_out, 16384);
        WOLFSENTRY_BYTE_STREAM_DECLARE_HEAP(json_out2, 16384);
        wolfsentry_hitcount_t n_seen = 0;
        char err_buf[512];

        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_BYTE_STREAM_INIT_HEAP(json_out2) != NULL);

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT, &main_routes));

        WOLFSENTRY_BYTE_STREAM_RESET(json_out);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_route_table_dump_json_start(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                main_routes,
                &cursor,
                WOLFSENTRY_BYTE_STREAM_PTR(json_out),
                WOLFSENTRY_BYTE_STREAM_SPC(json_out),
                WOLFSENTRY_FORMAT_FLAG_NONE));

        for (;;) {
            ret = wolfsentry_route_table_dump_json_next(
                 WOLFSENTRY_CONTEXT_ARGS_OUT,
                 main_routes,
                 cursor,
                 WOLFSENTRY_BYTE_STREAM_PTR(json_out),
                 WOLFSENTRY_BYTE_STREAM_SPC(json_out),
                 WOLFSENTRY_FORMAT_FLAG_NONE);
            if (ret < 0) {
                if (! WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND))
                    WOLFSENTRY_EXIT_ON_FAILURE(ret);
                WOLFSENTRY_EXIT_ON_FAILURE(
                    wolfsentry_route_table_dump_json_end(
                        WOLFSENTRY_CONTEXT_ARGS_OUT,
                        main_routes,
                        &cursor,
                        WOLFSENTRY_BYTE_STREAM_PTR(json_out),
                        WOLFSENTRY_BYTE_STREAM_SPC(json_out),
                        WOLFSENTRY_FORMAT_FLAG_NONE));
            } else
                ++n_seen;
            if (ret < 0)
                break;
        }

        WOLFSENTRY_EXIT_ON_FALSE(n_seen == wolfsentry->routes->header.n_ents);

        main_routes_copy = *main_routes;

        ret = wolfsentry_config_json_oneshot(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            WOLFSENTRY_BYTE_STREAM_HEAD(json_out),
            WOLFSENTRY_BYTE_STREAM_LEN(json_out),
            WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT | WOLFSENTRY_CONFIG_LOAD_FLAG_FLUSH_ONLY_ROUTES,
            err_buf,
            sizeof err_buf);
        if (ret < 0) {
            (void)fprintf(stderr, "%.*s\n", (int)sizeof err_buf, err_buf);
            WOLFSENTRY_EXIT_ON_FAILURE(ret);
        }

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT, &main_routes));

        WOLFSENTRY_EXIT_ON_FALSE((main_routes->max_purgeable_routes == main_routes_copy.max_purgeable_routes) &&
                                 (main_routes->default_policy == main_routes_copy.default_policy));

        WOLFSENTRY_BYTE_STREAM_RESET(json_out2);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_route_table_dump_json_start(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                main_routes,
                &cursor,
                WOLFSENTRY_BYTE_STREAM_PTR(json_out2),
                WOLFSENTRY_BYTE_STREAM_SPC(json_out2),
                WOLFSENTRY_FORMAT_FLAG_NONE));

        for (;;) {
            ret = wolfsentry_route_table_dump_json_next(
                 WOLFSENTRY_CONTEXT_ARGS_OUT,
                 main_routes,
                 cursor,
                 WOLFSENTRY_BYTE_STREAM_PTR(json_out2),
                 WOLFSENTRY_BYTE_STREAM_SPC(json_out2),
                 WOLFSENTRY_FORMAT_FLAG_NONE);
            if (ret < 0) {
                WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND));
                WOLFSENTRY_EXIT_ON_FAILURE(
                    wolfsentry_route_table_dump_json_end(
                        WOLFSENTRY_CONTEXT_ARGS_OUT,
                        main_routes,
                        &cursor,
                        WOLFSENTRY_BYTE_STREAM_PTR(json_out2),
                        WOLFSENTRY_BYTE_STREAM_SPC(json_out2),
                        WOLFSENTRY_FORMAT_FLAG_NONE));
                break;
            }
        }

        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_BYTE_STREAM_LEN(json_out2) == WOLFSENTRY_BYTE_STREAM_LEN(json_out));
        WOLFSENTRY_EXIT_ON_FALSE(memcmp(json_out, json_out2, WOLFSENTRY_BYTE_STREAM_LEN(json_out)) == 0);

        ret = wolfsentry_config_json_oneshot(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            WOLFSENTRY_BYTE_STREAM_HEAD(json_out),
            WOLFSENTRY_BYTE_STREAM_LEN(json_out),
            WOLFSENTRY_CONFIG_LOAD_FLAG_FLUSH_ONLY_ROUTES,
            err_buf,
            sizeof err_buf);
        if (ret < 0) {
            (void)fprintf(stderr, "%.*s\n", (int)sizeof err_buf, err_buf);
            WOLFSENTRY_EXIT_ON_FAILURE(ret);
        }

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT, &main_routes));

        WOLFSENTRY_BYTE_STREAM_RESET(json_out2);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_route_table_dump_json_start(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                main_routes,
                &cursor,
                WOLFSENTRY_BYTE_STREAM_PTR(json_out2),
                WOLFSENTRY_BYTE_STREAM_SPC(json_out2),
                WOLFSENTRY_FORMAT_FLAG_NONE));

        for (;;) {
            ret = wolfsentry_route_table_dump_json_next(
                 WOLFSENTRY_CONTEXT_ARGS_OUT,
                 main_routes,
                 cursor,
                 WOLFSENTRY_BYTE_STREAM_PTR(json_out2),
                 WOLFSENTRY_BYTE_STREAM_SPC(json_out2),
                 WOLFSENTRY_FORMAT_FLAG_NONE);
            if (ret < 0) {
                WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND));
                WOLFSENTRY_EXIT_ON_FAILURE(
                    wolfsentry_route_table_dump_json_end(
                        WOLFSENTRY_CONTEXT_ARGS_OUT,
                        main_routes,
                        &cursor,
                        WOLFSENTRY_BYTE_STREAM_PTR(json_out2),
                        WOLFSENTRY_BYTE_STREAM_SPC(json_out2),
                        WOLFSENTRY_FORMAT_FLAG_NONE));
                break;
            }
        }

        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_BYTE_STREAM_LEN(json_out2) == WOLFSENTRY_BYTE_STREAM_LEN(json_out));
        WOLFSENTRY_EXIT_ON_FALSE(memcmp(json_out, json_out2, WOLFSENTRY_BYTE_STREAM_LEN(json_out)) == 0);

        WOLFSENTRY_EXIT_ON_FALSE(n_seen == wolfsentry->routes->header.n_ents);

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));

        WOLFSENTRY_BYTE_STREAM_FREE_HEAP(json_out2);
    }

    WOLFSENTRY_EXIT_ON_FAILURE(json_feed_file(WOLFSENTRY_CONTEXT_ARGS_OUT, fname, WOLFSENTRY_CONFIG_LOAD_FLAG_NONE, 1));

    {
        struct wolfsentry_context *ctx_clone;

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_clone(WOLFSENTRY_CONTEXT_ARGS_OUT, &ctx_clone, WOLFSENTRY_CLONE_FLAG_AS_AT_CREATION));
        WOLFSENTRY_EXIT_ON_FAILURE(json_feed_file(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(ctx_clone), fname, WOLFSENTRY_CONFIG_LOAD_FLAG_NONE, 1));

#ifdef WOLFSENTRY_HAVE_JSON_DOM
        {
            static const char *sequential_test_json = "{ \"wolfsentry-config-version\" : 1, \"user-values\" : { \"user-json2\" : { \"json\" : { \"z\" : 26, \"y\" : 25, \"x\" : 24 } } } }";

            WOLFSENTRY_EXIT_ON_FAILURE(
                wolfsentry_config_json_oneshot(
                    WOLFSENTRY_CONTEXT_ARGS_OUT_EX(ctx_clone),
                    (const unsigned char *)sequential_test_json,
                    strlen(sequential_test_json),
                    WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH | WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_MAINTAINDICTORDER,
                    NULL,
                    0));
        }
#endif

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_exchange(WOLFSENTRY_CONTEXT_ARGS_OUT, ctx_clone));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_free(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&ctx_clone)));
    }

    {
        struct wolfsentry_context *ctx_clone;

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_clone(WOLFSENTRY_CONTEXT_ARGS_OUT, &ctx_clone, WOLFSENTRY_CLONE_FLAG_NONE));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_free(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&ctx_clone)));
    }

    {
        struct wolfsentry_cursor *cursor;
        struct wolfsentry_route *route;
        struct wolfsentry_route_exports route_exports;
        struct wolfsentry_route_table *main_routes;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_get_main_table(WOLFSENTRY_CONTEXT_ARGS_OUT, &main_routes));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_table_iterate_start(WOLFSENTRY_CONTEXT_ARGS_OUT, main_routes, &cursor));
        for (ret = wolfsentry_route_table_iterate_current(main_routes, cursor, &route);
             ret >= 0;
             ret = wolfsentry_route_table_iterate_next(main_routes, cursor, &route)) {
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_export(WOLFSENTRY_CONTEXT_ARGS_OUT, route, &route_exports));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_exports_render(WOLFSENTRY_CONTEXT_ARGS_OUT, &route_exports, stdout));
            putc('\n', stdout);
        }
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_table_iterate_end(WOLFSENTRY_CONTEXT_ARGS_OUT, main_routes, &cursor));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));
    }

#ifndef WOLFSENTRY_NO_STDIO
    {
        struct wolfsentry_kv_pair_internal *kv_ref;
        struct wolfsentry_cursor *cursor;
        const struct wolfsentry_kv_pair *kv_exports;
        const char *val_type;
        char val_buf[2048];
        int val_buf_space;
        wolfsentry_hitcount_t n_seen = 0;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_user_values_iterate_start(WOLFSENTRY_CONTEXT_ARGS_OUT, &cursor));
        for (ret = wolfsentry_user_values_iterate_current(WOLFSENTRY_CONTEXT_ARGS_OUT, cursor, &kv_ref);
             ret >= 0;
             ret = wolfsentry_user_values_iterate_next(WOLFSENTRY_CONTEXT_ARGS_OUT, cursor, &kv_ref)) {
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_kv_pair_export(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_ref, &kv_exports));
            val_buf_space = sizeof val_buf;
            if (wolfsentry_kv_type_to_string(WOLFSENTRY_KV_TYPE(kv_exports), &val_type) < 0)
                val_type = "?";
            if (wolfsentry_kv_render_value(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_exports, val_buf, &val_buf_space) < 0) {
                if (WOLFSENTRY_KV_TYPE(kv_exports) == WOLFSENTRY_KV_BYTES)
                    (void)snprintf(val_buf, sizeof val_buf, "<%.*s>", (int)WOLFSENTRY_KV_V_BYTES_LEN(kv_exports), WOLFSENTRY_KV_V_BYTES(kv_exports));
                else
                    strcpy(val_buf,"?");
            }
            switch (WOLFSENTRY_KV_TYPE(kv_exports)) {
            case WOLFSENTRY_KV_TRUE:
            case WOLFSENTRY_KV_FALSE:
            case WOLFSENTRY_KV_NULL:
                printf("{ \"%.*s\" : %s }\n",
                       (int)WOLFSENTRY_KV_KEY_LEN(kv_exports),
                       WOLFSENTRY_KV_KEY(kv_exports),
                       val_buf);
                break;
            default:
                printf("{ \"%.*s\" : { \"%s\" : %s } }\n",
                       (int)WOLFSENTRY_KV_KEY_LEN(kv_exports),
                       WOLFSENTRY_KV_KEY(kv_exports),
                       val_type,
                       val_buf);
            }
            ++n_seen;
        }
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_user_values_iterate_end(WOLFSENTRY_CONTEXT_ARGS_OUT, &cursor));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));
        WOLFSENTRY_EXIT_ON_FALSE(n_seen == wolfsentry->user_values->header.n_ents);
    }
#endif

    {
        struct {
            struct wolfsentry_sockaddr sa;
            byte addr_buf[4];
        } remote, local;
        wolfsentry_route_flags_t inexact_matches;
        wolfsentry_action_res_t action_results;

        remote.sa.sa_family = local.sa.sa_family = AF_INET;
        remote.sa.sa_proto = local.sa.sa_proto = IPPROTO_TCP;
        remote.sa.sa_port = 12345;
        local.sa.sa_port = 443;
        remote.sa.addr_len = local.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;
        remote.sa.interface = local.sa.interface = 1;
        memcpy(remote.sa.addr,"\177\0\0\1",sizeof remote.addr_buf);
        memcpy(local.sa.addr,"\177\0\0\1",sizeof local.addr_buf);

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches, &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
    }

    {
        struct {
            struct wolfsentry_sockaddr sa;
            byte addr_buf[4];
        } remote, local;
        wolfsentry_route_flags_t inexact_matches;
        wolfsentry_action_res_t action_results;

        remote.sa.sa_family = local.sa.sa_family = WOLFSENTRY_AF_CHAOS;
        remote.sa.sa_proto = local.sa.sa_proto = IPPROTO_TCP;
        remote.sa.sa_port = 12345;
        local.sa.sa_port = 443;
        remote.sa.addr_len = local.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;
        remote.sa.interface = local.sa.interface = 1;
        memcpy(remote.sa.addr,"\177\0\0\1",sizeof remote.addr_buf);
        memcpy(local.sa.addr,"\177\0\0\1",sizeof local.addr_buf);

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches, &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_FALLTHROUGH));
    }

    {
        struct {
            struct wolfsentry_sockaddr sa;
            byte addr_buf[4];
        } remote, local;
        wolfsentry_route_flags_t inexact_matches;
        wolfsentry_action_res_t action_results;

        remote.sa.sa_family = local.sa.sa_family = AF_INET;
        remote.sa.sa_proto = local.sa.sa_proto = IPPROTO_TCP;
        remote.sa.sa_port = 0;
        local.sa.sa_port = 13579;
        remote.sa.addr_len = local.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;
        remote.sa.interface = local.sa.interface = 0;
        memcpy(remote.sa.addr,"\1\2\3\4",sizeof remote.addr_buf);
        memcpy(local.sa.addr,"\0\0\0\0",sizeof local.addr_buf);

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches, &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_PORT_RESET));
    }

#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
/* test bitmap-based matching of CAN addresses. */
    {
        struct {
            struct wolfsentry_sockaddr sa;
            byte addr_buf[4];
        } remote, local;
        wolfsentry_route_flags_t inexact_matches;
        wolfsentry_action_res_t action_results;

        remote.sa.sa_family = local.sa.sa_family = WOLFSENTRY_AF_CAN;
        remote.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;;
        local.sa.addr_len = 0;
        remote.sa.interface = local.sa.interface = 0;
        memcpy(remote.sa.addr,"\x1f\xff\xff\xed",sizeof remote.addr_buf);

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
                WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches, &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_USER0));

        memcpy(remote.sa.addr,"\x1f\xff\xff\xec",sizeof remote.addr_buf);

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
                WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches, &action_results));

        WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_USER0));

        memcpy(remote.sa.addr,"\x00\x00\x07\xcb",sizeof remote.addr_buf);

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
                WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches, &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_USER1));

        memcpy(remote.sa.addr,"\x1f\xff\xff\xff",sizeof remote.addr_buf);

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
                WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches, &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_USER2));

        memcpy(remote.sa.addr,"\x1f\xff\x01\x23",sizeof remote.addr_buf);

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
                WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches, &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_USER3));

        /* one prefix-matched CAN address to try */
        memcpy(remote.sa.addr,"\x15\x67\x01\x22",sizeof remote.addr_buf);

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
                WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD |
                WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches, &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_USER4));
    }
#endif /* WOLFSENTRY_ADDR_BITMASK_MATCHING */

#ifdef WOLFSENTRY_HAVE_JSON_DOM
    {
        unsigned char *test_json_document = NULL;
        int fd = -1;
        JSON_VALUE p_root;
        JSON_VALUE *v1 = NULL, *v2 = NULL, *v3 = NULL;
        struct stat st;
        static const JSON_CONFIG centijson_config = {
            65536,  /* max_total_len */
            1000,  /* max_total_values */
            20,  /* max_number_len */
            WOLFSENTRY_KV_MAX_VALUE_BYTES,  /* max_string_len */
            WOLFSENTRY_MAX_LABEL_BYTES,  /* max_key_len */
            10,  /* max_nesting_level */
            JSON_NOSCALARROOT   /* flags */
        };
        JSON_INPUT_POS json_pos;
        const unsigned char *s;
        size_t alen, i;

        WOLFSENTRY_EXIT_ON_SYSFAILURE(fd = open(fname, O_RDONLY));
        WOLFSENTRY_EXIT_ON_SYSFAILURE(fstat(fd, &st));
        WOLFSENTRY_EXIT_ON_SYSFALSE((test_json_document = (unsigned char *)malloc((size_t)st.st_size)) != NULL);
        WOLFSENTRY_EXIT_ON_SYSFALSE(read(fd, test_json_document, (size_t)st.st_size) == st.st_size);

        if ((ret = json_dom_parse(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), test_json_document, (size_t)st.st_size, &centijson_config,
                                  0 /* dom_flags */, &p_root, &json_pos)) < 0) {
            void *p = memchr((const char *)(test_json_document + json_pos.offset), '\n', (size_t)st.st_size - json_pos.offset);
            int linelen = p ? ((int)((unsigned char *)p - (test_json_document + json_pos.offset)) + (int)json_pos.column_number - 1) :
                (((int)st.st_size - (int)json_pos.offset) + (int)json_pos.column_number - 1);
            if (WOLFSENTRY_ERROR_DECODE_SOURCE_ID(ret) == WOLFSENTRY_SOURCE_ID_UNSET)
                (void)fprintf(stderr, "json_dom_parse failed at offset " SIZET_FMT ", L%u, col %u, with centijson code %d: %s\n", json_pos.offset,json_pos.line_number, json_pos.column_number, ret, json_dom_error_str(ret));
            else
                (void)fprintf(stderr, "json_dom_parse failed at offset " SIZET_FMT ", L%u, col %u, with " WOLFSENTRY_ERROR_FMT "\n", json_pos.offset,json_pos.line_number, json_pos.column_number, WOLFSENTRY_ERROR_FMT_ARGS(ret));
            (void)fprintf(stderr,"%.*s\n", linelen, test_json_document + json_pos.offset - json_pos.column_number + 1);
            exit(1);
        }

        WOLFSENTRY_EXIT_ON_TRUE((v1 = json_value_path(&p_root, "wolfsentry-config-version")) == NULL);
        WOLFSENTRY_EXIT_ON_FALSE(json_value_uint32(v1) == 1U);
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_centijson_errcode_translate(json_value_fini(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), v1)));

        WOLFSENTRY_EXIT_ON_TRUE((v1 = json_value_path(&p_root, "default-policies")) == NULL);
        WOLFSENTRY_EXIT_ON_TRUE((v2 = json_value_path(v1, "default-policy")) == NULL);
        WOLFSENTRY_EXIT_ON_TRUE((s = json_value_string(v2)) == NULL);
        WOLFSENTRY_EXIT_ON_FALSE(strcmp((const char *)s, "reject") == 0);
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_centijson_errcode_translate(json_value_fini(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), v2)));

        WOLFSENTRY_EXIT_ON_TRUE((v2 = json_value_path(v1, "default-event")) == NULL);
        WOLFSENTRY_EXIT_ON_TRUE((s = json_value_string(v2)) == NULL);
        WOLFSENTRY_EXIT_ON_FALSE(strcmp((const char *)s, "static-route-parent") == 0);
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_centijson_errcode_translate(json_value_fini(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), v2)));
        v2 = NULL;

        WOLFSENTRY_EXIT_ON_TRUE((v1 = json_value_path(&p_root, "static-routes-insert")) == NULL);
        WOLFSENTRY_EXIT_ON_TRUE((alen = json_value_array_size(v1)) == 0);
        for (i = 0; i < alen; ++i) {
            WOLFSENTRY_EXIT_ON_TRUE((v2 = json_value_array_get(v1, i)) == NULL);
            v3 = json_value_path(v2, "family");
            if (v3) {
                WOLFSENTRY_EXIT_ON_TRUE((json_value_string(v3) == NULL) && (json_value_int32(v3) <= 0));
                WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_centijson_errcode_translate(json_value_fini(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), v3)));
                v3 = NULL;
            }
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_centijson_errcode_translate(json_value_fini(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), v2)));
            v2 = NULL;
        }
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_centijson_errcode_translate(json_value_fini(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), v1)));

        WOLFSENTRY_EXIT_ON_TRUE((v1 = json_value_path(&p_root, "user-values/user-null")) == NULL);
        WOLFSENTRY_EXIT_ON_FALSE(json_value_type(v1) == JSON_VALUE_NULL);

        if (v3)
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_centijson_errcode_translate(json_value_fini(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), v3)));
        if (v2)
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_centijson_errcode_translate(json_value_fini(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), v2)));
        if (v1)
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_centijson_errcode_translate(json_value_fini(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), v1)));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_centijson_errcode_translate(json_value_fini(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), &p_root)));
        if (test_json_document != NULL)
            free(test_json_document);
        if (fd != -1)
            (void)close(fd);
    }
#endif /* WOLFSENTRY_HAVE_JSON_DOM */


    /* test aux event, flag bit filters & frobbing, and good/bad route insertion by
     * wolfsentry_builtin_action_track_peer()
     */
    {
        struct {
            struct wolfsentry_sockaddr sa;
            byte addr_buf[4];
        } remote, local;
        wolfsentry_route_flags_t inexact_matches;
        wolfsentry_action_res_t action_results;
        struct wolfsentry_route *ephemeral_route;
        wolfsentry_route_flags_t ephemeral_route_flags;
        int i;

        /* first, trigger insertion of DNS dynamic pinhole. */

        remote.sa.sa_family = local.sa.sa_family = AF_INET;
        remote.sa.sa_proto = local.sa.sa_proto = IPPROTO_UDP;
        remote.sa.sa_port = 53;
        local.sa.sa_port = 65432;
        remote.sa.addr_len = local.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;
        remote.sa.interface = local.sa.interface = 0;
        memcpy(remote.sa.addr,"\1\2\3\4",sizeof remote.addr_buf);
        memcpy(local.sa.addr,"\0\0\0\0",sizeof local.addr_buf);

        action_results = WOLFSENTRY_ACTION_RES_USER_BASE | (WOLFSENTRY_ACTION_RES_USER_BASE << 1U) | (WOLFSENTRY_ACTION_RES_USER_BASE << 3U);

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_route_event_dispatch_with_inited_result(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches,
                &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(action_results == (WOLFSENTRY_ACTION_RES_ACCEPT | WOLFSENTRY_ACTION_RES_INSERTED | WOLFSENTRY_ACTION_RES_USER_BASE | (WOLFSENTRY_ACTION_RES_USER_BASE << 1U) | (WOLFSENTRY_ACTION_RES_USER_BASE << 3U)));

        /* next, make sure the dynamic pinhole is live, by checking for an exact match. */

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_route_event_dispatch(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches,
                &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(action_results == (WOLFSENTRY_ACTION_RES_ACCEPT | WOLFSENTRY_ACTION_RES_USER5));
        WOLFSENTRY_EXIT_ON_FALSE(inexact_matches == WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD);

        /* make sure the pinhole route has the expected flags on it. */

        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_table_ent_get_by_id(WOLFSENTRY_CONTEXT_ARGS_OUT, id, (struct wolfsentry_table_ent_header **)&ephemeral_route));
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_get_flags(ephemeral_route, &ephemeral_route_flags));
        /* make sure it's really ephemeral. */
        WOLFSENTRY_EXIT_ON_FALSE(ephemeral_route->meta.purge_after != 0);
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));
        WOLFSENTRY_EXIT_ON_FALSE(ephemeral_route_flags ==
                                 (WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD |
                                  WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
                                  WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT |
                                  WOLFSENTRY_ROUTE_FLAG_IN_TABLE |
                                  WOLFSENTRY_ROUTE_FLAG_INSERT_ACTIONS_CALLED |
                                  WOLFSENTRY_ROUTE_FLAG_GREENLISTED));

        /* now trigger insertion of a tracking rule to catch a simulated port scan. */

        remote.sa.sa_family = local.sa.sa_family = AF_INET;
        remote.sa.sa_proto = local.sa.sa_proto = IPPROTO_TCP;
        remote.sa.sa_port = 1234;
        local.sa.sa_port = 65432;
        remote.sa.addr_len = local.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;
        remote.sa.interface = local.sa.interface = 0;
        memcpy(remote.sa.addr,"\1\2\3\4",sizeof remote.addr_buf);
        memcpy(local.sa.addr,"\0\0\0\0",sizeof local.addr_buf);

        action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE | WOLFSENTRY_ACTION_RES_DEROGATORY;

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_route_event_dispatch_with_inited_result(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches,
                &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(action_results == (WOLFSENTRY_ACTION_RES_REJECT | WOLFSENTRY_ACTION_RES_DEROGATORY | WOLFSENTRY_ACTION_RES_FALLTHROUGH | WOLFSENTRY_ACTION_RES_INSERTED | WOLFSENTRY_ACTION_RES_UNREACHABLE | (WOLFSENTRY_ACTION_RES_USER_BASE << 4U)));

        /* iteratively increment the derog-thresh-for-penalty-boxing. */
        for (i=0; i<3; ++i) {
            action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE | WOLFSENTRY_ACTION_RES_DEROGATORY;

            WOLFSENTRY_EXIT_ON_FAILURE(
                wolfsentry_route_event_dispatch_with_inited_result(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    &remote.sa,
                    &local.sa,
                    WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                    "call-in-from-unit-test",
                    WOLFSENTRY_LENGTH_NULL_TERMINATED,
                    (void *)0x12345678 /* caller_arg */,
                    &id,
                    &inexact_matches,
                    &action_results));

            WOLFSENTRY_EXIT_ON_FALSE(action_results == (WOLFSENTRY_ACTION_RES_REJECT | WOLFSENTRY_ACTION_RES_DEROGATORY | WOLFSENTRY_ACTION_RES_FALLTHROUGH | WOLFSENTRY_ACTION_RES_UNREACHABLE | WOLFSENTRY_ACTION_RES_USER5));
        }

        /* trigger the penalty boxing. */
        action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE | WOLFSENTRY_ACTION_RES_DEROGATORY;

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_route_event_dispatch_with_inited_result(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches,
                &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(action_results == (WOLFSENTRY_ACTION_RES_REJECT | WOLFSENTRY_ACTION_RES_DEROGATORY | WOLFSENTRY_ACTION_RES_UPDATE | WOLFSENTRY_ACTION_RES_UNREACHABLE | WOLFSENTRY_ACTION_RES_USER5));

        /* confirm the penalty boxing. */
        action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE | WOLFSENTRY_ACTION_RES_DEROGATORY;

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_route_event_dispatch_with_inited_result(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches,
                &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(action_results == (WOLFSENTRY_ACTION_RES_REJECT | WOLFSENTRY_ACTION_RES_DEROGATORY | WOLFSENTRY_ACTION_RES_UNREACHABLE | WOLFSENTRY_ACTION_RES_USER5));


#ifdef WOLFSENTRY_UNITTEST_BENCHMARKS
        {
            struct timespec start_at, end_at;
            uint64_t start_at_cycles, end_at_cycles;
            double ns_per_call, cycles_per_call;

            test_action_enabled = 0;

            WOLFSENTRY_EXIT_ON_SYSFAILURE(clock_gettime(CLOCK_MONOTONIC, &start_at));
            start_at_cycles = get_intel_cycles();
            for (i=0; i<1000000; ++i) {
                action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE | WOLFSENTRY_ACTION_RES_DEROGATORY;
                WOLFSENTRY_EXIT_ON_FAILURE(
                    wolfsentry_route_event_dispatch_with_inited_result(
                        WOLFSENTRY_CONTEXT_ARGS_OUT,
                        &remote.sa,
                        &local.sa,
                        WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                        "call-in-from-unit-test",
                        WOLFSENTRY_LENGTH_NULL_TERMINATED,
                        (void *)0x12345678 /* caller_arg */,
                        &id,
                        &inexact_matches,
                        &action_results));
            }
            end_at_cycles = get_intel_cycles();
            WOLFSENTRY_EXIT_ON_SYSFAILURE(clock_gettime(CLOCK_MONOTONIC, &end_at));
            ns_per_call = ((double)(end_at.tv_sec - start_at.tv_sec) * 1000000000.0 + (double)(end_at.tv_nsec - start_at.tv_nsec)) / (double)i;
            cycles_per_call = (double)(end_at_cycles - start_at_cycles) / (double)i;
            printf("benchmark wolfsentry_route_event_dispatch_with_inited_result() with JSON-loaded route table, matching penalty-boxed route: %.2f ns/call %.2f cycles/call\n", ns_per_call, cycles_per_call);

#ifdef WOLFSENTRY_MAX_CYCLES_PER_CALL_JSON_LOADED
	if (cycles_per_call > (double)WOLFSENTRY_MAX_CYCLES_PER_CALL_JSON_LOADED) {
            (void)fprintf(stderr, "benchmark wolfsentry_route_event_dispatch_with_inited_result() with JSON-loaded route table, matching penalty-boxed route: measured %.2f cycles/call exceeds max %.2f\n", cycles_per_call, (double)WOLFSENTRY_MAX_CYCLES_PER_CALL_JSON_LOADED);
            WOLFSENTRY_EXIT_ON_TRUE(cycles_per_call > (double)WOLFSENTRY_MAX_CYCLES_PER_CALL_JSON_LOADED);
        }
#endif

            WOLFSENTRY_EXIT_ON_FALSE(action_results == (WOLFSENTRY_ACTION_RES_REJECT | WOLFSENTRY_ACTION_RES_DEROGATORY | WOLFSENTRY_ACTION_RES_UNREACHABLE | WOLFSENTRY_ACTION_RES_USER5));

            test_action_enabled = 1;
        }
#endif /* WOLFSENTRY_UNITTEST_BENCHMARKS */


        /* force release from penalty box with explicit _RES_COMMENDABLE.
         * note that the result will still be _REJECT because of the fallthrough policy in test-config.json.
         * in practice, port scanning defenses are only needed on configurations that default open, in which
         * case release from the penalty box would restore fallthrough to _ACCEPT.
         * on the other hand, where port scanning is being tracked purely for purposes of IDS-type visibility,
         * fallthrough to _REJECT is perfectly appropriate.
         */
        action_results = WOLFSENTRY_ACTION_RES_COMMENDABLE;

        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_route_event_dispatch_with_inited_result(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches,
                &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(action_results == (WOLFSENTRY_ACTION_RES_REJECT | WOLFSENTRY_ACTION_RES_COMMENDABLE | WOLFSENTRY_ACTION_RES_UPDATE | WOLFSENTRY_ACTION_RES_FALLTHROUGH | WOLFSENTRY_ACTION_RES_USER5));

        /* recheck to confirm no update on a second match with zero initial action_results. */
        WOLFSENTRY_EXIT_ON_FAILURE(
            wolfsentry_route_event_dispatch(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                &remote.sa,
                &local.sa,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                "call-in-from-unit-test",
                WOLFSENTRY_LENGTH_NULL_TERMINATED,
                (void *)0x12345678 /* caller_arg */,
                &id,
                &inexact_matches,
                &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(action_results == (WOLFSENTRY_ACTION_RES_REJECT | WOLFSENTRY_ACTION_RES_FALLTHROUGH | WOLFSENTRY_ACTION_RES_USER5));

        {
            struct wolfsentry_route_exports ephemeral_route_exports;
            wolfsentry_ent_id_t reinsert_id;
            wolfsentry_time_t purge_after_after_deletion;

            /* increment connection_count. */
            action_results = WOLFSENTRY_ACTION_RES_CONNECT;
            WOLFSENTRY_EXIT_ON_FAILURE(
                wolfsentry_route_event_dispatch_with_inited_result(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    &remote.sa,
                    &local.sa,
                    WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                    "call-in-from-unit-test",
                    WOLFSENTRY_LENGTH_NULL_TERMINATED,
                    (void *)0x12345678 /* caller_arg */,
                    &id,
                    &inexact_matches,
                    &action_results));

            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_table_ent_get_by_id(WOLFSENTRY_CONTEXT_ARGS_OUT, id, (struct wolfsentry_table_ent_header **)&ephemeral_route));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_export(WOLFSENTRY_CONTEXT_ARGS_OUT, ephemeral_route, &ephemeral_route_exports));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));

            WOLFSENTRY_EXIT_UNLESS_EXPECTED_SUCCESS(
                DEFERRED,
                wolfsentry_route_delete_by_id(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    NULL /* caller_arg */,
                    id,
                    NULL /* trigger_label */,
                    0 /* trigger_label_len */,
                    &action_results));

            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_table_ent_get_by_id(WOLFSENTRY_CONTEXT_ARGS_OUT, id, (struct wolfsentry_table_ent_header **)&ephemeral_route));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_export(WOLFSENTRY_CONTEXT_ARGS_OUT, ephemeral_route, &ephemeral_route_exports));
            purge_after_after_deletion = ephemeral_route_exports.meta.purge_after;
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));

            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_reset_metadata_exports(&ephemeral_route_exports));

            WOLFSENTRY_EXIT_UNLESS_EXPECTED_SUCCESS(
                ALREADY_OK,
                wolfsentry_route_insert_by_exports(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    NULL /* caller_arg */,
                    &ephemeral_route_exports,
                    &reinsert_id,
                    &action_results));

            WOLFSENTRY_EXIT_ON_FALSE(reinsert_id == id);

            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_table_ent_get_by_id(WOLFSENTRY_CONTEXT_ARGS_OUT, id, (struct wolfsentry_table_ent_header **)&ephemeral_route));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_export(WOLFSENTRY_CONTEXT_ARGS_OUT, ephemeral_route, &ephemeral_route_exports));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));

            WOLFSENTRY_EXIT_ON_TRUE(ephemeral_route_exports.meta.purge_after == purge_after_after_deletion);
            WOLFSENTRY_EXIT_ON_FALSE(ephemeral_route_exports.meta.connection_count == 1);

            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_mutex(WOLFSENTRY_CONTEXT_ARGS_OUT));
            WOLFSENTRY_EXIT_ON_FAILURE(
                wolfsentry_route_purge_time_set(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    ephemeral_route,
                    0));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));

            /* decrement connection_count. */
            action_results = WOLFSENTRY_ACTION_RES_DISCONNECT;
            WOLFSENTRY_EXIT_ON_FAILURE(
                wolfsentry_route_event_dispatch_with_inited_result(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    &remote.sa,
                    &local.sa,
                    WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
                    "call-in-from-unit-test",
                    WOLFSENTRY_LENGTH_NULL_TERMINATED,
                    (void *)0x12345678 /* caller_arg */,
                    &id,
                    &inexact_matches,
                    &action_results));

            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_table_ent_get_by_id(WOLFSENTRY_CONTEXT_ARGS_OUT, id, (struct wolfsentry_table_ent_header **)&ephemeral_route));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_export(WOLFSENTRY_CONTEXT_ARGS_OUT, ephemeral_route, &ephemeral_route_exports));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));

            WOLFSENTRY_EXIT_ON_FALSE(ephemeral_route_exports.meta.purge_after == 0);
            WOLFSENTRY_EXIT_ON_FALSE(ephemeral_route_exports.meta.connection_count == 0);

            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_mutex(WOLFSENTRY_CONTEXT_ARGS_OUT));
            WOLFSENTRY_EXIT_ON_FAILURE(
                wolfsentry_route_purge_time_set(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    ephemeral_route,
                    1));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));

            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_stale_purge(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL, NULL));

            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_lock_shared(WOLFSENTRY_CONTEXT_ARGS_OUT));
            WOLFSENTRY_EXIT_UNLESS_EXPECTED_FAILURE(ITEM_NOT_FOUND, wolfsentry_table_ent_get_by_id(WOLFSENTRY_CONTEXT_ARGS_OUT, id, (struct wolfsentry_table_ent_header **)&ephemeral_route));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_context_unlock(WOLFSENTRY_CONTEXT_ARGS_OUT));
        }
    }

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&wolfsentry)));

    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE));

    WOLFSENTRY_RETURN_OK;
}

#endif /* TEST_JSON */

#ifdef TEST_JSON_CORPUS

#include "wolfsentry/wolfsentry_json.h"
#include <wolfsentry/centijson_dom.h>

static int dump_string_for_json(const unsigned char* str, size_t size, void* user_data) {
    (void)user_data;
    printf("%.*s", (int)size, str);
    return 0;
}

static int test_json_corpus(void) {
    wolfsentry_errcode_t ret = WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);
    struct wolfsentry_context *wolfsentry;

    WOLFSENTRY_THREAD_HEADER_CHECKED(WOLFSENTRY_THREAD_FLAG_NONE);

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_init_ex(
            wolfsentry_build_settings,
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(WOLFSENTRY_TEST_HPI),
            NULL /* config */,
            &wolfsentry,
            WOLFSENTRY_INIT_FLAG_NONE));

    do {
        static JSON_CONFIG centijson_config = {
            65536,  /* max_total_len */
            10000,  /* max_total_values */
            20,  /* max_number_len */
            4096,  /* max_string_len */
            255,  /* max_key_len */
            10,  /* max_nesting_level */
            0 /*JSON_IGNOREILLUTF8VALUE*/ /* flags */
        };
        unsigned dom_flags = 0;
        JSON_VALUE p_root, p_clone;
        JSON_INPUT_POS json_pos;
        DIR *corpus_dir;
        int corpus_dirfd;
        struct dirent *scenario_ent;
        int scenario_fd;
        struct stat st;
        const unsigned char *scenario = MAP_FAILED;
        const char *corpus_path;
        char *cp, *endcp;
        int dump_json = 0;
        int ignore_failed_parse = 0;

        if (! (corpus_path = getenv("JSON_TEST_CORPUS_DIR"))) {
            printf("JSON_TEST_CORPUS_DIR unset -- skipping test_json_corpus().\n");
            ret = 0;
            break;
        }

#define PARSE_UNSIGNED_EV(ev, type, elname) do { if ((cp = getenv(ev))) { \
            centijson_config.elname = (type)strtoul(cp, &endcp, 0);     \
            WOLFSENTRY_EXIT_ON_FALSE((endcp != cp) || (*endcp == 0));   \
            } } while (0)

        PARSE_UNSIGNED_EV("JSON_TEST_CORPUS_MAX_TOTAL_LEN", size_t, max_total_len);
        PARSE_UNSIGNED_EV("JSON_TEST_CORPUS_MAX_TOTAL_VALUES", size_t, max_total_values);
        PARSE_UNSIGNED_EV("JSON_TEST_CORPUS_MAX_STRING_LEN", size_t, max_string_len);
        PARSE_UNSIGNED_EV("JSON_TEST_CORPUS_MAX_KEY_LEN", size_t, max_key_len);
        PARSE_UNSIGNED_EV("JSON_TEST_CORPUS_MAX_NESTING_LEVEL", unsigned, max_nesting_level);

        if ((cp = getenv("JSON_TEST_CORPUS_FLAGS"))) {
            static const struct { const char *name; unsigned int flag; unsigned int dom_flag; } centijson_flag_map[] = {
#define FLAG_MAP_ENT(name) { #name, JSON_ ## name, 0 }
                FLAG_MAP_ENT(NONULLASROOT),
                FLAG_MAP_ENT(NOBOOLASROOT),
                FLAG_MAP_ENT(NONUMBERASROOT),
                FLAG_MAP_ENT(NOSTRINGASROOT),
                FLAG_MAP_ENT(NOARRAYASROOT),
                FLAG_MAP_ENT(NOOBJECTASROOT),
                FLAG_MAP_ENT(IGNOREILLUTF8KEY),
                FLAG_MAP_ENT(FIXILLUTF8KEY),
                FLAG_MAP_ENT(IGNOREILLUTF8VALUE),
                FLAG_MAP_ENT(FIXILLUTF8VALUE),
                FLAG_MAP_ENT(NOSCALARROOT) /* compound flag */,
                FLAG_MAP_ENT(NOVECTORROOT) /* compound flag */,
#define FLAG_MAP_DOM_ENT(name) { #name, 0, JSON_DOM_ ## name }
                FLAG_MAP_DOM_ENT(DUPKEY_ABORT),
                FLAG_MAP_DOM_ENT(DUPKEY_USEFIRST),
                FLAG_MAP_DOM_ENT(DUPKEY_USELAST),
                FLAG_MAP_DOM_ENT(MAINTAINDICTORDER)
            };
            while (*cp != 0) {
                size_t label_len, i;
                endcp = strchr(cp, '|');
                if (endcp)
                    label_len = (size_t)(endcp - cp);
                else
                    label_len = strlen(cp);
                for (i = 0; i < sizeof centijson_flag_map / sizeof centijson_flag_map[0]; ++i) {
                    if ((label_len == strlen(centijson_flag_map[i].name)) && (! memcmp(cp, centijson_flag_map[i].name, label_len))) {
                        centijson_config.flags |= centijson_flag_map[i].flag;
                        dom_flags |= centijson_flag_map[i].dom_flag;
                        break;
                    }
                }
                if (i == sizeof centijson_flag_map / sizeof centijson_flag_map[0]) {
                    (void)fprintf(stderr, "unrecognized flag \"%.*s\" in JSON_TEST_CORPUS_FLAGS.\n", (int)label_len, cp);
                    exit(1);
                }
                cp += label_len;
                if (*cp == '|')
                    ++cp;
            }
        }

        if (getenv("JSON_TEST_CORPUS_DUMP"))
            dump_json = 1;

        if (getenv("JSON_TEST_CORPUS_IGNORE_FAILED_PARSE"))
            ignore_failed_parse = 1;

        corpus_dir = opendir(corpus_path);
        if (! corpus_dir) {
            perror(corpus_path);
            ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
            break;
        }
        corpus_dirfd = dirfd(corpus_dir);
        if (corpus_dirfd < 0) {
            perror(corpus_path);
            ret = WOLFSENTRY_ERROR_ENCODE(SYS_OP_FATAL);
            break;
        }

        json_value_init_null(&p_root);
        json_value_init_null(&p_clone);

        while ((scenario_ent = readdir(corpus_dir))) {
            size_t namelen = strlen(scenario_ent->d_name);
            if (namelen <= strlen(".json"))
                continue;
            if (strcmp(scenario_ent->d_name + strlen(scenario_ent->d_name) - strlen(".json"), ".json") != 0)
                continue;
            scenario_fd = openat(corpus_dirfd, scenario_ent->d_name, O_RDONLY);
            if (scenario_fd < 0) {
                perror(scenario_ent->d_name);
                continue;
            }
            if (fstat(scenario_fd, &st) < 0) {
                perror(scenario_ent->d_name);
                goto inner_cleanup;
            }
            scenario = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, scenario_fd, 0);
            if (scenario == MAP_FAILED) {
                perror(scenario_ent->d_name);
                goto inner_cleanup;
            }

            printf("%s\n", scenario_ent->d_name);

            if ((ret = json_dom_parse(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), scenario, (size_t)st.st_size, &centijson_config,
                                      dom_flags, &p_root, &json_pos)) < 0) {
                void *p = memchr((const char *)(scenario + json_pos.offset), '\n', (size_t)st.st_size - json_pos.offset);
                int linelen = p ? ((int)((unsigned char *)p - (scenario + json_pos.offset)) + (int)json_pos.column_number - 1) :
                    (((int)st.st_size - (int)json_pos.offset) + (int)json_pos.column_number - 1);
                if (WOLFSENTRY_ERROR_DECODE_SOURCE_ID(ret) == WOLFSENTRY_SOURCE_ID_UNSET)
                    (void)fprintf(stderr, "%s/%s: json_dom_parse failed at offset " SIZET_FMT ", L%u, col %u, with centijson code %d: %s\n", corpus_path, scenario_ent->d_name, json_pos.offset,json_pos.line_number, json_pos.column_number, ret, json_dom_error_str(ret));
                else
                    (void)fprintf(stderr, "%s/%s: json_dom_parse failed at offset " SIZET_FMT ", L%u, col %u, with " WOLFSENTRY_ERROR_FMT "\n", corpus_path, scenario_ent->d_name, json_pos.offset,json_pos.line_number, json_pos.column_number, WOLFSENTRY_ERROR_FMT_ARGS(ret));
                (void)fprintf(stderr,"%.*s\n", linelen, scenario + json_pos.offset - json_pos.column_number + 1);
                goto inner_cleanup;
            }

            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_centijson_errcode_translate(json_value_clone(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), &p_root, &p_clone)));

            if (dump_json) {
                WOLFSENTRY_EXIT_ON_FAILURE(json_dom_dump(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), &p_clone, dump_string_for_json, NULL /* user_data */, 2 /* tab_width */, JSON_DOM_DUMP_INDENTWITHSPACES | (dom_flags & JSON_DOM_MAINTAINDICTORDER ? JSON_DOM_DUMP_PREFERDICTORDER : 0)));
            }

        inner_cleanup:

            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_centijson_errcode_translate(json_value_fini(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), &p_root)));
            WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_centijson_errcode_translate(json_value_fini(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), &p_clone)));
            if (scenario_fd >= 0)
                (void)close(scenario_fd);
            if (scenario != MAP_FAILED) {
                munmap((void *)scenario, (size_t)st.st_size);
                scenario = MAP_FAILED;
            }

            if ((ret < 0) && (! ignore_failed_parse)) {
                ret = wolfsentry_centijson_errcode_translate(ret);
                ret = WOLFSENTRY_ERROR_RECODE(ret);
                break;
            }
        }

        WOLFSENTRY_EXIT_ON_SYSFAILURE(closedir(corpus_dir));
    } while (0);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(&wolfsentry)));

    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE));

    WOLFSENTRY_ERROR_RERETURN(ret);
}

#endif /* TEST_JSON_CORPUS */

#ifdef FREERTOS

int main(int argc, char* argv[]) {
    int ret = 0;
    (void)argc;
    (void)argv;

#ifdef TEST_LWIP
    #ifdef TEST_JSON_CONFIG_PATH
    ret = test_lwip(TEST_JSON_CONFIG_PATH);
    #else
    ret = test_lwip(NULL);
    #endif
#endif
    if (ret < 0)
        return ret;
    else
        return 0;
}

#else /* !FREERTOS */

int main(int argc, char* argv[]) {
    wolfsentry_errcode_t ret = 0; /* cppcheck-suppress unreadVariable
                                   */
    int err = 0;
    (void)argc;
    (void)argv;

#ifdef WOLFSENTRY_ERROR_STRINGS
    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_REGISTER_SOURCE());
    WOLFSENTRY_EXIT_ON_FAILURE(WOLFSENTRY_REGISTER_ERROR(UNIT_TEST_FAILURE, UNIT_TEST_FAILURE_MSG));
#endif

#ifdef TEST_INIT
    ret = test_init();
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        (void)fprintf(stderr, "test_init failed, " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err = 1;
    }
#endif

#ifdef TEST_LWIP
    #ifdef TEST_JSON_CONFIG_PATH
    ret = test_lwip(TEST_JSON_CONFIG_PATH);
    #else
    ret = test_lwip(NULL);
    #endif
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        (void)fprintf(stderr, "test_lwip failed, " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err = 1;
    }
#endif

#ifdef TEST_RWLOCKS
    ret = test_rw_locks();
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        (void)fprintf(stderr, "test_rw_locks failed, " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err = 1;
    }
#endif

#ifdef TEST_STATIC_ROUTES
    ret = test_static_routes();
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        (void)fprintf(stderr, "test_static_routes failed, " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err = 1;
    }
#endif

#ifdef TEST_DYNAMIC_RULES
    ret = test_dynamic_rules();
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        (void)fprintf(stderr, "test_dynamic_rules failed, " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err = 1;
    }
#endif

#ifdef TEST_USER_VALUES
    ret = test_user_values();
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        (void)fprintf(stderr, "test_user_values failed, " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err = 1;
    }
#endif

#ifdef TEST_USER_ADDR_FAMILIES
    ret = test_user_addr_families();
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        (void)fprintf(stderr, "test_addr_families failed, " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err = 1;
    }
#endif

#ifdef TEST_JSON
#if defined(WOLFSENTRY_PROTOCOL_NAMES) && !defined(WOLFSENTRY_NO_GETPROTOBY)
#ifdef EXTRA_TEST_JSON_CONFIG_PATH
    ret = test_json(TEST_JSON_CONFIG_PATH, EXTRA_TEST_JSON_CONFIG_PATH);
#else
    ret = test_json(TEST_JSON_CONFIG_PATH, NULL);
#endif
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        (void)fprintf(stderr, "test_json failed for " TEST_JSON_CONFIG_PATH ", " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err = 1;
    }
#endif
    ret = test_json(TEST_NUMERIC_JSON_CONFIG_PATH, NULL);
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        (void)fprintf(stderr, "test_json failed for " TEST_NUMERIC_JSON_CONFIG_PATH ", " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err = 1;
    }
#endif

#ifdef TEST_JSON_CORPUS
    ret = test_json_corpus();
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        (void)fprintf(stderr, "test_json_corpus failed, " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err = 1;
    }
#endif

    WOLFSENTRY_RETURN_VALUE(err);
}

#endif /* !FREERTOS */

#ifdef FREERTOS

/* provide warning-free dummy syscall and callback stubs for newlib-nano (same
 * effect as -specs=nosys.specs, but no warnings) and FreeRTOS dependencies.
 */
void _exit(int status) {
    (void)status;
    for (;;);
}
int _close(int fd);
int _close(int fd) {
    (void)fd;
    return -1;
}
int _lseek(int fd, off_t offset, int whence);
int _lseek(int fd, off_t offset, int whence) {
    (void)fd;
    (void)offset;
    (void)whence;
    return -1;
}
ssize_t _read(int fildes, void *buf, size_t nbyte);
ssize_t _read(int fildes, void *buf, size_t nbyte) {
    (void)fildes;
    (void)buf;
    (void)nbyte;
    return -1;
}
void *_sbrk(intptr_t increment);
void *_sbrk(intptr_t increment) {
    (void)increment;
    return NULL;
}
ssize_t _write(int fd, const void *buf, size_t count);
ssize_t _write(int fd, const void *buf, size_t count) {
    (void)fd;
    (void)buf;
    (void)count;
    return -1;
}
int _kill(pid_t pid, int sig);
int _kill(pid_t pid, int sig) {
    (void)pid;
    (void)sig;
    return -1;
}
int _getpid(void);
int _getpid(void) {
    return -1;
}
struct stat;
int _fstat(int fd, struct stat *statbuf);
int _fstat(int fd, struct stat *statbuf) {
    (void)fd;
    (void)statbuf;
    return -1;
}
int _isatty(int fd);
int _isatty(int fd) {
    (void)fd;
    return 0; /* note, return 0 for error, not -1. */
}

void vApplicationMallocFailedHook(void) {
    for(;;);
}

void vApplicationStackOverflowHook(TaskHandle_t pxTask, char *pcTaskName) {
    (void)pcTaskName;
    (void)pxTask;
    for(;;);
}

void vApplicationTickHook(void) {
}

void vAssertCalled( const char *pcFileName, uint32_t ulLine ) {
    (void)pcFileName;
    (void)ulLine;
}

void vApplicationGetIdleTaskMemory(StaticTask_t **ppxIdleTaskTCBBuffer, StackType_t **ppxIdleTaskStackBuffer, uint32_t *pulIdleTaskStackSize) {
    (void)ppxIdleTaskTCBBuffer;
    (void)ppxIdleTaskStackBuffer;
    (void)pulIdleTaskStackSize;
}

void vApplicationGetTimerTaskMemory(StaticTask_t **ppxTimerTaskTCBBuffer, StackType_t **ppxTimerTaskStackBuffer, uint32_t *pulTimerTaskStackSize);
void vApplicationGetTimerTaskMemory(StaticTask_t **ppxTimerTaskTCBBuffer, StackType_t **ppxTimerTaskStackBuffer, uint32_t *pulTimerTaskStackSize) {
    (void)ppxTimerTaskTCBBuffer;
    (void)ppxTimerTaskStackBuffer;
    (void)pulTimerTaskStackSize;
}

#endif
