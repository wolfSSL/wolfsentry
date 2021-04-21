/*
 * unittests.c
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

#define _GNU_SOURCE

#include "../src/wolfsentry_internal.h"

#include <stdlib.h>

#ifdef WOLFSENTRY_NO_STDIO
#define printf(...)
#endif

#ifdef WOLFSENTRY_THREADSAFE

#include <unistd.h>
#include <pthread.h>

#define WOLFSENTRY_EXIT_ON_FAILURE(...) do { wolfsentry_errcode_t _retval = (__VA_ARGS__); if (_retval < 0) { WOLFSENTRY_WARN(#__VA_ARGS__ ": " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(_retval)); exit(1); }} while(0)
#define WOLFSENTRY_EXIT_ON_SUCCESS(...) do { if ((__VA_ARGS__) == 0) { WOLFSENTRY_WARN(#__VA_ARGS__ " should have failed, but succeeded.\n"); exit(1); }} while(0)
#define WOLFSENTRY_EXIT_ON_FALSE(...) do { if (! (__VA_ARGS__)) { WOLFSENTRY_WARN(#__VA_ARGS__ " should have been true, but was false.\n"); exit(1); }} while(0)
#define WOLFSENTRY_EXIT_ON_TRUE(...) do { if (__VA_ARGS__) { WOLFSENTRY_WARN(#__VA_ARGS__ " should have been false, but was true.\n"); exit(1); }} while(0)
#define WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(...) do { int _pthread_ret; if ((_pthread_ret = (__VA_ARGS__)) != 0) { WOLFSENTRY_WARN(#__VA_ARGS__ ": %s\n", strerror(_pthread_ret)); exit(1); }} while(0)

#else /* !WOLFSENTRY_THREADSAFE */

#define WOLFSENTRY_EXIT_ON_FAILURE(...) do { wolfsentry_errcode_t _retval = (__VA_ARGS__); if (_retval < 0) { WOLFSENTRY_WARN(#__VA_ARGS__ ": " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(_retval)); return 1; }} while(0)
#define WOLFSENTRY_EXIT_ON_SUCCESS(...) do { if ((__VA_ARGS__) == 0) { WOLFSENTRY_WARN(#__VA_ARGS__ " should have failed, but succeeded.\n"); return 1; }} while(0)
#define WOLFSENTRY_EXIT_ON_FALSE(...) do { if (! (__VA_ARGS__)) { WOLFSENTRY_WARN(#__VA_ARGS__ " should have been true, but was false.\n"); return 1; }} while(0)
#define WOLFSENTRY_EXIT_ON_TRUE(...) do { if (__VA_ARGS__) { WOLFSENTRY_WARN(#__VA_ARGS__ " should have been false, but was true.\n"); return 1; }} while(0)

#endif /* WOLFSENTRY_THREADSAFE */

/* If not defined use default allocators */
#ifndef WOLFSENTRY_TEST_HPI
#  define WOLFSENTRY_TEST_HPI NULL
#else
extern struct wolfsentry_host_platform_interface* WOLFSENTRY_TEST_HPI;
#endif

#define TEST_SKIP(name) static int name (void) { printf("[  skipping " #name "  ]\n"); return 0; }


#ifdef TEST_INIT

static wolfsentry_errcode_t test_init (void) {
    struct wolfsentry_context *wolfsentry;
    struct wolfsentry_eventconfig config = { .route_private_data_size = 32, .max_connection_count = 10 };
    wolfsentry_errcode_t ret;

    ret = wolfsentry_init(WOLFSENTRY_TEST_HPI,
                          &config,
                          &wolfsentry);
    printf("wolfsentry_init() returns " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
    if (ret < 0)
        return ret;

    ret = wolfsentry_shutdown(&wolfsentry);
    printf("wolfsentry_shutdown() returns " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));

    return ret;
}

#endif /* TEST_INIT */

#if defined(TEST_RWLOCKS)

#if defined(WOLFSENTRY_THREADSAFE)

struct rwlock_args {
    struct wolfsentry_context *wolfsentry;
    volatile int *measured_sequence;
    volatile int *measured_sequence_i;
    int thread_id;
    struct wolfsentry_rwlock *lock;
    wolfsentry_time_t max_wait;
};

static void *rd_routine(struct rwlock_args *args) {
    if (args->max_wait >= 0)
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared_timed(args->wolfsentry, args->lock, args->max_wait));
    else
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared(args->lock));
    int i = WOLFSENTRY_ATOMIC_POSTINCREMENT(*args->measured_sequence_i,1);
    args->measured_sequence[i] = args->thread_id;
    usleep(10000);
    i = WOLFSENTRY_ATOMIC_POSTINCREMENT(*args->measured_sequence_i,1);
    args->measured_sequence[i] = args->thread_id + 4;
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(args->lock));
    return 0;
}

static void *wr_routine(struct rwlock_args *args) {
    if (args->max_wait >= 0)
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex_timed(args->wolfsentry, args->lock, args->max_wait));
    else
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex(args->lock));
    int i = WOLFSENTRY_ATOMIC_POSTINCREMENT(*args->measured_sequence_i,1);
    args->measured_sequence[i] = args->thread_id;
    usleep(10000);
    i = WOLFSENTRY_ATOMIC_POSTINCREMENT(*args->measured_sequence_i,1);
    args->measured_sequence[i] = args->thread_id + 4;
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(args->lock));
    return 0;
}

static void *rd2wr_routine(struct rwlock_args *args) {
    if (args->max_wait >= 0)
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared_timed(args->wolfsentry, args->lock, args->max_wait));
    else
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared(args->lock));
    int i = WOLFSENTRY_ATOMIC_POSTINCREMENT(*args->measured_sequence_i,1);
    args->measured_sequence[i] = args->thread_id;
    if (args->max_wait >= 0)
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared2mutex_timed(args->wolfsentry, args->lock, args->max_wait));
    else
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_shared2mutex(args->lock));
    i = WOLFSENTRY_ATOMIC_POSTINCREMENT(*args->measured_sequence_i,1);
    args->measured_sequence[i] = args->thread_id + 4;
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(args->lock));
    return 0;
}

static int test_rw_locks (void) {
    struct wolfsentry_context *wolfsentry;
    struct wolfsentry_rwlock *lock;
    struct wolfsentry_eventconfig config = { .route_private_data_size = 32, .max_connection_count = 10 };

    (void)alarm(1);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_init(WOLFSENTRY_TEST_HPI,
                                               &config,
                                               &wolfsentry));
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_alloc(wolfsentry, &lock, 0 /* pshared */));

    volatile int measured_sequence[8], measured_sequence_i = 0;

    pthread_t thread1, thread2, thread3, thread4;
    struct rwlock_args thread1_args = {
        .wolfsentry = wolfsentry,
        .measured_sequence = measured_sequence,
        .measured_sequence_i = &measured_sequence_i,
        .lock = lock,
        .max_wait = -1
    }, thread2_args = thread1_args, thread3_args = thread1_args, thread4_args = thread1_args;

    thread1_args.thread_id = 1;
    thread2_args.thread_id = 2;
    thread3_args.thread_id = 3;
    thread4_args.thread_id = 4;

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex_timed(wolfsentry,lock,0));

    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread1, 0 /* attr */, (void *(*)(void *))rd_routine, (void *)&thread1_args));
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread2, 0 /* attr */, (void *(*)(void *))rd_routine, (void *)&thread2_args));
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread3, 0 /* attr */, (void *(*)(void *))wr_routine, (void *)&thread3_args));

    usleep(10000);
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(lock));

    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread1, 0 /* retval */));

    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread4, 0 /* attr */, (void *(*)(void *))wr_routine, (void *)&thread4_args));
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
        printf("wrong sequence at L%d.  should be {3,7,1,2,5,6,4,8} (the middle 4 are safely permutable), but got {", __LINE__);
        for (size_t i = 0; i < sizeof measured_sequence / sizeof measured_sequence[0]; ++i)
            printf("%d%s",measured_sequence[i], i == (sizeof measured_sequence / sizeof measured_sequence[0]) - 1 ? "}.\n" : ",");
        return 1;
    }


    /* now a scenario with shared2mutex and mutex2shared in the mix: */

    measured_sequence_i = 0;

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex(lock));

    thread1_args.max_wait = 100000; /* builtin wolfsentry_time_t is microseconds, same as usleep(). */
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread1, 0 /* attr */, (void *(*)(void *))rd_routine, (void *)&thread1_args));
    usleep(10000);
    thread2_args.max_wait = 100000;
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread2, 0 /* attr */, (void *(*)(void *))rd2wr_routine, (void *)&thread2_args));

    usleep(10000);

    /* this transition advances thread1 and thread2 to both hold shared locks.
     * non-negligible chance that thread2 goes into shared2mutex wait before
     * thread1 can get a shared lock.
     */
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_mutex2shared(lock));
    usleep(10000);

    /* this thread has to wait until thread2 is done with its shared2mutex sequence. */

/* constraint: thread2 must unlock (6) before thread3 locks (3) */
/* constraint: thread3 lock-unlock (3, 7) must be adjacent */
    thread3_args.max_wait = 100000;
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread3, 0 /* attr */, (void *(*)(void *))wr_routine, (void *)&thread3_args));
    usleep(10000);

    /* this one must fail, because at this point thread2 must be in shared2mutex wait. */
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_ERROR_CODE_IS(wolfsentry_lock_shared2mutex(lock), BUSY));

    /* take the opportunity to test expected failures of the _timed() variants. */
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_ERROR_CODE_IS(wolfsentry_lock_mutex_timed(wolfsentry,lock,0), BUSY));
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_ERROR_CODE_IS(wolfsentry_lock_mutex_timed(wolfsentry,lock,1000), TIMED_OUT));
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_ERROR_CODE_IS(wolfsentry_lock_shared_timed(wolfsentry,lock,0), BUSY));
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_ERROR_CODE_IS(wolfsentry_lock_shared_timed(wolfsentry,lock,1000), TIMED_OUT));

    /* this unlock allows thread2 to finally get its mutex. */
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_unlock(lock));

    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread1, 0 /* retval */));

/* constraint: thread2 must unlock (6) before thread4 locks (4) */
/* constraint: thread4 lock-unlock (4, 8) must be adjacent */
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_create(&thread4, 0 /* attr */, (void *(*)(void *))wr_routine, (void *)&thread4_args));
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread4, 0 /* retval */));

    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread2, 0 /* retval */));
    WOLFSENTRY_EXIT_ON_FAILURE_PTHREAD(pthread_join(thread3, 0 /* retval */));

    int measured_sequence_transposed[8];
    for (int i=0; i<8; ++i)
        measured_sequence_transposed[measured_sequence[i] - 1] = i + 1;
#define SEQ(x) measured_sequence_transposed[(x)-1]
    if ((SEQ(6) > SEQ(3)) ||
        (SEQ(7) - SEQ(3) != 1) ||
        (SEQ(6) > SEQ(4)) ||
        (SEQ(8) - SEQ(4) != 1)) {
        printf("wrong sequence at L%d.  got {", __LINE__);
        for (size_t i = 0; i < sizeof measured_sequence / sizeof measured_sequence[0]; ++i)
            printf("%d%s",measured_sequence[i], i == (sizeof measured_sequence / sizeof measured_sequence[0]) - 1 ? "}.\n" : ",");
        return 1;
    }


    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_lock_free(wolfsentry, &lock));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_shutdown(&wolfsentry));

    return 0;
}

#else

TEST_SKIP(test_rw_locks)

#endif /* WOLFSENTRY_THREADSAFE */

#endif /* TEST_RWLOCKS */

#ifdef TEST_STATIC_ROUTES

#ifdef LWIP
#include "lwip-socket.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#ifndef PRIVATE_DATA_SIZE
#define PRIVATE_DATA_SIZE 32
#endif

#ifndef PRIVATE_DATA_ALIGNMENT
#define PRIVATE_DATA_ALIGNMENT 16
#endif

static int test_static_routes (void) {

    struct wolfsentry_context *wolfsentry;
    wolfsentry_action_res_t action_results;
    int n_deleted;
    wolfsentry_ent_id_t id;
    wolfsentry_route_flags_t inexact_matches;

    struct {
        struct wolfsentry_sockaddr sa;
        byte addr_buf[4];
    } remote, local, remote_wildcard, local_wildcard;

    struct wolfsentry_eventconfig config = { .route_private_data_size = PRIVATE_DATA_SIZE, .route_private_data_alignment = PRIVATE_DATA_ALIGNMENT, .max_connection_count = 10 };

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_init(
            WOLFSENTRY_TEST_HPI,
            &config,
            &wolfsentry));

    remote.sa.sa_family = local.sa.sa_family = AF_INET;
    remote.sa.sa_proto = local.sa.sa_proto = IPPROTO_TCP;
    remote.sa.sa_port = 12345;
    local.sa.sa_port = 443;
    remote.sa.addr_len = local.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;
    remote.sa.interface = local.sa.interface = 1;
    memcpy(remote.sa.addr,"\0\1\2\3",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\377\376\375\374",sizeof local.addr_buf);

    wolfsentry_route_flags_t flags = WOLFSENTRY_ROUTE_FLAG_NONE, flags_wildcard;
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    memcpy(remote.sa.addr,"\4\5\6\7",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);

    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

#if 0
    puts("table after first 2 inserts:");
    for (struct wolfsentry_route *i = (struct wolfsentry_route *)wolfsentry->routes_static.header.head;
         i;
         i = (struct wolfsentry_route *)(i->header.next))
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_render(i, stdout));
    putchar('\n');
#endif

    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);

    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));

    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);

    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));

    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_GREENLISTED);
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED);
    memcpy(remote.sa.addr,"\3\4\5\6",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_GREENLISTED);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED);
    memcpy(remote.sa.addr,"\2\3\4\5",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);


    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    struct wolfsentry_route_table *static_routes;
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_get_table_static(wolfsentry, &static_routes));

    struct wolfsentry_route *route_ref;
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_get_reference(
                                 wolfsentry,
                                 static_routes,
                                 &remote.sa,
                                 &local.sa,
                                 flags,
                                 0 /* event_label_len */,
                                 0 /* event_label */,
                                 1 /* exact_p */,
                                 &inexact_matches,
                                 &route_ref));

    byte *private_data;
    size_t private_data_size;
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_get_private_data(
                                 wolfsentry,
                                 route_ref,
                                 (void **)&private_data,
                                 &private_data_size));

    if (private_data_size < PRIVATE_DATA_SIZE) {
        printf("private_data_size is %lu but expected %d.\n",private_data_size,PRIVATE_DATA_SIZE);
        return 1;
    }
    if ((PRIVATE_DATA_ALIGNMENT > 0) && ((uint64_t)private_data % (uint64_t)PRIVATE_DATA_ALIGNMENT)) {
        printf("private_data (%p) is not aligned to %d.\n",private_data,PRIVATE_DATA_ALIGNMENT);
        return 1;
    }

    for (byte *i = private_data, *i_end = private_data + private_data_size; i < i_end; ++i)
        *i = 'x';

#if 0
    puts("table after deleting 4.5.6.7 and inserting 3 more:");
    for (struct wolfsentry_route *i = (struct wolfsentry_route *)wolfsentry->routes_static.header.head;
         i;
         i = (struct wolfsentry_route *)(i->header.next))
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_render(i, stdout));
#endif

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_drop_reference(wolfsentry, route_ref, &action_results));
    WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_DEALLOCATED));

    /* now test basic eventless dispatch using exact-match ents in the static table. */

    WOLFSENTRY_CLEAR_ALL_BITS(action_results);
    wolfsentry_ent_id_t route_id;

    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);
    memcpy(remote.sa.addr,"\3\4\5\6",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
    WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
    WOLFSENTRY_EXIT_ON_FALSE(inexact_matches == 0);

    flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);
    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

    memcpy(remote.sa.addr,"\2\3\4\5",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
    WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
    WOLFSENTRY_EXIT_ON_FALSE(inexact_matches == 0);

    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
    WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
    WOLFSENTRY_EXIT_ON_FALSE(inexact_matches == 0);

    memcpy(remote.sa.addr,"\0\1\2\3",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\377\376\375\374",sizeof local.addr_buf);
    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

    flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);
    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
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

    for (int prefixlen = sizeof remote.addr_buf * BITS_PER_BYTE;
         prefixlen >= 8;
         --prefixlen) {
        remote.sa.addr_len = (wolfsentry_addr_bits_t)prefixlen;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

        remote.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
        WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
        WOLFSENTRY_EXIT_ON_TRUE(prefixlen < (int)(sizeof remote.addr_buf * BITS_PER_BYTE) ? ! WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD) : WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD));

        remote.sa.addr_len = (wolfsentry_addr_bits_t)prefixlen;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
        WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


        local.sa.addr_len = (wolfsentry_addr_bits_t)prefixlen;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

        local.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

        WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT));
        WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT));
        WOLFSENTRY_EXIT_ON_TRUE(prefixlen < (int)(sizeof local.addr_buf * BITS_PER_BYTE) ? ! WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD) : WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD));

        local.sa.addr_len = (wolfsentry_addr_bits_t)prefixlen;
        WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
        WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);

    }


    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    remote_wildcard.sa.sa_port = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);


    local.sa.sa_port = 8765;
    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    local.sa.sa_port = local_wildcard.sa.sa_port;

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_by_id(wolfsentry, NULL /* caller_arg */, route_id, NULL /* event_label */, 0 /* event_label_len */, &action_results));

    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(action_results, WOLFSENTRY_ACTION_RES_DEALLOCATED));

    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    local_wildcard.sa.sa_port = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    remote_wildcard.sa.sa_port = local_wildcard.sa.sa_port = 0;
    remote_wildcard.sa.sa_proto = local_wildcard.sa.sa_proto = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD);
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD);
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD));
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD));
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    local_wildcard.sa.addr_len = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    remote_wildcard.sa.sa_port = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD);
    local_wildcard.sa.addr_len = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD));
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    remote_wildcard.sa.addr_len = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    local_wildcard.sa.interface = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);


    remote_wildcard = remote;
    local_wildcard = local;
    flags_wildcard = flags;

    remote_wildcard.sa.interface = 0;
    WOLFSENTRY_SET_BITS(flags_wildcard, WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
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

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_insert_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &id, &action_results));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_event_dispatch(wolfsentry, &remote.sa, &local.sa, flags, NULL /* event_label */, 0 /* event_label_len */, NULL /* caller_arg */,
                                                           &route_id, &inexact_matches, &action_results));
    WOLFSENTRY_EXIT_ON_FALSE(route_id == id);
    WOLFSENTRY_EXIT_ON_FALSE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD));
    WOLFSENTRY_EXIT_ON_TRUE(WOLFSENTRY_CHECK_BITS(inexact_matches, WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD));

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);
    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote_wildcard.sa, &local_wildcard.sa, flags_wildcard, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));


    remote.sa.sa_family = local.sa.sa_family = AF_INET;
    remote.sa.sa_proto = local.sa.sa_proto = IPPROTO_TCP;
    remote.sa.sa_port = 12345;
    local.sa.sa_port = 443;
    remote.sa.addr_len = local.sa.addr_len = sizeof remote.addr_buf * BITS_PER_BYTE;
    remote.sa.interface = local.sa.interface = 1;
    memcpy(remote.sa.addr,"\0\1\2\3",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\377\376\375\374",sizeof local.addr_buf);

    WOLFSENTRY_CLEAR_ALL_BITS(flags);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);
    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));

    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_GREENLISTED);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED);
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);
    memcpy(remote.sa.addr,"\2\3\4\5",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);
    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));

    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);
    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));

    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_GREENLISTED);
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED);
    WOLFSENTRY_CLEAR_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN);
    WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT);
    memcpy(remote.sa.addr,"\3\4\5\6",sizeof remote.addr_buf);
    memcpy(local.sa.addr,"\373\372\371\370",sizeof local.addr_buf);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));
    WOLFSENTRY_EXIT_ON_FALSE(n_deleted == 1);
    WOLFSENTRY_EXIT_ON_SUCCESS(wolfsentry_route_delete_static(wolfsentry, NULL /* caller_arg */, &remote.sa, &local.sa, flags, 0 /* event_label_len */, 0 /* event_label */, &action_results, &n_deleted));

    WOLFSENTRY_EXIT_ON_FALSE(wolfsentry->routes_static.header.n_ents == 0);

    printf("all subtests succeeded -- %d distinct ents inserted and deleted.\n",wolfsentry->id_counter);

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_shutdown(&wolfsentry));

    return 0;
}
#endif /* TEST_STATIC_ROUTES */

#ifdef TEST_DYNAMIC_RULES

#ifdef LWIP
#include "lwip-socket.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#ifndef PRIVATE_DATA_SIZE
#define PRIVATE_DATA_SIZE 32
#endif

#ifndef PRIVATE_DATA_ALIGNMENT
#define PRIVATE_DATA_ALIGNMENT 8
#endif

static wolfsentry_errcode_t wolfsentry_action_dummy_callback(
    struct wolfsentry_context *wolfsentry,
    void *handler_context,
    void *caller_arg,
    const struct wolfsentry_event *event,
    struct wolfsentry_route_table *route_table,
    const struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results)
{
    (void)wolfsentry;
    (void)handler_context;
    (void)caller_arg;
    (void)event;
    (void)route_table;
    (void)route;
    (void)action_results;

    return 0;
}


static int test_dynamic_rules (void) {

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

    struct wolfsentry_eventconfig config = { .route_private_data_size = PRIVATE_DATA_SIZE, .route_private_data_alignment = PRIVATE_DATA_ALIGNMENT, .max_connection_count = 10 };

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_init(
            WOLFSENTRY_TEST_HPI,
            &config,
            &wolfsentry));


    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            wolfsentry,
            "connect",
            -1 /* label_len */,
            10,
            NULL /* config */,
            &id));

    /* track port scanning */
    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            wolfsentry,
            "connection_refused",
            -1 /* label_len */,
            10,
            NULL /* config */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            wolfsentry,
            "disconnect",
            -1 /* label_len */,
            10,
            NULL /* config */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            wolfsentry,
            "authentication_succeeded",
            -1 /* label_len */,
            10,
            NULL /* config */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            wolfsentry,
            "authentication_failed",
            -1 /* label_len */,
            10,
            NULL /* config */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            wolfsentry,
            "negotiation_abandoned",
            -1 /* label_len */,
            10,
            NULL /* config */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            wolfsentry,
            "insertion_side_effect_demo",
            -1 /* label_len */,
            10,
            NULL /* config */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            wolfsentry,
            "match_side_effect_demo",
            -1 /* label_len */,
            10,
            NULL /* config */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_event_insert(
            wolfsentry,
            "deletion_side_effect_demo",
            -1 /* label_len */,
            10,
            NULL /* config */,
            &id));

#if 0
int wolfsentry_event_set_subevent(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t subevent_type,
    const char *subevent_label,
    int subevent_label_len);
#endif

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            wolfsentry,
            "insert_always",
            -1 /* label_len */,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            wolfsentry,
            "set_connect_wildcards",
            -1 /* label_len */,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            wolfsentry,
            "set_connectionreset_wildcards",
            -1 /* label_len */,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            wolfsentry,
            "increment_derogatory",
            -1 /* label_len */,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            wolfsentry,
            "increment_commendable",
            -1 /* label_len */,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            wolfsentry,
            "check_counts",
            -1 /* label_len */,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            wolfsentry,
            "add_to_greenlist",
            -1 /* label_len */,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));

    WOLFSENTRY_EXIT_ON_FAILURE(
        wolfsentry_action_insert(
            wolfsentry,
            "del_from_greenlist",
            -1 /* label_len */,
            wolfsentry_action_dummy_callback,
            NULL /* handler_context */,
            &id));


#if 0
int wolfsentry_action_list_append(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_action_list *action_list,
    const char *label,
    int label_len);


int wolfsentry_event_insert(
    struct wolfsentry_context *wolfsentry,
    const char *label,
    int label_len,
    wolfsentry_priority_t priority,
    wolfsentry_ent_id_t id);



int wolfsentry_event_action_append(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    const char *action_label,
    int action_label_len);


int wolfsentry_event_set_subevent(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t subevent_type,
    const char *subevent_label,
    int subevent_label_len);




int wolfsentry_event_action_delete(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    const char *action_label,
    int action_label_len);



int wolfsentry_event_delete(
    struct wolfsentry_context *wolfsentry,
    const char *label,
    int label_len);



int wolfsentry_action_delete(
    struct wolfsentry_context *wolfsentry,
    const char *label,
    int label_len);

#endif /* 0 */

    WOLFSENTRY_EXIT_ON_FAILURE(wolfsentry_shutdown(&wolfsentry));

    return 0;
}
#endif /* TEST_DYNAMIC_RULES */


int main (int argc, char* argv[]) {
    wolfsentry_errcode_t ret = 0;
    int err = 0;
    (void)argc;
    (void)argv;

#ifdef TEST_INIT
    ret = test_init();
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        printf("test_init failed, " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err = 1;
    }
#endif

#ifdef TEST_RWLOCKS
    ret = test_rw_locks();
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        printf("test_rw_locks failed, " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err = 1;
    }
#endif

#ifdef TEST_STATIC_ROUTES
    ret = test_static_routes();
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        printf("test_static_routes failed, " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err = 1;
    }
#endif

#ifdef TEST_DYNAMIC_RULES
    ret = test_dynamic_rules();
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        printf("test_dynamic_rules failed, " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err = 1;
    }
#endif

    return err;
}
