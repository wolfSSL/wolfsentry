/*
 * wolfsentry_internal.h
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

#ifndef WOLFSENTRY_INTERNAL_H
#define WOLFSENTRY_INTERNAL_H

#include "wolfsentry/wolfsentry.h"
#include "wolfsentry/wolfsentry_util.h"

#ifdef WOLFSENTRY_REFCOUNT_TYPE
typedef WOLFSENTRY_REFCOUNT_TYPE wolfsentry_refcount_t;
#else
typedef uint32_t wolfsentry_refcount_t;
#endif

#include "wolfsentry_ll.h"

#ifdef WOLFSENTRY_THREADSAFE

#define WOLFSENTRY_THREAD_ID_SENT ~0UL /* lock handoff not yet implemented. */

enum wolfsentry_rwlock_state {
    WOLFSENTRY_LOCK_UNINITED = 0,
    WOLFSENTRY_LOCK_UNLOCKED,
    WOLFSENTRY_LOCK_SHARED,
    WOLFSENTRY_LOCK_EXCLUSIVE,
    WOLFSENTRY_LOCK_MAX = 0x7fffffff /* force enum to be 32 bits, for intrinsic atomicity. */
};

struct wolfsentry_rwlock {
    const struct wolfsentry_host_platform_interface *hpi;
    sem_t sem;
    sem_t sem_read_waiters;
    sem_t sem_write_waiters;
    sem_t sem_read2write_waiters;
    volatile wolfsentry_thread_id_t write_lock_holder;
    volatile wolfsentry_thread_id_t read2write_reservation_holder;
    union {
        volatile int read;
        volatile int write;
    } holder_count;
    volatile int read_waiter_count;
    volatile int write_waiter_count;
    volatile int read2write_waiter_read_count; /* the recursion depth of the shared lock held by read2write_reservation_holder */
    volatile enum wolfsentry_rwlock_state state;
    volatile int promoted_at_count;
    wolfsentry_lock_flags_t flags;
};

struct wolfsentry_thread_context {
    wolfsentry_thread_id_t id;
    void *user_context;
    struct timespec deadline;
    wolfsentry_thread_flags_t current_thread_flags;
    struct wolfsentry_rwlock *tracked_shared_lock; /* if !_THREAD_FLAG_READONLY,
                                            * locker can have shared lock(s) only
                                            * for this lock.  if another shared lock is
                                            * obtained, first this one will be
                                            * promoted.  a currently held lock can
                                            * be demoted only if it matches
                                            * current_shared_lock, or current_shared_lock is null.
                                            */
    int recursion_of_tracked_lock; /* recursion count for outermost_shared_lock/current_shared_lock -- 1 if locked only once. */
    int shared_count; /* total count of shared locks held */
    int mutex_and_reservation_count;
};

#define WOLFSENTRY_THREAD_GET_ID (thread ? thread->id : WOLFSENTRY_THREAD_GET_ID_HANDLER())

#define WOLFSENTRY_THREAD_ASSERT_INITED(thread) do {                     \
    if (((thread) == NULL) || ((thread)->id == WOLFSENTRY_THREAD_NO_ID)) \
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);                            \
    } while (0)

#define WOLFSENTRY_THREAD_ASSERT_NULL_OR_INITED(thread) do {             \
    if (((thread) != NULL) && ((thread)->id == WOLFSENTRY_THREAD_NO_ID)) \
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);                            \
    } while (0)

#define WOLFSENTRY_LOCK_ASSERT_INITED(lock) do {                         \
    if (((lock) == NULL) || (WOLFSENTRY_ATOMIC_LOAD((lock)->state) == WOLFSENTRY_LOCK_UNINITED)) \
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);                            \
    } while (0)

#if defined(__GNUC__) && defined(static_assert) && !defined(__STRICT_ANSI__)
static_assert(sizeof(struct wolfsentry_thread_context_public) >= sizeof(struct wolfsentry_thread_context), "wolfsentry_thread_context_public is too small for wolfsentry_thread_context");
static_assert(__alignof__(struct wolfsentry_thread_context_public) >= __alignof__(struct wolfsentry_thread_context), "alignment of wolfsentry_thread_context_public is too small for wolfsentry_thread_context");
#endif

#define WOLFSENTRY_HAVE_MUTEX_OR_RETURN_EX(ctx) do {            \
        wolfsentry_errcode_t _lock_ret =                        \
          wolfsentry_lock_have_mutex(                           \
            &(ctx)->lock,                                       \
            thread,                                             \
            WOLFSENTRY_LOCK_FLAG_NONE);                         \
        WOLFSENTRY_RERETURN_IF_ERROR(_lock_ret);                \
    } while (0)
#define WOLFSENTRY_HAVE_MUTEX_OR_RETURN() WOLFSENTRY_HAVE_MUTEX_OR_RETURN_EX(wolfsentry)

#define WOLFSENTRY_HAVE_SHLOCK_OR_RETURN_EX(ctx) do {           \
        wolfsentry_errcode_t _lock_ret =                        \
          wolfsentry_lock_have_shared(                          \
            &(ctx)->lock,                                       \
            thread,                                             \
            WOLFSENTRY_LOCK_FLAG_NONE);                         \
        WOLFSENTRY_RERETURN_IF_ERROR(_lock_ret);                \
    } while (0)
#define WOLFSENTRY_HAVE_SHLOCK_OR_RETURN() WOLFSENTRY_HAVE_SHLOCK_OR_RETURN_EX(wolfsentry)

#define WOLFSENTRY_HAVE_A_LOCK_OR_RETURN_EX(ctx) do {           \
        wolfsentry_errcode_t _lock_ret =                        \
          wolfsentry_lock_have_either(                          \
            &(ctx)->lock,                                       \
            thread,                                             \
            WOLFSENTRY_LOCK_FLAG_NONE);                         \
        WOLFSENTRY_RERETURN_IF_ERROR(_lock_ret);                \
    } while (0)
#define WOLFSENTRY_HAVE_A_LOCK_OR_RETURN() WOLFSENTRY_HAVE_A_LOCK_OR_RETURN_EX(wolfsentry)

#else /* !WOLFSENTRY_THREADSAFE */

#define WOLFSENTRY_THREAD_ASSERT_INITED(thread) DO_NOTHING
#define WOLFSENTRY_THREAD_ASSERT_NULL_OR_INITED(thread) DO_NOTHING

#define WOLFSENTRY_HAVE_MUTEX_OR_RETURN_EX(ctx) (void)(ctx)
#define WOLFSENTRY_HAVE_MUTEX_OR_RETURN() (void)wolfsentry
#define WOLFSENTRY_HAVE_SHLOCK_OR_RETURN_EX(ctx) (void)(ctx)
#define WOLFSENTRY_HAVE_SHLOCK_OR_RETURN() (void)wolfsentry
#define WOLFSENTRY_HAVE_A_LOCK_OR_RETURN_EX(ctx) (void)(ctx)
#define WOLFSENTRY_HAVE_A_LOCK_OR_RETURN() (void)wolfsentry

#endif /* WOLFSENTRY_THREADSAFE */

#define WOLFSENTRY_REFCOUNT_INCREMENT(x, ret)                           \
    do {                                                                \
        wolfsentry_refcount_t _out;                                     \
        WOLFSENTRY_ATOMIC_INCREMENT_UNSIGNED_SAFELY_BY_ONE(x, _out);    \
        if (_out == 0)                                                  \
            (ret) = WOLFSENTRY_ERROR_ENCODE(OVERFLOW_AVERTED);          \
        else                                                            \
            (ret) = WOLFSENTRY_ERROR_ENCODE(OK);                        \
    } while(0)

#define WOLFSENTRY_REFCOUNT_DECREMENT(x, res, ret) \
    do {                                                                \
        WOLFSENTRY_ATOMIC_DECREMENT_UNSIGNED_SAFELY_BY_ONE(x, res);     \
        if ((res) == MAX_UINT_OF(x))                                    \
            (ret) = WOLFSENTRY_ERROR_ENCODE(INTERNAL_CHECK_FATAL);      \
        else                                                            \
            (ret) = WOLFSENTRY_ERROR_ENCODE(OK);                        \
    } while(0)

struct wolfsentry_table_header;

#ifdef __arm__
/* must be uint64-aligned to allow warning-free casts on ARM32. */
struct attr_align_to(8) wolfsentry_table_ent_header
#else
struct wolfsentry_table_ent_header
#endif
{
    struct wolfsentry_table_header *parent_table;
    struct wolfsentry_table_ent_header *prev, *next; /* these will be replaced by red-black table elements later. */
    struct wolfsentry_table_ent_header *prev_by_id, *next_by_id; /* these will be replaced by red-black table elements later. */
    wolfsentry_hitcount_t hitcount;
    wolfsentry_ent_id_t id;
    uint32_t padding1;
    wolfsentry_refcount_t refcount;
};

#define WOLFSENTRY_TABLE_ENT_HEADER_RESET(ent) do {                           \
        (ent).parent_table = NULL;                                            \
        (ent).prev = (ent).next = (ent).prev_by_id = (ent).next_by_id = NULL; \
        (ent).refcount = 1; }                                                 \
    while (0)

struct wolfsentry_context;

typedef int (*wolfsentry_ent_cmp_fn_t)(const struct wolfsentry_table_ent_header *left, const struct wolfsentry_table_ent_header *right);
typedef wolfsentry_errcode_t (*wolfsentry_ent_free_fn_t)(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_table_ent_header *ent, wolfsentry_action_res_t *action_results);

typedef wolfsentry_errcode_t (*wolfsentry_filter_function_t)(void *context, struct wolfsentry_table_ent_header *object, wolfsentry_action_res_t *action_results);
typedef wolfsentry_errcode_t (*wolfsentry_dropper_function_t)(void *context, struct wolfsentry_table_ent_header *object, wolfsentry_action_res_t *action_results);
typedef wolfsentry_errcode_t (*wolfsentry_map_function_t)(void *context, struct wolfsentry_table_ent_header *object, wolfsentry_action_res_t *action_results);

typedef wolfsentry_errcode_t (*wolfsentry_table_ent_clone_fn_t)(
    struct wolfsentry_context *src_context,
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread,
#endif
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *new_context,
    struct wolfsentry_table_ent_header **new_ent,
    wolfsentry_clone_flags_t flags);

typedef wolfsentry_errcode_t (*wolfsentry_coupled_table_ent_clone_fn_t)(
    struct wolfsentry_context *src_context,
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread,
#endif
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *new_context,
    struct wolfsentry_table_ent_header **new_ent1,
    struct wolfsentry_table_ent_header **new_ent2,
    wolfsentry_clone_flags_t flags);

typedef wolfsentry_errcode_t (*wolfsentry_table_ent_clone_map_fn_t)(
    struct wolfsentry_context *src_context,
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread,
#endif
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *new_context,
    struct wolfsentry_table_ent_header *new_ent,
    wolfsentry_clone_flags_t flags);

struct wolfsentry_table_header {
    struct wolfsentry_table_ent_header *head, *tail; /* these will be replaced by red-black table elements later. */
    wolfsentry_ent_cmp_fn_t cmp_fn;
    wolfsentry_ent_free_fn_t free_fn;
    wolfsentry_hitcount_t n_ents;
    wolfsentry_hitcount_t n_inserts;
    wolfsentry_hitcount_t n_deletes;
    wolfsentry_object_type_t ent_type;
};

#define WOLFSENTRY_TABLE_HEADER_RESET(table) do { \
        (table).head = (table).tail = NULL;       \
        (table).n_ents = 0;                       \
        (table).n_inserts = 0;                    \
        (table).n_deletes = 0;                    \
    } while (0)

struct wolfsentry_cursor {
    struct wolfsentry_table_ent_header *point;
};

struct wolfsentry_action {
    struct wolfsentry_table_ent_header header;
    wolfsentry_action_callback_t handler;
    void *handler_arg;
    wolfsentry_action_flags_t flags, flags_at_creation;
    byte label_len;
    char label[WOLFSENTRY_FLEXIBLE_ARRAY_SIZE];
};

struct wolfsentry_action_table {
    struct wolfsentry_table_header header;
};

struct wolfsentry_action_list_ent {
    struct wolfsentry_list_ent_header header;
    struct wolfsentry_action *action;
};

struct wolfsentry_action_list {
    struct wolfsentry_list_header header;
};

struct wolfsentry_eventconfig_internal {
    struct wolfsentry_eventconfig config; /* note route_private_data_size modified to include padding needed for route_private_data_alignment. */
    size_t route_private_data_padding; /* with top of struct wolfsentry_route aligned to private_data_alignment, this is the padding needed in addr_buf to get aligned.
                                        * note, struct wolfsentry_route is 8-byte-aligned by default, so there are no holes with normal sizeof(void *) alignment.
                                        */
};

struct wolfsentry_event {
    struct wolfsentry_table_ent_header header;

    wolfsentry_event_flags_t flags;

    struct wolfsentry_eventconfig_internal *config;

    struct wolfsentry_action_list post_action_list; /* in parent/trigger events, this decides whether to insert the route, and/or updates route state.
                                              * in child events, this does the work described immediately below.
                                              */

    struct wolfsentry_action_list insert_action_list;
    struct wolfsentry_action_list match_action_list;
    struct wolfsentry_action_list update_action_list;
    struct wolfsentry_action_list delete_action_list;
    struct wolfsentry_action_list decision_action_list;

    struct wolfsentry_event *aux_event; /* plugins that insert new routes can use this as parent, and autoinserted routes via WOLFSENTRY_ACTION_RES_INSERT use this. */

    wolfsentry_priority_t priority;

    byte label_len;
    char label[WOLFSENTRY_FLEXIBLE_ARRAY_SIZE];
};

struct wolfsentry_event_table {
    struct wolfsentry_table_header header;
};

struct wolfsentry_route {
    struct wolfsentry_table_ent_header header;

    struct wolfsentry_list_ent_header purge_links;
#define WOLFSENTRY_ROUTE_PURGE_HEADER_TO_TABLE_ENT_HEADER(purge_link) container_of(purge_link, struct wolfsentry_route, purge_links)

    struct wolfsentry_event *parent_event; /* applicable config is parent_event->config or if null, wolfsentry->config */

    wolfsentry_route_flags_t flags;

    wolfsentry_addr_family_t sa_family;
    wolfsentry_proto_t sa_proto;
    struct wolfsentry_route_endpoint remote, local;
    uint16_t data_addr_offset; /* 0 if there's no private_data */
    uint16_t data_addr_size;

    struct {
        wolfsentry_time_t insert_time;
        wolfsentry_time_t last_hit_time;
        wolfsentry_time_t last_penaltybox_time;
        wolfsentry_time_t purge_after;
#ifndef WOLFSENTRY_ROUTE_PURGE_MARGIN_SECONDS
#define WOLFSENTRY_ROUTE_PURGE_MARGIN_SECONDS 60
#endif
        uint16_t connection_count;
        uint16_t derogatory_count;
        uint16_t commendable_count;
    } meta;

    uint16_t data[WOLFSENTRY_FLEXIBLE_ARRAY_SIZE]; /* first the caller's private data area (if any),
                   * then the remote addr in big endian padded up to
                   * nearest byte, then local addr, then
                   * remote_extra_ports, then local_extra_ports.
                   */
};

#define WOLFSENTRY_ROUTE_REMOTE_ADDR(r) ((byte *)(r)->data + (r)->data_addr_offset)
#define WOLFSENTRY_ROUTE_REMOTE_ADDR_BITS(r) ((r)->remote.addr_len)
#define WOLFSENTRY_ROUTE_REMOTE_ADDR_BYTES(r) WOLFSENTRY_BITS_TO_BYTES((r)->remote.addr_len)
#define WOLFSENTRY_ROUTE_LOCAL_ADDR(r) ((byte *)(r)->data + (r)->data_addr_offset + WOLFSENTRY_ROUTE_REMOTE_ADDR_BYTES(r))
#define WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(r) ((r)->local.addr_len)
#define WOLFSENTRY_ROUTE_LOCAL_ADDR_BYTES(r) WOLFSENTRY_BITS_TO_BYTES((r)->local.addr_len)
#define WOLFSENTRY_ROUTE_REMOTE_PORT_COUNT(r) (1U + (r)->remote.extra_port_count)
#define WOLFSENTRY_ROUTE_LOCAL_PORT_COUNT(r) (1U + (r)->local.extra_port_count)
#define WOLFSENTRY_ROUTE_REMOTE_EXTRA_PORTS(r) ((wolfsentry_port_t *)(r)->data + (((r)->data_addr_offset + (unsigned)WOLFSENTRY_ROUTE_REMOTE_ADDR_BYTES(r) + (unsigned)WOLFSENTRY_ROUTE_LOCAL_ADDR_BYTES(r) + 1U) / sizeof (r)->data[0]))
#define WOLFSENTRY_ROUTE_LOCAL_EXTRA_PORTS(r) (WOLFSENTRY_ROUTE_REMOTE_EXTRA_PORTS(r) + (r)->remote.extra_port_count)
#define WOLFSENTRY_ROUTE_BUF_SIZE(r) (WOLFSENTRY_ROUTE_REMOTE_ADDR_BYTES(r) + WOLFSENTRY_ROUTE_LOCAL_ADDR_BYTES(r) + ((WOLFSENTRY_ROUTE_REMOTE_ADDR_BYTES(r) + WOLFSENTRY_ROUTE_LOCAL_ADDR_BYTES(r)) & 1) + (WOLFSENTRY_ROUTE_REMOTE_PORT_COUNT(r) * sizeof(wolfsentry_port_t)) + (WOLFSENTRY_ROUTE_LOCAL_PORT_COUNT(r) * sizeof(wolfsentry_port_t)))

#define WOLFSENTRY_ROUTE_REMOTE_PORT_GET(r, i) ((i) ? WOLFSENTRY_ROUTE_REMOTE_EXTRA_PORTS(r)[(i)-1] : (r)->remote.sa_port)
#define WOLFSENTRY_ROUTE_LOCAL_PORT_GET(r, i) ((i) ? WOLFSENTRY_ROUTE_LOCAL_EXTRA_PORTS(r)[(i)-1] : (r)->local.sa_port)

struct wolfsentry_route_table {
    struct wolfsentry_table_header header;
    struct wolfsentry_list_header purge_list;
    wolfsentry_hitcount_t max_purgeable_routes;
    struct wolfsentry_event *default_event; /* used as the parent_event by wolfsentry_route_dispatch() for a static route match with a null parent_event. */
    struct wolfsentry_route *fallthrough_route; /* used as the rule_route when no rule_route is matched or inserted. */
    wolfsentry_action_res_t default_policy;
    wolfsentry_priority_t highest_priority_route_in_table;
};

struct wolfsentry_kv_pair_internal {
    struct wolfsentry_table_ent_header header;
    struct wolfsentry_kv_pair kv;
};

struct wolfsentry_kv_table {
    struct wolfsentry_table_header header;
    wolfsentry_kv_validator_t validator;
};

struct wolfsentry_addr_family_bynumber {
    struct wolfsentry_table_ent_header header;
    wolfsentry_addr_family_t number;
    wolfsentry_addr_family_parser_t parser;
    wolfsentry_addr_family_formatter_t formatter;
    wolfsentry_addr_bits_t max_addr_bits;
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    struct wolfsentry_addr_family_byname *byname_ent; /* 1:1 mapping between _bynumber and _byname tables */
#endif
};

struct wolfsentry_addr_family_bynumber_table {
    struct wolfsentry_table_header header;
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    struct wolfsentry_addr_family_byname_table *byname_table;
#endif
};

#ifdef WOLFSENTRY_PROTOCOL_NAMES
struct wolfsentry_addr_family_byname {
    struct wolfsentry_table_ent_header header;
    struct wolfsentry_addr_family_bynumber *bynumber_ent; /* 1:1 mapping between _bynumber and _byname tables */
    byte name_len;
    char name[WOLFSENTRY_FLEXIBLE_ARRAY_SIZE];
};

struct wolfsentry_addr_family_byname_table {
    struct wolfsentry_table_header header;
    struct wolfsentry_addr_family_bynumber_table *bynumber_table;
};
#endif

struct wolfsentry_cleanup_hook_ent {
    struct wolfsentry_list_ent_header header;
    wolfsentry_cleanup_callback_t handler;
    void *arg;
};

struct wolfsentry_context {
    struct wolfsentry_host_platform_interface hpi;
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_rwlock lock;
#endif
    wolfsentry_make_id_cb_t mk_id_cb;
    union {
        void *mk_id_cb_arg;
        wolfsentry_ent_id_t id_counter;
    } mk_id_cb_state;
    struct wolfsentry_eventconfig_internal config, config_at_creation;
    struct wolfsentry_event_table *events;
    struct wolfsentry_action_table *actions;
    struct wolfsentry_route_table *routes;
    struct wolfsentry_kv_table *user_values;
    struct wolfsentry_addr_family_bynumber_table *addr_families_bynumber;
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    struct wolfsentry_addr_family_byname_table *addr_families_byname;
#endif
    struct wolfsentry_table_header ents_by_id;
    struct wolfsentry_list_header cleanup_hooks;
};

#ifdef WOLFSENTRY_THREADSAFE

#define WOLFSENTRY_MALLOC_1(allocator, size) ((allocator).malloc((allocator).context, thread, size))
#define WOLFSENTRY_FREE_1(allocator, ptr) (allocator).free((allocator).context, thread, ptr)
#define WOLFSENTRY_REALLOC_1(allocator, ptr, size) ((allocator).realloc(wolfsentry->hpi.allocator.context, thread, ptr, size))
#define WOLFSENTRY_MEMALIGN_1(allocator, alignment, size) ((allocator).memalign ? (allocator).memalign((allocator).context, thread, alignment, size) : NULL)
#define WOLFSENTRY_FREE_ALIGNED_1(allocator, ptr) ((allocator).memalign ? (allocator).free_aligned((allocator).context, thread, ptr) : (void)NULL)

#else /* !WOLFSENTRY_THREADSAFE */

#define WOLFSENTRY_MALLOC_1(allocator, size) ((allocator).malloc((allocator).context, size))
#define WOLFSENTRY_FREE_1(allocator, ptr) (allocator).free((allocator).context, ptr)
#define WOLFSENTRY_REALLOC_1(allocator, ptr, size) ((allocator).realloc(wolfsentry->hpi.allocator.context, ptr, size))
#define WOLFSENTRY_MEMALIGN_1(allocator, alignment, size) ((allocator).memalign ? (allocator).memalign((allocator).context, alignment, size) : NULL)
#define WOLFSENTRY_FREE_ALIGNED_1(allocator, ptr) ((allocator).memalign ? (allocator).free_aligned((allocator).context, ptr) : (void)NULL)

#endif /* WOLFSENTRY_THREADSAFE */

#define WOLFSENTRY_MALLOC(size) WOLFSENTRY_MALLOC_1(wolfsentry->hpi.allocator, size)
#define WOLFSENTRY_FREE(ptr) WOLFSENTRY_FREE_1(wolfsentry->hpi.allocator, ptr)
#define WOLFSENTRY_REALLOC(ptr, size) WOLFSENTRY_REALLOC_1(wolfsentry->hpi.allocator, ptr, size)
#define WOLFSENTRY_MEMALIGN(alignment, size) WOLFSENTRY_MEMALIGN_1(wolfsentry->hpi.allocator, alignment, size)
#define WOLFSENTRY_FREE_ALIGNED(ptr) WOLFSENTRY_FREE_ALIGNED_1(wolfsentry->hpi.allocator, ptr)

#define WOLFSENTRY_GET_TIME_1(timecbs, time_p) ((timecbs).get_time((timecbs).context, time_p))
#define WOLFSENTRY_DIFF_TIME_1(timecbs, later, earlier) ((timecbs).diff_time(later, earlier))
#define WOLFSENTRY_ADD_TIME_1(timecbs, start_time, time_interval) ((timecbs).add_time(start_time, time_interval))
#define WOLFSENTRY_TO_EPOCH_TIME_1(timecbs, when, epoch_secs, epoch_nsecs) ((timecbs).to_epoch_time(when, epoch_secs, epoch_nsecs))
#define WOLFSENTRY_FROM_EPOCH_TIME_1(timecbs, epoch_secs, epoch_nsecs, when) ((timecbs).from_epoch_time(epoch_secs, epoch_nsecs, when))
#define WOLFSENTRY_INTERVAL_TO_SECONDS_1(timecbs, howlong, howlong_secs, howlong_nsecs) ((timecbs).interval_to_seconds(howlong, howlong_secs, howlong_nsecs))
#define WOLFSENTRY_INTERVAL_FROM_SECONDS_1(timecbs, howlong_secs, howlong_nsecs, howlong) ((timecbs).interval_from_seconds(howlong_secs, howlong_nsecs, howlong))

#define WOLFSENTRY_GET_TIME(time_p) WOLFSENTRY_GET_TIME_1(wolfsentry->hpi.timecbs, time_p)
#define WOLFSENTRY_DIFF_TIME(later, earlier) WOLFSENTRY_DIFF_TIME_1(wolfsentry->hpi.timecbs, later, earlier)
#define WOLFSENTRY_ADD_TIME(start_time, time_interval) WOLFSENTRY_ADD_TIME_1(wolfsentry->hpi.timecbs, start_time, time_interval)
#define WOLFSENTRY_TO_EPOCH_TIME(when, epoch_secs, epoch_nsecs) WOLFSENTRY_TO_EPOCH_TIME_1(wolfsentry->hpi.timecbs, when, epoch_secs, epoch_nsecs)
#define WOLFSENTRY_FROM_EPOCH_TIME(epoch_secs, epoch_nsecs, when) WOLFSENTRY_FROM_EPOCH_TIME_1(wolfsentry->hpi.timecbs, epoch_secs, epoch_nsecs, when)
#define WOLFSENTRY_INTERVAL_TO_SECONDS(howlong, howlong_secs, howlong_nsecs) WOLFSENTRY_INTERVAL_TO_SECONDS_1(wolfsentry->hpi.timecbs, howlong, howlong_secs, howlong_nsecs)
#define WOLFSENTRY_INTERVAL_FROM_SECONDS(howlong_secs, howlong_nsecs, howlong) WOLFSENTRY_INTERVAL_FROM_SECONDS_1(wolfsentry->hpi.timecbs, howlong_secs, howlong_nsecs, howlong)

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_id_allocate(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_table_ent_header *ent);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_label_is_builtin(const char *label, int label_len);

WOLFSENTRY_LOCAL int wolfsentry_event_key_cmp(
    const struct wolfsentry_event *left,
    const struct wolfsentry_event *right);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_event_table_init(
    struct wolfsentry_event_table *event_table);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_event_table_clone_header(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_table_init(
    struct wolfsentry_action_table *action_table);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_table_clone_header(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_route_table_init(
    struct wolfsentry_route_table *route_table);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_route_table_fallthrough_route_alloc(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_route_table_clone_header(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags);
WOLFSENTRY_LOCAL_VOID wolfsentry_route_table_free(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table **route_table);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_route_copy_metadata(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *from_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_route_table *to_table);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_init(
    struct wolfsentry_kv_table *kv_table);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_clone_header(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_bynumber_table_init(
    struct wolfsentry_addr_family_bynumber_table *addr_family_bynumber_table);
#ifndef WOLFSENTRY_PROTOCOL_NAMES
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_bynumber_table_clone_header(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags);
#endif
#ifdef WOLFSENTRY_PROTOCOL_NAMES
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_byname_table_init(
    struct wolfsentry_addr_family_byname_table *addr_family_byname_table);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_table_clone_headers(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *src_table1,
    struct wolfsentry_table_header *src_table2,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table1,
    struct wolfsentry_table_header *dest_table2,
    wolfsentry_clone_flags_t flags);
#endif

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_table_ent_insert(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_table_ent_header *ent, struct wolfsentry_table_header *table, int unique_p);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_table_ent_get(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_table_header *table, struct wolfsentry_table_ent_header **ent);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_table_ent_delete(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_table_ent_header **ent);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_table_ent_drop_reference(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_table_ent_header *ent, wolfsentry_action_res_t *action_results);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_table_ent_delete_1(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_table_ent_header *ent);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_table_ent_insert_by_id(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_table_ent_header *ent);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_table_ent_delete_by_id_1(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_table_ent_header *ent);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_table_ent_delete_by_id(WOLFSENTRY_CONTEXT_ARGS_IN, wolfsentry_ent_id_t id, struct wolfsentry_table_ent_header **ent);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_table_clone(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_coupled_table_clone(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *src_table1,
    struct wolfsentry_table_header *src_table2,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table1,
    struct wolfsentry_table_header *dest_table2,
    wolfsentry_clone_flags_t flags);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_insert_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *label,
    int label_len,
    wolfsentry_action_flags_t flags,
    wolfsentry_action_callback_t handler,
    void *handler_arg,
    wolfsentry_ent_id_t *id);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_insert_builtins(
    WOLFSENTRY_CONTEXT_ARGS_IN);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_clone(
    struct wolfsentry_context *src_context,
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread,
#endif
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header **new_ent,
    wolfsentry_clone_flags_t flags);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_event_clone_bare(
    struct wolfsentry_context *src_context,
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread,
#endif
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header **new_ent,
    wolfsentry_clone_flags_t flags);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_event_clone_resolve(
    struct wolfsentry_context *src_context,
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread,
#endif
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header *new_ent,
    wolfsentry_clone_flags_t flags);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_route_clone(
    struct wolfsentry_context *src_context,
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread,
#endif
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header **new_ent,
    wolfsentry_clone_flags_t flags);

WOLFSENTRY_LOCAL_VOID wolfsentry_route_purge_list_insert(
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *route_to_insert);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_table_free_ents(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_table_header *table);

static inline __wolfsentry_wur struct wolfsentry_table_ent_header *wolfsentry_table_first(const struct wolfsentry_table_header *table) {
    return table->head;
}
static inline __wolfsentry_wur struct wolfsentry_table_ent_header *wolfsentry_table_last(const struct wolfsentry_table_header *table) {
    return table->tail;
}
static inline __wolfsentry_wur struct wolfsentry_table_ent_header * wolfsentry_table_cursor_current(const struct wolfsentry_cursor *cursor) {
    return cursor->point;
}
static inline void wolfsentry_table_cursor_seek_to_head(const struct wolfsentry_table_header *table, struct wolfsentry_cursor *cursor) {
    cursor->point = table->head;
}
static inline void wolfsentry_table_cursor_seek_to_tail(const struct wolfsentry_table_header *table, struct wolfsentry_cursor *cursor) {
    cursor->point = table->tail;
}
static inline struct wolfsentry_table_ent_header * wolfsentry_table_cursor_prev(struct wolfsentry_cursor *cursor) {
    if (cursor->point == NULL)
        return NULL;
    cursor->point = cursor->point->prev;
    return cursor->point;
}
static inline struct wolfsentry_table_ent_header * wolfsentry_table_cursor_next(struct wolfsentry_cursor *cursor) {
    if (cursor->point == NULL)
        return NULL;
    cursor->point = cursor->point->next;
    return cursor->point;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_table_cursor_init(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_cursor *cursor);
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_table_cursor_seek(const struct wolfsentry_table_header *table, const struct wolfsentry_table_ent_header *ent, struct wolfsentry_cursor *cursor, int *cursor_position);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_table_filter(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *table,
    wolfsentry_filter_function_t filter,
    void *filter_arg,
    wolfsentry_dropper_function_t dropper,
    void *dropper_arg);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_table_map(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *table,
    wolfsentry_map_function_t fn,
    void *map_context,
    wolfsentry_action_res_t *action_results);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_list_append(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *action_list,
    const char *label,
    int label_len);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_list_prepend(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *action_list,
    const char *label,
    int label_len);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_list_insert_after(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *action_list,
    const char *label,
    int label_len,
    const char *point_label,
    int point_label_len);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_list_clone(
    struct wolfsentry_context *src_context,
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread,
#endif
    struct wolfsentry_action_list *src_action_list,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_action_list *dest_action_list,
    wolfsentry_clone_flags_t flags);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_list_delete(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *action_list,
    const char *label,
    int label_len);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_list_delete_all(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *action_list);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_list_dispatch(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg,
    struct wolfsentry_event *action_event,
    struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *trigger_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_eventconfig_load(
    const struct wolfsentry_eventconfig *supplied,
    struct wolfsentry_eventconfig_internal *internal);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_eventconfig_get_1(
    const struct wolfsentry_eventconfig_internal *internal,
    struct wolfsentry_eventconfig *exported);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_eventconfig_update_1(
    const struct wolfsentry_eventconfig *supplied,
    struct wolfsentry_eventconfig_internal *internal);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_new(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    int data_len, /* length with terminating null if WOLFSENTRY_KV_STRING, base64 length with null if WOLFSENTRY_KV_BYTES, 0 otherwise */
    struct wolfsentry_kv_pair_internal **kv);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_drop_reference(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_pair_internal *kv,
    wolfsentry_action_res_t *action_results);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_set_mutability(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    struct wolfsentry_kv_pair_internal *kv,
    int mutable);

WOLFSENTRY_LOCAL int wolfsentry_kv_get_mutability(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    const struct wolfsentry_kv_pair_internal *kv);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_insert(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    struct wolfsentry_kv_pair_internal *kv);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_set(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    struct wolfsentry_kv_pair_internal *kv);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_get_reference(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    const char *key,
    int key_len,
    wolfsentry_kv_type_t type,
    struct wolfsentry_kv_pair_internal **kv);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_get_type(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    const char *key,
    int key_len,
    wolfsentry_kv_type_t *type);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_clone(
    struct wolfsentry_context *src_context,
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread,
#endif
    struct wolfsentry_table_ent_header * const src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header ** const new_ent,
    wolfsentry_clone_flags_t flags);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_delete(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    const char *key,
    int key_len);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_set_validator(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    wolfsentry_kv_validator_t validator,
    wolfsentry_action_res_t *action_results);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_iterate_start(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_table *table,
    struct wolfsentry_cursor **cursor);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_iterate_seek_to_head(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_table *table,
    struct wolfsentry_cursor *cursor);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_iterate_seek_to_tail(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_table *table,
    struct wolfsentry_cursor *cursor);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_iterate_current(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_kv_pair_internal **kv);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_iterate_prev(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_kv_pair_internal **kv);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_iterate_next(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_kv_pair_internal **kv);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_iterate_end(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_table *table,
    struct wolfsentry_cursor **cursor);

#ifdef WOLFSENTRY_PROTOCOL_NAMES
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_table_pair(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_addr_family_bynumber_table *bynumber_table,
    struct wolfsentry_addr_family_byname_table *byname_table);
#endif

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_insert(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_addr_family_bynumber_table *bynumber_table,
    wolfsentry_addr_family_t family_bynumber,
    const char *family_byname,
    int family_byname_len,
    wolfsentry_addr_family_parser_t parser,
    wolfsentry_addr_family_formatter_t formatter,
    int max_addr_bits);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_get_bynumber(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_addr_family_t family_bynumber,
    const struct wolfsentry_addr_family_bynumber **addr_family);

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_get_byname(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_addr_family_t family_bynumber,
    const char *family_byname,
    int family_byname_len,
    const struct wolfsentry_addr_family_bynumber **addr_family);

#ifdef WOLFSENTRY_PROTOCOL_NAMES
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_clone(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header **new_ent1,
    struct wolfsentry_table_ent_header **new_ent2,
    wolfsentry_clone_flags_t flags);
#else
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_bynumber_clone(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header **new_ent,
    wolfsentry_clone_flags_t flags);
#endif

#endif /* WOLFSENTRY_INTERNAL_H */
