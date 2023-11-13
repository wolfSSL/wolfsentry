/*
 * events.c
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

#include "wolfsentry_internal.h"

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_EVENTS_C

static inline int wolfsentry_event_key_cmp_1(const char *left_label, const unsigned int left_label_len, const char *right_label, const unsigned int right_label_len) {
    int ret;

    if (left_label_len >= right_label_len) {
        ret = memcmp(left_label, right_label, right_label_len);
        if ((ret == 0) && (left_label_len != right_label_len))
            ret = 1;
    } else {
        ret = memcmp(left_label, right_label, left_label_len);
        if (ret == 0)
            ret = -1;
    }

    WOLFSENTRY_RETURN_VALUE(ret);
}

WOLFSENTRY_LOCAL int wolfsentry_event_key_cmp(const struct wolfsentry_event *left, const struct wolfsentry_event *right) {
    return wolfsentry_event_key_cmp_1(left->label, left->label_len, right->label, right->label_len);
}

static int wolfsentry_event_key_cmp_generic(const struct wolfsentry_table_ent_header *left, const struct wolfsentry_table_ent_header *right) {
    return wolfsentry_event_key_cmp_1(
        ((const struct wolfsentry_event *)left)->label,
        ((const struct wolfsentry_event *)left)->label_len,
        ((const struct wolfsentry_event *)right)->label,
        ((const struct wolfsentry_event *)right)->label_len);
}

static wolfsentry_errcode_t wolfsentry_event_init_1(const char *label, int label_len, wolfsentry_priority_t priority, const struct wolfsentry_eventconfig *config, struct wolfsentry_event *event, size_t event_size) {
    if (label_len <= 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (event_size < sizeof *event + (size_t)label_len + 1)
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);

    memset(&event->header, 0, sizeof event->header);

    event->priority = priority;
    memcpy(event->label, label, (size_t)label_len);
    event->label[label_len] = 0;
    event->label_len = (byte)label_len;

    event->header.refcount = 1;
    event->header.id = WOLFSENTRY_ENT_ID_NONE;

    if (config) {
        wolfsentry_errcode_t ret = wolfsentry_eventconfig_load(config, event->config);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
    }

    WOLFSENTRY_RETURN_OK;
}

static void wolfsentry_event_free(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_event *event) {
    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_delete_all(WOLFSENTRY_CONTEXT_ARGS_OUT, &event->post_action_list));
    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_delete_all(WOLFSENTRY_CONTEXT_ARGS_OUT, &event->insert_action_list));
    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_delete_all(WOLFSENTRY_CONTEXT_ARGS_OUT, &event->match_action_list));
    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_delete_all(WOLFSENTRY_CONTEXT_ARGS_OUT, &event->update_action_list));
    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_delete_all(WOLFSENTRY_CONTEXT_ARGS_OUT, &event->delete_action_list));
    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_delete_all(WOLFSENTRY_CONTEXT_ARGS_OUT, &event->decision_action_list));
    if (event->config)
        WOLFSENTRY_FREE(event->config);
    WOLFSENTRY_FREE(event);
    WOLFSENTRY_RETURN_VOID;
}

static wolfsentry_errcode_t wolfsentry_event_new_1(WOLFSENTRY_CONTEXT_ARGS_IN, const char *label, int label_len, wolfsentry_priority_t priority, const struct wolfsentry_eventconfig *config, struct wolfsentry_event **event) {
    size_t new_size;
    wolfsentry_errcode_t ret;

    if ((label_len == 0) || (label == NULL) || (event == NULL))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (label_len < 0)
        label_len = (int)strlen(label);
    if (label_len > WOLFSENTRY_MAX_LABEL_BYTES)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);

    new_size = sizeof **event + (size_t)label_len + 1;

    if ((*event = (struct wolfsentry_event *)WOLFSENTRY_MALLOC(new_size)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);

    memset(*event, 0, new_size);

    if (config) {
        if (((*event)->config = (struct wolfsentry_eventconfig_internal *)WOLFSENTRY_MALLOC(sizeof *((*event)->config))) == NULL) {
            WOLFSENTRY_FREE(*event);
            WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
        }
    }

    ret = wolfsentry_event_init_1(label, label_len, priority, config, *event, new_size);
    if (ret < 0) {
        wolfsentry_event_free(WOLFSENTRY_CONTEXT_ARGS_OUT, *event);
        *event = NULL;
    }
    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_event_clone_bare(
    struct wolfsentry_context *src_context,
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread,
#endif
    struct wolfsentry_table_ent_header * const src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header ** const new_ent,
    wolfsentry_clone_flags_t flags)
{
    struct wolfsentry_event * const src_event = (struct wolfsentry_event * const)src_ent;
    struct wolfsentry_event ** const new_event = (struct wolfsentry_event ** const)new_ent;
    size_t new_size = sizeof *src_event + (size_t)(src_event->label_len) + 1;

#ifdef WOLFSENTRY_THREADSAFE
    (void)thread;
#endif
    (void)src_context;
    (void)flags;

    if ((*new_event = WOLFSENTRY_MALLOC_1(dest_context->hpi.allocator, new_size)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    memcpy(*new_event, src_event, new_size);
    WOLFSENTRY_TABLE_ENT_HEADER_RESET(**new_ent);

    WOLFSENTRY_LIST_HEADER_RESET((*new_event)->post_action_list.header);
    WOLFSENTRY_LIST_HEADER_RESET((*new_event)->insert_action_list.header);
    WOLFSENTRY_LIST_HEADER_RESET((*new_event)->match_action_list.header);
    WOLFSENTRY_LIST_HEADER_RESET((*new_event)->update_action_list.header);
    WOLFSENTRY_LIST_HEADER_RESET((*new_event)->delete_action_list.header);
    WOLFSENTRY_LIST_HEADER_RESET((*new_event)->decision_action_list.header);

    (*new_event)->aux_event = NULL;

    if (src_event->config) {
        if (((*new_event)->config = WOLFSENTRY_MALLOC_1(dest_context->hpi.allocator, sizeof *(*new_event)->config)) == NULL) {
            WOLFSENTRY_FREE_1(dest_context->hpi.allocator, *new_event);
            WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
        }
        memcpy((*new_event)->config, src_event->config, sizeof *(*new_event)->config);
    }

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_event_clone_resolve(
    struct wolfsentry_context *src_context,
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread,
#endif
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header *new_ent,
    wolfsentry_clone_flags_t flags)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event * const src_event = (struct wolfsentry_event * const)src_ent;
    struct wolfsentry_event * const new_event = (struct wolfsentry_event * const)new_ent;

    ret = wolfsentry_action_list_clone(
        src_context,
#ifdef WOLFSENTRY_THREADSAFE
        thread,
#endif
        &src_event->post_action_list,
        dest_context,
        &new_event->post_action_list,
        flags);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_action_list_clone(
        src_context,
#ifdef WOLFSENTRY_THREADSAFE
        thread,
#endif
        &src_event->insert_action_list,
        dest_context,
        &new_event->insert_action_list,
        flags);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_action_list_clone(
        src_context,
#ifdef WOLFSENTRY_THREADSAFE
        thread,
#endif
        &src_event->match_action_list,
        dest_context,
        &new_event->match_action_list,
        flags);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_action_list_clone(
        src_context,
#ifdef WOLFSENTRY_THREADSAFE
        thread,
#endif
        &src_event->update_action_list,
        dest_context,
        &new_event->update_action_list,
        flags);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_action_list_clone(
        src_context,
#ifdef WOLFSENTRY_THREADSAFE
        thread,
#endif
        &src_event->delete_action_list,
        dest_context,
        &new_event->delete_action_list,
        flags);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_action_list_clone(
        src_context,
#ifdef WOLFSENTRY_THREADSAFE
        thread,
#endif
        &src_event->decision_action_list,
        dest_context,
        &new_event->decision_action_list,
        flags);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    if (src_event->aux_event) {
        new_event->aux_event = src_event->aux_event;
        if ((ret = wolfsentry_table_ent_get(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(dest_context), &dest_context->events->header, (struct wolfsentry_table_ent_header **)&new_event->aux_event)) < 0) {
            new_event->aux_event = NULL;
            WOLFSENTRY_ERROR_RETURN_RECODED(ret);
        }
        WOLFSENTRY_REFCOUNT_INCREMENT(new_event->aux_event->header.refcount, ret);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
    }

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_insert(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *label,
    int label_len,
    wolfsentry_priority_t priority,
    const struct wolfsentry_eventconfig *config,
    wolfsentry_event_flags_t flags,
    wolfsentry_ent_id_t *id)
{
    struct wolfsentry_event *new;
    wolfsentry_errcode_t ret;

    ret = wolfsentry_label_is_builtin(label, label_len);
    if (WOLFSENTRY_SUCCESS_CODE_IS(ret, YES))
        WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);

    WOLFSENTRY_MUTEX_OR_RETURN();

    (void)flags; /* for now */

    ret = wolfsentry_event_new_1(WOLFSENTRY_CONTEXT_ARGS_OUT, label, label_len, priority, config, &new);
    WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);

    if ((ret = wolfsentry_id_allocate(WOLFSENTRY_CONTEXT_ARGS_OUT, &new->header)) < 0) {
        wolfsentry_event_free(WOLFSENTRY_CONTEXT_ARGS_OUT, new);
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    }
    if (id)
        *id = new->header.id;
    if ((ret = wolfsentry_table_ent_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, &new->header, &wolfsentry->events->header, 1 /* unique_p */)) < 0) {
        wolfsentry_event_free(WOLFSENTRY_CONTEXT_ARGS_OUT, new);
        WOLFSENTRY_ERROR_UNLOCK_AND_RETURN_RECODED(ret);
    }

    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API const char *wolfsentry_event_get_label(const struct wolfsentry_event *event)
{
    return event ? event->label : (const char *)event;
}

WOLFSENTRY_API wolfsentry_event_flags_t wolfsentry_event_get_flags(const struct wolfsentry_event *event)
{
    return event ? event->flags : WOLFSENTRY_EVENT_FLAG_NONE;
}

WOLFSENTRY_API const struct wolfsentry_event *wolfsentry_event_get_aux_event(const struct wolfsentry_event *event)
{
    return event ? event->aux_event : NULL;
}

static wolfsentry_errcode_t wolfsentry_event_get_1(WOLFSENTRY_CONTEXT_ARGS_IN, const char *label, int label_len, struct wolfsentry_event **event) {
    wolfsentry_errcode_t ret;
    struct {
        struct wolfsentry_event event;
        byte buf[WOLFSENTRY_MAX_LABEL_BYTES];
    } target;
    struct wolfsentry_event *event_1 = &target.event;

    if (label_len == 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (label_len < 0)
        label_len = (int)strlen(label);
    if (label_len > WOLFSENTRY_MAX_LABEL_BYTES)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);

    ret = wolfsentry_event_init_1(label, label_len, 0, NULL, &target.event, sizeof target);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_table_ent_get(WOLFSENTRY_CONTEXT_ARGS_OUT, &wolfsentry->events->header, (struct wolfsentry_table_ent_header **)&event_1);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    *event = event_1;

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_get_config(WOLFSENTRY_CONTEXT_ARGS_IN, const char *label, int label_len, struct wolfsentry_eventconfig *config) {
    struct wolfsentry_event *event;
    wolfsentry_errcode_t ret;

    WOLFSENTRY_SHARED_OR_RETURN();

    ret = wolfsentry_event_get_1(WOLFSENTRY_CONTEXT_ARGS_OUT, label, label_len, &event);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    if (event->config == NULL)
        ret = wolfsentry_eventconfig_get_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &wolfsentry->config, config);
    else
        ret = wolfsentry_eventconfig_get_1(WOLFSENTRY_CONTEXT_ARGS_OUT, event->config, config);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_update_config(WOLFSENTRY_CONTEXT_ARGS_IN, const char *label, int label_len, const struct wolfsentry_eventconfig *config) {
    struct wolfsentry_event *event;
    wolfsentry_errcode_t ret;

    WOLFSENTRY_MUTEX_OR_RETURN();

    ret = wolfsentry_event_get_1(WOLFSENTRY_CONTEXT_ARGS_OUT, label, label_len, &event);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    if (event->config == NULL) {
        if ((event->config = (struct wolfsentry_eventconfig_internal *)WOLFSENTRY_MALLOC(sizeof *event->config)) == NULL)
            WOLFSENTRY_ERROR_UNLOCK_AND_RETURN(SYS_RESOURCE_FAILED);
        if ((ret = wolfsentry_eventconfig_load(config, event->config)) < 0) {
            WOLFSENTRY_FREE(event->config);
            event->config = NULL;
        }
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    } else {
        ret = wolfsentry_eventconfig_load(config, event->config);
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    }
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_get_reference(WOLFSENTRY_CONTEXT_ARGS_IN, const char *label, int label_len, struct wolfsentry_event **event) {
    wolfsentry_errcode_t ret;

    /* avoid lock recursion overhead -- this function is mainly called by
     * wolfsentry_route_event_dispatch_1(), which gets a lock before calling.
     */
    if (WOLFSENTRY_HAVE_A_LOCK() < 0) {
        WOLFSENTRY_SHARED_OR_RETURN();

        ret = wolfsentry_event_get_1(WOLFSENTRY_CONTEXT_ARGS_OUT, label, label_len, event);
        WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);
        WOLFSENTRY_REFCOUNT_INCREMENT((*event)->header.refcount, ret);
        WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);

        WOLFSENTRY_UNLOCK_AND_RETURN_OK;
    } else {
        ret = wolfsentry_event_get_1(WOLFSENTRY_CONTEXT_ARGS_OUT, label, label_len, event);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        WOLFSENTRY_REFCOUNT_INCREMENT((*event)->header.refcount, ret);
        WOLFSENTRY_ERROR_RERETURN(ret);
    }
}

/* NOLINTBEGIN(misc-no-recursion) */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_event *event, wolfsentry_action_res_t *action_results) {
    wolfsentry_errcode_t ret;
    wolfsentry_refcount_t refs_left;
    if (event->header.refcount <= 0)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if ((event->header.parent_table != NULL) &&
        (event->header.parent_table->ent_type != WOLFSENTRY_OBJECT_TYPE_EVENT))
        WOLFSENTRY_ERROR_RETURN(WRONG_OBJECT);
    if (action_results)
        WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    WOLFSENTRY_REFCOUNT_DECREMENT(event->header.refcount, refs_left, ret);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    if (refs_left > 0)
        WOLFSENTRY_RETURN_OK;
    if (event->aux_event) {
        ret = wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event->aux_event, NULL);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        event->aux_event = NULL;
    }
    wolfsentry_event_free(WOLFSENTRY_CONTEXT_ARGS_OUT, event);
    if (action_results)
        WOLFSENTRY_SET_BITS(*action_results, WOLFSENTRY_ACTION_RES_DEALLOCATED);
    WOLFSENTRY_RETURN_OK;
}
/* NOLINTEND(misc-no-recursion) */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_delete(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *label,
    int label_len,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *old;

    WOLFSENTRY_MUTEX_OR_RETURN();

    ret = wolfsentry_event_get_1(WOLFSENTRY_CONTEXT_ARGS_OUT, label, label_len, &old);
    WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_table_ent_delete_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &old->header);
    WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, old, action_results);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_flush_all(WOLFSENTRY_CONTEXT_ARGS_IN) {
    wolfsentry_errcode_t ret;
    WOLFSENTRY_MUTEX_OR_RETURN();
    ret = wolfsentry_table_free_ents(WOLFSENTRY_CONTEXT_ARGS_OUT, &wolfsentry->events->header);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

typedef enum { W_E_A_A_PREPEND, W_E_A_A_APPEND, W_E_A_A_INSERT, W_E_A_A_DELETE } w_e_a_a_how_t;

static inline wolfsentry_errcode_t wolfsentry_event_action_change_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t which_action_list,
    w_e_a_a_how_t how,
    const char *action_label,
    int action_label_len,
    const char *point_action_label,
    int point_action_label_len)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *event;
    struct wolfsentry_action_list *w_a_l = NULL;

    WOLFSENTRY_MUTEX_OR_RETURN();

    ret = wolfsentry_event_get_1(WOLFSENTRY_CONTEXT_ARGS_OUT, event_label, event_label_len, &event);
    WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);

    switch (which_action_list) {
    case WOLFSENTRY_ACTION_TYPE_POST:
        w_a_l = &event->post_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_INSERT:
        w_a_l = &event->insert_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_MATCH:
        w_a_l = &event->match_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_UPDATE:
        w_a_l = &event->update_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_DELETE:
        w_a_l = &event->delete_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_DECISION:
        w_a_l = &event->decision_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_NONE:
        break;
    }

    if (w_a_l == NULL)
        WOLFSENTRY_ERROR_UNLOCK_AND_RETURN(INVALID_ARG);

    switch (how) {
    case W_E_A_A_PREPEND:
        ret = wolfsentry_action_list_prepend(WOLFSENTRY_CONTEXT_ARGS_OUT, w_a_l, action_label, action_label_len);
        break;
    case W_E_A_A_APPEND:
        ret = wolfsentry_action_list_append(WOLFSENTRY_CONTEXT_ARGS_OUT, w_a_l, action_label, action_label_len);
        break;
    case W_E_A_A_INSERT:
        ret = wolfsentry_action_list_insert_after(WOLFSENTRY_CONTEXT_ARGS_OUT, w_a_l, action_label, action_label_len, point_action_label, point_action_label_len);
        break;
    case W_E_A_A_DELETE:
        ret = wolfsentry_action_list_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, w_a_l, action_label, action_label_len);
        break;
    };
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_prepend(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t which_action_list,
    const char *action_label,
    int action_label_len
)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_event_action_change_1(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        event_label,
        event_label_len,
        which_action_list,
        W_E_A_A_PREPEND,
        action_label,
        action_label_len,
        NULL /* point_action_label */,
        0 /* point_action_label_len */));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_append(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t which_action_list,
    const char *action_label,
    int action_label_len)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_event_action_change_1(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        event_label,
        event_label_len,
        which_action_list,
        W_E_A_A_APPEND,
        action_label,
        action_label_len,
        NULL /* point_action_label */,
        0 /* point_action_label_len */));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_insert_after(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t which_action_list,
    const char *action_label,
    int action_label_len,
    const char *point_action_label,
    int point_action_label_len)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_event_action_change_1(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        event_label,
        event_label_len,
        which_action_list,
        W_E_A_A_INSERT,
        action_label,
        action_label_len,
        point_action_label,
        point_action_label_len));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_delete(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t which_action_list,
    const char *action_label,
    int action_label_len)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_event_action_change_1(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        event_label,
        event_label_len,
        which_action_list,
        W_E_A_A_DELETE,
        action_label,
        action_label_len,
        NULL /* point_action_label */,
        0 /* point_action_label_len */));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_set_aux_event(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *event_label,
    int event_label_len,
    const char *aux_event_label,
    int aux_event_label_len)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *event, *aux_event = NULL;

    WOLFSENTRY_MUTEX_OR_RETURN();

    ret = wolfsentry_event_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event_label, event_label_len, &event);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    if (WOLFSENTRY_CHECK_BITS(event->flags, WOLFSENTRY_EVENT_FLAG_IS_SUBEVENT)) {
        ret = WOLFSENTRY_ERROR_ENCODE(INCOMPATIBLE_STATE);
        goto out;
    }
    if (aux_event_label) {
        ret = wolfsentry_event_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, aux_event_label, aux_event_label_len, &aux_event);
        if (ret < 0) {
            aux_event = NULL;
            goto out;
        }
        if (WOLFSENTRY_CHECK_BITS(aux_event->flags, WOLFSENTRY_EVENT_FLAG_IS_PARENT_EVENT)) {
            ret = WOLFSENTRY_ERROR_ENCODE(INCOMPATIBLE_STATE);
            goto out;
        }
    } else
        aux_event = NULL;

    if (event->aux_event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event->aux_event, NULL /* action_results */));
    event->aux_event = aux_event;
    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event, NULL /* action_results */));
    if (aux_event) {
        if (ret < 0)
            WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, aux_event, NULL /* action_results */));
        else {
            if (! WOLFSENTRY_CHECK_BITS(aux_event->flags, WOLFSENTRY_EVENT_FLAG_IS_SUBEVENT))
                WOLFSENTRY_SET_BITS(aux_event->flags, WOLFSENTRY_EVENT_FLAG_IS_SUBEVENT);
        }
    }

    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}


WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_list_start(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t which_action_list,
    struct wolfsentry_action_list_ent **cursor)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *event;
    struct wolfsentry_action_list *w_a_l = NULL;

    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();

    ret = wolfsentry_event_get_1(WOLFSENTRY_CONTEXT_ARGS_OUT, event_label, event_label_len, &event);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    switch (which_action_list) {
    case WOLFSENTRY_ACTION_TYPE_POST:
        w_a_l = &event->post_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_INSERT:
        w_a_l = &event->insert_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_MATCH:
        w_a_l = &event->match_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_UPDATE:
        w_a_l = &event->update_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_DELETE:
        w_a_l = &event->delete_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_DECISION:
        w_a_l = &event->decision_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_NONE:
        break;
    }

    if (w_a_l == NULL)
        WOLFSENTRY_ERROR_UNLOCK_AND_RETURN(INVALID_ARG);

    *cursor = (struct wolfsentry_action_list_ent *)w_a_l->header.head;
    if (*cursor == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_list_next(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list_ent **cursor,
    const char **action_label,
    int *action_label_len)
{
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();

    if (*cursor == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    else {
        *action_label = (*cursor)->action->label;
        *action_label_len = (*cursor)->action->label_len;
        (*cursor) = (struct wolfsentry_action_list_ent *)(*cursor)->header.next;
    }
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_event_action_list_done(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list_ent **cursor)
{
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();

    *cursor = NULL;
    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_event_drop_reference_generic(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_table_ent_header *event, wolfsentry_action_res_t *action_results) {
    return wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, (struct wolfsentry_event *)event, action_results);
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_event_table_init(
    struct wolfsentry_event_table *event_table)
{
    WOLFSENTRY_TABLE_HEADER_RESET(event_table->header);
    event_table->header.cmp_fn = wolfsentry_event_key_cmp_generic;
    event_table->header.free_fn = wolfsentry_event_drop_reference_generic;
    event_table->header.ent_type = WOLFSENTRY_OBJECT_TYPE_EVENT;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_event_table_clone_header(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    (void)src_table;
    (void)dest_context;
    (void)dest_table;
    (void)flags;
    WOLFSENTRY_RETURN_OK;
}
