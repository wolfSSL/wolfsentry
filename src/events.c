/*
 * events.c
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

    return ret;
}

int wolfsentry_event_key_cmp(struct wolfsentry_event *left, struct wolfsentry_event *right) {
    return wolfsentry_event_key_cmp_1(left->label, left->label_len, right->label, right->label_len);
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
        if (ret < 0)
            return ret;
    }

    WOLFSENTRY_RETURN_OK;
}

static void wolfsentry_event_free(struct wolfsentry_context *wolfsentry, struct wolfsentry_event *event) {
    (void)wolfsentry_action_list_delete_all(wolfsentry, &event->action_list);
    if (event->config)
        WOLFSENTRY_FREE(event->config);
    WOLFSENTRY_FREE(event);
}

static wolfsentry_errcode_t wolfsentry_event_new_1(struct wolfsentry_context *wolfsentry, const char *label, int label_len, wolfsentry_priority_t priority, const struct wolfsentry_eventconfig *config, struct wolfsentry_event **event) {
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
        wolfsentry_event_free(wolfsentry, *event);
        *event = NULL;
    }
    return ret;
}

wolfsentry_errcode_t wolfsentry_event_clone_bare(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_table_ent_header * const src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header ** const new_ent,
    wolfsentry_clone_flags_t flags)
{
    struct wolfsentry_event * const src_event = (struct wolfsentry_event * const)src_ent;
    struct wolfsentry_event ** const new_event = (struct wolfsentry_event ** const)new_ent;
    size_t new_size = sizeof *src_event + (size_t)(src_event->label_len) + 1;

    (void)wolfsentry;
    (void)flags;

    if ((*new_event = dest_context->allocator.malloc(dest_context->allocator.context, new_size)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    memcpy(*new_event, src_event, new_size);
    WOLFSENTRY_TABLE_ENT_HEADER_RESET(**new_ent);

    (*new_event)->insert_event = NULL;
    (*new_event)->match_event = NULL;
    (*new_event)->delete_event = NULL;
    (*new_event)->decision_event = NULL;
    WOLFSENTRY_LIST_HEADER_RESET((*new_event)->action_list.header);

    if (src_event->config) {
        if (((*new_event)->config = dest_context->allocator.malloc(dest_context->allocator.context, sizeof *(*new_event)->config)) == NULL) {
            dest_context->allocator.free(dest_context->allocator.context, *new_event);
            WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
        }
        memcpy((*new_event)->config, src_event->config, sizeof *(*new_event)->config);
    }

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_event_clone_resolve(
    struct wolfsentry_context *src_context,
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header *new_ent,
    wolfsentry_clone_flags_t flags)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event * const src_event = (struct wolfsentry_event * const)src_ent;
    struct wolfsentry_event * const new_event = (struct wolfsentry_event * const)new_ent;

    if ((ret = wolfsentry_action_list_clone(
             src_context,
             &src_event->action_list,
             dest_context,
             &new_event->action_list,
             flags)) < 0)
        return ret;

    if (src_event->insert_event) {
        new_event->insert_event = src_event->insert_event;
        if ((ret = wolfsentry_table_ent_get(&dest_context->events->header, (struct wolfsentry_table_ent_header **)&new_event->insert_event)) < 0) {
            new_event->insert_event = NULL;
            WOLFSENTRY_ERROR_RERETURN(ret);
        }
        WOLFSENTRY_REFCOUNT_INCREMENT(new_event->insert_event->header.refcount);
    }

    if (src_event->match_event) {
        new_event->match_event = src_event->match_event;
        if ((ret = wolfsentry_table_ent_get(&dest_context->events->header, (struct wolfsentry_table_ent_header **)&new_event->match_event)) < 0) {
            new_event->match_event = NULL;
            WOLFSENTRY_ERROR_RERETURN(ret);
        }
        WOLFSENTRY_REFCOUNT_INCREMENT(new_event->match_event->header.refcount);
    }

    if (src_event->delete_event) {
        new_event->delete_event = src_event->delete_event;
        if ((ret = wolfsentry_table_ent_get(&dest_context->events->header, (struct wolfsentry_table_ent_header **)&new_event->delete_event)) < 0) {
            new_event->delete_event = NULL;
            WOLFSENTRY_ERROR_RERETURN(ret);
        }
        WOLFSENTRY_REFCOUNT_INCREMENT(new_event->delete_event->header.refcount);
    }

    if (src_event->decision_event) {
        new_event->decision_event = src_event->decision_event;
        if ((ret = wolfsentry_table_ent_get(&dest_context->events->header, (struct wolfsentry_table_ent_header **)&new_event->decision_event)) < 0) {
            new_event->decision_event = NULL;
            WOLFSENTRY_ERROR_RERETURN(ret);
        }
        WOLFSENTRY_REFCOUNT_INCREMENT(new_event->decision_event->header.refcount);
    }

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_event_insert(
    struct wolfsentry_context *wolfsentry,
    const char *label,
    int label_len,
    wolfsentry_priority_t priority,
    const struct wolfsentry_eventconfig *config,
    wolfsentry_event_flags_t flags,
    wolfsentry_ent_id_t *id)
{
    struct wolfsentry_event *new;
    wolfsentry_errcode_t ret;

    (void)flags; /* for now */

    if ((ret = wolfsentry_event_new_1(wolfsentry, label, label_len, priority, config, &new)) < 0)
        return ret;
    if ((ret = wolfsentry_id_allocate(wolfsentry, &new->header)) < 0) {
        wolfsentry_event_free(wolfsentry, new);
        return ret;
    }
    if (id)
        *id = new->header.id;
    if ((ret = wolfsentry_table_ent_insert(wolfsentry, &new->header, &wolfsentry->events->header, 1 /* unique_p */)) < 0) {
        wolfsentry_table_ent_delete_by_id_1(wolfsentry, &new->header);
        wolfsentry_event_free(wolfsentry, new);
        WOLFSENTRY_ERROR_RERETURN(ret);
    }

    return ret;
}

const char *wolfsentry_event_get_label(const struct wolfsentry_event *event)
{
    return event ? event->label : (const char *)event;
}

wolfsentry_event_flags_t wolfsentry_event_get_flags(const struct wolfsentry_event *event)
{
    return event ? event->flags : WOLFSENTRY_EVENT_FLAG_NONE;
}

static wolfsentry_errcode_t wolfsentry_event_get_1(struct wolfsentry_context *wolfsentry, const char *label, int label_len, struct wolfsentry_event **event) {
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

    if ((ret = wolfsentry_event_init_1(label, label_len, 0, NULL, &target.event, sizeof target)) < 0)
        return ret;

    if ((ret = wolfsentry_table_ent_get(&wolfsentry->events->header, (struct wolfsentry_table_ent_header **)&event_1)) < 0)
        return ret;

    *event = event_1;

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_event_get_config(struct wolfsentry_context *wolfsentry, const char *label, int label_len, struct wolfsentry_eventconfig *config) {
    struct wolfsentry_event *event;
    wolfsentry_errcode_t ret = wolfsentry_event_get_1(wolfsentry, label, label_len, &event);
    if (ret < 0)
        return ret;
    if (event->config == NULL)
        return wolfsentry_eventconfig_get_1(&wolfsentry->config, config);
    else
        return wolfsentry_eventconfig_get_1(event->config, config);
}

wolfsentry_errcode_t wolfsentry_event_update_config(struct wolfsentry_context *wolfsentry, const char *label, int label_len, struct wolfsentry_eventconfig *config) {
    struct wolfsentry_event *event;
    wolfsentry_errcode_t ret = wolfsentry_event_get_1(wolfsentry, label, label_len, &event);
    if (ret < 0)
        return ret;
    if (WOLFSENTRY_CHECK_BITS(event->flags, WOLFSENTRY_EVENT_FLAG_IS_SUBEVENT))
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);

    if (event->config == NULL) {
        if ((event->config = (struct wolfsentry_eventconfig_internal *)WOLFSENTRY_MALLOC(sizeof *event->config)) == NULL)
            WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
        if ((ret = wolfsentry_eventconfig_load(config, event->config)) < 0) {
            WOLFSENTRY_FREE(event->config);
            event->config = NULL;
        }
        return ret;
    } else
        return wolfsentry_eventconfig_load(config, event->config);
}

wolfsentry_errcode_t wolfsentry_event_get_reference(struct wolfsentry_context *wolfsentry, const char *label, int label_len, struct wolfsentry_event **event) {
    wolfsentry_errcode_t ret;

    if ((ret = wolfsentry_event_get_1(wolfsentry, label, label_len, event)) < 0)
        return ret;
    WOLFSENTRY_REFCOUNT_INCREMENT((*event)->header.refcount);

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_event_drop_reference(struct wolfsentry_context *wolfsentry, struct wolfsentry_event *event, wolfsentry_action_res_t *action_results) {
    if (event->header.refcount <= 0)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if ((event->header.parent_table != NULL) &&
        (event->header.parent_table->ent_type != WOLFSENTRY_OBJECT_TYPE_EVENT))
        WOLFSENTRY_ERROR_RETURN(WRONG_OBJECT);
    if (action_results)
        WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    if (WOLFSENTRY_REFCOUNT_DECREMENT(event->header.refcount) > 0)
        WOLFSENTRY_RETURN_OK;
    if (event->insert_event)
        wolfsentry_event_drop_reference(wolfsentry, event->insert_event, NULL);
    if (event->match_event)
        wolfsentry_event_drop_reference(wolfsentry, event->match_event, NULL);
    if (event->delete_event)
        wolfsentry_event_drop_reference(wolfsentry, event->delete_event, NULL);
    if (event->decision_event)
        wolfsentry_event_drop_reference(wolfsentry, event->decision_event, NULL);
    wolfsentry_event_free(wolfsentry, event);
    if (action_results)
        WOLFSENTRY_SET_BITS(*action_results, WOLFSENTRY_ACTION_RES_DEALLOCATED);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_event_delete(
    struct wolfsentry_context *wolfsentry,
    const char *label,
    int label_len,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *old;

    if ((ret = wolfsentry_event_get_1(wolfsentry, label, label_len, &old)) < 0)
        return ret;

    if ((ret = wolfsentry_action_list_delete_all(wolfsentry, &old->action_list)) < 0)
        return ret;

    if (old->insert_event) {
        if ((ret = wolfsentry_event_drop_reference(wolfsentry, old->insert_event, NULL /* action_results */)) < 0)
            return ret;
        old->insert_event = NULL;
    }
    if (old->match_event) {
        if ((ret = wolfsentry_event_drop_reference(wolfsentry, old->match_event, NULL /* action_results */)) < 0)
            return ret;
        old->match_event = NULL;
    }
    if (old->delete_event) {
        if ((ret = wolfsentry_event_drop_reference(wolfsentry, old->delete_event, NULL /* action_results */)) < 0)
            return ret;
        old->delete_event = NULL;
    }
    if (old->decision_event) {
        if ((ret = wolfsentry_event_drop_reference(wolfsentry, old->decision_event, NULL /* action_results */)) < 0)
            return ret;
        old->decision_event = NULL;
    }

    if ((ret = wolfsentry_table_ent_delete_1(wolfsentry, &old->header)) < 0)
        return ret;

    return wolfsentry_event_drop_reference(wolfsentry, old, action_results);
}

wolfsentry_errcode_t wolfsentry_event_flush_all(struct wolfsentry_context *wolfsentry) {
    return wolfsentry_table_free_ents(wolfsentry, &wolfsentry->events->header);
}

typedef enum { W_E_A_A_PREPEND, W_E_A_A_APPEND, W_E_A_A_INSERT, W_E_A_A_DELETE } w_e_a_a_what_t;

static inline wolfsentry_errcode_t wolfsentry_event_action_change_1(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    w_e_a_a_what_t what,
    const char *action_label,
    int action_label_len,
    const char *point_action_label,
    int point_action_label_len)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *event;

    if ((ret = wolfsentry_event_get_1(wolfsentry, event_label, event_label_len, &event)) < 0)
        return ret;

    switch (what) {
    case W_E_A_A_PREPEND:
        ret = wolfsentry_action_list_prepend(wolfsentry, &event->action_list, action_label, action_label_len);
        break;
    case W_E_A_A_APPEND:
        ret = wolfsentry_action_list_append(wolfsentry, &event->action_list, action_label, action_label_len);
        break;
    case W_E_A_A_INSERT:
        ret = wolfsentry_action_list_insert_after(wolfsentry, &event->action_list, action_label, action_label_len, point_action_label, point_action_label_len);
        break;
    case W_E_A_A_DELETE:
        ret = wolfsentry_action_list_delete(wolfsentry, &event->action_list, action_label, action_label_len);
        break;
    };
    return ret;
}

wolfsentry_errcode_t wolfsentry_event_action_prepend(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    const char *action_label,
    int action_label_len)
{
    return wolfsentry_event_action_change_1(
        wolfsentry,
        event_label,
        event_label_len,
        W_E_A_A_PREPEND,
        action_label,
        action_label_len,
        NULL /* point_action_label */,
        0 /* point_action_label_len */);
}

wolfsentry_errcode_t wolfsentry_event_action_append(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    const char *action_label,
    int action_label_len)
{
    return wolfsentry_event_action_change_1(
        wolfsentry,
        event_label,
        event_label_len,
        W_E_A_A_APPEND,
        action_label,
        action_label_len,
        NULL /* point_action_label */,
        0 /* point_action_label_len */);
}

wolfsentry_errcode_t wolfsentry_event_action_insert_after(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    const char *action_label,
    int action_label_len,
    const char *point_action_label,
    int point_action_label_len)
{
    return wolfsentry_event_action_change_1(
        wolfsentry,
        event_label,
        event_label_len,
        W_E_A_A_INSERT,
        action_label,
        action_label_len,
        point_action_label,
        point_action_label_len);
}

wolfsentry_errcode_t wolfsentry_event_action_delete(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    const char *action_label,
    int action_label_len)
{
    return wolfsentry_event_action_change_1(
        wolfsentry,
        event_label,
        event_label_len,
        W_E_A_A_DELETE,
        action_label,
        action_label_len,
        NULL /* point_action_label */,
        0 /* point_action_label_len */);
}

wolfsentry_errcode_t wolfsentry_event_set_subevent(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_type_t subevent_type,
    const char *subevent_label,
    int subevent_label_len)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *event, *subevent = NULL;

    if ((ret = wolfsentry_event_get_reference(wolfsentry, event_label, event_label_len, &event)) < 0)
        return ret;
    if (WOLFSENTRY_CHECK_BITS(event->flags, WOLFSENTRY_EVENT_FLAG_IS_SUBEVENT)) {
        ret = WOLFSENTRY_ERROR_ENCODE(INCOMPATIBLE_STATE);
        goto out;
    }
    if (subevent_label) {
        if ((ret = wolfsentry_event_get_reference(wolfsentry, subevent_label, subevent_label_len, &subevent)) < 0) {
            subevent = NULL;
            goto out;
        }
        if (WOLFSENTRY_CHECK_BITS(subevent->flags, WOLFSENTRY_EVENT_FLAG_IS_PARENT_EVENT)) {
            ret = WOLFSENTRY_ERROR_ENCODE(INCOMPATIBLE_STATE);
            goto out;
        }
        if (subevent->config != NULL) {
            ret = WOLFSENTRY_ERROR_ENCODE(INCOMPATIBLE_STATE);
            goto out;
        }
    } else
        subevent = NULL;

    ret = WOLFSENTRY_ERROR_ENCODE(NOT_OK);
    switch(subevent_type) {
    case WOLFSENTRY_ACTION_TYPE_INSERT:
        if (event->insert_event)
            WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, event->insert_event, NULL /* action_results */));
        event->insert_event = subevent;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        break;
    case WOLFSENTRY_ACTION_TYPE_MATCH:
        if (event->match_event)
            WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, event->match_event, NULL /* action_results */));
        event->match_event = subevent;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        break;
    case WOLFSENTRY_ACTION_TYPE_DELETE:
        if (event->delete_event)
            WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, event->delete_event, NULL /* action_results */));
        event->delete_event = subevent;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        break;
    case WOLFSENTRY_ACTION_TYPE_DECISION:
        if (event->decision_event)
            WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, event->decision_event, NULL /* action_results */));
        event->decision_event = subevent;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        break;
    case WOLFSENTRY_ACTION_TYPE_POST:
    case WOLFSENTRY_ACTION_TYPE_NONE:
        break;
    }

  out:

    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, event, NULL /* action_results */));
    if (subevent) {
        if (ret < 0)
            WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, subevent, NULL /* action_results */));
        else {
            if (! WOLFSENTRY_CHECK_BITS(subevent->flags, WOLFSENTRY_EVENT_FLAG_IS_SUBEVENT))
                WOLFSENTRY_SET_BITS(subevent->flags, WOLFSENTRY_EVENT_FLAG_IS_SUBEVENT);
        }
    }

    return ret;
}


/* caller must obtain a shared lock before calling this, and free the
 * lock when done iterating wolfsentry_event_action_list_next().
 */
wolfsentry_errcode_t wolfsentry_event_action_list_start(
    struct wolfsentry_context *wolfsentry,
    const char *event_label,
    int event_label_len,
    struct wolfsentry_action_list_ent **cursor)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *event;
    if ((ret = wolfsentry_event_get_1(wolfsentry, event_label, event_label_len, &event)) < 0)
        return ret;
    *cursor = (struct wolfsentry_action_list_ent *)event->action_list.header.head;
    if (*cursor == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_event_action_list_next(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_action_list_ent **cursor,
    const char **action_label,
    int *action_label_len)
{
    (void)wolfsentry;
    if (*cursor == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    else {
        *action_label = (*cursor)->action->label;
        *action_label_len = (*cursor)->action->label_len;
        (*cursor) = (struct wolfsentry_action_list_ent *)(*cursor)->header.next;
    }
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_event_table_init(
    struct wolfsentry_event_table *event_table)
{
    WOLFSENTRY_TABLE_HEADER_RESET(event_table->header);
    event_table->header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_event_key_cmp;
    event_table->header.free_fn = (wolfsentry_ent_free_fn_t)wolfsentry_event_drop_reference;
    event_table->header.ent_type = WOLFSENTRY_OBJECT_TYPE_EVENT;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_event_table_clone_header(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags)
{
    (void)wolfsentry;
    (void)src_table;
    (void)dest_context;
    (void)dest_table;
    (void)flags;
    WOLFSENTRY_RETURN_OK;
}
