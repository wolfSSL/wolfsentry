/*
 * internal.c
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

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_INTERNAL_C

wolfsentry_errcode_t wolfsentry_table_ent_insert(struct wolfsentry_context *wolfsentry, struct wolfsentry_table_ent_header *ent, struct wolfsentry_table_header *table, int unique_p) {
    struct wolfsentry_table_ent_header *i = table->head;
    int cmpret;

    if (ent->id == WOLFSENTRY_ENT_ID_NONE)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    while (i) {
        if ((cmpret = table->cmp_fn(i, ent)) >= 0)
            break;
        i = i->next;
    }
    if (i) {
        if ((cmpret == 0) && unique_p) {
            if (ent->id != WOLFSENTRY_ENT_ID_NONE)
                wolfsentry_table_ent_delete_by_id_1(wolfsentry, ent);
            WOLFSENTRY_ERROR_RETURN(ITEM_ALREADY_PRESENT);
        }
        ent->prev = i->prev;
        ent->next = i;
        if (i->prev) {
            i->prev->next = ent;
        } else {
            table->head = ent;
        }
        i->prev = ent;
    } else if (table->tail) {
        table->tail->next = ent;
        ent->prev = table->tail;
        ent->next = NULL;
        table->tail = ent;
    } else {
        table->head = table->tail = ent;
        ent->prev = ent->next = NULL;
    }
    ++table->n_ents;
    ++table->n_inserts;
    ent->parent_table = table;

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_table_clone_map(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_table_ent_clone_map_fn_t clone_map_fn,
    wolfsentry_clone_flags_t flags)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_table_ent_header *i, *i_new;

    if ((wolfsentry == dest_context) || (src_table == dest_table))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (src_table->ent_type != dest_table->ent_type)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (src_table->n_ents != dest_table->n_ents)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    for (i = src_table->head, i_new = dest_table->head;
         i && i_new;
         i = i->next, i_new = i_new->next) {
        if ((ret = clone_map_fn(wolfsentry, i, dest_context, i_new, flags)) < 0)
            return ret;
    }
    if (i || i_new)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_table_clone(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags)
{
    wolfsentry_errcode_t ret;
    wolfsentry_table_ent_clone_fn_t clone_fn = NULL;
    struct wolfsentry_table_ent_header *prev = NULL, *new = NULL, *i;

    if ((wolfsentry == dest_context) || (src_table == dest_table))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (src_table->ent_type != dest_table->ent_type)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (dest_table->head != NULL)
        WOLFSENTRY_ERROR_RETURN(BUSY);

    switch(src_table->ent_type) {
    case WOLFSENTRY_OBJECT_TYPE_ACTION:
        if ((ret = wolfsentry_action_table_clone_header(wolfsentry, src_table, dest_context, dest_table, flags)) < 0)
            return ret;
        clone_fn = wolfsentry_action_clone;
        break;
    case WOLFSENTRY_OBJECT_TYPE_EVENT:
        if ((ret = wolfsentry_event_table_clone_header(wolfsentry, src_table, dest_context, dest_table, flags)) < 0)
            return ret;
        clone_fn = wolfsentry_event_clone_bare;
        break;
    case WOLFSENTRY_OBJECT_TYPE_ROUTE:
        if ((ret = wolfsentry_route_table_clone_header(wolfsentry, src_table, dest_context, dest_table, flags)) < 0)
            return ret;
        clone_fn = wolfsentry_route_clone;
        break;
    case WOLFSENTRY_OBJECT_TYPE_KV:
        if ((ret = wolfsentry_kv_table_clone_header(wolfsentry, src_table, dest_context, dest_table, flags)) < 0)
            return ret;
        clone_fn = wolfsentry_kv_clone;
        break;

#ifdef WOLFSENTRY_PROTOCOL_NAMES
    case WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNUMBER:
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
#else
    case WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNUMBER:
        if ((ret = wolfsentry_addr_family_bynumber_table_clone_header(wolfsentry, src_table, dest_context, dest_table, flags)) < 0)
            return ret;
        clone_fn = wolfsentry_addr_family_bynumber_clone;
        break;
#endif

    case WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNAME:
    case WOLFSENTRY_OBJECT_TYPE_UNINITED:
    case WOLFSENTRY_OBJECT_TYPE_TABLE:
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

    if (clone_fn == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    for (i = src_table->head;
         i;
         i = i->next) {
        if ((ret = clone_fn(wolfsentry, i, dest_context, &new, flags)) < 0)
            goto out;
        new->parent_table = dest_table;
        if (prev)
            prev->next = new;
        else
            dest_table->head = new;
        prev = new;
        if ((ret = wolfsentry_table_ent_insert_by_id(dest_context, new)) < 0)
            goto out;
    }
    dest_table->tail = new;

    dest_table->n_ents = src_table->n_ents;

    /* event cloning is tricky because events refer to other events by pointer, so a second pass through the table is needed. */
    if (src_table->ent_type == WOLFSENTRY_OBJECT_TYPE_EVENT) {
        if ((ret = wolfsentry_table_clone_map(wolfsentry, &wolfsentry->events->header, dest_context, &dest_context->events->header, wolfsentry_event_clone_resolve, flags)) < 0)
            goto out;
    }

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    return ret;
}

#ifdef WOLFSENTRY_PROTOCOL_NAMES
wolfsentry_errcode_t wolfsentry_coupled_table_clone(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_table_header *src_table1,
    struct wolfsentry_table_header *src_table2,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table1,
    struct wolfsentry_table_header *dest_table2,
    wolfsentry_clone_flags_t flags)
{
    wolfsentry_errcode_t ret;
    wolfsentry_coupled_table_ent_clone_fn_t clone_fn = NULL;
    struct wolfsentry_table_ent_header *prev = NULL, *new1 = NULL, *new2 = NULL, *i;

    if ((wolfsentry == dest_context) ||
        (src_table1 == src_table2) ||
        (src_table1 == dest_table1) ||
        (src_table1 == dest_table2) ||
        (src_table2 == dest_table2) ||
        (dest_table1 == dest_table2))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (src_table1->ent_type != dest_table1->ent_type)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (src_table2->ent_type != dest_table2->ent_type)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (dest_table1->head != NULL)
        WOLFSENTRY_ERROR_RETURN(BUSY);
    if (dest_table2->head != NULL)
        WOLFSENTRY_ERROR_RETURN(BUSY);

    switch(src_table1->ent_type) {
    case WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNUMBER:
        if (src_table2->ent_type != WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNAME)
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        if ((ret = wolfsentry_addr_family_table_clone_headers(wolfsentry, src_table1, src_table2, dest_context, dest_table1, dest_table2, flags)) < 0)
            return ret;
        clone_fn = wolfsentry_addr_family_clone;
        break;
    case WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNAME:
    case WOLFSENTRY_OBJECT_TYPE_ACTION:
    case WOLFSENTRY_OBJECT_TYPE_EVENT:
    case WOLFSENTRY_OBJECT_TYPE_ROUTE:
    case WOLFSENTRY_OBJECT_TYPE_KV:
    case WOLFSENTRY_OBJECT_TYPE_UNINITED:
    case WOLFSENTRY_OBJECT_TYPE_TABLE:
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

    if (clone_fn == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    for (i = src_table1->head;
         i;
         i = i->next) {
        if ((ret = clone_fn(wolfsentry, i, dest_context, &new1, &new2, flags)) < 0)
            goto out;
        new1->parent_table = dest_table1;
        new2->parent_table = dest_table2;
        if (prev)
            prev->next = new1;
        else
            dest_table1->head = new1;
        prev = new1;
        if ((ret = wolfsentry_table_ent_insert_by_id(dest_context, new1)) < 0)
            goto out;
        if ((ret = wolfsentry_table_ent_insert_by_id(dest_context, new2)) < 0)
            goto out;
        if ((ret = wolfsentry_table_ent_insert(dest_context, new2, dest_table2, 1 /* unique_p */)) < 0)
            goto out;
    }
    dest_table1->tail = new1;

    dest_table1->n_ents = src_table1->n_ents;

    if (dest_table2->n_ents != src_table2->n_ents)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    return ret;
}
#endif /* WOLFSENTRY_PROTOCOL_NAMES */

static inline int wolfsentry_ent_id_cmp(struct wolfsentry_table_ent_header *left, wolfsentry_ent_id_t right_id) {
    if (left->id < right_id)
        return -1;
    else if (left->id > right_id)
        return 1;
    else
        return 0;
}

wolfsentry_errcode_t wolfsentry_id_allocate(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_table_ent_header *ent)
{
    wolfsentry_errcode_t ret;
    for (;;) {
        if (wolfsentry->mk_id_cb) {
            ret = wolfsentry->mk_id_cb(wolfsentry->mk_id_cb_state.mk_id_cb_arg, &ent->id);
            if (ret < 0)
                return ret;
        } else {
            ent->id = ++wolfsentry->mk_id_cb_state.id_counter;
        }

        ret = wolfsentry_table_ent_insert_by_id(wolfsentry, ent);
        if (! WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_ALREADY_PRESENT))
            return ret;
    }
    /* not reached */
}

wolfsentry_ent_id_t wolfsentry_get_object_id(const void *object) {
    return ((const struct wolfsentry_table_ent_header *)object)->id;
}

wolfsentry_errcode_t wolfsentry_table_ent_insert_by_id(struct wolfsentry_context *wolfsentry, struct wolfsentry_table_ent_header *ent) {
    struct wolfsentry_table_ent_header *i = wolfsentry->ents_by_id.head;
    int cmpret;

    if (ent->id == WOLFSENTRY_ENT_ID_NONE)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    while (i) {
        if ((cmpret = wolfsentry_ent_id_cmp(i, ent->id)) >= 0)
            break;
        i = i->next_by_id;
    }
    if (i) {
        if (cmpret == 0)
            WOLFSENTRY_ERROR_RETURN(ITEM_ALREADY_PRESENT);
        ent->prev_by_id = i->prev_by_id;
        ent->next_by_id = i;
        if (i->prev_by_id) {
            i->prev_by_id->next_by_id = ent;
        } else {
            wolfsentry->ents_by_id.head = ent;
        }
        i->prev_by_id = ent;
    } else if (wolfsentry->ents_by_id.tail) {
        wolfsentry->ents_by_id.tail->next_by_id = ent;
        ent->prev_by_id = wolfsentry->ents_by_id.tail;
        ent->next_by_id = NULL;
        wolfsentry->ents_by_id.tail = ent;
    } else {
        wolfsentry->ents_by_id.head = wolfsentry->ents_by_id.tail = ent;
        ent->prev_by_id = ent->next_by_id = NULL;
    }
    ++wolfsentry->ents_by_id.n_ents;
    ++wolfsentry->ents_by_id.n_inserts;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_table_ent_get_by_id(struct wolfsentry_context *wolfsentry, wolfsentry_ent_id_t id, struct wolfsentry_table_ent_header **ent) {
    struct wolfsentry_table_ent_header *i;

    if (id == WOLFSENTRY_ENT_ID_NONE)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    for (i = wolfsentry->ents_by_id.head; i; i = i->next) {
        int c = wolfsentry_ent_id_cmp(i, id);
        if (c >= 0) {
            if (c == 0) {
                *ent = i;
                WOLFSENTRY_RETURN_OK;
            }
            WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
        }
    }
    WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
}

void wolfsentry_table_ent_delete_by_id_1(struct wolfsentry_context *wolfsentry, struct wolfsentry_table_ent_header *ent) {
    if (ent->prev_by_id)
        ent->prev_by_id->next_by_id = ent->next_by_id;
    else
        wolfsentry->ents_by_id.head = ent->next_by_id;
    if (ent->next_by_id)
        ent->next_by_id->prev_by_id = ent->prev_by_id;
    else
        wolfsentry->ents_by_id.tail = ent->prev_by_id;
    ent->prev_by_id = ent->next_by_id = NULL;
    --wolfsentry->ents_by_id.n_ents;
    ++wolfsentry->ents_by_id.n_deletes;
}

wolfsentry_errcode_t wolfsentry_table_ent_delete_by_id(struct wolfsentry_context *wolfsentry, wolfsentry_ent_id_t id, struct wolfsentry_table_ent_header **ent) {
    wolfsentry_errcode_t ret;

    if (id == WOLFSENTRY_ENT_ID_NONE)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((ret = wolfsentry_table_ent_get_by_id(wolfsentry, id, ent)) < 0)
        return ret;
    wolfsentry_table_ent_delete_by_id_1(wolfsentry, *ent);
    if ((*ent)->parent_table)
        wolfsentry_table_ent_delete_1(wolfsentry, *ent);

    WOLFSENTRY_RETURN_OK;
}
#include <stdlib.h>

wolfsentry_errcode_t wolfsentry_table_ent_get(struct wolfsentry_table_header *table, struct wolfsentry_table_ent_header **ent) {
    struct wolfsentry_table_ent_header *i = table->head;
    while (i) {
        int c = table->cmp_fn(i, *ent);
        if (c >= 0) {
            if (c == 0) {
                *ent = i;
                WOLFSENTRY_RETURN_OK;
            }
            WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
        }
        i = i->next;
    }
    WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
}

wolfsentry_errcode_t wolfsentry_table_ent_delete_1(struct wolfsentry_context *wolfsentry, struct wolfsentry_table_ent_header *ent) {
    if (ent->parent_table == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (ent->prev)
        ent->prev->next = ent->next;
    else
        ent->parent_table->head = ent->next;
    if (ent->next)
        ent->next->prev = ent->prev;
    else
        ent->parent_table->tail = ent->prev;
    ent->prev = ent->next = NULL;
    --ent->parent_table->n_ents;
    ++ent->parent_table->n_deletes;
    ent->parent_table = NULL;

    if (ent->id != WOLFSENTRY_ENT_ID_NONE)
        wolfsentry_table_ent_delete_by_id_1(wolfsentry, ent);

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_table_ent_delete(struct wolfsentry_context *wolfsentry, struct wolfsentry_table_ent_header **ent) {
    struct wolfsentry_table_ent_header *i;

    if ((*ent)->parent_table == NULL) {
        WOLFSENTRY_WARN("%s called with null parent table\n", "wolfsentry_table_ent_delete");
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

    i = (*ent)->parent_table->head;
    (void)wolfsentry;
    while (i) {
        int c = (*ent)->parent_table->cmp_fn(i, *ent);
        if (c >= 0) {
            if (c == 0) {
                *ent = i;
                return wolfsentry_table_ent_delete_1(wolfsentry, i);
            }
            WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
        }
        i = i->next;
    }
    WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
}

wolfsentry_errcode_t wolfsentry_table_ent_drop_reference(struct wolfsentry_context *wolfsentry, struct wolfsentry_table_ent_header *ent, wolfsentry_action_res_t *action_results) {
    if (ent->refcount <= 0)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if (action_results)
        WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    if (WOLFSENTRY_REFCOUNT_DECREMENT(ent->refcount) > 0)
        WOLFSENTRY_RETURN_OK;
    WOLFSENTRY_FREE(ent);
    if (action_results)
        WOLFSENTRY_SET_BITS(*action_results, WOLFSENTRY_ACTION_RES_DEALLOCATED);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_table_free_ents(struct wolfsentry_context *wolfsentry, struct wolfsentry_table_header *table) {
    struct wolfsentry_table_ent_header *i = table->head, *next;
    wolfsentry_errcode_t ret;
    WOLFSENTRY_TABLE_HEADER_RESET(*table);
    /* coupled objects are freed as a pair, e.g. ents in
     * wolfsentry_addr_family_byname_table are freed when the corresponding
     * wolfsentry_addr_family_bynumber_table ents are freed.
     */
    if (table->free_fn == NULL)
        WOLFSENTRY_RETURN_OK;
    while (i) {
        next = i->next;
        wolfsentry_table_ent_delete_by_id_1(wolfsentry, i);
        if ((ret = table->free_fn(wolfsentry, i, NULL /* action_results */)) < 0)
            return ret;
        i = next;
    }
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_table_cursor_init(struct wolfsentry_context *wolfsentry, struct wolfsentry_cursor *cursor) {
    (void)wolfsentry;
    memset(cursor, 0, sizeof *cursor);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_table_cursor_seek_to_head(const struct wolfsentry_table_header *table, struct wolfsentry_cursor *cursor) {
    cursor->point = table->head;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_table_cursor_seek_to_tail(const struct wolfsentry_table_header *table, struct wolfsentry_cursor *cursor) {
    cursor->point = table->tail;
    WOLFSENTRY_RETURN_OK;
}

struct wolfsentry_table_ent_header * wolfsentry_table_cursor_current(const struct wolfsentry_cursor *cursor) {
    return cursor->point;
}

struct wolfsentry_table_ent_header * wolfsentry_table_cursor_prev(struct wolfsentry_cursor *cursor) {
    if (cursor->point == NULL)
        return NULL;
    cursor->point = cursor->point->prev;
    return cursor->point;
}

struct wolfsentry_table_ent_header * wolfsentry_table_cursor_next(struct wolfsentry_cursor *cursor) {
    if (cursor->point == NULL)
        return NULL;
    cursor->point = cursor->point->next;
    return cursor->point;
}

/* in a fashion analogous to the values returned by comparison
 * functions, *cursor_position is set to -1, 0, or 1, depending on
 * whether cursor is initialized to point to the ent immediately
 * before where the search ent would be, right on the search ent, or
 * immediately after where the search ent would be.
 */
wolfsentry_errcode_t wolfsentry_table_cursor_seek(const struct wolfsentry_table_header *table, const struct wolfsentry_table_ent_header *ent, struct wolfsentry_cursor *cursor, int *cursor_position) {
    struct wolfsentry_table_ent_header *i = table->head;
    while (i) {
        int c = table->cmp_fn(i, ent);
        if (c >= 0) {
            cursor->point = i;
            *cursor_position = c;
            WOLFSENTRY_RETURN_OK;
        }
        i = i->next;
    }
    cursor->point = table->tail;
    *cursor_position = -1;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_table_filter(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_table_header *table,
    wolfsentry_filter_function_t filter,
    void *filter_context,
    wolfsentry_dropper_function_t dropper,
    void *dropper_context)
{
    /* with linked lists, this is easy, but it will be a lot trickier with red-black trees. */
    wolfsentry_errcode_t ret = WOLFSENTRY_ERROR_ENCODE(OK);
    struct wolfsentry_table_ent_header *i, *i_next;

    for (i = table->head; i; i = i_next) {
        i_next = i->next;

        if ((ret = filter(filter_context, i, NULL /* action_results */)) < 0)
            break;
        if (ret > 0)
            continue;
        if ((ret = wolfsentry_table_ent_delete_1(wolfsentry, i)) < 0)
            break;
        if ((ret = dropper(dropper_context, i, NULL /* action_results */)) < 0)
            break;
    }

    return ret;
}

wolfsentry_errcode_t wolfsentry_table_map(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_table_header *table,
    wolfsentry_map_function_t fn,
    void *map_context,
    wolfsentry_action_res_t *action_results)
{
    /* with linked lists, this is easy, but it will be a lot trickier with red-black trees. */
    wolfsentry_errcode_t ret = WOLFSENTRY_ERROR_ENCODE(OK);
    struct wolfsentry_table_ent_header *i, *i_next;

    (void)wolfsentry;

    for (i = table->head; i; i = i_next) {
        i_next = i->next;

        if ((ret = fn(map_context, i, action_results)) < 0)
            break;
    }

    return ret;
}
