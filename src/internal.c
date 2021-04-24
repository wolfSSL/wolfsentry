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

    if (ent->id != WOLFSENTRY_ENT_ID_NONE) {
        wolfsentry_errcode_t ret = wolfsentry_table_ent_insert_by_id(wolfsentry, ent);
        if (ret < 0)
            return ret;
    }

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
    ent->parent_table = table;

    WOLFSENTRY_RETURN_OK;
}

static inline int wolfsentry_ent_id_cmp(struct wolfsentry_table_ent_header *left, wolfsentry_ent_id_t right_id) {
    if (left->id < right_id)
        return -1;
    else if (left->id > right_id)
        return 1;
    else
        return 0;
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
    ent->parent_table = NULL;

    if (ent->id != WOLFSENTRY_ENT_ID_NONE)
        wolfsentry_table_ent_delete_by_id_1(wolfsentry, ent);

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_table_ent_delete(struct wolfsentry_context *wolfsentry, struct wolfsentry_table_ent_header **ent) {
    struct wolfsentry_table_ent_header *i;

    if ((*ent)->parent_table == NULL) {
        WOLFSENTRY_WARN("%s called with null parent table\n",__FUNCTION__);
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
    table->head = NULL;
    table->tail = NULL;
    while (i) {
        next = i->next;
        if ((ret = table->free_fn(wolfsentry, i, NULL /* action_results */)) < 0)
            return ret;
        --table->n_ents;
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
