/*
 * routes.c
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

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_ROUTES_C

static inline int cmp_addrs(
    byte *left_addr,
    int left_addr_len,
    byte *right_addr,
    int right_addr_len,
    int left_wildcard_p,
    int match_subnets_p,
    int *inexact_p)
{
    int cmp;

    *inexact_p = 0;

    if (left_addr_len != right_addr_len) {
        int min_addr_len = (left_addr_len < right_addr_len) ? left_addr_len : right_addr_len;

        if (left_wildcard_p || (min_addr_len == 0))
            *inexact_p = 1;
        else if (match_subnets_p) {
            size_t min_bytes = WOLFSENTRY_BITS_TO_BYTES((size_t)min_addr_len);
            if ((min_addr_len & 0x7) == 0) {
                if ((cmp = memcmp(left_addr, right_addr, min_bytes - 1)))
                    return cmp;
                else
                    *inexact_p = 1;
            } else {
                if (min_bytes > 1) {
                    if ((cmp = memcmp(left_addr, right_addr, min_bytes - 1)))
                        return cmp;
                }
                if ((left_addr[min_bytes - 1] >> (min_addr_len & 0x7)) ==
                    (right_addr[min_bytes - 1] >> (min_addr_len & 0x7)))
                    *inexact_p = 1;
                else if (left_addr[min_bytes - 1] < right_addr[min_bytes - 1])
                    return -1;
                else
                    return 1;
            }
        } else {
            if ((cmp = memcmp(left_addr, right_addr, WOLFSENTRY_BITS_TO_BYTES((size_t)min_addr_len))))
                return cmp;
            else if (left_addr_len < right_addr_len)
                return -1;
            else
                return 1;
        }
    } else {
        if ((cmp = memcmp(left_addr, right_addr, WOLFSENTRY_BITS_TO_BYTES((size_t)left_addr_len)))) {
            if (left_wildcard_p)
                *inexact_p = 1;
            else
                return cmp;
        }
    }
    return 0;
}

static int wolfsentry_route_key_cmp_1(
    struct wolfsentry_route *left,
    struct wolfsentry_route *right,
    int match_wildcards_p,
    wolfsentry_route_flags_t *inexact_matches)
{
    int cmp, inexact_p;

    if (inexact_matches)
        *inexact_matches = 0;

    if (left->sa_family != right->sa_family) {
        if (match_wildcards_p && (left->flags & WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD;
        } else if (left->sa_family < right->sa_family)
            return -1;
        else
            return 1;
    }

    cmp = cmp_addrs(WOLFSENTRY_ROUTE_REMOTE_ADDR(left), left->remote.addr_len,
                    WOLFSENTRY_ROUTE_REMOTE_ADDR(right), right->remote.addr_len,
                    match_wildcards_p && (left->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD),
                    match_wildcards_p,
                    &inexact_p);
    if (cmp)
        return cmp;
    if (inexact_p && inexact_matches)
        *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD;

    if (left->sa_proto != right->sa_proto) {
        if (match_wildcards_p && (left->flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD;
        } else if (left->sa_proto < right->sa_proto)
            return -1;
        else
            return 1;
    }

    if (left->local.sa_port != right->local.sa_port) {
        if (match_wildcards_p && (left->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD;
        } else if (left->local.sa_port < right->local.sa_port)
            return -1;
        else
            return 1;
    }

    if ((left->parent_event == NULL) && (right->parent_event == NULL)) {
        /* Intentionally left empty */
    }
    else if ((left->parent_event == NULL) || (right->parent_event == NULL)) {
        /* null event acts like a priority of -1, so to speak. */
        if (right->parent_event == NULL) {
            if (match_wildcards_p && (left->flags & WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD)) {
                if (inexact_matches)
                    *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD;
            } else
                return -1;
        } else if (left->parent_event == NULL) {
            if (match_wildcards_p && (left->flags & WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD)) {
                if (inexact_matches)
                    *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD;
            } else
                return -1;
        }
    } else {
        if (left->parent_event->priority < right->parent_event->priority) {
            if (match_wildcards_p && (left->flags & WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD)) {
                if (inexact_matches)
                    *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD;
            } else
                return -1;
        } else if (left->parent_event->priority > right->parent_event->priority) {
            if (match_wildcards_p && (left->flags & WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD)) {
                if (inexact_matches)
                    *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD;
            } else
                return -1;
        }
    }

    cmp = cmp_addrs(WOLFSENTRY_ROUTE_LOCAL_ADDR(left), left->local.addr_len,
                    WOLFSENTRY_ROUTE_LOCAL_ADDR(right), right->local.addr_len,
                    match_wildcards_p && (left->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD),
                    match_wildcards_p,
                    &inexact_p);
    if (cmp)
        return cmp;
    if (inexact_p && inexact_matches)
        *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD;

    if (left->remote.sa_port != right->remote.sa_port) {
        if (match_wildcards_p && (left->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        } else if (left->remote.sa_port < right->remote.sa_port)
            return -1;
        else
            return 1;
    }

    if (left->remote.interface != right->remote.interface) {
        if (match_wildcards_p && (left->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD;
        } else if (left->remote.interface < right->remote.interface)
            return -1;
        else
            return 1;
    }

    if (left->local.interface != right->local.interface) {
        if (match_wildcards_p && (left->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD;
        } else if (left->local.interface < right->local.interface)
            return -1;
        else
            return 1;
    }

    if (match_wildcards_p) {
        if (right->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN) {
            if (! (left->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN))
                return -1;
        }
        if (right->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT) {
            if (! (left->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT))
                return -1;
        }
    } else {
        wolfsentry_route_flags_t masked_left_flags = left->flags & WOLFSENTRY_ROUTE_IMMUTABLE_FLAGS;
        wolfsentry_route_flags_t masked_right_flags = right->flags & WOLFSENTRY_ROUTE_IMMUTABLE_FLAGS;
        if (masked_left_flags != masked_right_flags) {
            if (masked_left_flags < masked_right_flags)
                return -1;
            else
                return 1;
        }
    }

    /* do a final check on the name of the event, so that routes with
     * different trigger events with same priority are nonetheless
     * distinguishable.
     */

    if (! ((left->parent_event == NULL) || (right->parent_event == NULL) || (inexact_matches && (*inexact_matches & WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD)))) {
        cmp = wolfsentry_event_key_cmp(left->parent_event, right->parent_event);
        if (cmp) {
            if (match_wildcards_p && (left->flags & WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD)) {
                if (inexact_matches)
                    *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD;
            } else
                return cmp;
        }
    }

    return 0;
}

int wolfsentry_route_key_cmp(struct wolfsentry_route *left, struct wolfsentry_route *right) {
    return wolfsentry_route_key_cmp_1(left, right, 0 /* match_wildcards_p */, NULL /* inexact_matches */);
}

static void wolfsentry_route_update_flags_1(
    struct wolfsentry_route *route,
    wolfsentry_route_flags_t flags_to_set,
    wolfsentry_route_flags_t flags_to_clear,
    wolfsentry_route_flags_t *flags_before,
    wolfsentry_route_flags_t *flags_after);

static wolfsentry_errcode_t wolfsentry_route_drop_reference_1(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results)
{
    if (route->header.refcount <= 0)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if (WOLFSENTRY_REFCOUNT_DECREMENT(route->header.refcount) > 0)
        WOLFSENTRY_RETURN_OK;
    if (route->parent_event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, route->parent_event, NULL /* action_results */));
    WOLFSENTRY_FREE(route);
    if (action_results)
        WOLFSENTRY_SET_BITS(*action_results, WOLFSENTRY_ACTION_RES_DEALLOCATED);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_drop_reference(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results)
{
    if (action_results)
        WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    return wolfsentry_route_drop_reference_1(wolfsentry, route, action_results);
}

static wolfsentry_errcode_t wolfsentry_route_init(
    struct wolfsentry_event *parent_event,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    int data_addr_offset,
    int data_addr_size,
    struct wolfsentry_route *new
    )
{
    if (data_addr_size < WOLFSENTRY_BITS_TO_BYTES(remote->addr_len) + WOLFSENTRY_BITS_TO_BYTES(local->addr_len))
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    if (data_addr_size > MAX_UINT_OF(uint16_t))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    if (data_addr_offset > MAX_UINT_OF(uint16_t))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    if (! (flags & (WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN | WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT)))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    memset(new,0,offsetof(struct wolfsentry_route, data));

    new->parent_event = parent_event;
    new->flags = flags;
    new->sa_family = remote->sa_family;
    new->sa_proto = remote->sa_proto;
    new->remote.sa_port = remote->sa_port;
    new->remote.addr_len = remote->addr_len;
    new->remote.interface = remote->interface;
    new->local.sa_port = local->sa_port;
    new->local.addr_len = local->addr_len;
    new->local.interface = local->interface;
    new->data_addr_offset = (uint16_t)data_addr_offset;
    new->data_addr_size = (uint16_t)data_addr_size;

    if (data_addr_offset > 0)
        memset(new->data, 0, (size_t)data_addr_offset); /* zero private data. */

    memcpy(WOLFSENTRY_ROUTE_REMOTE_ADDR(new), remote->addr, WOLFSENTRY_BITS_TO_BYTES((size_t)remote->addr_len));
    memcpy(WOLFSENTRY_ROUTE_LOCAL_ADDR(new), local->addr, WOLFSENTRY_BITS_TO_BYTES((size_t)local->addr_len));

    /* make sure the pad bits in the addresses are zero. */
    {
        int left_over_bits = remote->addr_len % BITS_PER_BYTE;
        if (left_over_bits) {
            byte *remote_lsb = WOLFSENTRY_ROUTE_REMOTE_ADDR(new) + WOLFSENTRY_BITS_TO_BYTES(remote->addr_len) - 1;
            if (*remote_lsb & (0xffu >> (BITS_PER_BYTE - left_over_bits)))
                *remote_lsb &= (byte)(0xffu << left_over_bits);
        }
    }
    {
        int left_over_bits = local->addr_len % BITS_PER_BYTE;
        if (left_over_bits) {
            byte *local_lsb = WOLFSENTRY_ROUTE_LOCAL_ADDR(new) + WOLFSENTRY_BITS_TO_BYTES(local->addr_len) - 1;
            if (*local_lsb & (0xffu >> (BITS_PER_BYTE - left_over_bits)))
                *local_lsb &= (byte)(0xffu << left_over_bits);
        }
    }

    new->header.refcount = 1;
    new->header.id = WOLFSENTRY_ENT_ID_NONE;

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_new(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_event *parent_event,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    struct wolfsentry_route **new
    )
{
    size_t new_size;
    wolfsentry_errcode_t ret;
    struct wolfsentry_eventconfig_internal *config = (parent_event && parent_event->config) ? parent_event->config : &wolfsentry->config;

    new_size = WOLFSENTRY_BITS_TO_BYTES((size_t)remote->addr_len) + WOLFSENTRY_BITS_TO_BYTES((size_t)local->addr_len);
    if (new_size > (size_t)(uint16_t)~0UL)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
    new_size += offsetof(struct wolfsentry_route, data);
    new_size += config->config.route_private_data_size;

    if (config->config.route_private_data_alignment == 0)
        *new = WOLFSENTRY_MALLOC(new_size);
    else
        *new = WOLFSENTRY_MEMALIGN(config->config.route_private_data_alignment, new_size);
    if (*new == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    return wolfsentry_route_init(parent_event, remote, local, flags, (int)config->config.route_private_data_size, (int)(new_size - offsetof(struct wolfsentry_route, data)), *new);

    return ret;
}

static wolfsentry_errcode_t wolfsentry_route_insert_1(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *route,
    struct wolfsentry_event *trigger_event,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;

    /* make sure fields marked as wildcards are set to zero. */
    if (((route->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD) && (route->remote.interface != 0)) ||
        ((route->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD) && (route->local.interface != 0)) ||
        ((route->flags & WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD) && (route->sa_family != 0)) ||
        ((route->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD) && (route->remote.addr_len != 0)) ||
        ((route->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD) && (route->local.addr_len != 0)) ||
        ((route->flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD) && (route->sa_proto != 0)) ||
        ((route->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD) && (route->remote.sa_port != 0)) ||
        ((route->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD) && (route->local.sa_port != 0)))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    /* make sure wildcards are sensical. */
    if (((route->flags & WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD) &&
         ((! (route->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD)) ||
          (! (route->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD)) ||
          (! (route->flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD)))) ||
        ((route->flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD) &&
         ((! (route->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD)) ||
          (! (route->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD)))))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (WOLFSENTRY_CHECK_BITS(route->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE))
        WOLFSENTRY_ERROR_RETURN(ITEM_ALREADY_PRESENT);

    if ((ret = wolfsentry_id_generate(wolfsentry, WOLFSENTRY_OBJECT_TYPE_ROUTE, &route->header.id)) < 0)
        return ret;
    if ((ret = WOLFSENTRY_GET_TIME(&route->meta.insert_time)) < 0)
        return ret;
    WOLFSENTRY_SET_BITS(route->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE);
    if ((ret = wolfsentry_table_ent_insert(wolfsentry, &route->header, &route_table->header, 1 /* unique_p */)) < 0) {
        WOLFSENTRY_CLEAR_BITS(route->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE);
        return ret;
    }

    if (route->parent_event && route->parent_event->insert_event) {
        ret = wolfsentry_action_list_dispatch(wolfsentry, caller_arg, &route->parent_event->insert_event->action_list, trigger_event, route_table, route, action_results);
        if (ret < 0) {
            wolfsentry_route_flags_t flags_before, flags_after;
            (void)wolfsentry_table_ent_delete_1(wolfsentry, &route->header);
            wolfsentry_route_update_flags_1(route, WOLFSENTRY_ROUTE_FLAG_NONE, WOLFSENTRY_ROUTE_FLAG_IN_TABLE, &flags_before, &flags_after);
        }
        return ret;
    } else
        WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_insert_2(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_sockaddr *remote,
    struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    struct wolfsentry_event *parent_event,
    wolfsentry_ent_id_t *id,
    wolfsentry_action_res_t *action_results)
{
    struct wolfsentry_route *new;
    wolfsentry_errcode_t ret;

    if ((remote->sa_family != local->sa_family) ||
        (remote->sa_proto != local->sa_proto))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((ret = wolfsentry_route_new(wolfsentry, parent_event, remote, local, flags, &new)) < 0)
        return ret;

    if ((ret = wolfsentry_route_insert_1(wolfsentry, caller_arg, route_table, new, NULL /* trigger_event */, action_results)) < 0)
        goto out;

    if (id)
        *id = new->header.id;

    if (parent_event)
        WOLFSENTRY_REFCOUNT_INCREMENT(parent_event->header.refcount);

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    if (ret < 0)
        WOLFSENTRY_FREE(new);

    return ret;
}


wolfsentry_errcode_t wolfsentry_route_insert_static(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    struct wolfsentry_sockaddr *remote,
    struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    wolfsentry_ent_id_t *id,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *event = NULL;
    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(wolfsentry, event_label, event_label_len, &event)) < 0)
            return ret;
    }
    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    ret = wolfsentry_route_insert_2(wolfsentry, caller_arg, &wolfsentry->routes_static, remote, local, flags, event, id, action_results);
    if (event)
        wolfsentry_event_drop_reference(wolfsentry, event, NULL /* action_results */); /* if the insert succeeded, the refcount was incremented. */
    return ret;
}

static wolfsentry_errcode_t wolfsentry_route_lookup_1(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *table,
    struct wolfsentry_sockaddr *remote,
    struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    struct wolfsentry_event *parent_event,
    int exact_p,
    wolfsentry_route_flags_t *inexact_matches,
    struct wolfsentry_route **route)
{
    struct {
        struct wolfsentry_route route;
        byte buf[WOLFSENTRY_MAX_ADDR_BYTES * 2];
    } target;
    struct wolfsentry_cursor cursor;
    int cursor_position;
    struct wolfsentry_route *i;
    wolfsentry_priority_t highest_priority_seen = 0;
    struct wolfsentry_route *highest_priority_match_seen = NULL;
    wolfsentry_route_flags_t highest_priority_inexact_matches;
    wolfsentry_errcode_t ret;

    if ((ret = wolfsentry_table_cursor_init(wolfsentry, &cursor)) < 0)
        goto out;

    if ((ret = wolfsentry_route_init(parent_event, remote, local, flags, 0 /* data_addr_offset */, sizeof target.buf, &target.route)) < 0)
        goto out;

    if ((ret = wolfsentry_table_cursor_seek(&table->header, &target.route.header, &cursor, &cursor_position)) < 0)
        goto out;

    if (inexact_matches)
        *inexact_matches = WOLFSENTRY_ROUTE_FLAG_NONE;

    /* return exact match immediately. */
    if ((cursor_position == 0) && (exact_p || (! WOLFSENTRY_CHECK_BITS(((struct wolfsentry_route *)cursor.point)->flags, WOLFSENTRY_ROUTE_FLAG_PENDING_DELETE)))) {
        *route = (struct wolfsentry_route *)cursor.point;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        goto out;
    }

    if (exact_p) {
        ret = WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);
        goto out;
    }

    if (cursor_position == -1)
        wolfsentry_table_cursor_seek_to_tail(&table->header, &cursor);

    if ((i = (struct wolfsentry_route *)wolfsentry_table_cursor_current(&cursor)) == NULL) {
        ret = WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);
        goto out;
    }

    for (; i; i = (struct wolfsentry_route *)wolfsentry_table_cursor_prev(&cursor)) {
        if (WOLFSENTRY_CHECK_BITS(i->flags, WOLFSENTRY_ROUTE_FLAG_PENDING_DELETE))
            continue;
        cursor_position = wolfsentry_route_key_cmp_1(i, &target.route, 1 /* match_wildcards_p */, inexact_matches);
        if (cursor_position == 0) {
            if (i->parent_event == NULL) {
                *route = i;
                ret = WOLFSENTRY_ERROR_ENCODE(OK);
                goto out;
            }
            if ((highest_priority_match_seen == NULL) || (i->parent_event->priority < highest_priority_seen)) {
                highest_priority_match_seen = i;
                if (inexact_matches)
                    highest_priority_inexact_matches = *inexact_matches;
                highest_priority_seen = i->parent_event->priority;
            }
        } else {
            if (highest_priority_match_seen)
                break;
        }
    }

    if (highest_priority_match_seen) {
        *route = highest_priority_match_seen;
        if (inexact_matches)
            *inexact_matches = highest_priority_inexact_matches;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
    } else {
        ret = WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);
    }

  out:

    if (ret >= 0) {
        if (! (flags & WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_HITS))
            WOLFSENTRY_ATOMIC_INCREMENT((*route)->header.hitcount, 1);
    }

    return ret;
}

wolfsentry_errcode_t wolfsentry_route_get_table_static(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table **table)
{
    *table = &wolfsentry->routes_static;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_get_table_dynamic(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table **table)
{
    *table = &wolfsentry->routes_dynamic;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_table_default_policy_set(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t default_policy)
{
    (void)wolfsentry;
    if (WOLFSENTRY_MASKOUT_BITS(default_policy, WOLFSENTRY_ROUTE_DEFAULT_POLICY_MASK) != WOLFSENTRY_ACTION_RES_NONE)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    table->default_policy = default_policy;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_table_default_policy_get(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *default_policy)
{
    (void)wolfsentry;
    *default_policy = table->default_policy;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_get_reference(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *table,
    struct wolfsentry_sockaddr *remote,
    struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    int exact_p,
    wolfsentry_route_flags_t *inexact_matches,
    struct wolfsentry_route **route)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *event = NULL;
    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(wolfsentry, event_label, event_label_len, &event)) < 0)
            return ret;
    }
    ret = wolfsentry_route_lookup_1(wolfsentry, table, remote, local, flags, event, exact_p, inexact_matches, (struct wolfsentry_route **)route);
    if (event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, event, NULL /* action_results */));
    if (ret < 0)
        return ret;
    WOLFSENTRY_REFCOUNT_INCREMENT((*route)->header.refcount);
    WOLFSENTRY_RETURN_OK;
}

static inline wolfsentry_errcode_t wolfsentry_route_delete_0(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_event *trigger_event,
    struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;

    if (route->parent_event && route->parent_event->delete_event) {
        ret = wolfsentry_action_list_dispatch(wolfsentry, caller_arg, &route->parent_event->delete_event->action_list, trigger_event, route_table, route, action_results);
        if (ret < 0)
            WOLFSENTRY_WARN("%s returned " WOLFSENTRY_ERROR_FMT, __FUNCTION__, WOLFSENTRY_ERROR_FMT_ARGS(ret));
    }

    if ((ret = wolfsentry_table_ent_delete_1(wolfsentry, &route->header)) < 0)
        return ret;

    {
        wolfsentry_route_flags_t flags_before, flags_after;
        wolfsentry_route_update_flags_1(route, WOLFSENTRY_ROUTE_FLAG_NONE, WOLFSENTRY_ROUTE_FLAG_IN_TABLE, &flags_before, &flags_after);
    }
    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(wolfsentry, route, action_results));

    WOLFSENTRY_RETURN_OK;
}

static inline wolfsentry_errcode_t wolfsentry_route_delete_1(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *route_table,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    struct wolfsentry_sockaddr *remote,
    struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    struct wolfsentry_event *event,
    wolfsentry_action_res_t *action_results,
    int *n_deleted)
{
    wolfsentry_errcode_t ret = WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);
    struct wolfsentry_route *route = NULL;

    for (;;) {
        wolfsentry_errcode_t lookup_ret = wolfsentry_route_lookup_1(wolfsentry, &wolfsentry->routes_static, remote, local, flags, event, 1 /* exact_p */, NULL /* inexact matches */, &route);
        if (lookup_ret < 0)
            break;
        WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP);
        ret = wolfsentry_route_delete_0(wolfsentry, caller_arg, route_table, NULL /* trigger_event */, route, action_results);
        if (ret < 0)
            break;
        else
            ++(*n_deleted);
    }

    return ret;
}

wolfsentry_errcode_t wolfsentry_route_delete_static(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    struct wolfsentry_sockaddr *remote,
    struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_res_t *action_results,
    int *n_deleted)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *event = NULL;
    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(wolfsentry, event_label, event_label_len, &event)) < 0)
            return ret;
    }

    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    *n_deleted = 0;
    ret = wolfsentry_route_delete_1(wolfsentry, &wolfsentry->routes_static, caller_arg, remote, local, flags, event, action_results, n_deleted);
    if (event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, event, NULL /* action_results */));
    return ret;
}

wolfsentry_errcode_t wolfsentry_route_delete_dynamic(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    struct wolfsentry_sockaddr *remote,
    struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_res_t *action_results,
    int *n_deleted)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *event = NULL;
    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(wolfsentry, event_label, event_label_len, &event)) < 0)
            return ret;
    }
    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    *n_deleted = 0;
    ret = wolfsentry_route_delete_1(wolfsentry, &wolfsentry->routes_dynamic, caller_arg, remote, local, flags, event, action_results, n_deleted);
    if (event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, event, NULL /* action_results */));
    return ret;
}

wolfsentry_errcode_t wolfsentry_route_delete_everywhere(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    struct wolfsentry_sockaddr *remote,
    struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_res_t *action_results,
    int *n_deleted)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *event = NULL;
    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(wolfsentry, event_label, event_label_len, &event)) < 0)
            return ret;
    }
    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    *n_deleted = 0;
    ret = wolfsentry_route_delete_1(wolfsentry, &wolfsentry->routes_static, caller_arg, remote, local, flags, event, action_results, n_deleted);
    if ((ret >= 0) || WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND))
        ret = wolfsentry_route_delete_1(wolfsentry, &wolfsentry->routes_dynamic, caller_arg, remote, local, flags, event, action_results, n_deleted);
    if (event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, event, NULL /* action_results */));
    return ret;
}

wolfsentry_errcode_t wolfsentry_route_delete_by_id(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_ent_id_t id,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *event = NULL;
    struct wolfsentry_route *route;

    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(wolfsentry, event_label, event_label_len, &event)) < 0)
            return ret;
    }
    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);

    if ((ret = wolfsentry_table_ent_get_by_id(wolfsentry, id, (struct wolfsentry_table_ent_header **)&route)) < 0)
        goto out;
    if (route->header.parent_table == NULL) {
        ret = WOLFSENTRY_ERROR_ENCODE(INTERNAL_CHECK_FATAL);
        goto out;
    }
    if (route->header.parent_table->ent_type != WOLFSENTRY_OBJECT_TYPE_ROUTE) {
        ret = WOLFSENTRY_ERROR_ENCODE(WRONG_OBJECT);
        goto out;
    }

    ret = wolfsentry_route_delete_0(wolfsentry, caller_arg, (struct wolfsentry_route_table *)route->header.parent_table, event, route, action_results);

  out:
    if (event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, event, NULL /* action_results */));
    return ret;
}

static wolfsentry_errcode_t wolfsentry_route_event_dispatch_1(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_event *trigger_event,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *route,
    int inserted,
    wolfsentry_action_res_t *action_results
    )
{
    struct wolfsentry_eventconfig_internal *config = (route->parent_event && route->parent_event->config) ? route->parent_event->config : &wolfsentry->config;

    if (! (route->flags & WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_HITS))
        WOLFSENTRY_ATOMIC_INCREMENT(route->header.hitcount, 1);

    WOLFSENTRY_WARN_ON_FAILURE(WOLFSENTRY_GET_TIME(&route->meta.last_hit_time));

    if (trigger_event && (! inserted)) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_dispatch(wolfsentry, caller_arg, &trigger_event->action_list, trigger_event, route_table, route, action_results));
        WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP);
    }

    if (route->parent_event && route->parent_event->match_event && route->parent_event->match_event->action_list.header.head) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_dispatch(wolfsentry, caller_arg, &route->parent_event->match_event->action_list, trigger_event, route_table, route, action_results));
        WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP);
    }

    if (! (route->flags & WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_CURRENT_CONNECTIONS)) {
        if (*action_results & WOLFSENTRY_ACTION_RES_CONNECT) {
            if (route->meta.connection_count >= config->config.max_connection_count) {
                *action_results |= WOLFSENTRY_ACTION_RES_REJECT;
                WOLFSENTRY_RETURN_OK;
            }
            if (WOLFSENTRY_ATOMIC_INCREMENT_BY_ONE(route->meta.connection_count) > config->config.max_connection_count) {
                WOLFSENTRY_ATOMIC_DECREMENT_BY_ONE(route->meta.connection_count);
                *action_results |= WOLFSENTRY_ACTION_RES_REJECT;
                WOLFSENTRY_RETURN_OK;
            }
        } else if (*action_results & WOLFSENTRY_ACTION_RES_DISCONNECT)
            WOLFSENTRY_ATOMIC_DECREMENT_BY_ONE(route->meta.connection_count);
    }
    if (*action_results & WOLFSENTRY_ACTION_RES_DEROGATORY)
        WOLFSENTRY_ATOMIC_INCREMENT_BY_ONE(route->meta.derogatory_count);
    if (*action_results & WOLFSENTRY_ACTION_RES_COMMENDABLE)
        WOLFSENTRY_ATOMIC_INCREMENT_BY_ONE(route->meta.commendable_count);

    if ((route->flags & WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED)) {
        if (route->meta.penaltybox_duration_seconds > 0) {
            wolfsentry_time_t penaltybox_duration, now;
            wolfsentry_errcode_t ret = WOLFSENTRY_GET_TIME(&now);
            if (ret < 0)
                return ret;
            ret = WOLFSENTRY_INTERVAL_FROM_SECONDS(route->meta.penaltybox_duration_seconds, 0, &penaltybox_duration);
            if (ret < 0)
                return ret;
            if (WOLFSENTRY_DIFF_TIME(now, route->meta.last_penaltybox_time) > penaltybox_duration) {
                wolfsentry_route_flags_t flags_before, flags_after;
                WOLFSENTRY_WARN_ON_FAILURE(
                    wolfsentry_route_update_flags(
                        wolfsentry,
                        route,
                        WOLFSENTRY_ROUTE_FLAG_NONE,
                        WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED,
                        &flags_before,
                        &flags_after));
            } else
                *action_results |= WOLFSENTRY_ACTION_RES_REJECT;
        } else
            *action_results |= WOLFSENTRY_ACTION_RES_REJECT;
        WOLFSENTRY_RETURN_OK;
    } else if ((route->flags & WOLFSENTRY_ROUTE_FLAG_GREENLISTED)) {
        *action_results |= WOLFSENTRY_ACTION_RES_ACCEPT;
        WOLFSENTRY_RETURN_OK;
    }

    if (! WOLFSENTRY_MASKIN_BITS(*action_results, WOLFSENTRY_ACTION_RES_ACCEPT|WOLFSENTRY_ACTION_RES_REJECT))
        *action_results |= wolfsentry->routes_static.default_policy;
    if (! WOLFSENTRY_MASKIN_BITS(*action_results, WOLFSENTRY_ACTION_RES_ACCEPT|WOLFSENTRY_ACTION_RES_REJECT))
        *action_results |= wolfsentry->routes_dynamic.default_policy;

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_event_dispatch(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_sockaddr *remote,
    struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_ent_id_t *id,
    wolfsentry_route_flags_t *inexact_matches,
    wolfsentry_action_res_t *action_results
    )
{
    struct wolfsentry_route_table *route_table = NULL;
    struct wolfsentry_route *route;
    struct wolfsentry_event *trigger_event = NULL;
    int inserted = 0;
    wolfsentry_errcode_t ret;

    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);

    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(wolfsentry, event_label, event_label_len, &trigger_event)) < 0)
            return ret;
    }

    if (id)
        *id = WOLFSENTRY_ENT_ID_NONE;

    if ((ret = wolfsentry_route_lookup_1(wolfsentry, &wolfsentry->routes_static, remote, local, flags, NULL /* event */, 0 /* exact_p */, inexact_matches, &route)) >= 0) {
        route_table = &wolfsentry->routes_static;
    } else if (WOLFSENTRY_CHECK_BITS(wolfsentry->routes_static.default_policy, WOLFSENTRY_ACTION_RES_STOP)) {
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        goto out;
    } else if ((ret = wolfsentry_route_lookup_1(wolfsentry, &wolfsentry->routes_dynamic, remote, local, flags, NULL /* event */, 0 /* exact_p */, inexact_matches, &route)) >= 0) {
        route_table = &wolfsentry->routes_dynamic;
    } else if (trigger_event || wolfsentry->routes_dynamic.default_event) {
        struct wolfsentry_event *parent_event;

        route_table = &wolfsentry->routes_dynamic;

        if (trigger_event)
            parent_event = trigger_event;
        else {
            parent_event = route_table->default_event;
            WOLFSENTRY_REFCOUNT_INCREMENT(parent_event->header.refcount);
        }

        if ((ret = wolfsentry_route_new(wolfsentry, parent_event, remote, local, flags, &route)) < 0) {
            WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, parent_event, NULL /* action_results */));
            return ret;
        }

        if (parent_event->action_list.header.head)
            ret = wolfsentry_action_list_dispatch(wolfsentry, caller_arg, &parent_event->action_list, parent_event, route_table, route, action_results);
        else
            WOLFSENTRY_SET_BITS(*action_results, WOLFSENTRY_ACTION_RES_INSERT);

        if ((ret >= 0) && (*action_results & WOLFSENTRY_ACTION_RES_INSERT)) {
            WOLFSENTRY_WARN_ON_FAILURE(ret = wolfsentry_route_insert_1(wolfsentry, caller_arg, route_table, route, parent_event, action_results));
            if (ret < 0) {
                WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(wolfsentry, route, NULL /* action_results */));
                return ret;
            }
            inserted = 1;
            WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP);
            if (inexact_matches)
                *inexact_matches = WOLFSENTRY_ROUTE_FLAG_NONE;
        } else {
            WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(wolfsentry, route, NULL /* action_results */));
            if (ret >= 0)
                ret = WOLFSENTRY_ERROR_ENCODE(NOT_INSERTED); /* not an error */
            return ret;
        }
    } else {
        /* carry through ret from final wolfsentry_route_lookup_1(). */
        goto out;
    }

    if (id)
        *id = route->header.id;

    ret = wolfsentry_route_event_dispatch_1(wolfsentry, trigger_event, caller_arg, route_table, route, inserted, action_results);

  out:

    if (trigger_event && (! inserted))
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, trigger_event, NULL /* action_results */));

    if (route_table == NULL) {
        if (inexact_matches)
            *inexact_matches = WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD | WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD;
        *action_results = wolfsentry->routes_static.default_policy;
        if (WOLFSENTRY_CHECK_BITS(wolfsentry->routes_static.default_policy, WOLFSENTRY_ACTION_RES_STOP)) {
            WOLFSENTRY_RETURN_OK;
        }
        *action_results |= wolfsentry->routes_dynamic.default_policy;
    }

    return ret;
}

wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_id(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_ent_id_t id,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_action_res_t *action_results
    )
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *trigger_event = NULL;
    struct wolfsentry_route *route;

    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(wolfsentry, event_label, event_label_len, &trigger_event)) < 0)
            return ret;
    }
    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);

    if ((ret = wolfsentry_table_ent_get_by_id(wolfsentry, id, (struct wolfsentry_table_ent_header **)&route)) < 0)
        goto out;
    if (route->header.parent_table == NULL) {
        ret = WOLFSENTRY_ERROR_ENCODE(INTERNAL_CHECK_FATAL);
        goto out;
    }
    if (route->header.parent_table->ent_type != WOLFSENTRY_OBJECT_TYPE_ROUTE) {
        ret = WOLFSENTRY_ERROR_ENCODE(WRONG_OBJECT);
        goto out;
    }

    ret = wolfsentry_route_event_dispatch_1(wolfsentry, trigger_event, caller_arg, (struct wolfsentry_route_table *)route->header.parent_table, route, 0 /* inserted */, action_results);

  out:
    if (trigger_event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, trigger_event, NULL /* action_results */));
    return ret;
}

struct check_if_route_expired_args {
    struct wolfsentry_context *wolfsentry;
    struct wolfsentry_route_table *table;
    wolfsentry_time_t now;
};

static wolfsentry_errcode_t check_if_route_expired(struct check_if_route_expired_args *args, struct wolfsentry_route *route, wolfsentry_action_res_t *action_results) {
    (void)action_results;
    if (args->wolfsentry->timecbs.diff_time(args->now, route->meta.last_hit_time) < args->table->purge_age)
        return 1;
    else
        return 0;
}

wolfsentry_errcode_t wolfsentry_route_stale_purge(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *table)
{
    struct check_if_route_expired_args check_if_route_expired_args;
    wolfsentry_errcode_t ret;
    if ((ret = WOLFSENTRY_GET_TIME(&check_if_route_expired_args.now)) < 0)
        return ret;
    check_if_route_expired_args.wolfsentry = wolfsentry;
    check_if_route_expired_args.table = table;
    return wolfsentry_table_filter(
        wolfsentry,
        &table->header,
        (wolfsentry_filter_function_t)check_if_route_expired,
        &check_if_route_expired_args,
        (wolfsentry_dropper_function_t)wolfsentry_route_drop_reference_1,
        wolfsentry);
}

wolfsentry_errcode_t wolfsentry_route_get_private_data(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route *route,
    void **private_data,
    size_t *private_data_size)
{
    struct wolfsentry_eventconfig_internal *config = (route->parent_event && route->parent_event->config) ? route->parent_event->config : &wolfsentry->config;
    if (config->config.route_private_data_size == 0)
        WOLFSENTRY_ERROR_RETURN(DATA_MISSING);
    *private_data = route->data + config->route_private_data_padding;
    if (private_data_size)
        *private_data_size = config->config.route_private_data_size - config->route_private_data_padding;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_get_flags(
    struct wolfsentry_route *route,
    wolfsentry_route_flags_t *flags)
{
    *flags = route->flags;
    WOLFSENTRY_RETURN_OK;
}

static void wolfsentry_route_update_flags_1(
    struct wolfsentry_route *route,
    wolfsentry_route_flags_t flags_to_set,
    wolfsentry_route_flags_t flags_to_clear,
    wolfsentry_route_flags_t *flags_before,
    wolfsentry_route_flags_t *flags_after)
{
    WOLFSENTRY_ATOMIC_UPDATE(route->flags, flags_to_set, flags_to_clear, flags_before, flags_after);
}

wolfsentry_errcode_t wolfsentry_route_update_flags(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route *route,
    wolfsentry_route_flags_t flags_to_set,
    wolfsentry_route_flags_t flags_to_clear,
    wolfsentry_route_flags_t *flags_before,
    wolfsentry_route_flags_t *flags_after)
{
    if ((flags_to_set & (WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED|WOLFSENTRY_ROUTE_FLAG_GREENLISTED)) ==
        (WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED|WOLFSENTRY_ROUTE_FLAG_GREENLISTED))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((flags_to_set | flags_to_clear) & (WOLFSENTRY_ROUTE_IMMUTABLE_FLAGS | WOLFSENTRY_ROUTE_FLAG_PENDING_DELETE | WOLFSENTRY_ROUTE_FLAG_IN_TABLE))
        WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);

    wolfsentry_route_update_flags_1(route, flags_to_set, flags_to_clear, flags_before, flags_after);
    if ((*flags_after & WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED) && (! (*flags_before & WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED)))
        WOLFSENTRY_WARN_ON_FAILURE(WOLFSENTRY_GET_TIME(&route->meta.last_penaltybox_time));
    else if ((*flags_before & WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED) && (! (*flags_after & WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED))) {
        WOLFSENTRY_ATOMIC_DECREMENT(route->meta.derogatory_count, route->meta.derogatory_count);
        WOLFSENTRY_ATOMIC_DECREMENT(route->meta.commendable_count, route->meta.commendable_count);
    }
    WOLFSENTRY_RETURN_OK;
}

/* only possible before route is inserted. */
wolfsentry_errcode_t wolfsentry_route_set_wildcard(
    struct wolfsentry_route *route,
    wolfsentry_route_flags_t wildcards_to_set)
{
    if (route->flags & WOLFSENTRY_ROUTE_FLAG_IN_TABLE)
        WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);

    if (wildcards_to_set & WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD)
        route->flags |= WOLFSENTRY_ROUTE_FLAG_TRIGGER_WILDCARD;
    if (wildcards_to_set & WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD) {
        route->flags |= WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD;
        route->remote.interface = 0;
    }
    if (wildcards_to_set & WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD) {
        route->flags |= WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD;
        route->local.interface = 0;
    }
    if (wildcards_to_set & WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD) {
        route->flags |= WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD;
        route->sa_family = 0;
    }
    if (wildcards_to_set & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD) {
        route->flags |= WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD;
        route->remote.addr_len = 0;
    }
    if (wildcards_to_set & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD) {
        route->flags |= WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD;
        route->local.addr_len = 0;
    }
    if (wildcards_to_set & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD) {
        route->flags |= WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD;
        route->sa_proto = 0;
    }
    if (wildcards_to_set & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD) {
        route->flags |= WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        route->remote.sa_port = 0;
    }
    if (wildcards_to_set & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD) {
        route->flags |= WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD;
        route->local.sa_port = 0;
    }

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_get_metadata(
    struct wolfsentry_route *route,
    const struct wolfsentry_route_metadata **metadata)
{
    *metadata = &route->meta;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_set_penaltybox_duration_seconds(
    struct wolfsentry_route *route,
    int penaltybox_duration_seconds)
{
    if (penaltybox_duration_seconds < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (penaltybox_duration_seconds > MAX_UINT_OF(route->meta.penaltybox_duration_seconds))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    route->meta.penaltybox_duration_seconds = (uint16_t)penaltybox_duration_seconds;
    WOLFSENTRY_RETURN_OK;
}

#ifndef WOLFSENTRY_NO_STDIO

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static wolfsentry_errcode_t wolfsentry_route_render_endpoint(struct wolfsentry_route *r, int sa_local_p, FILE *f) {
    char addr_buf[16], fmt_buf[256];

    struct wolfsentry_route_endpoint *e = (sa_local_p ? &r->local : &r->remote);
    size_t addr_bytes = (size_t)(sa_local_p ? WOLFSENTRY_ROUTE_LOCAL_ADDR_BYTES(r) : WOLFSENTRY_ROUTE_REMOTE_ADDR_BYTES(r));
    void *addr = (sa_local_p ? WOLFSENTRY_ROUTE_LOCAL_ADDR(r) : WOLFSENTRY_ROUTE_REMOTE_ADDR(r));

    if (addr_bytes > sizeof addr_buf)
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);

    if (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD))
        fputs("*", stdout);
    else {
        memset(addr_buf, 0, sizeof addr_buf);
        memcpy(addr_buf, addr, addr_bytes);
        if (inet_ntop(r->sa_family, addr_buf, fmt_buf, sizeof fmt_buf) == NULL)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FAILED);

        fprintf(f, "%s/%d", fmt_buf, (int)e->addr_len);
    }

    fprintf(f, ":%d", (int)e->sa_port);

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_render(struct wolfsentry_route *r, FILE *f) {
    wolfsentry_errcode_t ret = wolfsentry_route_render_endpoint(r, 0 /* sa_local_p */, f);
    if (ret < 0)
        return ret;

    fprintf(f, " %s-%s ",
            (r->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT) ? "<" : "",
            (r->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN) ? ">" : "");

    if ((ret = wolfsentry_route_render_endpoint(r, 1 /* sa_local_p */, f)) < 0)
        return ret;

    fputc('\n',f);

    WOLFSENTRY_RETURN_OK;
}

#endif /* !WOLFSENTRY_NO_STDIO */
