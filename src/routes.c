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
    int wildcard_p,
    int match_subnets_p,
    int *inexact_p)
{
    int cmp;

    *inexact_p = 0;

    if (left_addr_len != right_addr_len) {
        int min_addr_len = (left_addr_len < right_addr_len) ? left_addr_len : right_addr_len;

        if (wildcard_p || (min_addr_len == 0))
            *inexact_p = 1;
        else if (match_subnets_p) {
            size_t min_bytes = WOLFSENTRY_BITS_TO_BYTES((size_t)min_addr_len);
            if ((min_addr_len & 0x7) == 0) {
                if ((cmp = memcmp(left_addr, right_addr, min_bytes)))
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
            if (wildcard_p)
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
    wolfsentry_route_flags_t wildcard_flags = left->flags | right->flags;

    if (inexact_matches)
        *inexact_matches = 0;

    if (left->sa_family != right->sa_family) {
        if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD;
        } else if (left->sa_family < right->sa_family)
            return -1;
        else
            return 1;
    }

    cmp = cmp_addrs(WOLFSENTRY_ROUTE_REMOTE_ADDR(left), left->remote.addr_len,
                    WOLFSENTRY_ROUTE_REMOTE_ADDR(right), right->remote.addr_len,
                    match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD),
                    match_wildcards_p,
                    &inexact_p);
    if (cmp)
        return cmp;
    if (inexact_p && inexact_matches)
        *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD;

    if (left->sa_proto != right->sa_proto) {
        if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD;
        } else if (left->sa_proto < right->sa_proto)
            return -1;
        else
            return 1;
    }

    if (left->local.sa_port != right->local.sa_port) {
        if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD)) {
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
            if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD)) {
                if (inexact_matches)
                    *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
            } else
                return -1;
        } else if (left->parent_event == NULL) {
            if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD)) {
                if (inexact_matches)
                    *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
            } else
                return -1;
        }
    } else {
        if (left->parent_event->priority < right->parent_event->priority) {
            if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD)) {
                if (inexact_matches)
                    *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
            } else
                return -1;
        } else if (left->parent_event->priority > right->parent_event->priority) {
            if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD)) {
                if (inexact_matches)
                    *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
            } else
                return -1;
        }
    }

    cmp = cmp_addrs(WOLFSENTRY_ROUTE_LOCAL_ADDR(left), left->local.addr_len,
                    WOLFSENTRY_ROUTE_LOCAL_ADDR(right), right->local.addr_len,
                    match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD),
                    match_wildcards_p,
                    &inexact_p);
    if (cmp)
        return cmp;
    if (inexact_p && inexact_matches)
        *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD;

    if (left->remote.sa_port != right->remote.sa_port) {
        if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        } else if (left->remote.sa_port < right->remote.sa_port)
            return -1;
        else
            return 1;
    }

    if (left->remote.interface != right->remote.interface) {
        if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD;
        } else if (left->remote.interface < right->remote.interface)
            return -1;
        else
            return 1;
    }

    if (left->local.interface != right->local.interface) {
        if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD)) {
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

    if (! ((left->parent_event == NULL) || (right->parent_event == NULL) || (inexact_matches && (*inexact_matches & WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD)))) {
        cmp = wolfsentry_event_key_cmp(left->parent_event, right->parent_event);
        if (cmp) {
            if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD)) {
                if (inexact_matches)
                    *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
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
    if ((unsigned)data_addr_size > MAX_UINT_OF(uint16_t))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    if ((unsigned)data_addr_offset > MAX_UINT_OF(uint16_t))
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
    if (new_size & 1)
        ++new_size;
    /* extra_ports storage will go here. */

    if (config->config.route_private_data_alignment == 0)
        *new = (struct wolfsentry_route *)WOLFSENTRY_MALLOC(new_size);
    else
        *new = WOLFSENTRY_MEMALIGN(config->config.route_private_data_alignment, new_size);
    if (*new == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    return wolfsentry_route_init(parent_event, remote, local, flags, (int)config->config.route_private_data_size, (int)(new_size - offsetof(struct wolfsentry_route, data)), *new);

    return ret;
}

wolfsentry_errcode_t wolfsentry_route_clone(
    struct wolfsentry_context *src_context,
    struct wolfsentry_table_ent_header * const src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header ** const new_ent,
    wolfsentry_clone_flags_t flags)
{
    struct wolfsentry_route * const src_route = (struct wolfsentry_route * const)src_ent;
    struct wolfsentry_route ** const new_route = (struct wolfsentry_route ** const)new_ent;
    struct wolfsentry_eventconfig_internal *config = (src_route->parent_event && src_route->parent_event->config) ? src_route->parent_event->config : &src_context->config;
    size_t new_size;

    (void)flags;

    new_size = WOLFSENTRY_BITS_TO_BYTES((size_t)src_route->remote.addr_len) + WOLFSENTRY_BITS_TO_BYTES((size_t)src_route->local.addr_len);
    if (new_size > (size_t)(uint16_t)~0UL)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
    new_size += offsetof(struct wolfsentry_route, data);
    new_size += config->config.route_private_data_size;
    if (new_size & 1)
        ++new_size;
    /* extra_ports storage will go here. */

    if ((*new_route = dest_context->allocator.malloc(dest_context->allocator.context, new_size)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    memcpy(*new_route, src_route, new_size);
    WOLFSENTRY_TABLE_ENT_HEADER_RESET(**new_ent);

    if (src_route->parent_event) {
        wolfsentry_errcode_t ret;
        (*new_route)->parent_event = src_route->parent_event;
        if ((ret = wolfsentry_table_ent_get(&dest_context->events.header, (struct wolfsentry_table_ent_header **)&(*new_route)->parent_event)) < 0) {
            dest_context->allocator.free(dest_context->allocator.context, *new_route);
            return ret;
        }
        WOLFSENTRY_REFCOUNT_INCREMENT((*new_route)->parent_event->header.refcount);
    }

    WOLFSENTRY_RETURN_OK;
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

    if (route->parent_event && WOLFSENTRY_CHECK_BITS(route->parent_event->flags, WOLFSENTRY_EVENT_FLAG_IS_SUBEVENT))
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);

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
        ret = wolfsentry_action_list_dispatch(
            wolfsentry,
            caller_arg,
            route->parent_event->insert_event,
            trigger_event,
            WOLFSENTRY_ACTION_TYPE_INSERT,
            route_table,
            route,
            action_results);
        if (ret < 0) {
            wolfsentry_route_flags_t flags_before, flags_after;
            (void)wolfsentry_table_ent_delete_1(wolfsentry, &route->header);
            wolfsentry_route_update_flags_1(route, WOLFSENTRY_ROUTE_FLAG_NONE, WOLFSENTRY_ROUTE_FLAG_IN_TABLE, &flags_before, &flags_after);
        }
        return ret;
    } else {
        if (route->parent_event) {
            if (! WOLFSENTRY_CHECK_BITS(route->parent_event->flags, WOLFSENTRY_EVENT_FLAG_IS_PARENT_EVENT))
                WOLFSENTRY_SET_BITS(route->parent_event->flags, WOLFSENTRY_EVENT_FLAG_IS_PARENT_EVENT);
        }
        WOLFSENTRY_RETURN_OK;
    }
}

static wolfsentry_errcode_t wolfsentry_route_insert_2(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    struct wolfsentry_route_table *route_table,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
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

    if ((ret = wolfsentry_route_insert_1(wolfsentry, caller_arg, route_table, new, parent_event, action_results)) < 0)
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
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
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
    const struct wolfsentry_route_table *table,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
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
    wolfsentry_route_flags_t highest_priority_inexact_matches = 0;
    wolfsentry_errcode_t ret;

    if ((ret = wolfsentry_table_cursor_init(wolfsentry, &cursor)) < 0)
        goto out;

    if (! exact_p)
        WOLFSENTRY_SET_BITS(flags, WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD);

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
    const struct wolfsentry_route_table *table,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
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
        ret = wolfsentry_action_list_dispatch(
            wolfsentry,
            caller_arg,
            route->parent_event->delete_event,
            trigger_event,
            WOLFSENTRY_ACTION_TYPE_DELETE,
            route_table,
            route,
            action_results);
        if (ret < 0)
            WOLFSENTRY_WARN("wolfsentry_route_delete_0 returned " WOLFSENTRY_ERROR_FMT, WOLFSENTRY_ERROR_FMT_ARGS(ret));
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
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
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
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
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
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
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
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
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

static wolfsentry_errcode_t wolfsentry_route_event_dispatch_0(
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
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_dispatch(
                                       wolfsentry,
                                       caller_arg,
                                       trigger_event,
                                       trigger_event,
                                       WOLFSENTRY_ACTION_TYPE_POST,
                                       route_table,
                                       route,
                                       action_results));
        if (action_results)
            WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP);
    }

    if (route->parent_event && route->parent_event->match_event && route->parent_event->match_event->action_list.header.head) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_dispatch(
                                       wolfsentry,
                                       caller_arg,
                                       route->parent_event->match_event,
                                       trigger_event,
                                       WOLFSENTRY_ACTION_TYPE_MATCH,
                                       route_table,
                                       route,
                                       action_results));
        if (action_results)
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
        if ((config->config.penaltybox_duration > 0) && (route->meta.last_penaltybox_time != 0)) {
            wolfsentry_time_t now;
            wolfsentry_errcode_t ret = WOLFSENTRY_GET_TIME(&now);
            if (ret < 0)
                return ret;
            if (WOLFSENTRY_DIFF_TIME(now, route->meta.last_penaltybox_time) > config->config.penaltybox_duration) {
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

static wolfsentry_errcode_t wolfsentry_route_event_dispatch_1(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
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
            ret = wolfsentry_action_list_dispatch(
                wolfsentry,
                caller_arg,
                parent_event,
                parent_event,
                WOLFSENTRY_ACTION_TYPE_POST,
                route_table,
                route,
                action_results);
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

    ret = wolfsentry_route_event_dispatch_0(wolfsentry, trigger_event, caller_arg, route_table, route, inserted, action_results);

  out:

    if (trigger_event && (! inserted))
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, trigger_event, NULL /* action_results */));

    if (route_table == NULL) {
        if (inexact_matches)
            *inexact_matches = WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD | WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD;
        *action_results = wolfsentry->routes_static.default_policy;
        if (WOLFSENTRY_CHECK_BITS(wolfsentry->routes_static.default_policy, WOLFSENTRY_ACTION_RES_STOP)) {
            WOLFSENTRY_RETURN_OK;
        }
        *action_results |= wolfsentry->routes_dynamic.default_policy;
    }

    return ret;
}

wolfsentry_errcode_t wolfsentry_route_event_dispatch(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_ent_id_t *id,
    wolfsentry_route_flags_t *inexact_matches,
    wolfsentry_action_res_t *action_results
    )
{
    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    return wolfsentry_route_event_dispatch_1(wolfsentry, remote, local, flags, event_label, event_label_len, caller_arg, id, inexact_matches, action_results);
}

static wolfsentry_errcode_t check_user_inited_result(wolfsentry_action_res_t action_results) {
    if (WOLFSENTRY_MASKIN_BITS(action_results,
                               WOLFSENTRY_ACTION_RES_ACCEPT |
                               WOLFSENTRY_ACTION_RES_REJECT |
                               WOLFSENTRY_ACTION_RES_STOP |
                               WOLFSENTRY_ACTION_RES_DEALLOCATED |
                               WOLFSENTRY_ACTION_RES_ERROR))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else
        WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_event_dispatch_with_inited_result(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_ent_id_t *id,
    wolfsentry_route_flags_t *inexact_matches,
    wolfsentry_action_res_t *action_results
    )
{
    int ret = check_user_inited_result(*action_results);
    if (ret < 0)
        return ret;
    return wolfsentry_route_event_dispatch_1(wolfsentry, remote, local, flags, event_label, event_label_len, caller_arg, id, inexact_matches, action_results);
}

static wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_id_1(
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

    ret = wolfsentry_route_event_dispatch_0(wolfsentry, trigger_event, caller_arg, (struct wolfsentry_route_table *)route->header.parent_table, route, 0 /* inserted */, action_results);

  out:
    if (trigger_event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, trigger_event, NULL /* action_results */));
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
    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    return wolfsentry_route_event_dispatch_by_id_1(wolfsentry, id, event_label, event_label_len, caller_arg, action_results);
}

wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_id_with_inited_result(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_ent_id_t id,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_action_res_t *action_results
    )
{
    int ret = check_user_inited_result(*action_results);
    if (ret < 0)
        return ret;
    return wolfsentry_route_event_dispatch_by_id_1(wolfsentry, id, event_label, event_label_len, caller_arg, action_results);
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

static wolfsentry_errcode_t wolfsentry_route_delete_for_filter(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results)
{
    return wolfsentry_route_delete_0(
        wolfsentry,
        NULL /* caller_arg */,
        (struct wolfsentry_route_table *)route->header.parent_table,
        NULL /* trigger_event */,
        route,
        action_results
        );
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
        (wolfsentry_dropper_function_t)wolfsentry_route_delete_for_filter,
        wolfsentry);
}

wolfsentry_errcode_t wolfsentry_route_flush_table(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *table)
{
    return wolfsentry_table_map(
        wolfsentry,
        &table->header,
        (wolfsentry_map_function_t)wolfsentry_route_delete_for_filter,
        wolfsentry);
}

static wolfsentry_errcode_t wolfsentry_route_clear_insert_action_status(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results)
{
    (void)wolfsentry;
    (void)action_results;
    if (WOLFSENTRY_CHECK_BITS(route->flags, WOLFSENTRY_ROUTE_FLAG_INSERT_ACTIONS_CALLED))
        WOLFSENTRY_CLEAR_BITS(route->flags, WOLFSENTRY_ROUTE_FLAG_INSERT_ACTIONS_CALLED);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_bulk_clear_insert_action_status(
    struct wolfsentry_context *wolfsentry)
{
    wolfsentry_errcode_t ret;
    ret = wolfsentry_table_map(
        wolfsentry,
        &wolfsentry->routes_dynamic.header,
        (wolfsentry_map_function_t)wolfsentry_route_clear_insert_action_status,
        wolfsentry);
    if (ret < 0)
        return ret;
    return wolfsentry_table_map(
        wolfsentry,
        &wolfsentry->routes_dynamic.header,
        (wolfsentry_map_function_t)wolfsentry_route_clear_insert_action_status,
        wolfsentry);
}

static wolfsentry_errcode_t wolfsentry_route_call_insert_action(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results)
{
    if (route->parent_event && route->parent_event->insert_event) {
        wolfsentry_errcode_t ret = wolfsentry_action_list_dispatch(
            wolfsentry,
            NULL /* caller_arg */,
            route->parent_event->insert_event,
            NULL /* trigger_event */,
            WOLFSENTRY_ACTION_TYPE_INSERT,
            (struct wolfsentry_route_table *)route->header.parent_table,
            route,
            action_results);
        if (WOLFSENTRY_ERROR_CODE_IS(ret, OK))
            return ret;
        else if (WOLFSENTRY_ERROR_CODE_IS(ret, ALREADY))
            WOLFSENTRY_RETURN_OK;
        else
            return ret;
    } else
        WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_bulk_insert_actions(
    struct wolfsentry_context *wolfsentry)
{
    wolfsentry_errcode_t ret;
    ret = wolfsentry_table_map(
        wolfsentry,
        &wolfsentry->routes_dynamic.header,
        (wolfsentry_map_function_t)wolfsentry_route_call_insert_action,
        wolfsentry);
    if (ret < 0)
        return ret;
    return wolfsentry_table_map(
        wolfsentry,
        &wolfsentry->routes_dynamic.header,
        (wolfsentry_map_function_t)wolfsentry_route_call_insert_action,
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
    *private_data = (byte *)route->data + config->route_private_data_padding;
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

    if (wildcards_to_set & WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD)
        route->flags |= WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
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

wolfsentry_errcode_t wolfsentry_route_export(
    const struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route *route,
    struct wolfsentry_route_exports *route_exports)
{
    const struct wolfsentry_eventconfig_internal *config = (route->parent_event && route->parent_event->config) ? route->parent_event->config : &wolfsentry->config;
    if (route->parent_event) {
        route_exports->parent_event_label = route->parent_event->label;
        route_exports->parent_event_label_len = route->parent_event->label_len;
    } else {
        route_exports->parent_event_label = NULL;
        route_exports->parent_event_label_len = 0;
    }
    route_exports->flags = route->flags;
    route_exports->sa_family = route->sa_family;
    route_exports->sa_proto = route->sa_proto;
    route_exports->remote = route->remote;
    route_exports->local = route->local;
    route_exports->remote_address = WOLFSENTRY_ROUTE_REMOTE_ADDR(route);
    route_exports->local_address = WOLFSENTRY_ROUTE_LOCAL_ADDR(route);
    if (route->remote.extra_port_count > 0)
        route_exports->remote_extra_ports = (wolfsentry_port_t *)WOLFSENTRY_ROUTE_REMOTE_EXTRA_PORTS(route);
    else
        route_exports->remote_extra_ports = NULL;
    if (route->local.extra_port_count > 0)
        route_exports->local_extra_ports = (wolfsentry_port_t *)WOLFSENTRY_ROUTE_LOCAL_EXTRA_PORTS(route);
    else
        route_exports->local_extra_ports = NULL;
    route_exports->meta = &route->meta;
    if (config->config.route_private_data_size == 0) {
        route_exports->private_data = NULL;
        route_exports->private_data_size = 0;
    } else {
        route_exports->private_data = (byte *)route->data + config->route_private_data_padding;
        route_exports->private_data_size = config->config.route_private_data_size - config->route_private_data_padding;
    }
    WOLFSENTRY_RETURN_OK;
}

const struct wolfsentry_event *wolfsentry_route_parent_event(const struct wolfsentry_route *route) {
    return route->parent_event;
}

wolfsentry_errcode_t wolfsentry_route_table_iterate_start(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor **cursor)
{
    int ret;
    if ((*cursor = (struct wolfsentry_cursor *)WOLFSENTRY_MALLOC(sizeof **cursor)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if ((ret = wolfsentry_table_cursor_init(wolfsentry, *cursor)) < 0)
        goto out;
    if ((ret = wolfsentry_table_cursor_seek_to_head((const struct wolfsentry_table_header *)table, *cursor)) < 0)
        goto out;
  out:
    if (ret < 0)
        WOLFSENTRY_FREE(*cursor);
    return ret;
}

wolfsentry_errcode_t wolfsentry_route_table_iterate_seek_to_head(
    const struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor)
{
    (void)wolfsentry;
    return wolfsentry_table_cursor_seek_to_head((const struct wolfsentry_table_header *)table, cursor);
}

wolfsentry_errcode_t wolfsentry_route_table_iterate_seek_to_tail(
    const struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor)
{
    (void)wolfsentry;
    return wolfsentry_table_cursor_seek_to_tail((const struct wolfsentry_table_header *)table, cursor);
}

wolfsentry_errcode_t wolfsentry_route_table_iterate_current(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_route **route)
{
    (void)wolfsentry;
    (void)table;
    *route = (struct wolfsentry_route *)wolfsentry_table_cursor_current(cursor);
    if (*route == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_table_iterate_prev(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_route **route)
{
    (void)wolfsentry;
    (void)table;
    *route = (struct wolfsentry_route *)wolfsentry_table_cursor_prev(cursor);
    if (*route == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_table_iterate_next(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_route **route)
{
    (void)wolfsentry;
    (void)table;
    *route = (struct wolfsentry_route *)wolfsentry_table_cursor_next(cursor);
    if (*route == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_table_iterate_end(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor **cursor)
{
    (void)table;
    WOLFSENTRY_FREE(*cursor);
    *cursor = NULL;
    WOLFSENTRY_RETURN_OK;
}

#ifdef WOLFSENTRY_PROTOCOL_NAMES

wolfsentry_family_t wolfsentry_family_pton(const char *family_name, size_t family_name_len) {
    if (strcaseeq(family_name, "UNIX", family_name_len))
        return WOLFSENTRY_AF_UNIX;
    if (strcaseeq(family_name, "LOCAL", family_name_len))
        return WOLFSENTRY_AF_LOCAL;
    if (strcaseeq(family_name, "INET", family_name_len))
        return WOLFSENTRY_AF_INET;
    if (strcaseeq(family_name, "AX25", family_name_len))
        return WOLFSENTRY_AF_AX25;
    if (strcaseeq(family_name, "IPX", family_name_len))
        return WOLFSENTRY_AF_IPX;
    if (strcaseeq(family_name, "APPLETALK", family_name_len))
        return WOLFSENTRY_AF_APPLETALK;
    if (strcaseeq(family_name, "NETROM", family_name_len))
        return WOLFSENTRY_AF_NETROM;
    if (strcaseeq(family_name, "BRIDGE", family_name_len))
        return WOLFSENTRY_AF_BRIDGE;
    if (strcaseeq(family_name, "ATMPVC", family_name_len))
        return WOLFSENTRY_AF_ATMPVC;
    if (strcaseeq(family_name, "X25", family_name_len))
        return WOLFSENTRY_AF_X25;
    if (strcaseeq(family_name, "INET6", family_name_len))
        return WOLFSENTRY_AF_INET6;
    if (strcaseeq(family_name, "ROSE", family_name_len))
        return WOLFSENTRY_AF_ROSE;
    if (strcaseeq(family_name, "DECnet", family_name_len))
        return WOLFSENTRY_AF_DECnet;
    if (strcaseeq(family_name, "NETBEUI", family_name_len))
        return WOLFSENTRY_AF_NETBEUI;
    if (strcaseeq(family_name, "SECURITY", family_name_len))
        return WOLFSENTRY_AF_SECURITY;
    if (strcaseeq(family_name, "KEY", family_name_len))
        return WOLFSENTRY_AF_KEY;
    if (strcaseeq(family_name, "NETLINK", family_name_len))
        return WOLFSENTRY_AF_NETLINK;
    if (strcaseeq(family_name, "ROUTE", family_name_len))
        return WOLFSENTRY_AF_ROUTE;
    if (strcaseeq(family_name, "PACKET", family_name_len))
        return WOLFSENTRY_AF_PACKET;
    if (strcaseeq(family_name, "ASH", family_name_len))
        return WOLFSENTRY_AF_ASH;
    if (strcaseeq(family_name, "ECONET", family_name_len))
        return WOLFSENTRY_AF_ECONET;
    if (strcaseeq(family_name, "ATMSVC", family_name_len))
        return WOLFSENTRY_AF_ATMSVC;
    if (strcaseeq(family_name, "RDS", family_name_len))
        return WOLFSENTRY_AF_RDS;
    if (strcaseeq(family_name, "SNA", family_name_len))
        return WOLFSENTRY_AF_SNA;
    if (strcaseeq(family_name, "IRDA", family_name_len))
        return WOLFSENTRY_AF_IRDA;
    if (strcaseeq(family_name, "PPPOX", family_name_len))
        return WOLFSENTRY_AF_PPPOX;
    if (strcaseeq(family_name, "WANPIPE", family_name_len))
        return WOLFSENTRY_AF_WANPIPE;
    if (strcaseeq(family_name, "LLC", family_name_len))
        return WOLFSENTRY_AF_LLC;
    if (strcaseeq(family_name, "IB", family_name_len))
        return WOLFSENTRY_AF_IB;
    if (strcaseeq(family_name, "MPLS", family_name_len))
        return WOLFSENTRY_AF_MPLS;
    if (strcaseeq(family_name, "CAN", family_name_len))
        return WOLFSENTRY_AF_CAN;
    if (strcaseeq(family_name, "TIPC", family_name_len))
        return WOLFSENTRY_AF_TIPC;
    if (strcaseeq(family_name, "BLUETOOTH", family_name_len))
        return WOLFSENTRY_AF_BLUETOOTH;
    if (strcaseeq(family_name, "IUCV", family_name_len))
        return WOLFSENTRY_AF_IUCV;
    if (strcaseeq(family_name, "RXRPC", family_name_len))
        return WOLFSENTRY_AF_RXRPC;
    if (strcaseeq(family_name, "ISDN", family_name_len))
        return WOLFSENTRY_AF_ISDN;
    if (strcaseeq(family_name, "PHONET", family_name_len))
        return WOLFSENTRY_AF_PHONET;
    if (strcaseeq(family_name, "IEEE802154", family_name_len))
        return WOLFSENTRY_AF_IEEE802154;
    if (strcaseeq(family_name, "CAIF", family_name_len))
        return WOLFSENTRY_AF_CAIF;
    if (strcaseeq(family_name, "ALG", family_name_len))
        return WOLFSENTRY_AF_ALG;
    if (strcaseeq(family_name, "NFC", family_name_len))
        return WOLFSENTRY_AF_NFC;
    if (strcaseeq(family_name, "VSOCK", family_name_len))
        return WOLFSENTRY_AF_VSOCK;
    if (strcaseeq(family_name, "KCM", family_name_len))
        return WOLFSENTRY_AF_KCM;
    if (strcaseeq(family_name, "QIPCRTR", family_name_len))
        return WOLFSENTRY_AF_QIPCRTR;
    if (strcaseeq(family_name, "SMC", family_name_len))
        return WOLFSENTRY_AF_SMC;
    if (strcaseeq(family_name, "XDP", family_name_len))
        return WOLFSENTRY_AF_XDP;
    if (strcaseeq(family_name, "IMPLINK", family_name_len))
        return WOLFSENTRY_AF_IMPLINK;
    if (strcaseeq(family_name, "PUP", family_name_len))
        return WOLFSENTRY_AF_PUP;
    if (strcaseeq(family_name, "CHAOS", family_name_len))
        return WOLFSENTRY_AF_CHAOS;
    if (strcaseeq(family_name, "NETBIOS", family_name_len))
        return WOLFSENTRY_AF_NETBIOS;
    if (strcaseeq(family_name, "ISO", family_name_len))
        return WOLFSENTRY_AF_ISO;
    if (strcaseeq(family_name, "OSI", family_name_len))
        return WOLFSENTRY_AF_OSI;
    if (strcaseeq(family_name, "ECMA", family_name_len))
        return WOLFSENTRY_AF_ECMA;
    if (strcaseeq(family_name, "DATAKIT", family_name_len))
        return WOLFSENTRY_AF_DATAKIT;
    if (strcaseeq(family_name, "DLI", family_name_len))
        return WOLFSENTRY_AF_DLI;
    if (strcaseeq(family_name, "LAT", family_name_len))
        return WOLFSENTRY_AF_LAT;
    if (strcaseeq(family_name, "HYLINK", family_name_len))
        return WOLFSENTRY_AF_HYLINK;
    if (strcaseeq(family_name, "LINK", family_name_len))
        return WOLFSENTRY_AF_LINK;
    if (strcaseeq(family_name, "COIP", family_name_len))
        return WOLFSENTRY_AF_COIP;
    if (strcaseeq(family_name, "CNT", family_name_len))
        return WOLFSENTRY_AF_CNT;
    if (strcaseeq(family_name, "SIP", family_name_len))
        return WOLFSENTRY_AF_SIP;
    if (strcaseeq(family_name, "SLOW", family_name_len))
        return WOLFSENTRY_AF_SLOW;
    if (strcaseeq(family_name, "SCLUSTER", family_name_len))
        return WOLFSENTRY_AF_SCLUSTER;
    if (strcaseeq(family_name, "ARP", family_name_len))
        return WOLFSENTRY_AF_ARP;
    if (strcaseeq(family_name, "IEEE80211", family_name_len))
        return WOLFSENTRY_AF_IEEE80211;
    if (strcaseeq(family_name, "INET_SDP", family_name_len))
        return WOLFSENTRY_AF_INET_SDP;
    if (strcaseeq(family_name, "INET6_SDP", family_name_len))
        return WOLFSENTRY_AF_INET6_SDP;
    if (strcaseeq(family_name, "HYPERV", family_name_len))
        return WOLFSENTRY_AF_HYPERV;
    return WOLFSENTRY_AF_UNSPEC;
}

const char *wolfsentry_family_ntop(wolfsentry_family_t family) {
    switch(family) {
    case WOLFSENTRY_AF_UNSPEC:
        return "UNSPEC";
    case WOLFSENTRY_AF_LOCAL: /* AF_UNIX is an alias. */
        return "LOCAL";
    case WOLFSENTRY_AF_INET:
        return "INET";
    case WOLFSENTRY_AF_AX25:
        return "AX25";
    case WOLFSENTRY_AF_IPX:
        return "IPX";
    case WOLFSENTRY_AF_APPLETALK:
        return "APPLETALK";
    case WOLFSENTRY_AF_NETROM:
        return "NETROM";
    case WOLFSENTRY_AF_BRIDGE:
        return "BRIDGE";
    case WOLFSENTRY_AF_ATMPVC:
        return "ATMPVC";
    case WOLFSENTRY_AF_X25:
        return "X25";
    case WOLFSENTRY_AF_INET6:
        return "INET6";
    case WOLFSENTRY_AF_ROSE:
        return "ROSE";
    case WOLFSENTRY_AF_DECnet:
        return "DECnet";
    case WOLFSENTRY_AF_NETBEUI:
        return "NETBEUI";
    case WOLFSENTRY_AF_SECURITY:
        return "SECURITY";
    case WOLFSENTRY_AF_KEY:
        return "KEY";
    case WOLFSENTRY_AF_ROUTE: /* AF_NETLINK is an alias. */
        return "ROUTE";
    case WOLFSENTRY_AF_PACKET:
        return "PACKET";
    case WOLFSENTRY_AF_ASH:
        return "ASH";
    case WOLFSENTRY_AF_ECONET:
        return "ECONET";
    case WOLFSENTRY_AF_ATMSVC:
        return "ATMSVC";
    case WOLFSENTRY_AF_RDS:
        return "RDS";
    case WOLFSENTRY_AF_SNA:
        return "SNA";
    case WOLFSENTRY_AF_IRDA:
        return "IRDA";
    case WOLFSENTRY_AF_PPPOX:
        return "PPPOX";
    case WOLFSENTRY_AF_WANPIPE:
        return "WANPIPE";
    case WOLFSENTRY_AF_LLC:
        return "LLC";
    case WOLFSENTRY_AF_IB:
        return "IB";
    case WOLFSENTRY_AF_MPLS:
        return "MPLS";
    case WOLFSENTRY_AF_CAN:
        return "CAN";
    case WOLFSENTRY_AF_TIPC:
        return "TIPC";
    case WOLFSENTRY_AF_BLUETOOTH:
        return "BLUETOOTH";
    case WOLFSENTRY_AF_IUCV:
        return "IUCV";
    case WOLFSENTRY_AF_RXRPC:
        return "RXRPC";
    case WOLFSENTRY_AF_ISDN:
        return "ISDN";
    case WOLFSENTRY_AF_PHONET:
        return "PHONET";
    case WOLFSENTRY_AF_IEEE802154:
        return "IEEE802154";
    case WOLFSENTRY_AF_CAIF:
        return "CAIF";
    case WOLFSENTRY_AF_ALG:
        return "ALG";
    case WOLFSENTRY_AF_NFC:
        return "NFC";
    case WOLFSENTRY_AF_VSOCK:
        return "VSOCK";
    case WOLFSENTRY_AF_KCM:
        return "KCM";
    case WOLFSENTRY_AF_QIPCRTR:
        return "QIPCRTR";
    case WOLFSENTRY_AF_SMC:
        return "SMC";
    case WOLFSENTRY_AF_XDP:
        return "XDP";
    case WOLFSENTRY_AF_IMPLINK:
        return "IMPLINK";
    case WOLFSENTRY_AF_PUP:
        return "PUP";
    case WOLFSENTRY_AF_CHAOS:
        return "CHAOS";
    case WOLFSENTRY_AF_NETBIOS:
        return "NETBIOS";
    case WOLFSENTRY_AF_ISO: /* AF_OSI is an alias. */
        return "ISO";
    case WOLFSENTRY_AF_ECMA:
        return "ECMA";
    case WOLFSENTRY_AF_DATAKIT:
        return "DATAKIT";
    case WOLFSENTRY_AF_DLI:
        return "DLI";
    case WOLFSENTRY_AF_LAT:
        return "LAT";
    case WOLFSENTRY_AF_HYLINK:
        return "HYLINK";
    case WOLFSENTRY_AF_LINK:
        return "LINK";
    case WOLFSENTRY_AF_COIP:
        return "COIP";
    case WOLFSENTRY_AF_CNT:
        return "CNT";
    case WOLFSENTRY_AF_SIP:
        return "SIP";
    case WOLFSENTRY_AF_SLOW:
        return "SLOW";
    case WOLFSENTRY_AF_SCLUSTER:
        return "SCLUSTER";
    case WOLFSENTRY_AF_ARP:
        return "ARP";
    case WOLFSENTRY_AF_IEEE80211:
        return "IEEE80211";
    case WOLFSENTRY_AF_INET_SDP:
        return "INET_SDP";
    case WOLFSENTRY_AF_INET6_SDP:
        return "INET6_SDP";
    case WOLFSENTRY_AF_HYPERV:
        return "HYPERV";
    default:
        return NULL;
    }
}

#endif /* WOLFSENTRY_PROTOCOL_NAMES */

#ifndef WOLFSENTRY_NO_STDIO

#ifndef WOLFSENTRY_LWIP
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#else
#include <lwip/inet.h>
#include <lwip/sockets.h>
#endif
#ifdef WOLFSENTRY_PROTOCOL_NAMES
#include <netdb.h>
#endif

static wolfsentry_errcode_t wolfsentry_route_render_proto(int proto, wolfsentry_route_flags_t flags, FILE *f) {
    if (WOLFSENTRY_CHECK_BITS(flags, WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD)) {
        fprintf(f, ", proto = *");
        WOLFSENTRY_RETURN_OK;
    }
#ifndef WOLFSENTRY_PROTOCOL_NAMES
    (void)flags;
#else
    if (WOLFSENTRY_CHECK_BITS(flags, WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS)) {
        struct protoent *p = getprotobynumber(proto);
        if (p)
            fprintf(f, ", proto = %s", p->p_name);
        else
            fprintf(f, ", proto = %d", proto);
    } else
#endif
        fprintf(f, ", proto = %d", proto);
    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_render_address(int sa_family, int addr_bits, const byte *addr, size_t addr_bytes, FILE *f) {
    char addr_buf[16], fmt_buf[256];

    if (addr_bytes > sizeof addr_buf)
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);

    if (sa_family == WOLFSENTRY_AF_LINK) {
        int i;
        for (i=0; i < (addr_bits >> 3); ++i)
            fprintf(f, "%s%02x", i ? ":" : "", (unsigned int)addr[i]);
    } else if (sa_family == WOLFSENTRY_AF_INET) {
        memset(addr_buf, 0, sizeof addr_buf);
        memcpy(addr_buf, addr, addr_bytes);
        if (inet_ntop(AF_INET, addr_buf, fmt_buf, sizeof fmt_buf) == NULL)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FAILED);
        fprintf(f, "%s/%d", fmt_buf, addr_bits);
    } else if (sa_family == WOLFSENTRY_AF_INET6) {
        memset(addr_buf, 0, sizeof addr_buf);
        memcpy(addr_buf, addr, addr_bytes);
        if (inet_ntop(AF_INET6, addr_buf, fmt_buf, sizeof fmt_buf) == NULL)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FAILED);
        fprintf(f, "[%s]/%d", fmt_buf, addr_bits);
    } else if (sa_family == WOLFSENTRY_AF_LOCAL) {
        fprintf(f, "\"%.*s\"", (int)addr_bytes, addr);
    } else
        WOLFSENTRY_ERROR_RETURN(OP_NOT_SUPP_FOR_PROTO);
    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_render_endpoint(const struct wolfsentry_route *r, int sa_local_p, FILE *f) {
    const struct wolfsentry_route_endpoint *e = (sa_local_p ? &r->local : &r->remote);
    size_t addr_bytes = (size_t)(sa_local_p ? WOLFSENTRY_ROUTE_LOCAL_ADDR_BYTES(r) : WOLFSENTRY_ROUTE_REMOTE_ADDR_BYTES(r));
    const void *addr = (sa_local_p ? WOLFSENTRY_ROUTE_LOCAL_ADDR(r) : WOLFSENTRY_ROUTE_REMOTE_ADDR(r));

    if (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD))
        fputs("*", stdout);
    else {
        wolfsentry_errcode_t ret = wolfsentry_route_render_address(r->sa_family, (int)e->addr_len, addr, addr_bytes, f);
        if (ret < 0)
            return ret;
    }

    if (! (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD)))
        fprintf(f, "%%%d", e->interface);

    if (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD))
        fprintf(f, ":*");
    else
        fprintf(f, ":%d", (int)e->sa_port);

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_render(const struct wolfsentry_route *r, FILE *f) {
    wolfsentry_errcode_t ret = wolfsentry_route_render_endpoint(r, 0 /* sa_local_p */, f);
    if (ret < 0)
        return ret;

    fprintf(f, " %s-%s ",
            (r->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT) ? "<" : "",
            (r->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN) ? ">" : "");

    if ((ret = wolfsentry_route_render_endpoint(r, 1 /* sa_local_p */, f)) < 0)
        return ret;

    if (WOLFSENTRY_CHECK_BITS(r->flags, WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD))
        fprintf(f, ", ev = *");
    else if (r->parent_event != NULL)
        fprintf(f, ", ev = \"%.*s\"", (int)r->parent_event->label_len, r->parent_event->label);

    if (WOLFSENTRY_CHECK_BITS(r->flags, WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD))
        fprintf(f, ", AF = *");
    else {
#ifdef WOLFSENTRY_PROTOCOL_NAMES
        const char *family_name = wolfsentry_family_ntop(r->sa_family);
        if (family_name)
            fprintf(f, ", AF = %s", family_name);
        else
#endif
            fprintf(f, ", AF = %d", r->sa_family);
    }

    wolfsentry_route_render_proto(r->sa_proto, r->flags, f);

    fputc('\n',f);

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_exports_render_endpoint(const struct wolfsentry_route_exports *r, int sa_local_p, FILE *f) {
    const struct wolfsentry_route_endpoint *e = (sa_local_p ? &r->local : &r->remote);
    size_t addr_bytes = (size_t)(sa_local_p ? WOLFSENTRY_ROUTE_LOCAL_ADDR_BYTES(r) : WOLFSENTRY_ROUTE_REMOTE_ADDR_BYTES(r));
    const byte *addr = (sa_local_p ? r->local_address : r->remote_address);

    if (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD))
        fputs("*", stdout);
    else {
        wolfsentry_errcode_t ret = wolfsentry_route_render_address(r->sa_family, (int)e->addr_len, addr, addr_bytes, f);
        if (ret < 0)
            return ret;
    }

    if (! (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD)))
        fprintf(f, "%%%d", e->interface);

    if (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD))
        fprintf(f, ":*");
    else
        fprintf(f, ":%d", (int)e->sa_port);

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_exports_render(const struct wolfsentry_route_exports *r, FILE *f) {
    wolfsentry_errcode_t ret = wolfsentry_route_exports_render_endpoint(r, 0 /* sa_local_p */, f);
    if (ret < 0)
        return ret;

    fprintf(f, " %s-%s ",
            (r->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT) ? "<" : "",
            (r->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN) ? ">" : "");

    if ((ret = wolfsentry_route_exports_render_endpoint(r, 1 /* sa_local_p */, f)) < 0)
        return ret;

    if (WOLFSENTRY_CHECK_BITS(r->flags, WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD))
        fprintf(f, ", AF = *");
    else {
#ifdef WOLFSENTRY_PROTOCOL_NAMES
        const char *family_name = wolfsentry_family_ntop(r->sa_family);
        if (family_name)
            fprintf(f, ", AF = %s", family_name);
        else
#endif
            fprintf(f, ", AF = %d", r->sa_family);
    }

    wolfsentry_route_render_proto(r->sa_proto, r->flags, f);

    if (WOLFSENTRY_CHECK_BITS(r->flags, WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD))
        fprintf(f, ", ev = *");
    else if (r->parent_event_label_len > 0)
        fprintf(f, ", ev = \"%.*s\"", (int)r->parent_event_label_len, r->parent_event_label);

    fputc('\n',f);

    WOLFSENTRY_RETURN_OK;
}

#endif /* !WOLFSENTRY_NO_STDIO */
