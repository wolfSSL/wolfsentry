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
        *inexact_matches = WOLFSENTRY_ROUTE_FLAG_NONE;

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

static int wolfsentry_route_key_cmp(struct wolfsentry_route *left, struct wolfsentry_route *right) {
    return wolfsentry_route_key_cmp_1(left, right, 0 /* match_wildcards_p */, NULL /* inexact_matches */);
}

static void wolfsentry_route_update_flags_1(
    struct wolfsentry_route *route,
    wolfsentry_route_flags_t flags_to_set,
    wolfsentry_route_flags_t flags_to_clear,
    wolfsentry_route_flags_t *flags_before,
    wolfsentry_route_flags_t *flags_after);

static void wolfsentry_route_free_1(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_eventconfig_internal *config,
    struct wolfsentry_route *route)
{
    if (config->config.route_private_data_alignment == 0)
        WOLFSENTRY_FREE(route);
    else
        WOLFSENTRY_FREE_ALIGNED(route);
}

static wolfsentry_errcode_t wolfsentry_route_drop_reference_1(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results)
{
    struct wolfsentry_eventconfig_internal *config = (route->parent_event && route->parent_event->config) ? route->parent_event->config : &wolfsentry->config;
    if (route->header.refcount <= 0)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if ((route->header.parent_table != NULL) &&
        (route->header.parent_table->ent_type != WOLFSENTRY_OBJECT_TYPE_ROUTE))
        WOLFSENTRY_ERROR_RETURN(WRONG_OBJECT);
    if (WOLFSENTRY_REFCOUNT_DECREMENT(route->header.refcount) > 0)
        WOLFSENTRY_RETURN_OK;
    if (route->parent_event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, route->parent_event, NULL /* action_results */));
    wolfsentry_route_free_1(wolfsentry, config, route);
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
    size_t data_addr_size,
    struct wolfsentry_route *new)
{
    if (data_addr_size < WOLFSENTRY_BITS_TO_BYTES(remote->addr_len) + WOLFSENTRY_BITS_TO_BYTES(local->addr_len))
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    if (data_addr_size > MAX_UINT_OF(uint16_t))
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
                *remote_lsb = (byte)(*remote_lsb & (0xffu << left_over_bits));
        }
    }
    {
        int left_over_bits = local->addr_len % BITS_PER_BYTE;
        if (left_over_bits) {
            byte *local_lsb = WOLFSENTRY_ROUTE_LOCAL_ADDR(new) + WOLFSENTRY_BITS_TO_BYTES(local->addr_len) - 1;
            if (*local_lsb & (0xffu >> (BITS_PER_BYTE - left_over_bits)))
                *local_lsb = (byte)(*local_lsb & (0xffu << left_over_bits));
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
    struct wolfsentry_route **new)
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
    ret = wolfsentry_route_init(parent_event, remote, local, flags, (int)config->config.route_private_data_size, new_size - offsetof(struct wolfsentry_route, data), *new);
    if (ret < 0) {
        wolfsentry_route_free_1(wolfsentry, config, *new);
        *new = NULL;
    } else {
        if (parent_event != NULL) {
            WOLFSENTRY_REFCOUNT_INCREMENT(parent_event->header.refcount);
        }
    }

    return ret;
}

wolfsentry_errcode_t wolfsentry_route_table_fallthrough_route_alloc(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *route_table)
{
    static const struct wolfsentry_sockaddr fallthrough_sockaddr = { 0 };
    wolfsentry_errcode_t ret;

    if (route_table->fallthrough_route != NULL)
        WOLFSENTRY_ERROR_RETURN(ALREADY);
    if ((ret = wolfsentry_route_new(
             wolfsentry,
             NULL /* parent_event */,
             &fallthrough_sockaddr,
             &fallthrough_sockaddr,
             (WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD |
              WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD |
              WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD |
              WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD |
              WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
              WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD |
              WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD |
              WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD |
              WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD |
              WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
              WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT),
             &route_table->fallthrough_route)) < 0)
        return ret;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_table_fallthrough_route_get(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *route_table,
    const struct wolfsentry_route **fallthrough_route)
{
    (void)wolfsentry;
    if (route_table->fallthrough_route == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    else {
        *fallthrough_route = route_table->fallthrough_route;
        WOLFSENTRY_RETURN_OK;
    }
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
    wolfsentry_errcode_t ret;

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
        (*new_route)->parent_event = src_route->parent_event;
        if ((ret = wolfsentry_table_ent_get(&dest_context->events->header, (struct wolfsentry_table_ent_header **)&(*new_route)->parent_event)) < 0) {
            wolfsentry_route_free_1(dest_context, config, *new_route);
            return ret;
        }
        WOLFSENTRY_REFCOUNT_INCREMENT((*new_route)->parent_event->header.refcount);
    }

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_insert_1(
    struct wolfsentry_context *wolfsentry,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_route *target_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *route_to_insert,
    struct wolfsentry_event *trigger_event,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;

    /* make sure fields marked as wildcards are set to zero. */
    if (((route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD) && (route_to_insert->remote.interface != 0)) ||
        ((route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD) && (route_to_insert->local.interface != 0)) ||
        ((route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD) && (route_to_insert->sa_family != 0)) ||
        ((route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD) && (route_to_insert->remote.addr_len != 0)) ||
        ((route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD) && (route_to_insert->local.addr_len != 0)) ||
        ((route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD) && (route_to_insert->sa_proto != 0)) ||
        ((route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD) && (route_to_insert->remote.sa_port != 0)) ||
        ((route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD) && (route_to_insert->local.sa_port != 0)))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    /* make sure wildcards are sensical. */
    if (((route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD) &&
         ((! (route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD)) ||
          (! (route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD)) ||
          (! (route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD)))) ||
        ((route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD) &&
         ((! (route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD)) ||
          (! (route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD)))))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (WOLFSENTRY_CHECK_BITS(route_to_insert->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE))
        WOLFSENTRY_ERROR_RETURN(ITEM_ALREADY_PRESENT);

    if (route_to_insert->parent_event && WOLFSENTRY_CHECK_BITS(route_to_insert->parent_event->flags, WOLFSENTRY_EVENT_FLAG_IS_SUBEVENT))
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);

    if ((ret = WOLFSENTRY_GET_TIME(&route_to_insert->meta.insert_time)) < 0)
        return ret;
    if ((ret = wolfsentry_id_allocate(wolfsentry, &route_to_insert->header)) < 0)
        return ret;
    WOLFSENTRY_SET_BITS(route_to_insert->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE);
    if ((ret = wolfsentry_table_ent_insert(wolfsentry, &route_to_insert->header, &route_table->header, 1 /* unique_p */)) < 0) {
        WOLFSENTRY_CLEAR_BITS(route_to_insert->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE);
        wolfsentry_table_ent_delete_by_id_1(wolfsentry, &route_to_insert->header);
        route_to_insert->header.id = WOLFSENTRY_ENT_ID_NONE;
        return ret;
    }

    if (route_to_insert->parent_event && route_to_insert->parent_event->insert_event) {
        ret = wolfsentry_action_list_dispatch(
            wolfsentry,
            caller_arg,
            route_to_insert->parent_event->insert_event,
            trigger_event,
            WOLFSENTRY_ACTION_TYPE_INSERT,
            target_route,
            route_table,
            route_to_insert,
            action_results);
        if (ret < 0) {
            wolfsentry_route_flags_t flags_before, flags_after;
            (void)wolfsentry_table_ent_delete_1(wolfsentry, &route_to_insert->header);
            wolfsentry_route_update_flags_1(route_to_insert, WOLFSENTRY_ROUTE_FLAG_NONE, WOLFSENTRY_ROUTE_FLAG_IN_TABLE, &flags_before, &flags_after);
        }
        return ret;
    } else {
        if (route_to_insert->parent_event) {
            if (! WOLFSENTRY_CHECK_BITS(route_to_insert->parent_event->flags, WOLFSENTRY_EVENT_FLAG_IS_PARENT_EVENT))
                WOLFSENTRY_SET_BITS(route_to_insert->parent_event->flags, WOLFSENTRY_EVENT_FLAG_IS_PARENT_EVENT);
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

    if ((ret = wolfsentry_route_insert_1(wolfsentry, caller_arg, NULL /* target_route */, route_table, new, parent_event, action_results)) < 0)
        goto out;

    if (id)
        *id = new->header.id;

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    if (ret < 0)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(wolfsentry, new, NULL /* action_results */));

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
    ret = wolfsentry_route_insert_2(wolfsentry, caller_arg, wolfsentry->routes_static, remote, local, flags, event, id, action_results);
    if (event != NULL)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, event, NULL /* action_results */));
    return ret;
}

static wolfsentry_errcode_t wolfsentry_route_lookup_0(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_route *target_route,
    int exact_p,
    wolfsentry_route_flags_t *inexact_matches,
    struct wolfsentry_route **found_route)
{
    struct wolfsentry_cursor cursor;
    int cursor_position;
    struct wolfsentry_route *i;
    wolfsentry_priority_t highest_priority_seen = 0;
    struct wolfsentry_route *highest_priority_match_seen = NULL;
    wolfsentry_route_flags_t highest_priority_inexact_matches = 0;
    wolfsentry_errcode_t ret;

    *found_route = NULL;

    if ((ret = wolfsentry_table_cursor_init(wolfsentry, &cursor)) < 0)
        goto out;

    if ((ret = wolfsentry_table_cursor_seek(&table->header, &target_route->header, &cursor, &cursor_position)) < 0)
        goto out;

    if (inexact_matches)
        *inexact_matches = WOLFSENTRY_ROUTE_FLAG_NONE;

    if (! exact_p)
        WOLFSENTRY_SET_BITS(target_route->flags, WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD);

    /* return exact match immediately. */
    if ((cursor_position == 0) && (exact_p || (! WOLFSENTRY_CHECK_BITS(((struct wolfsentry_route *)cursor.point)->flags, WOLFSENTRY_ROUTE_FLAG_PENDING_DELETE)))) {
        *found_route = (struct wolfsentry_route *)cursor.point;
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
        cursor_position = wolfsentry_route_key_cmp_1(i, target_route, 1 /* match_wildcards_p */, inexact_matches);
        if (cursor_position == 0) {
            if (i->parent_event == NULL) {
                *found_route = i;
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
        *found_route = highest_priority_match_seen;
        if (inexact_matches)
            *inexact_matches = highest_priority_inexact_matches;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
    } else {
        ret = WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);
    }

  out:

    if (ret >= 0) {
        if (! (target_route->flags & WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_HITS))
            WOLFSENTRY_ATOMIC_INCREMENT((*found_route)->header.hitcount, 1);
    }

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
    struct wolfsentry_route **found_route)
{
    struct {
        struct wolfsentry_route route;
        byte buf[WOLFSENTRY_MAX_ADDR_BYTES * 2];
    } target;
    wolfsentry_errcode_t ret;

    if ((ret = wolfsentry_route_init(parent_event, remote, local, flags, 0 /* data_addr_offset */, sizeof target.buf, &target.route)) < 0)
        return ret;

    return wolfsentry_route_lookup_0(wolfsentry, table, &target.route, exact_p, inexact_matches, found_route);
}

wolfsentry_errcode_t wolfsentry_route_get_table_static(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table **table)
{
    *table = wolfsentry->routes_static;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_get_table_dynamic(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table **table)
{
    *table = wolfsentry->routes_dynamic;
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
    if (event != NULL)
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
            NULL /* target_route */,
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
        wolfsentry_errcode_t lookup_ret = wolfsentry_route_lookup_1(wolfsentry, wolfsentry->routes_static, remote, local, flags, event, 1 /* exact_p */, NULL /* inexact matches */, &route);
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
    ret = wolfsentry_route_delete_1(wolfsentry, wolfsentry->routes_static, caller_arg, remote, local, flags, event, action_results, n_deleted);
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
    ret = wolfsentry_route_delete_1(wolfsentry, wolfsentry->routes_dynamic, caller_arg, remote, local, flags, event, action_results, n_deleted);
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
    ret = wolfsentry_route_delete_1(wolfsentry, wolfsentry->routes_static, caller_arg, remote, local, flags, event, action_results, n_deleted);
    if ((ret >= 0) || WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND))
        ret = wolfsentry_route_delete_1(wolfsentry, wolfsentry->routes_dynamic, caller_arg, remote, local, flags, event, action_results, n_deleted);
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
    const struct wolfsentry_route *target_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results
    )
{
    struct wolfsentry_event *parent_event = rule_route->parent_event ? rule_route->parent_event : route_table->default_event;
    struct wolfsentry_eventconfig_internal *config = (parent_event && parent_event->config) ? parent_event->config : &wolfsentry->config;
    wolfsentry_errcode_t ret;
    WOLFSENTRY_WARN_ON_FAILURE(WOLFSENTRY_GET_TIME(&rule_route->meta.last_hit_time));

    if (trigger_event) {
        /* for dynamic blocking, e.g. of a port scanner, one of the plugins in
         * trigger_event->action_list must call wolfsentry_route_set_wildcard(),
         * in addition to setting _ACTION_RES_INSERT.
         */
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_dispatch(
                                       wolfsentry,
                                       caller_arg,
                                       trigger_event,
                                       trigger_event,
                                       WOLFSENTRY_ACTION_TYPE_POST,
                                       target_route,
                                       route_table,
                                       rule_route,
                                       action_results));
        if (action_results)
            WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP);
    }

    if ((route_table == wolfsentry->routes_dynamic) &&
        (*action_results & WOLFSENTRY_ACTION_RES_INSERT) &&
        (! WOLFSENTRY_CHECK_BITS(rule_route->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE)))
    {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_insert_1(wolfsentry, caller_arg, target_route, route_table, rule_route, trigger_event, action_results));
    } else {
        /* tell the caller that no new entry was needed. */
        if (action_results)
            WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_INSERT);
    }

    /* if the rule_route still isn't in the table at this point, then switch to the fallthrough rule. */
    if ((! WOLFSENTRY_CHECK_BITS(rule_route->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE)) && (route_table->fallthrough_route != NULL)) {
        rule_route = route_table->fallthrough_route;
        if (rule_route) {
            if (action_results)
                *action_results |= WOLFSENTRY_ACTION_RES_FALLTHROUGH;
            if (! (rule_route->flags & WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_HITS))
                WOLFSENTRY_ATOMIC_INCREMENT(rule_route->header.hitcount, 1);
        }
        parent_event = route_table->default_event;
    }

    if (parent_event && parent_event->match_event && parent_event->match_event->action_list.header.head) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_dispatch(
                                       wolfsentry,
                                       caller_arg,
                                       parent_event->match_event,
                                       trigger_event,
                                       WOLFSENTRY_ACTION_TYPE_MATCH,
                                       target_route,
                                       route_table,
                                       rule_route,
                                       action_results));
        if (action_results)
            WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP);
    }

    if (! (rule_route->flags & WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_CURRENT_CONNECTIONS)) {
        if (*action_results & WOLFSENTRY_ACTION_RES_CONNECT) {
            if (rule_route->meta.connection_count >= config->config.max_connection_count) {
                *action_results |= WOLFSENTRY_ACTION_RES_REJECT;
                ret = WOLFSENTRY_ERROR_ENCODE(OK);
                goto done;
            }
            if (WOLFSENTRY_ATOMIC_INCREMENT_BY_ONE(rule_route->meta.connection_count) > config->config.max_connection_count) {
                WOLFSENTRY_ATOMIC_DECREMENT_BY_ONE(rule_route->meta.connection_count);
                *action_results |= WOLFSENTRY_ACTION_RES_REJECT;
                ret = WOLFSENTRY_ERROR_ENCODE(OK);
                goto done;
            }
        } else if (*action_results & WOLFSENTRY_ACTION_RES_DISCONNECT)
            WOLFSENTRY_ATOMIC_DECREMENT_BY_ONE(rule_route->meta.connection_count);
    }
    if (*action_results & WOLFSENTRY_ACTION_RES_DEROGATORY)
        WOLFSENTRY_ATOMIC_INCREMENT_BY_ONE(rule_route->meta.derogatory_count);
    if (*action_results & WOLFSENTRY_ACTION_RES_COMMENDABLE)
        WOLFSENTRY_ATOMIC_INCREMENT_BY_ONE(rule_route->meta.commendable_count);

    if ((rule_route->flags & WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED)) {
        if ((config->config.penaltybox_duration > 0) && (rule_route->meta.last_penaltybox_time != 0)) {
            wolfsentry_time_t now;
            ret = WOLFSENTRY_GET_TIME(&now);
            if (ret < 0) {
                *action_results |= WOLFSENTRY_ACTION_RES_ERROR;
                goto done;
            }
            if (WOLFSENTRY_DIFF_TIME(now, rule_route->meta.last_penaltybox_time) > config->config.penaltybox_duration) {
                wolfsentry_route_flags_t flags_before, flags_after;
                WOLFSENTRY_WARN_ON_FAILURE(
                    wolfsentry_route_update_flags(
                        wolfsentry,
                        rule_route,
                        WOLFSENTRY_ROUTE_FLAG_NONE,
                        WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED,
                        &flags_before,
                        &flags_after));
            } else
                *action_results |= WOLFSENTRY_ACTION_RES_REJECT;
        } else
            *action_results |= WOLFSENTRY_ACTION_RES_REJECT;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        goto done;
    } else if ((rule_route->flags & WOLFSENTRY_ROUTE_FLAG_GREENLISTED)) {
        *action_results |= WOLFSENTRY_ACTION_RES_ACCEPT;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        goto done;
    }

    if (! WOLFSENTRY_MASKIN_BITS(*action_results, WOLFSENTRY_ACTION_RES_ACCEPT|WOLFSENTRY_ACTION_RES_REJECT))
        *action_results |= wolfsentry->routes_static->default_policy;
    if (! WOLFSENTRY_MASKIN_BITS(*action_results, WOLFSENTRY_ACTION_RES_ACCEPT|WOLFSENTRY_ACTION_RES_REJECT))
        *action_results |= wolfsentry->routes_dynamic->default_policy;

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  done:

    if (parent_event && parent_event->decision_event && parent_event->decision_event->action_list.header.head) {
        if (action_results)
            WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP);
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_dispatch(
                                       wolfsentry,
                                       caller_arg,
                                       parent_event->decision_event,
                                       trigger_event,
                                       WOLFSENTRY_ACTION_TYPE_DECISION,
                                       target_route,
                                       route_table,
                                       rule_route,
                                       action_results));
    }

    return ret;
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
    struct wolfsentry_route *target_route = NULL;
    struct wolfsentry_route *rule_route = NULL;
    struct wolfsentry_event *trigger_event = NULL;
    wolfsentry_errcode_t ret;

    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(wolfsentry, event_label, event_label_len, &trigger_event)) < 0)
            return ret;
    }

    if (id)
        *id = WOLFSENTRY_ENT_ID_NONE;

    if ((ret = wolfsentry_route_new(wolfsentry, trigger_event, remote, local, flags, &target_route)) < 0)
        goto just_free_resources;

    /* simple static route match. */
    if ((ret = wolfsentry_route_lookup_0(wolfsentry, wolfsentry->routes_static, target_route, 0 /* exact_p */, inexact_matches, &rule_route)) >= 0) {
        route_table = wolfsentry->routes_static;
    }

    /* if dynamic is disabled, use default static policy. */
    else if (WOLFSENTRY_CHECK_BITS(wolfsentry->routes_static->default_policy, WOLFSENTRY_ACTION_RES_STOP)) {
        route_table = wolfsentry->routes_static;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
    }

    /* dynamic route match. */
    else if ((ret = wolfsentry_route_lookup_0(wolfsentry, wolfsentry->routes_dynamic, target_route, 0 /* exact_p */, inexact_matches, &rule_route)) >= 0) {
        route_table = wolfsentry->routes_dynamic;
    }

    /* dynamic route insertion (or not -- plugins (if any) will decide). */
    else if (trigger_event || wolfsentry->routes_dynamic->default_event) {
        route_table = wolfsentry->routes_dynamic;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
    }

    /* nothing to do. */
    else {
        /* carry through ret from final wolfsentry_route_lookup_1(). */
        goto just_free_resources;
    }

    if (rule_route == NULL) {
        if ((ret = wolfsentry_route_clone(wolfsentry, &target_route->header, wolfsentry, (struct wolfsentry_table_ent_header **)&rule_route, WOLFSENTRY_CLONE_FLAG_NONE)) < 0)
            goto just_free_resources;
        if ((rule_route->parent_event == NULL) && (route_table->default_event != NULL)) {
            rule_route->parent_event = route_table->default_event;
            WOLFSENTRY_REFCOUNT_INCREMENT(rule_route->parent_event->header.refcount);
        }
    }

    ret = wolfsentry_route_event_dispatch_0(wolfsentry, trigger_event, caller_arg, target_route, route_table, rule_route, action_results);

    if (id && WOLFSENTRY_CHECK_BITS(rule_route->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE))
        *id = rule_route->header.id;

  just_free_resources:

    if ((rule_route != NULL) && (! WOLFSENTRY_CHECK_BITS(rule_route->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE)))
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(wolfsentry, rule_route, NULL /* action_results */));

    if (target_route != NULL)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(wolfsentry, target_route, NULL /* action_results */));

    if (trigger_event != NULL)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, trigger_event, NULL /* action_results */));

    if (route_table == NULL) {
        /* set bits in inexact_matches to communicate that matching fell through to a default policy. */
        if (inexact_matches)
            *inexact_matches = WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD | WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD;
        *action_results = wolfsentry->routes_static->default_policy;
        /* inform caller that no entry was found or added. */
        WOLFSENTRY_SET_BITS(*action_results, WOLFSENTRY_ACTION_RES_INSERT|WOLFSENTRY_ACTION_RES_DELETE);
        if (WOLFSENTRY_CHECK_BITS(wolfsentry->routes_static->default_policy, WOLFSENTRY_ACTION_RES_STOP)) {
            WOLFSENTRY_RETURN_OK;
        }
        *action_results |= wolfsentry->routes_dynamic->default_policy;
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

    ret = wolfsentry_route_event_dispatch_0(wolfsentry, trigger_event, caller_arg, NULL /* target_route */, (struct wolfsentry_route_table *)route->header.parent_table, route, action_results);

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
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *action_results)
{
    return wolfsentry_table_map(
        wolfsentry,
        &table->header,
        (wolfsentry_map_function_t)wolfsentry_route_delete_for_filter,
        wolfsentry,
        action_results);
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
    struct wolfsentry_context *wolfsentry,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    ret = wolfsentry_table_map(
        wolfsentry,
        &wolfsentry->routes_dynamic->header,
        (wolfsentry_map_function_t)wolfsentry_route_clear_insert_action_status,
        wolfsentry, action_results);
    if (ret < 0)
        return ret;
    return wolfsentry_table_map(
        wolfsentry,
        &wolfsentry->routes_dynamic->header,
        (wolfsentry_map_function_t)wolfsentry_route_clear_insert_action_status,
        wolfsentry, action_results);
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
            NULL /* target_route */,
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
    struct wolfsentry_context *wolfsentry,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    ret = wolfsentry_table_map(
        wolfsentry,
        &wolfsentry->routes_dynamic->header,
        (wolfsentry_map_function_t)wolfsentry_route_call_insert_action,
        wolfsentry, action_results);
    if (ret < 0)
        return ret;
    return wolfsentry_table_map(
        wolfsentry,
        &wolfsentry->routes_dynamic->header,
        (wolfsentry_map_function_t)wolfsentry_route_call_insert_action,
        wolfsentry, action_results);
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

    if ((flags_to_set | flags_to_clear) & (WOLFSENTRY_ROUTE_FLAG_PENDING_DELETE | WOLFSENTRY_ROUTE_FLAG_IN_TABLE))
        WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);

    if ((route->flags & WOLFSENTRY_ROUTE_FLAG_IN_TABLE) && ((flags_to_set | flags_to_clear) & WOLFSENTRY_ROUTE_IMMUTABLE_FLAGS))
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
    const struct wolfsentry_route *route,
    struct wolfsentry_route_metadata_exports *metadata)
{
    metadata->insert_time = route->meta.insert_time;
    metadata->last_hit_time = route->meta.last_hit_time;
    metadata->last_penaltybox_time = route->meta.last_penaltybox_time;
    metadata->connection_count = route->meta.connection_count;
    metadata->derogatory_count = route->meta.derogatory_count;
    metadata->commendable_count = route->meta.commendable_count;
    metadata->hit_count = route->header.hitcount;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_table_clear_default_event(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *table)
{
    wolfsentry_errcode_t ret;
    if (table->default_event != NULL) {
        if ((ret = wolfsentry_event_drop_reference(wolfsentry, table->default_event, NULL /* action_results */)) < 0)
            return ret;
        table->default_event = NULL;
    }
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_table_set_default_event(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *table,
    const char *event_label,
    int event_label_len)
{
    struct wolfsentry_event *event = NULL;
    wolfsentry_errcode_t ret;
    if ((ret = wolfsentry_event_get_reference(wolfsentry, event_label, event_label_len, &event)) < 0)
        return ret;
    if ((ret = wolfsentry_route_table_clear_default_event(wolfsentry, table)) < 0) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, event, NULL /* action_results */));
        return ret;
    }
    table->default_event = event;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_table_get_default_event(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table *table,
    char *event_label,
    int *event_label_len)
{
    (void)wolfsentry;
    if (table->default_event == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    if (table->default_event->label_len >= *event_label_len)
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    memcpy(event_label, table->default_event->label, (size_t)(table->default_event->label_len + 1));
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_export(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route *route,
    struct wolfsentry_route_exports *route_exports)
{
    wolfsentry_errcode_t ret;
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
    if ((ret = wolfsentry_route_get_metadata(route, &route_exports->meta)) < 0)
        return ret;
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
    if ((ret = wolfsentry_table_cursor_seek_to_head(&table->header, *cursor)) < 0)
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
    return wolfsentry_table_cursor_seek_to_head(&table->header, cursor);
}

wolfsentry_errcode_t wolfsentry_route_table_iterate_seek_to_tail(
    const struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor)
{
    (void)wolfsentry;
    return wolfsentry_table_cursor_seek_to_tail(&table->header, cursor);
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

wolfsentry_errcode_t wolfsentry_route_format_address(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_addr_family_t sa_family,
    const byte *addr,
    unsigned int addr_bits,
    char *buf,
    int *buflen)
{
    wolfsentry_addr_family_formatter_t formatter;
    const char *buf_at_start = buf;

    if (WOLFSENTRY_ERROR_CODE_IS(
            wolfsentry_addr_family_get_formatter(
                wolfsentry,
                (wolfsentry_addr_family_t)sa_family,
                &formatter),
            OK))
    {
        wolfsentry_errcode_t ret = formatter(wolfsentry, addr, addr_bits, buf, buflen);
        if (ret < 0)
            return ret;
        WOLFSENTRY_RETURN_OK;
    }

    if (sa_family == WOLFSENTRY_AF_LINK) {
        unsigned int i;
        if ((addr_bits >> 3) * 3 > (size_t)*buflen)
            WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
        for (i=0; i < (addr_bits >> 3); ++i) {
            if (i > 0)
                *buf++ = ':';
            buf += sprintf(buf, "%02x", (unsigned int)addr[i]);
        }
        *buf = 0;
        *buflen = (int)(buf - buf_at_start);
        WOLFSENTRY_RETURN_OK;
    } else if (sa_family == WOLFSENTRY_AF_INET) {
        byte addr_buf[sizeof(struct in_addr)];
        memset(addr_buf, 0, sizeof addr_buf);
        memcpy(addr_buf, addr, WOLFSENTRY_BITS_TO_BYTES(addr_bits));
        if (inet_ntop(AF_INET, addr, buf, (socklen_t)*buflen) == NULL)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FAILED);
        *buflen = (int)strlen(buf);
        WOLFSENTRY_RETURN_OK;
    } else if (sa_family == WOLFSENTRY_AF_INET6) {
        byte addr_buf[sizeof(struct in6_addr)];
        memset(addr_buf, 0, sizeof addr_buf);
        memcpy(addr_buf, addr, WOLFSENTRY_BITS_TO_BYTES(addr_bits));
        if (inet_ntop(AF_INET6, addr, buf, (socklen_t)*buflen) == NULL)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FAILED);
        *buflen = (int)strlen(buf);
        WOLFSENTRY_RETURN_OK;
    } else if (sa_family == WOLFSENTRY_AF_LOCAL) {
        if (WOLFSENTRY_BITS_TO_BYTES(addr_bits) >= (size_t)*buflen)
            WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
        memcpy(buf, addr, WOLFSENTRY_BITS_TO_BYTES(addr_bits));
        buf[WOLFSENTRY_BITS_TO_BYTES(addr_bits)] = 0;
        *buflen = (int)WOLFSENTRY_BITS_TO_BYTES(addr_bits);
        WOLFSENTRY_RETURN_OK;
    } else
        WOLFSENTRY_ERROR_RETURN(OP_NOT_SUPP_FOR_PROTO);
}

static wolfsentry_errcode_t wolfsentry_route_render_address(struct wolfsentry_context *wolfsentry, int sa_family, unsigned int addr_bits, const byte *addr, size_t addr_bytes, FILE *f) {
    char fmt_buf[256], addr_buf[WOLFSENTRY_MAX_ADDR_BYTES];
    wolfsentry_addr_family_formatter_t formatter;

    if (WOLFSENTRY_ERROR_CODE_IS(
            wolfsentry_addr_family_get_formatter(
                wolfsentry,
                (wolfsentry_addr_family_t)sa_family,
                &formatter),
            OK))
    {
        int fmt_buf_len = (int)sizeof fmt_buf;
        wolfsentry_errcode_t ret = formatter(wolfsentry, addr, addr_bits, fmt_buf, &fmt_buf_len);
        if (ret < 0)
            return ret;
        if (fwrite(fmt_buf, 1, (size_t)fmt_buf_len, f) != (size_t)fmt_buf_len)
            WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
        WOLFSENTRY_RETURN_OK;
    }

    if (addr_bytes > sizeof addr_buf)
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);

    if (sa_family == WOLFSENTRY_AF_LINK) {
        unsigned int i;
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

static wolfsentry_errcode_t wolfsentry_route_render_endpoint(struct wolfsentry_context *wolfsentry, const struct wolfsentry_route *r, int sa_local_p, FILE *f) {
    const struct wolfsentry_route_endpoint *e = (sa_local_p ? &r->local : &r->remote);
    size_t addr_bytes = (size_t)(sa_local_p ? WOLFSENTRY_ROUTE_LOCAL_ADDR_BYTES(r) : WOLFSENTRY_ROUTE_REMOTE_ADDR_BYTES(r));
    const void *addr = (sa_local_p ? WOLFSENTRY_ROUTE_LOCAL_ADDR(r) : WOLFSENTRY_ROUTE_REMOTE_ADDR(r));

    if (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD))
        fputs("*", stdout);
    else {
        wolfsentry_errcode_t ret = wolfsentry_route_render_address(wolfsentry, r->sa_family, e->addr_len, addr, addr_bytes, f);
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

wolfsentry_errcode_t wolfsentry_route_render(struct wolfsentry_context *wolfsentry, const struct wolfsentry_route *r, FILE *f) {
    wolfsentry_errcode_t ret = wolfsentry_route_render_endpoint(wolfsentry, r, 0 /* sa_local_p */, f);

    (void)wolfsentry;

    if (ret < 0)
        return ret;

    fprintf(f, " %s-%s ",
            (r->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT) ? "<" : "",
            (r->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN) ? ">" : "");

    if ((ret = wolfsentry_route_render_endpoint(wolfsentry, r, 1 /* sa_local_p */, f)) < 0)
        return ret;

    if (WOLFSENTRY_CHECK_BITS(r->flags, WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD))
        fprintf(f, ", ev = *");
    else if (r->parent_event != NULL)
        fprintf(f, ", ev = \"%.*s\"", (int)r->parent_event->label_len, r->parent_event->label);

    if (WOLFSENTRY_CHECK_BITS(r->flags, WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD))
        fprintf(f, ", AF = *");
    else {
#ifdef WOLFSENTRY_PROTOCOL_NAMES
        struct wolfsentry_addr_family_bynumber *addr_family;
        const char *family_name = wolfsentry_addr_family_ntop(wolfsentry, r->sa_family, &addr_family, &ret);
        if (family_name && WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
            fprintf(f, ", AF = %s", family_name);
            if (addr_family) {
                if ((ret = wolfsentry_addr_family_drop_reference(wolfsentry, addr_family, NULL /* action_results */ )) < 0)
                    return ret;
            }
        } else
#endif
            fprintf(f, ", AF = %d", r->sa_family);
    }

    wolfsentry_route_render_proto(r->sa_proto, r->flags, f);

    fputc('\n',f);

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_exports_render_endpoint(struct wolfsentry_context *wolfsentry, const struct wolfsentry_route_exports *r, int sa_local_p, FILE *f) {
    const struct wolfsentry_route_endpoint *e = (sa_local_p ? &r->local : &r->remote);
    size_t addr_bytes = (size_t)(sa_local_p ? WOLFSENTRY_ROUTE_LOCAL_ADDR_BYTES(r) : WOLFSENTRY_ROUTE_REMOTE_ADDR_BYTES(r));
    const byte *addr = (sa_local_p ? r->local_address : r->remote_address);

    if (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD))
        fputs("*", stdout);
    else {
        wolfsentry_errcode_t ret = wolfsentry_route_render_address(wolfsentry, r->sa_family, e->addr_len, addr, addr_bytes, f);
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

wolfsentry_errcode_t wolfsentry_route_exports_render(struct wolfsentry_context *wolfsentry, const struct wolfsentry_route_exports *r, FILE *f) {
    wolfsentry_errcode_t ret = wolfsentry_route_exports_render_endpoint(wolfsentry, r, 0 /* sa_local_p */, f);

    (void)wolfsentry;

    if (ret < 0)
        return ret;

    fprintf(f, " %s-%s ",
            (r->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT) ? "<" : "",
            (r->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN) ? ">" : "");

    if ((ret = wolfsentry_route_exports_render_endpoint(wolfsentry, r, 1 /* sa_local_p */, f)) < 0)
        return ret;

    if (WOLFSENTRY_CHECK_BITS(r->flags, WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD))
        fprintf(f, ", AF = *");
    else {
#ifdef WOLFSENTRY_PROTOCOL_NAMES
        struct wolfsentry_addr_family_bynumber *addr_family;
        const char *family_name = wolfsentry_addr_family_ntop(wolfsentry, r->sa_family, &addr_family, &ret);
        if (family_name && WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
            fprintf(f, ", AF = %s", family_name);
            if (addr_family) {
                if ((ret = wolfsentry_addr_family_drop_reference(wolfsentry, addr_family, NULL /* action_results */ )) < 0)
                    return ret;
            }
        } else
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

wolfsentry_errcode_t wolfsentry_route_table_init(
    struct wolfsentry_route_table *route_table)
{
    WOLFSENTRY_TABLE_HEADER_RESET(route_table->header);
    route_table->header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_route_key_cmp;
    route_table->header.free_fn = (wolfsentry_ent_free_fn_t)wolfsentry_route_drop_reference;
    route_table->header.ent_type = WOLFSENTRY_OBJECT_TYPE_ROUTE;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_route_table_clone_header(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags)
{
    wolfsentry_errcode_t ret;

    (void)wolfsentry;
    (void)flags;

    if (src_table->ent_type != WOLFSENTRY_OBJECT_TYPE_ROUTE)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (((struct wolfsentry_route_table *)src_table)->default_event != NULL) {
        struct wolfsentry_event *default_event;
        if (((struct wolfsentry_route_table *)dest_table)->default_event != NULL) {
            WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(dest_context, ((struct wolfsentry_route_table *)dest_table)->default_event, NULL /* action_results */));
            ((struct wolfsentry_route_table *)dest_table)->default_event = NULL;
        }
        if ((ret = wolfsentry_event_get_reference(dest_context, ((struct wolfsentry_route_table *)src_table)->default_event->label, ((struct wolfsentry_route_table *)src_table)->default_event->label_len, &default_event)) < 0)
            return ret;
        ((struct wolfsentry_route_table *)dest_table)->default_event = default_event;
    }

    if (((struct wolfsentry_route_table *)src_table)->fallthrough_route != NULL) {
        struct wolfsentry_event *fallthrough_route;
        if (((struct wolfsentry_route_table *)dest_table)->fallthrough_route != NULL) {
            WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(dest_context, ((struct wolfsentry_route_table *)dest_table)->fallthrough_route, NULL /* action_results */));
            ((struct wolfsentry_route_table *)dest_table)->fallthrough_route = NULL;
        }
        if ((ret = wolfsentry_table_ent_get_by_id(dest_context, ((struct wolfsentry_route_table *)src_table)->fallthrough_route->header.id, (struct wolfsentry_table_ent_header **)&fallthrough_route)) < 0)
            return ret;
        WOLFSENTRY_REFCOUNT_INCREMENT(fallthrough_route->header.refcount);
    }

    WOLFSENTRY_RETURN_OK;
}

void wolfsentry_route_table_free(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route_table **route_table)
{
    if ((*route_table)->fallthrough_route != NULL) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(wolfsentry, (*route_table)->fallthrough_route, NULL /* action_results */));
        (*route_table)->fallthrough_route = NULL;
    }
    if ((*route_table)->default_event != NULL) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(wolfsentry, (*route_table)->default_event, NULL /* action_results */));
        (*route_table)->default_event = NULL;
    }

    WOLFSENTRY_FREE(*route_table);
    *route_table = NULL;
}
