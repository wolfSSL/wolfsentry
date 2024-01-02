/*
 * routes.c
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

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_ROUTES_C

#include "wolfsentry_internal.h"

#ifndef WOLFSENTRY_NO_ALLOCA
#include <alloca.h>
#endif

#ifdef WOLFSENTRY_LWIP
#include <lwip/inet.h>
#include <lwip/sockets.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif
#ifndef WOLFSENTRY_NO_GETPROTOBY
#include <netdb.h>
#endif

static inline int cmp_addrs_prefixful(
    const byte *left_addr,
    int left_addr_len,
    const byte *right_addr,
    int right_addr_len,
    int wildcard_p,
    int match_subnets_p,
    int *inexact_p)
{
    int cmp;
    int min_addr_len = (left_addr_len < right_addr_len) ? left_addr_len : right_addr_len;

    *inexact_p = 0;

    /* zero-length (full wildcard) address always precedes nonzero-length address. */
    if (min_addr_len == 0) {
        if (left_addr_len == right_addr_len)
            return 0;
        else if (wildcard_p || match_subnets_p) {
            *inexact_p = 1;
            return 0;
        } else if (left_addr_len != 0)
            return 1;
        else /* right_addr_len != 0 */
            return -1;
    }

    if (left_addr_len != right_addr_len) {
        if (wildcard_p)
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

static inline int addr_prefix_match_size(
    const byte *a,
    int a_len,
    const byte *b,
    int b_len)
{
    int min_len = (a_len < b_len) ? a_len : b_len;
    int min_len_whole_bytes = min_len >> 3;
    int ret;

    if (min_len == 0)
        return 0;

    for (ret = 0; ret < min_len_whole_bytes; ++ret) {
        if (a[ret] != b[ret])
            break;
    }

    ret <<= 3;

    for (; ret < min_len; ++ret) {
        int byte_number = ret / 8;
        int bit_number = ret % 8;
        if ((a[byte_number] & (1U << bit_number)) != (b[byte_number] & (1U << bit_number)))
            break;
    }

    return ret;
}

#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING

static inline int is_bitmask_matching(wolfsentry_addr_family_t af, const struct wolfsentry_route_table *routes) {
    wolfsentry_addr_family_t i = 0;
    for (; i<routes->n_bitmask_matching_afs; ++i) {
        if (routes->bitmask_matching_afs[i].af == af)
            return 1;
    }
    return 0;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_bitmask_matching_upref(wolfsentry_addr_family_t af, struct wolfsentry_route_table *routes) {
    wolfsentry_addr_family_t i;
    for (i=0; i<routes->n_bitmask_matching_afs; ++i) {
        if (routes->bitmask_matching_afs[i].af == af) {
            if (routes->bitmask_matching_afs[i].refcount == MAX_UINT_OF(routes->bitmask_matching_afs[i].refcount))
                WOLFSENTRY_ERROR_RETURN(OVERFLOW_AVERTED);
            else
                ++routes->bitmask_matching_afs[i].refcount;
            WOLFSENTRY_RETURN_OK;
        }
    }
    if (routes->n_bitmask_matching_afs >= length_of_array(routes->bitmask_matching_afs))
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    routes->bitmask_matching_afs[routes->n_bitmask_matching_afs].af = af;
    routes->bitmask_matching_afs[routes->n_bitmask_matching_afs].refcount = 1;
    ++routes->n_bitmask_matching_afs;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_bitmask_matching_downref(wolfsentry_addr_family_t af, struct wolfsentry_route_table *routes) {
    wolfsentry_addr_family_t i = 0;
    for (; i<routes->n_bitmask_matching_afs; ++i) {
        if (routes->bitmask_matching_afs[i].af == af) {
            if (--routes->bitmask_matching_afs[i].refcount == 0) {
                --routes->n_bitmask_matching_afs;
                if (i < routes->n_bitmask_matching_afs)
                    routes->bitmask_matching_afs[i] = routes->bitmask_matching_afs[routes->n_bitmask_matching_afs];
                WOLFSENTRY_RETURN_OK;
            }
            WOLFSENTRY_RETURN_OK;
        }
    }
    WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
}

static inline int cmp_addrs_bitmaskful(
    const byte *left_addr,
    unsigned int left_addr_len,
    const byte *right_addr,
    unsigned int right_addr_len,
    int wildcard_p,
    int match_masked_p,
    int *inexact_p)
{
    int cmp;
    unsigned int min_addr_len;

    min_addr_len = (left_addr_len < right_addr_len) ? left_addr_len : right_addr_len;

    *inexact_p = 0;

    /* if match_masked_p, only one address can be bitmaskful, and it needs to be
     * at least twice the size of the non-maskful address.
     */
    if (match_masked_p) {
        if ((left_addr_len >> 1 < right_addr_len) &&
            (right_addr_len >> 1 < left_addr_len))
        {
            if (wildcard_p) {
                *inexact_p = 1;
                return 0;
            } else
                WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        }
    }

    /* zero-length (full wildcard) address always precedes nonzero-length address. */
    if (min_addr_len == 0) {
        if (left_addr_len == right_addr_len)
            return 0;
        else if (wildcard_p || match_masked_p) {
            *inexact_p = 1;
            return 0;
        } else if (left_addr_len != 0)
            return 1;
        else /* right_addr_len != 0 */
            return -1;
    }

    if (left_addr_len == right_addr_len) {
        /* same logic as prefixful -- lexically ordered purely for internal bookkeeping purposes. */
        if ((cmp = memcmp(left_addr, right_addr, WOLFSENTRY_BITS_TO_BYTES((size_t)left_addr_len)))) {
            if (wildcard_p)
                *inexact_p = 1;
            else
                return cmp;
        }
    } else {
        if (wildcard_p) {
            *inexact_p = 1;
        } else if (match_masked_p) {
            const byte *mask, *maskful_addr, *target_addr;
            unsigned int mask_len, i, padding_offset;

            if (left_addr_len < right_addr_len) {
                maskful_addr = right_addr;
                mask_len = right_addr_len >> 1;
                target_addr = left_addr;
                padding_offset = mask_len - left_addr_len;
            } else {
                maskful_addr = left_addr;
                mask_len = left_addr_len >> 1;
                target_addr = right_addr;
                padding_offset = mask_len - right_addr_len;
            }

            mask_len = WOLFSENTRY_BITS_TO_BYTES(mask_len);
            mask = maskful_addr + mask_len;

            for (i = 0; i < mask_len; ++i) {
                unsigned int x;
                if (i < padding_offset) {
                    if (maskful_addr[i] != 0)
                        return maskful_addr[i];
                    continue;
                }
                x = target_addr[i - padding_offset] & mask[i];
                if (x == maskful_addr[i]) {
                    if (target_addr[i - padding_offset] != maskful_addr[i])
                        *inexact_p = 1;
                    continue;
                }
                return (int)maskful_addr[i] - (int)x;
            }
        } else {
            /* same logic as prefixful -- lexically ordered purely for internal bookkeeping purposes. */
            if ((cmp = memcmp(left_addr, right_addr, WOLFSENTRY_BITS_TO_BYTES((size_t)min_addr_len))))
                return cmp;
            else if (left_addr_len < right_addr_len)
                return -1;
            else
                return 1;
        }
    }

    return 0;
}

static inline int addr_bitmask_match_size(
    const byte *a,
    unsigned int a_len,
    const byte *b,
    unsigned int b_len)
{
    const byte *longer_addr, *shorter_addr;
    unsigned int mask_len, i, padding_offset;
    int ret = 0;

    if (a_len < b_len) {
        longer_addr = b;
        mask_len = WOLFSENTRY_BITS_TO_BYTES(b_len >> 1);
        shorter_addr = a;
        padding_offset = mask_len - a_len;
    } else {
        longer_addr = a;
        mask_len = WOLFSENTRY_BITS_TO_BYTES(a_len >> 1);
        shorter_addr = b;
        padding_offset = mask_len - b_len;
    }

    for (ret = 0, i = 0; i < mask_len; ++i) {
        if (i < padding_offset)
            ret += popcount32(~(uint32_t)(longer_addr[i])) - 24;
        else
            ret += popcount32(~(uint32_t)(longer_addr[i] ^ shorter_addr[i - padding_offset])) - 24;
    }

    return ret;
}

#endif /* WOLFSENTRY_ADDR_BITMASK_MATCHING */

static int wolfsentry_route_key_cmp_1(
    const struct wolfsentry_route *left,
    const struct wolfsentry_route *right,
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
            WOLFSENTRY_RETURN_VALUE(-1);
        else
            WOLFSENTRY_RETURN_VALUE(1);
    }

#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    if (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK) {
        cmp = cmp_addrs_bitmaskful(WOLFSENTRY_ROUTE_REMOTE_ADDR(left), left->remote.addr_len,
                                   WOLFSENTRY_ROUTE_REMOTE_ADDR(right), right->remote.addr_len,
                                   match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD),
                                   match_wildcards_p,
                                   &inexact_p);
        if (cmp < -1)
            return cmp;
    } else
#endif
    {
        cmp = cmp_addrs_prefixful(WOLFSENTRY_ROUTE_REMOTE_ADDR(left), left->remote.addr_len,
                                  WOLFSENTRY_ROUTE_REMOTE_ADDR(right), right->remote.addr_len,
                                  match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD),
                                  match_wildcards_p,
                                  &inexact_p);
    }

    if (cmp)
        WOLFSENTRY_RETURN_VALUE(cmp);
    if (inexact_p && inexact_matches)
        *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD;

    if (left->sa_proto != right->sa_proto) {
        if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD;
        } else if (left->sa_proto < right->sa_proto)
            WOLFSENTRY_RETURN_VALUE(-1);
        else
            WOLFSENTRY_RETURN_VALUE(1);
    }

    if (left->local.sa_port != right->local.sa_port) {
        if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD;
        } else if (left->local.sa_port < right->local.sa_port)
            WOLFSENTRY_RETURN_VALUE(-1);
        else
            WOLFSENTRY_RETURN_VALUE(1);
    }

#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    if (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK) {
        cmp = cmp_addrs_bitmaskful(WOLFSENTRY_ROUTE_LOCAL_ADDR(left), left->local.addr_len,
                                   WOLFSENTRY_ROUTE_LOCAL_ADDR(right), right->local.addr_len,
                                   match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD),
                                   match_wildcards_p,
                                   &inexact_p);
        if (cmp < -1)
            return cmp;
    } else
#endif
    {
        cmp = cmp_addrs_prefixful(WOLFSENTRY_ROUTE_LOCAL_ADDR(left), left->local.addr_len,
                                  WOLFSENTRY_ROUTE_LOCAL_ADDR(right), right->local.addr_len,
                                  match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD),
                                  match_wildcards_p,
                                  &inexact_p);
    }

    if (cmp)
        WOLFSENTRY_RETURN_VALUE(cmp);
    if (inexact_p && inexact_matches)
        *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD;

    if (left->remote.sa_port != right->remote.sa_port) {
        if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        } else if (left->remote.sa_port < right->remote.sa_port)
            WOLFSENTRY_RETURN_VALUE(-1);
        else
            WOLFSENTRY_RETURN_VALUE(1);
    }

    if (left->remote.interface != right->remote.interface) {
        if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD;
        } else if (left->remote.interface < right->remote.interface)
            WOLFSENTRY_RETURN_VALUE(-1);
        else
            WOLFSENTRY_RETURN_VALUE(1);
    }

    if (left->local.interface != right->local.interface) {
        if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD;
        } else if (left->local.interface < right->local.interface)
            WOLFSENTRY_RETURN_VALUE(-1);
        else
            WOLFSENTRY_RETURN_VALUE(1);
    }

    /* when match_wildcards_p, caller is responsible for comparing/interpreting
     * flags.
     */
    if (! match_wildcards_p) {
        wolfsentry_route_flags_t masked_left_flags = left->flags & WOLFSENTRY_ROUTE_IMMUTABLE_FLAGS;
        wolfsentry_route_flags_t masked_right_flags = right->flags & WOLFSENTRY_ROUTE_IMMUTABLE_FLAGS;
        if (masked_left_flags != masked_right_flags) {
            if (masked_left_flags < masked_right_flags)
                WOLFSENTRY_RETURN_VALUE(-1);
            else
                WOLFSENTRY_RETURN_VALUE(1);
        }
    }

    {
        /* treat null parent_event as maximum priority, for unsurprising results on simple routes. */
        int left_effective_priority = left->parent_event ? left->parent_event->priority : 0;
        int right_effective_priority = right->parent_event ? right->parent_event->priority : 0;
        if (left_effective_priority != right_effective_priority) {
            if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD)) {
                if (inexact_matches)
                    *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
            } else if (left_effective_priority < right_effective_priority)
                WOLFSENTRY_RETURN_VALUE(-1);
            else
                WOLFSENTRY_RETURN_VALUE(1);
        }
    }

    /* do a final check on the exact event, so that routes with different parent
     * events with same priority are nonetheless distinguishable.
     */
    if (left->parent_event == right->parent_event)
        WOLFSENTRY_RETURN_VALUE(0);
    else if (inexact_matches && (*inexact_matches & WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD))
        WOLFSENTRY_RETURN_VALUE(0); /* previous test already determined they're different. */
    else if ((left->parent_event == NULL) || (right->parent_event == NULL)) {
        if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD)) {
            if (inexact_matches)
                *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
        } else if (left->parent_event == NULL)
            WOLFSENTRY_RETURN_VALUE(-1);
        else
            WOLFSENTRY_RETURN_VALUE(1);
    } else {
        cmp = wolfsentry_event_key_cmp(left->parent_event, right->parent_event);
        if (cmp) {
            if (match_wildcards_p && (wildcard_flags & WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD)) {
                if (inexact_matches)
                    *inexact_matches |= WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
            } else
                WOLFSENTRY_RETURN_VALUE(cmp);
        }
    }

    WOLFSENTRY_RETURN_VALUE(0);
}

static int compare_match_exactness(const struct wolfsentry_route *target, const struct wolfsentry_route *left, wolfsentry_route_flags_t left_inexact_matches, const struct wolfsentry_route *right, wolfsentry_route_flags_t right_inexact_matches) {
    int left_match_score = popcount32(WOLFSENTRY_ROUTE_WILDCARD_FLAGS) - popcount32(left_inexact_matches & WOLFSENTRY_ROUTE_WILDCARD_FLAGS);
    int right_match_score = popcount32(WOLFSENTRY_ROUTE_WILDCARD_FLAGS) - popcount32(right_inexact_matches & WOLFSENTRY_ROUTE_WILDCARD_FLAGS);
    if (left_match_score == right_match_score) {
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
        if (left->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK) {
            left_match_score = addr_bitmask_match_size(WOLFSENTRY_ROUTE_REMOTE_ADDR(target), WOLFSENTRY_ROUTE_REMOTE_ADDR_BITS(target), WOLFSENTRY_ROUTE_REMOTE_ADDR(left), WOLFSENTRY_ROUTE_REMOTE_ADDR_BITS(left));
        } else
#endif
        {
            left_match_score = addr_prefix_match_size(WOLFSENTRY_ROUTE_REMOTE_ADDR(target), WOLFSENTRY_ROUTE_REMOTE_ADDR_BITS(target), WOLFSENTRY_ROUTE_REMOTE_ADDR(left), WOLFSENTRY_ROUTE_REMOTE_ADDR_BITS(left));
        }
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
        if (right->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK) {
            right_match_score = addr_bitmask_match_size(WOLFSENTRY_ROUTE_REMOTE_ADDR(target), WOLFSENTRY_ROUTE_REMOTE_ADDR_BITS(target), WOLFSENTRY_ROUTE_REMOTE_ADDR(right), WOLFSENTRY_ROUTE_REMOTE_ADDR_BITS(right));
        } else
#endif
        {
            right_match_score = addr_prefix_match_size(WOLFSENTRY_ROUTE_LOCAL_ADDR(target), WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(target), WOLFSENTRY_ROUTE_LOCAL_ADDR(right), WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(right));
        }
    }

    if (left_match_score == right_match_score) {
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
        if (left->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK) {
            left_match_score = addr_bitmask_match_size(WOLFSENTRY_ROUTE_LOCAL_ADDR(target), WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(target), WOLFSENTRY_ROUTE_LOCAL_ADDR(left), WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(left));
        } else
#endif
        {
            left_match_score = addr_prefix_match_size(WOLFSENTRY_ROUTE_LOCAL_ADDR(target), WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(target), WOLFSENTRY_ROUTE_LOCAL_ADDR(left), WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(left));
        }
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
        if (right->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK) {
            right_match_score = addr_bitmask_match_size(WOLFSENTRY_ROUTE_LOCAL_ADDR(target), WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(target), WOLFSENTRY_ROUTE_LOCAL_ADDR(right), WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(right));
        } else
#endif
        {
            right_match_score = addr_prefix_match_size(WOLFSENTRY_ROUTE_LOCAL_ADDR(target), WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(target), WOLFSENTRY_ROUTE_LOCAL_ADDR(right), WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(right));
        }
    }

    if (left_match_score > right_match_score)
        return -1;
    else if (left_match_score < right_match_score)
        return 1;
    else
        return 0;
}

static void clamp_wildcard_fields_to_zero(struct wolfsentry_route *route) {
    if ((route->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD) && (route->remote.addr_len != 0))
        memset(WOLFSENTRY_ROUTE_REMOTE_ADDR(route), 0, WOLFSENTRY_ROUTE_REMOTE_ADDR_BYTES(route));
    if ((route->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD) && (route->local.addr_len != 0))
        memset(WOLFSENTRY_ROUTE_LOCAL_ADDR(route), 0, WOLFSENTRY_ROUTE_LOCAL_ADDR_BYTES(route));
    if (route->flags & WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD)
        route->sa_family = 0;
    if (route->flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD)
        route->sa_proto = 0;
    if (route->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD)
        route->remote.sa_port = 0;
    if (route->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD)
        route->remote.interface = 0;
    if (route->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD)
        route->local.sa_port = 0;
    if (route->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD)
        route->local.interface = 0;
}

static int wolfsentry_route_key_cmp(const struct wolfsentry_table_ent_header *left, const struct wolfsentry_table_ent_header *right) {
    return wolfsentry_route_key_cmp_1((struct wolfsentry_route *)left, (struct wolfsentry_route *)right, 0 /* match_wildcards_p */, NULL /* inexact_matches */);
}

static void wolfsentry_route_update_flags_1(
    struct wolfsentry_route *route,
    wolfsentry_route_flags_t flags_to_set,
    wolfsentry_route_flags_t flags_to_clear,
    wolfsentry_route_flags_t *flags_before,
    wolfsentry_route_flags_t *flags_after);

static void wolfsentry_route_free_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_eventconfig_internal *config,
    struct wolfsentry_route *route)
{
    if (config->config.route_private_data_alignment == 0)
        WOLFSENTRY_FREE(route);
    else
        WOLFSENTRY_FREE_ALIGNED(route);
    WOLFSENTRY_RETURN_VOID;
}

static wolfsentry_errcode_t wolfsentry_route_drop_reference_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results)
{
    struct wolfsentry_eventconfig_internal *config = (route->parent_event && route->parent_event->config) ? route->parent_event->config : &wolfsentry->config;
    wolfsentry_errcode_t ret;
    wolfsentry_refcount_t refs_left;
    if (route->header.refcount == 0)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if ((route->header.parent_table != NULL) &&
        (route->header.parent_table->ent_type != WOLFSENTRY_OBJECT_TYPE_ROUTE))
        WOLFSENTRY_ERROR_RETURN(WRONG_OBJECT);
    WOLFSENTRY_REFCOUNT_DECREMENT(route->header.refcount, refs_left, ret);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    if (refs_left > 0)
        WOLFSENTRY_RETURN_OK;
    if (route->parent_event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, route->parent_event, NULL /* action_results */));
    wolfsentry_route_free_1(WOLFSENTRY_CONTEXT_ARGS_OUT, config, route);
    if (action_results)
        WOLFSENTRY_SET_BITS(*action_results, WOLFSENTRY_ACTION_RES_DEALLOCATED);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_drop_reference(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results)
{
    if (action_results)
        WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_drop_reference_1(WOLFSENTRY_CONTEXT_ARGS_OUT, route, action_results));
}

static wolfsentry_errcode_t wolfsentry_route_drop_reference_generic(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_ent_header *route,
    wolfsentry_action_res_t *action_results)
{
    if (action_results)
        WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_drop_reference_1(WOLFSENTRY_CONTEXT_ARGS_OUT, (struct wolfsentry_route *)route, action_results));
}

static wolfsentry_errcode_t wolfsentry_route_init(
    struct wolfsentry_event *parent_event,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    int data_addr_offset,
    size_t new_size,
    struct wolfsentry_route *new)
{
    if (WOLFSENTRY_BITS_TO_BYTES(remote->addr_len) + WOLFSENTRY_BITS_TO_BYTES(local->addr_len) > MAX_UINT_OF(uint16_t))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    if ((unsigned)data_addr_offset > MAX_UINT_OF(uint16_t))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    if (new_size < offsetof(struct wolfsentry_route, data) + (size_t)data_addr_offset + WOLFSENTRY_BITS_TO_BYTES(remote->addr_len) + WOLFSENTRY_BITS_TO_BYTES(local->addr_len))
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    if (! (flags & (WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN | WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT)))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    /* bitmask-matched addresses must be byte-aligned, and since there is
     * both an address and a mask, that means the bottom 4 bits of each
     * address package must be zero.
     */
    if ((flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK) &&
        (remote->addr_len & 0xf))
    {
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }
    if ((flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK) &&
        (local->addr_len & 0xf))
    {
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }
#endif

    /* make sure wildcards are sensical. */
    if (((flags & WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD) &&
         ((! (flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD)) ||
          (! (flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD)) ||
          (! (flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD)))) ||
        ((flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD) &&
         ((! (flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD)) ||
          (! (flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD)))))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

#ifdef WOLFSENTRY_ROUTE_INIT_TEST_FOR_UNINITED_DATA
    /* don't initialize bytes in the allocation past the end of the address data. */
    if (new_size > offsetof(struct wolfsentry_route, data) + (size_t)data_addr_offset + WOLFSENTRY_BITS_TO_BYTES(remote->addr_len) + WOLFSENTRY_BITS_TO_BYTES(local->addr_len))
        new_size = offsetof(struct wolfsentry_route, data) + (size_t)data_addr_offset + WOLFSENTRY_BITS_TO_BYTES(remote->addr_len) + WOLFSENTRY_BITS_TO_BYTES(local->addr_len);
    for (int testbyte = 1, uninited_offset = 0;; ++testbyte) {
        byte *p;
        memset(new, testbyte, new_size);
    #if 0
    }
    #endif
#endif

    WOLFSENTRY_TABLE_ENT_HEADER_RESET(new->header);
    new->header.id = WOLFSENTRY_ENT_ID_NONE;
    new->header.hitcount = 0;
    WOLFSENTRY_LIST_ENT_HEADER_RESET(new->purge_links);
    new->parent_event = parent_event;
    new->flags = flags;
    new->sa_family = remote->sa_family;
    new->sa_proto = remote->sa_proto;
    new->remote.sa_port = remote->sa_port;
    new->remote.addr_len = remote->addr_len;
    new->remote.extra_port_count = 0;
    new->remote.interface = remote->interface;
    new->local.sa_port = local->sa_port;
    new->local.addr_len = local->addr_len;
    new->local.extra_port_count = 0;
    new->local.interface = local->interface;
    new->data_addr_offset = (uint16_t)data_addr_offset;
    new->data_addr_size = (uint16_t)(WOLFSENTRY_BITS_TO_BYTES(remote->addr_len) + WOLFSENTRY_BITS_TO_BYTES(local->addr_len));
    new->meta.insert_time = new->meta.last_hit_time = new->meta.last_penaltybox_time = new->meta.purge_after = 0;
    new->meta.connection_count = new->meta.derogatory_count = new->meta.commendable_count = 0;
    new->meta._pad1 = 0;

    if (data_addr_offset > 0)
        memset(new->data, 0, (size_t)data_addr_offset); /* zero private data. */

    if (remote->addr_len > 0)
        memcpy(WOLFSENTRY_ROUTE_REMOTE_ADDR(new), remote->addr, WOLFSENTRY_BITS_TO_BYTES(remote->addr_len));
    if (local->addr_len > 0)
        memcpy(WOLFSENTRY_ROUTE_LOCAL_ADDR(new), local->addr, WOLFSENTRY_BITS_TO_BYTES(local->addr_len));

    /* make sure the pad/ignored bits in the addresses are zero. */
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    if (flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK) {
        size_t i, addr_size = WOLFSENTRY_BITS_TO_BYTES(remote->addr_len) >> 1;
        for (i=0; i < addr_size; ++i)
            WOLFSENTRY_ROUTE_REMOTE_ADDR(new)[i] &= WOLFSENTRY_ROUTE_REMOTE_ADDR(new)[i + addr_size];
    }
    else
#endif
    {
        int left_over_bits = remote->addr_len % BITS_PER_BYTE;
        if (left_over_bits) {
            byte *remote_lsb = WOLFSENTRY_ROUTE_REMOTE_ADDR(new) + WOLFSENTRY_BITS_TO_BYTES(remote->addr_len) - 1;
            if (*remote_lsb & (0xffU >> (BITS_PER_BYTE - left_over_bits)))
                *remote_lsb = (byte)(*remote_lsb & (0xffU << left_over_bits));
        }
    }
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    if (flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK) {
        size_t i, addr_size = WOLFSENTRY_BITS_TO_BYTES(local->addr_len) >> 1;
        for (i=0; i < addr_size; ++i)
            WOLFSENTRY_ROUTE_LOCAL_ADDR(new)[i] &= WOLFSENTRY_ROUTE_LOCAL_ADDR(new)[i + addr_size];
    }
    else
#endif
    {
        int left_over_bits = local->addr_len % BITS_PER_BYTE;
        if (left_over_bits) {
            byte *local_lsb = WOLFSENTRY_ROUTE_LOCAL_ADDR(new) + WOLFSENTRY_BITS_TO_BYTES(local->addr_len) - 1;
            if (*local_lsb & (0xffU >> (BITS_PER_BYTE - left_over_bits)))
                *local_lsb = (byte)(*local_lsb & (0xffU << left_over_bits));
        }
    }

#ifdef WOLFSENTRY_ROUTE_INIT_TEST_FOR_UNINITED_DATA
    #if 0
    {
    #endif
        for (p = (byte *)new; p < (byte *)new + new_size; ++p) {
            if (*p == testbyte)
                break;
        }
        if (p < (byte *)new + new_size) {
            /* report the uninited byte that occurs latest, to ignore false positives. */
            if (uninited_offset < (int)(p - (byte *)new))
                uninited_offset = (int)(p - (byte *)new);
            if (testbyte == 255) {
                fprintf(stderr, "%s: uninitialized data found in struct wolfsentry_route %p at offset %d.\n", __FUNCTION__, (void *)new, uninited_offset);
                WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
            } else
                continue;
        }
        break;
    }
#endif

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_init_by_exports(
    struct wolfsentry_event *parent_event,
    const struct wolfsentry_route_exports *route_exports,
    size_t data_addr_offset,
    size_t new_size,
    struct wolfsentry_route *new)
{
    if (WOLFSENTRY_BITS_TO_BYTES(route_exports->remote.addr_len) + WOLFSENTRY_BITS_TO_BYTES(route_exports->local.addr_len) > MAX_UINT_OF(uint16_t))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    if (route_exports->private_data_size > data_addr_offset)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if ((unsigned)data_addr_offset > MAX_UINT_OF(uint16_t))
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    if (new_size < offsetof(struct wolfsentry_route, data) + (size_t)data_addr_offset + WOLFSENTRY_BITS_TO_BYTES(route_exports->remote.addr_len) + WOLFSENTRY_BITS_TO_BYTES(route_exports->local.addr_len))
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    if (! (route_exports->flags & (WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN | WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT)))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    /* bitmask-matched addresses must be byte-aligned, and since there is
     * both an address and a mask, that means the bottom 4 bits of each
     * address package must be zero.
     */
    if ((route_exports->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK) &&
        (route_exports->remote.addr_len & 0xf))
    {
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }
    if ((route_exports->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK) &&
        (route_exports->local.addr_len & 0xf))
    {
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }
#endif

    /* make sure wildcards are sensical. */
    if (((route_exports->flags & WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD) &&
         ((! (route_exports->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD)) ||
          (! (route_exports->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD)) ||
          (! (route_exports->flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD)))) ||
        ((route_exports->flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD) &&
         ((! (route_exports->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD)) ||
          (! (route_exports->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD)))))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

#ifdef WOLFSENTRY_ROUTE_INIT_TEST_FOR_UNINITED_DATA
    /* don't initialize bytes in the allocation past the end of the address data. */
    if (new_size > offsetof(struct wolfsentry_route, data) + (size_t)data_addr_offset + WOLFSENTRY_BITS_TO_BYTES(route_exports->remote.addr_len) + WOLFSENTRY_BITS_TO_BYTES(route_exports->local.addr_len))
        new_size = offsetof(struct wolfsentry_route, data) + (size_t)data_addr_offset + WOLFSENTRY_BITS_TO_BYTES(route_exports->remote.addr_len) + WOLFSENTRY_BITS_TO_BYTES(route_exports->local.addr_len);
    for (int testbyte = 1, uninited_offset = 0;; ++testbyte) {
        byte *p;
        memset(new, testbyte, new_size);
    #if 0
    }
    #endif
#endif

    WOLFSENTRY_TABLE_ENT_HEADER_RESET(new->header);
    new->header.id = WOLFSENTRY_ENT_ID_NONE;
    new->header.hitcount = 0;
    WOLFSENTRY_LIST_ENT_HEADER_RESET(new->purge_links);
    new->parent_event = parent_event;
    new->flags = route_exports->flags & ~WOLFSENTRY_ROUTE_INTERNAL_FLAGS;
    new->sa_family = route_exports->sa_family;
    new->sa_proto = route_exports->sa_proto;
    new->remote.sa_port = route_exports->remote.sa_port;
    new->remote.addr_len = route_exports->remote.addr_len;
    new->remote.extra_port_count = 0;
    new->remote.interface = route_exports->remote.interface;
    new->local.sa_port = route_exports->local.sa_port;
    new->local.addr_len = route_exports->local.addr_len;
    new->local.extra_port_count = 0;
    new->local.interface = route_exports->local.interface;
    new->data_addr_offset = (uint16_t)data_addr_offset;
    new->data_addr_size = (uint16_t)(WOLFSENTRY_BITS_TO_BYTES(route_exports->remote.addr_len) + WOLFSENTRY_BITS_TO_BYTES(route_exports->local.addr_len));
    new->meta.insert_time = new->meta.last_hit_time = new->meta.last_penaltybox_time = 0;
    new->meta._pad1 = 0;

    if (data_addr_offset > 0) {
        if (route_exports->private_data != NULL) {
            memcpy(new->data, route_exports->private_data, route_exports->private_data_size); /* copy private data. */
            if ((size_t)data_addr_offset > route_exports->private_data_size)
                memset((byte *)new->data + route_exports->private_data_size, 0, data_addr_offset - route_exports->private_data_size); /* zero the leftovers. */
        } else
            memset(new->data, 0, (size_t)data_addr_offset); /* zero private data. */
    }

    new->meta.purge_after = route_exports->meta.purge_after;
    new->meta.connection_count = route_exports->meta.connection_count;
    new->meta.derogatory_count = route_exports->meta.derogatory_count;
    new->meta.commendable_count = route_exports->meta.commendable_count;

    if (route_exports->remote.addr_len > 0) {
        memcpy(WOLFSENTRY_ROUTE_REMOTE_ADDR(new),
               route_exports->remote_address,
               WOLFSENTRY_BITS_TO_BYTES(route_exports->remote.addr_len));
    }
    if (route_exports->local.addr_len > 0) {
        memcpy(WOLFSENTRY_ROUTE_LOCAL_ADDR(new),
               route_exports->local_address,
               WOLFSENTRY_BITS_TO_BYTES(route_exports->local.addr_len));
    }

    /* make sure the pad/ignored bits in the addresses are zero. */
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    if (route_exports->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK) {
        size_t i, addr_size = WOLFSENTRY_BITS_TO_BYTES(route_exports->remote.addr_len) >> 1;
        for (i=0; i < addr_size; ++i)
            WOLFSENTRY_ROUTE_REMOTE_ADDR(new)[i] &= WOLFSENTRY_ROUTE_REMOTE_ADDR(new)[i + addr_size];
    }
    else
#endif
    {
        int left_over_bits = route_exports->remote.addr_len % BITS_PER_BYTE;
        if (left_over_bits) {
            byte *remote_lsb = WOLFSENTRY_ROUTE_REMOTE_ADDR(new) + WOLFSENTRY_BITS_TO_BYTES(route_exports->remote.addr_len) - 1;
            if (*remote_lsb & (0xffU >> (BITS_PER_BYTE - left_over_bits)))
                *remote_lsb = (byte)(*remote_lsb & (0xffU << left_over_bits));
        }
    }

#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    if (route_exports->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK) {
        size_t i, addr_size = WOLFSENTRY_BITS_TO_BYTES(route_exports->local.addr_len) >> 1;
        for (i=0; i < addr_size; ++i)
            WOLFSENTRY_ROUTE_LOCAL_ADDR(new)[i] &= WOLFSENTRY_ROUTE_LOCAL_ADDR(new)[i + addr_size];
    }
    else
#endif
    {
        int left_over_bits = route_exports->local.addr_len % BITS_PER_BYTE;
        if (left_over_bits) {
            byte *local_lsb = WOLFSENTRY_ROUTE_LOCAL_ADDR(new) + WOLFSENTRY_BITS_TO_BYTES(route_exports->local.addr_len) - 1;
            if (*local_lsb & (0xffU >> (BITS_PER_BYTE - left_over_bits)))
                *local_lsb = (byte)(*local_lsb & (0xffU << left_over_bits));
        }
    }

#ifdef WOLFSENTRY_ROUTE_INIT_TEST_FOR_UNINITED_DATA
    #if 0
    {
    #endif
        for (p = (byte *)new; p < (byte *)new + new_size; ++p) {
            if (*p == testbyte)
                break;
        }
        if (p < (byte *)new + new_size) {
            /* report the uninited byte that occurs latest, to ignore false positives. */
            if (uninited_offset < (int)(p - (byte *)new))
                uninited_offset = (int)(p - (byte *)new);
            if (testbyte == 255) {
                fprintf(stderr, "%s: uninitialized data found in struct wolfsentry_route %p at offset %d.\n", __FUNCTION__, (void *)new, uninited_offset);
                WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
            } else
                continue;
        }
        break;
    }
#endif

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_new(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_event *parent_event,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    struct wolfsentry_route **new)
{
    size_t new_size;
    wolfsentry_errcode_t ret;
    struct wolfsentry_eventconfig_internal *config = (parent_event && parent_event->config) ? parent_event->config : &wolfsentry->config;

    if (flags & (WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK | WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK)) {
#ifndef WOLFSENTRY_ADDR_BITMASK_MATCHING
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
#else
        /* bitmask-matched addresses must be byte-aligned, and since there is
         * both an address and a mask of equal length, that means the bottom 4
         * bits of each address package must be zero.
         */
        if (flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK) {
            if (remote->addr_len & 0xf)
                WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        }
        if (flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK) {
            if (local->addr_len & 0xf)
                WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        }
#endif
    }

    new_size = WOLFSENTRY_BITS_TO_BYTES(remote->addr_len) + WOLFSENTRY_BITS_TO_BYTES(local->addr_len);
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
    ret = wolfsentry_route_init(parent_event, remote, local, flags, (int)config->config.route_private_data_size, new_size, *new);
    if (ret < 0) {
        wolfsentry_route_free_1(WOLFSENTRY_CONTEXT_ARGS_OUT, config, *new);
        *new = NULL;
    } else {
        if (parent_event != NULL) {
            WOLFSENTRY_REFCOUNT_INCREMENT(parent_event->header.refcount, ret);
        }
    }

    WOLFSENTRY_ERROR_RERETURN(ret);
}

static wolfsentry_errcode_t wolfsentry_route_new_by_exports(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_event *parent_event,
    const struct wolfsentry_route_exports *route_exports,
    struct wolfsentry_route **new)
{
    size_t new_size;
    wolfsentry_errcode_t ret;
    struct wolfsentry_eventconfig_internal *config = (parent_event && parent_event->config) ? parent_event->config : &wolfsentry->config;

    if ((route_exports->private_data_size != 0) && (route_exports->private_data_size != config->config.route_private_data_size - config->route_private_data_padding))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (route_exports->flags & (WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK | WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK)) {
#ifndef WOLFSENTRY_ADDR_BITMASK_MATCHING
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
#else
        /* bitmask-matched addresses must be byte-aligned, and since there is
         * both an address and a mask of equal length, that means the bottom 4
         * bits of each address package must be zero.
         */
        if (route_exports->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK) {
            if (route_exports->remote.addr_len & 0xf)
                WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        }
        if (route_exports->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK) {
            if (route_exports->local.addr_len & 0xf)
                WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        }
#endif
    }
    new_size = WOLFSENTRY_BITS_TO_BYTES(route_exports->remote.addr_len) + WOLFSENTRY_BITS_TO_BYTES(route_exports->local.addr_len);
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
    ret = wolfsentry_route_init_by_exports(parent_event, route_exports, config->config.route_private_data_size, new_size, *new);
    if (ret < 0) {
        wolfsentry_route_free_1(WOLFSENTRY_CONTEXT_ARGS_OUT, config, *new);
        *new = NULL;
    } else {
        if (parent_event != NULL) {
            WOLFSENTRY_REFCOUNT_INCREMENT(parent_event->header.refcount, ret);
        }
    }

    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_route_table_fallthrough_route_alloc(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table)
{
    static const struct wolfsentry_sockaddr fallthrough_sockaddr = { 0 };
    wolfsentry_errcode_t ret;

    if (route_table->fallthrough_route != NULL)
        WOLFSENTRY_ERROR_RETURN(ALREADY);
    if ((ret = wolfsentry_route_new(
             WOLFSENTRY_CONTEXT_ARGS_OUT,
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
              WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT |
              WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_CURRENT_CONNECTIONS),
             &route_table->fallthrough_route)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_fallthrough_route_get(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
    const struct wolfsentry_route **fallthrough_route)
{
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();

    if (route_table->fallthrough_route == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    else {
        wolfsentry_errcode_t ret;
        *fallthrough_route = route_table->fallthrough_route;
        WOLFSENTRY_REFCOUNT_INCREMENT(route_table->fallthrough_route->header.refcount, ret);
        WOLFSENTRY_ERROR_RERETURN(ret);
    }
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_route_clone(
    struct wolfsentry_context *src_context,
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread,
#endif
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

    if (config->config.route_private_data_alignment == 0)
        *new_route = (struct wolfsentry_route *)WOLFSENTRY_MALLOC_1(dest_context->hpi.allocator, new_size);
    else
        *new_route = (struct wolfsentry_route *)WOLFSENTRY_MEMALIGN_1(dest_context->hpi.allocator, config->config.route_private_data_alignment, new_size);
    if (*new_route == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);

    if (src_route->data_addr_offset == config->config.route_private_data_size)
        memcpy(*new_route, src_route, new_size);
    else {
        /* provide for copying from a src that omits the private data segment (as occurs with wolfsentry_route_event_dispatch_1()). */

        /* first copy the struct itself */
        memcpy(*new_route, src_route, sizeof *src_route);

        /* now update the private data length. */
        (*new_route)->data_addr_offset = (uint16_t)config->config.route_private_data_size;

        /* now zero the private data section. */
        memset((*new_route)->data, 0, config->config.route_private_data_size);

        /* finally, copy the address section, carefully. */
        memcpy((byte *)(*new_route)->data + (*new_route)->data_addr_offset, src_route->data, src_route->data_addr_size);
    }

    WOLFSENTRY_TABLE_ENT_HEADER_RESET(**new_ent);

    if (src_route->parent_event) {
        (*new_route)->parent_event = src_route->parent_event;
        if ((ret = wolfsentry_table_ent_get(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(dest_context), &dest_context->events->header, (struct wolfsentry_table_ent_header **)&(*new_route)->parent_event)) < 0) {
            wolfsentry_route_free_1(dest_context,
#ifdef WOLFSENTRY_THREADSAFE
                                    thread,
#endif
                                    config, *new_route);
            WOLFSENTRY_ERROR_RERETURN(ret);
        }
        WOLFSENTRY_REFCOUNT_INCREMENT((*new_route)->parent_event->header.refcount, ret);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
    }

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_stale_purge_one_unconditionally(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *action_results);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_check_flags_sensical(wolfsentry_route_flags_t flags) {
    if (((flags & WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD) &&
         ((! (flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD)) ||
          (! (flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD)) ||
          (! (flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD)))) ||
        ((flags & WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD) &&
         ((! (flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD)) ||
          (! (flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD)))))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_insert_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_route *target_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *route_to_insert,
    struct wolfsentry_route **route_already_there_ret,
    struct wolfsentry_event *trigger_event,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_eventconfig_internal *config = (route_to_insert->parent_event && route_to_insert->parent_event->config) ? route_to_insert->parent_event->config : &wolfsentry->config;

    if (config->config.route_flags_to_clear_on_insert != 0)
        WOLFSENTRY_CLEAR_BITS(route_to_insert->flags, config->config.route_flags_to_clear_on_insert);

    if (config->config.route_flags_to_add_on_insert != 0)
        WOLFSENTRY_SET_BITS(route_to_insert->flags, config->config.route_flags_to_add_on_insert);

    ret = wolfsentry_route_check_flags_sensical(route_to_insert->flags);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    if (WOLFSENTRY_CHECK_BITS(route_to_insert->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE))
        WOLFSENTRY_ERROR_RETURN(ITEM_ALREADY_PRESENT);

    if ((ret = WOLFSENTRY_GET_TIME(&route_to_insert->meta.insert_time)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    if ((route_to_insert->meta.purge_after != 0) && (route_to_insert->meta.purge_after <= route_to_insert->meta.insert_time))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    /* fields marked as wildcards must be zeroed before insertion to meet
     * assumptions of table lookup logic.
     */
    clamp_wildcard_fields_to_zero(route_to_insert);

    if (*action_results & WOLFSENTRY_ACTION_RES_DEROGATORY)
        ++route_to_insert->meta.derogatory_count;
    if (*action_results & WOLFSENTRY_ACTION_RES_COMMENDABLE)
        ++route_to_insert->meta.commendable_count;
    if ((*action_results & WOLFSENTRY_ACTION_RES_CONNECT) && (! (route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_CURRENT_CONNECTIONS)))
        ++route_to_insert->meta.connection_count;

    if ((config->config.route_idle_time_for_purge > 0) && (route_to_insert->meta.purge_after == 0))
        route_to_insert->meta.purge_after = route_to_insert->meta.insert_time + config->config.route_idle_time_for_purge;

    if (route_to_insert->meta.purge_after) {
        wolfsentry_hitcount_t max_purgeable_routes;

        if ((ret = wolfsentry_route_table_max_purgeable_routes_get(WOLFSENTRY_CONTEXT_ARGS_OUT, route_table, &max_purgeable_routes)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);

        if ((max_purgeable_routes > 0) &&
            (route_table->purge_list.len >= max_purgeable_routes))
        {
            ret = wolfsentry_route_stale_purge_one_unconditionally(WOLFSENTRY_CONTEXT_ARGS_OUT, route_table, NULL /* action_results */);
            WOLFSENTRY_RERETURN_IF_ERROR(ret);
        }
    }

    if ((ret = wolfsentry_id_allocate(WOLFSENTRY_CONTEXT_ARGS_OUT, &route_to_insert->header)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    WOLFSENTRY_SET_BITS(route_to_insert->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE);
    if ((ret = wolfsentry_table_ent_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, &route_to_insert->header, &route_table->header, 1 /* unique_p */)) < 0) {
        if (WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_ALREADY_PRESENT)) {
            struct wolfsentry_route *route_already_there;
            WOLFSENTRY_CLEAR_BITS(route_to_insert->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE);
            route_already_there = route_to_insert;
            ret = wolfsentry_table_ent_get(WOLFSENTRY_CONTEXT_ARGS_OUT, &route_table->header, (struct wolfsentry_table_ent_header **)&route_already_there);
            if (WOLFSENTRY_IS_SUCCESS(ret)) {
                if (route_already_there_ret)
                    *route_already_there_ret = route_already_there;
                if (WOLFSENTRY_ATOMIC_LOAD(route_already_there->flags) & WOLFSENTRY_ROUTE_FLAG_PENDING_DELETE) {
                    wolfsentry_route_flags_t flags_before, flags_after;
                    wolfsentry_route_update_flags_1(route_already_there, WOLFSENTRY_ROUTE_FLAG_NONE, WOLFSENTRY_ROUTE_FLAG_PENDING_DELETE, &flags_before, &flags_after);
                    if (route_already_there->meta.purge_after)
                        wolfsentry_list_ent_delete(&route_table->purge_list, &route_already_there->purge_links);
                    route_already_there->meta.purge_after = route_to_insert->meta.purge_after;
                    if (route_already_there->meta.purge_after)
                        wolfsentry_route_purge_list_insert(route_table, route_already_there);
                    ret = WOLFSENTRY_SUCCESS_ENCODE(ALREADY_OK);
                } else
                    ret = WOLFSENTRY_ERROR_ENCODE(ITEM_ALREADY_PRESENT);
            }
        }

        WOLFSENTRY_ERROR_RERETURN(ret);
    }

#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    if (route_to_insert->flags & (WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK | WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK)) {
        if ((ret = wolfsentry_bitmask_matching_upref(route_to_insert->sa_family, route_table)) < 0) {
            WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_table_ent_delete_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &route_to_insert->header));
            WOLFSENTRY_ERROR_RERETURN(ret);
        }
    }
#endif

    WOLFSENTRY_SET_BITS(*action_results, WOLFSENTRY_ACTION_RES_INSERTED); /* signals to _dispatch_0() that counts were assigned to the newly inserted route. */

    if (route_to_insert->parent_event && (wolfsentry_list_ent_get_len(&route_to_insert->parent_event->insert_action_list.header) > 0)) {
        ret = wolfsentry_action_list_dispatch(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            caller_arg,
            route_to_insert->parent_event,
            trigger_event,
            WOLFSENTRY_ACTION_TYPE_INSERT,
            target_route,
            route_table,
            route_to_insert,
            action_results);
        if (ret < 0) {
            wolfsentry_route_flags_t flags_before, flags_after;
            WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_table_ent_delete_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &route_to_insert->header));
            wolfsentry_route_update_flags_1(route_to_insert, WOLFSENTRY_ROUTE_FLAG_NONE, WOLFSENTRY_ROUTE_FLAG_IN_TABLE, &flags_before, &flags_after);
        }
    } else {
        if (route_to_insert->parent_event) {
            if (! WOLFSENTRY_CHECK_BITS(route_to_insert->parent_event->flags, WOLFSENTRY_EVENT_FLAG_IS_PARENT_EVENT))
                WOLFSENTRY_SET_BITS(route_to_insert->parent_event->flags, WOLFSENTRY_EVENT_FLAG_IS_PARENT_EVENT);
        }
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
    }

    if (route_to_insert->meta.purge_after)
        wolfsentry_route_purge_list_insert(route_table, route_to_insert);

    if (route_to_insert->flags & WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD) {
        if ((route_table->last_af_wildcard_route == NULL) ||
            (wolfsentry_route_key_cmp_1(route_to_insert, route_table->last_af_wildcard_route, 0 /* match_wildcards_p */, NULL /* inexact_matches */) < 0))
        {
            route_table->last_af_wildcard_route = route_to_insert;
        }
    }

    {
        wolfsentry_priority_t effective_priority = route_to_insert->parent_event ? route_to_insert->parent_event->priority : 0;
        if (effective_priority < route_table->highest_priority_route_in_table)
            route_table->highest_priority_route_in_table = effective_priority;
    }

    WOLFSENTRY_ERROR_RERETURN(ret);
}

static wolfsentry_errcode_t wolfsentry_route_insert_2(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    struct wolfsentry_route_table *route_table,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    struct wolfsentry_event *parent_event,
    wolfsentry_ent_id_t *id,
    struct wolfsentry_route **route,
    wolfsentry_action_res_t *action_results)
{
    struct wolfsentry_route *new;
    struct wolfsentry_route *route_already_there = NULL;
    wolfsentry_errcode_t ret;

    if ((remote->sa_family != local->sa_family) ||
        (remote->sa_proto != local->sa_proto))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((ret = wolfsentry_route_new(WOLFSENTRY_CONTEXT_ARGS_OUT, parent_event, remote, local, flags, &new)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    ret = wolfsentry_route_insert_1(WOLFSENTRY_CONTEXT_ARGS_OUT, caller_arg, NULL /* target_route */, route_table, new, &route_already_there, parent_event, action_results);

    if (id) {
        if (route_already_there)
            *id = route_already_there->header.id;
        else if (WOLFSENTRY_IS_SUCCESS(ret))
            *id = new->header.id;
    }

    if (ret < 0)
        goto out;

    if (route) {
        if (route_already_there) {
            if (WOLFSENTRY_IS_SUCCESS(wolfsentry_object_checkout(WOLFSENTRY_CONTEXT_ARGS_OUT, route_already_there)))
                *route = route_already_there;
            else
                *route = NULL;
        } else {
            if (WOLFSENTRY_IS_SUCCESS(wolfsentry_object_checkout(WOLFSENTRY_CONTEXT_ARGS_OUT, new)))
                *route = new;
            else
                *route = NULL;
        }
    }

  out:

    if ((ret < 0) || route_already_there)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(WOLFSENTRY_CONTEXT_ARGS_OUT, new, NULL /* action_results */));

    WOLFSENTRY_ERROR_RERETURN(ret);
}

static wolfsentry_errcode_t wolfsentry_route_insert_by_exports_2(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    struct wolfsentry_route_table *route_table,
    const struct wolfsentry_route_exports *route_exports,
    struct wolfsentry_event *parent_event,
    wolfsentry_ent_id_t *id,
    struct wolfsentry_route **route,
    wolfsentry_action_res_t *action_results)
{
    struct wolfsentry_route *new;
    struct wolfsentry_route *route_already_there = NULL;
    wolfsentry_errcode_t ret;

    if ((ret = wolfsentry_route_new_by_exports(WOLFSENTRY_CONTEXT_ARGS_OUT, parent_event, route_exports, &new)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    ret = wolfsentry_route_insert_1(WOLFSENTRY_CONTEXT_ARGS_OUT, caller_arg, NULL /* target_route */, route_table, new, &route_already_there, parent_event, action_results);

    if (id) {
        if (route_already_there)
            *id = route_already_there->header.id;
        else if (WOLFSENTRY_IS_SUCCESS(ret))
            *id = new->header.id;
    }

    if (ret < 0)
        goto out;

    if (route) {
        if (route_already_there) {
            if (WOLFSENTRY_IS_SUCCESS(wolfsentry_object_checkout(WOLFSENTRY_CONTEXT_ARGS_OUT, route_already_there)))
                *route = route_already_there;
            else
                *route = NULL;
        } else {
            if (WOLFSENTRY_IS_SUCCESS(wolfsentry_object_checkout(WOLFSENTRY_CONTEXT_ARGS_OUT, new)))
                *route = new;
            else
                *route = NULL;
        }
    }

  out:

    if ((ret < 0) || route_already_there)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(WOLFSENTRY_CONTEXT_ARGS_OUT, new, NULL /* action_results */));

    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert_into_table(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
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

    WOLFSENTRY_MUTEX_OR_RETURN();

    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event_label, event_label_len, &event)) < 0)
            WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    }
    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    ret = wolfsentry_route_insert_2(WOLFSENTRY_CONTEXT_ARGS_OUT, caller_arg, route_table ? route_table : wolfsentry->routes, remote, local, flags, event, id, NULL /* route */, action_results);
    if (event != NULL)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event, NULL /* action_results */));
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert_by_exports_into_table(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_route_exports *route_exports,
    wolfsentry_ent_id_t *id,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *event = NULL;

    WOLFSENTRY_MUTEX_OR_RETURN();

    if (route_exports->parent_event_label) {
        if ((ret = wolfsentry_event_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, route_exports->parent_event_label, route_exports->parent_event_label_len, &event)) < 0)
            WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    }
    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    ret = wolfsentry_route_insert_by_exports_2(WOLFSENTRY_CONTEXT_ARGS_OUT, caller_arg, route_table ? route_table : wolfsentry->routes, route_exports, event, id, NULL /* route */, action_results);
    if (event != NULL)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event, NULL /* action_results */));
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    wolfsentry_ent_id_t *id,
    wolfsentry_action_res_t *action_results)
{
    WOLFSENTRY_ERROR_RERETURN(
        wolfsentry_route_insert_into_table(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            NULL,
            caller_arg,
            remote,
            local,
            flags,
            event_label,
            event_label_len,
            id,
            action_results));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert_by_exports(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_route_exports *route_exports,
    wolfsentry_ent_id_t *id,
    wolfsentry_action_res_t *action_results)
{
    WOLFSENTRY_ERROR_RERETURN(
        wolfsentry_route_insert_by_exports_into_table(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            NULL,
            caller_arg,
            route_exports,
            id,
            action_results));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert_into_table_and_check_out(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    struct wolfsentry_route **route,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *event = NULL;

    WOLFSENTRY_MUTEX_OR_RETURN();

    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event_label, event_label_len, &event)) < 0)
            WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    }
    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    ret = wolfsentry_route_insert_2(WOLFSENTRY_CONTEXT_ARGS_OUT, caller_arg, route_table ? route_table : wolfsentry->routes, remote, local, flags, event, NULL /* id */, route, action_results);
    if (event != NULL)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event, NULL /* action_results */));
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_insert_and_check_out(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    struct wolfsentry_route **route,
    wolfsentry_action_res_t *action_results)
{
    WOLFSENTRY_ERROR_RERETURN(
        wolfsentry_route_insert_into_table_and_check_out(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            NULL,
            caller_arg,
            remote,
            local,
            flags,
            event_label,
            event_label_len,
            route,
            action_results));
}

static void wolfsentry_route_increment_hitcount(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results)
{
    if (! (route->flags & WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_HITS)) {
        wolfsentry_hitcount_t post_hitcount;
        WOLFSENTRY_ATOMIC_INCREMENT_UNSIGNED_SAFELY_BY_ONE(route->header.hitcount, post_hitcount);
        if (post_hitcount == 0) {
            wolfsentry_route_flags_t flags_before, flags_after;
            WOLFSENTRY_WARN_ON_FAILURE(
                wolfsentry_route_update_flags(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    route,
                    WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_HITS,
                    WOLFSENTRY_ROUTE_FLAG_NONE,
                    &flags_before,
                    &flags_after,
                    action_results));
        }
    }
    WOLFSENTRY_RETURN_VOID;
}

static wolfsentry_errcode_t wolfsentry_route_lookup_0(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_route *target_route,
    int exact_p,
    wolfsentry_route_flags_t *inexact_matches,
    struct wolfsentry_route **found_route,
    wolfsentry_action_res_t *action_results)
{
    struct wolfsentry_cursor cursor;
    int cursor_position;
    struct wolfsentry_route *i;
    int highest_priority_seen = 0;
    struct wolfsentry_route *highest_priority_match_seen = NULL;
    wolfsentry_route_flags_t highest_priority_inexact_matches = 0;
    wolfsentry_errcode_t ret;
    int contiguous_search;
    wolfsentry_route_flags_t inexact_matches_buf;
    int seen_target_af;
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    int af_is_bitmask_matched;
#endif
#ifdef DEBUG_ROUTE_LOOKUP
    struct wolfsentry_route *i_prev = NULL;
#endif

#ifdef DEBUG_ROUTE_LOOKUP
    fprintf(stderr,"target: ");
    if (wolfsentry_route_render(WOLFSENTRY_CONTEXT_ARGS_OUT, target_route, stderr) < 0) {}
#endif

    *found_route = NULL;

    if ((ret = wolfsentry_table_cursor_init(WOLFSENTRY_CONTEXT_ARGS_OUT, &cursor)) < 0)
        goto out;

#ifdef DEBUG_ROUTE_LOOKUP
    fprintf(stderr,"\n------------------------------------------------------------------------\n");
    wolfsentry_table_cursor_seek_to_head(&table->header, &cursor);
    for (i = (struct wolfsentry_route *)wolfsentry_table_cursor_current(&cursor);
         i;
         i = (struct wolfsentry_route *)wolfsentry_table_cursor_next(&cursor))
    {
        if (i_prev)
            fprintf(stderr,"   %d\n", wolfsentry_route_key_cmp_1(i_prev, i, 0, NULL));
        i_prev = i;
        if (wolfsentry_route_render(WOLFSENTRY_CONTEXT_ARGS_OUT, i, stderr) < 0) {}
    }
    fprintf(stderr,"------------------------------------------------------------------------\n\n");
#endif

    if (inexact_matches == NULL)
        inexact_matches = &inexact_matches_buf;
    *inexact_matches = WOLFSENTRY_ROUTE_FLAG_NONE;

    /* the event ID isn't an intrinsic attribute of network/bus traffic, so for
     * !exact_p, it's always a wildcard.
     */
    if (! exact_p)
        WOLFSENTRY_SET_BITS(target_route->flags, WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD);

    /* if the target has wildcard holes in it (not strictly prefix-matching),
     * then seek to the tail and skip straight to reverse iteration.
     *
     * the test for this depends on the wildcard bits in the flag word being
     * crowded at the bottom of the word, in order (lsb is leftmost search
     * field).
     *
     * the flag bits must be inverted, so that a no-wildcard lookup has all 1's
     * in the positions masked by WOLFSENTRY_ROUTE_WILDCARD_FLAGS.
     */
    if (exact_p) {
        /* secondary search will be skipped. */
    } else if (((~target_route->flags & WOLFSENTRY_ROUTE_WILDCARD_FLAGS) + 1) & (~target_route->flags & WOLFSENTRY_ROUTE_WILDCARD_FLAGS)) {
        contiguous_search = 0;
        /* skip primary search for now -- once the table is a red-black tree, it
         * will be worth constructing a target_route_contiguous_wildcards and
         * doing both, avoiding the need to traverse the entire table.
         */
        goto just_seek_to_tail;
    } else
        contiguous_search = 1;

    if ((ret = wolfsentry_table_cursor_seek(&table->header, &target_route->header, &cursor, &cursor_position)) < 0)
        goto out;

#ifdef DEBUG_ROUTE_LOOKUP
    fprintf(stderr,"cursor.point: ");
    if (cursor.point) {
        if (wolfsentry_route_render(WOLFSENTRY_CONTEXT_ARGS_OUT, (struct wolfsentry_route *)cursor.point, stderr) < 0) {}
    } else
        fprintf(stderr, "(null)\n");
    fprintf(stderr,"  res: %d\n",cursor_position);
#endif

    if (exact_p) {
        /* meta.purge_after is ignored when exact_p */
        if (cursor_position == 0) {
            *inexact_matches = WOLFSENTRY_ROUTE_FLAG_NONE;
            *found_route = (struct wolfsentry_route *)cursor.point;
            ret = WOLFSENTRY_ERROR_ENCODE(OK);
        } else {
            ret = WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);
        }
        goto out;
    }

    /* short circuit if we know there can't be a higher priority
     * match elsewhere in the table.
     */
    if (cursor_position == 0) {
        struct wolfsentry_event *parent_event = ((struct wolfsentry_route *)cursor.point)->parent_event ? ((struct wolfsentry_route *)cursor.point)->parent_event : NULL;
        if ((action_results == NULL) || (parent_event == NULL) || (parent_event->config == NULL) ||
            (((*action_results & parent_event->config->config.action_res_filter_bits_set) == parent_event->config->config.action_res_filter_bits_set) &&
             ((~(*action_results) & parent_event->config->config.action_res_filter_bits_unset) == parent_event->config->config.action_res_filter_bits_unset)))
        {
            int effective_priority = parent_event ? parent_event->priority : 0;
            if (effective_priority <= table->highest_priority_route_in_table) {
                if (inexact_matches != NULL)
                    *inexact_matches = WOLFSENTRY_ROUTE_FLAG_NONE;
                *found_route = (struct wolfsentry_route *)cursor.point;
                ret = WOLFSENTRY_ERROR_ENCODE(OK);
                goto out;
            }
        }
    }

    if (cursor_position == -1) {
    just_seek_to_tail:
        wolfsentry_table_cursor_seek_to_tail(&table->header, &cursor);
    }

    /* if the current and preceding cursor positions don't have a matching AF,
     * and the caller didn't request wildcard AF, then we can either skip to
     * table->last_af_wildcard_route, or end early if it's null.
     */
    if (! (target_route->flags & WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD)) {
        struct wolfsentry_route *point = (struct wolfsentry_route *)wolfsentry_table_cursor_current(&cursor);
        if ((point == NULL) ||
            ((point->sa_family != target_route->sa_family) &&
             ((point->header.prev == NULL) ||
              (((struct wolfsentry_route *)point->header.prev)->sa_family != target_route->sa_family))))
        {
            if (table->last_af_wildcard_route)
                wolfsentry_table_cursor_set(&cursor, &table->last_af_wildcard_route->header);
            else {
                ret = WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);
                goto out;
            }
        }
    }

#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    /* even if contiguous_search, bitmask matching is noncontiguous for the
     * addresses themselves, but is still grouped together by address family, so
     * we can assure best match is found by seeking to the end of the address
     * family span.
     */

    af_is_bitmask_matched = is_bitmask_matching(target_route->sa_family, table);

    if (af_is_bitmask_matched) {
        struct wolfsentry_route *j;

        for (i = j = (struct wolfsentry_route *)wolfsentry_table_cursor_current(&cursor);
             i && (i->sa_family == target_route->sa_family);
             j = i, i = (struct wolfsentry_route *)wolfsentry_table_cursor_next(&cursor));
        if (j)
            wolfsentry_table_cursor_set(&cursor, &j->header);
        else
            wolfsentry_table_cursor_seek_to_tail(&table->header, &cursor);
    }
#endif

    seen_target_af = 0;

    for (i = (struct wolfsentry_route *)wolfsentry_table_cursor_current(&cursor);
         i;
         i = (struct wolfsentry_route *)wolfsentry_table_cursor_prev(&cursor))
    {
        if (i->sa_family == target_route->sa_family) {
            if (! seen_target_af)
                seen_target_af = 1;
        } else {
            if (seen_target_af &&
                (! (target_route->flags & WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD)))
            {
                if (table->last_af_wildcard_route) {
                    i = table->last_af_wildcard_route;
                    wolfsentry_table_cursor_set(&cursor, &i->header);
                } else
                    break;
            }
        }

        /* ignore routes that don't cover the direction of the target. */
        if (! (i->flags & WOLFSENTRY_MASKIN_BITS(target_route->flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN|WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT)))
            continue;
        /* ignore routes that don't meet actions_results constraints. */
        if (action_results && i->parent_event && i->parent_event->config &&
            (((*action_results & i->parent_event->config->config.action_res_filter_bits_set) != i->parent_event->config->config.action_res_filter_bits_set) ||
             ((~(*action_results) & i->parent_event->config->config.action_res_filter_bits_unset) != i->parent_event->config->config.action_res_filter_bits_unset)))
        {
            continue;
        }
        /* if *action_results has _EXCLUDE_REJECT_ROUTES set on entry to
         * wolfsentry_route_lookup_0(), it was set via
         * wolfsentry_route_event_dispatch_with_inited_result() for a
         * bind/listen query that should succeed if any routes can succeed.
         * this requires ignoring routes with _PENALTYBOXED/_PORT_RESET set.
         */
        if (action_results &&
            WOLFSENTRY_CHECK_BITS(*action_results, WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES) &&
            WOLFSENTRY_MASKIN_BITS(i->flags, WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED))
        {
            continue;
        }

        cursor_position = wolfsentry_route_key_cmp_1(i, target_route, 1 /* match_wildcards_p */, inexact_matches);

#ifdef DEBUG_ROUTE_LOOKUP
        fprintf(stderr,"i: ");
        if (wolfsentry_route_render(WOLFSENTRY_CONTEXT_ARGS_OUT, i, stderr) < 0) {}
        fprintf(stderr,"\n  res: %d\n",cursor_position);
        fputs("  inexact_matches: ", stderr);
        if (wolfsentry_route_render_flags(*inexact_matches, stderr) < 0) {}
        fputc('\n', stderr);
#endif

        if (cursor_position == 0) {
            /* preference is a match with the highest-priority event, with null
             * events having highest priority, and ties broken using
             * compare_match_exactness().
             */
            int effective_priority = i->parent_event ? i->parent_event->priority : 0;
            if ((highest_priority_match_seen == NULL) ||
                (effective_priority < highest_priority_seen) ||
                ((effective_priority == highest_priority_seen) &&
                 (compare_match_exactness(target_route, i, *inexact_matches, highest_priority_match_seen, highest_priority_inexact_matches) < 0)))
            {
                highest_priority_match_seen = i;
                highest_priority_inexact_matches = *inexact_matches;
                highest_priority_seen = effective_priority;
            }
        }

        /* short circuit if we know there can't be a higher priority
         * match in a later iteration.
         */
        if (contiguous_search &&
            highest_priority_match_seen &&
            ((highest_priority_inexact_matches & WOLFSENTRY_ROUTE_WILDCARD_FLAGS) == 0) &&
            (highest_priority_seen <= table->highest_priority_route_in_table))
        {
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
            /* with bitmask af's, iteration must continue until the end of the
             * span for the AF, because bitmask matching isn't contiguous,
             * notwithstanding contiguous_search (reflecting only wildcard
             * contiguity).
             */
            if (af_is_bitmask_matched) {
                if (seen_target_af && (i->sa_family != target_route->sa_family))
                    break;
            } else {
                break;
            }
#else
            break;
#endif
        }
    }

    if (highest_priority_match_seen) {
        *found_route = highest_priority_match_seen;
        *inexact_matches = highest_priority_inexact_matches;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
    } else {
        ret = WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);
    }

  out:

    if (action_results && WOLFSENTRY_CHECK_BITS(*action_results, WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES))
        WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES);

    if ((*found_route != NULL) && WOLFSENTRY_IS_SUCCESS(ret) && (action_results != NULL))
        wolfsentry_route_increment_hitcount(WOLFSENTRY_CONTEXT_ARGS_OUT, *found_route, action_results);

#ifdef DEBUG_ROUTE_LOOKUP
    if (ret < 0)
        fprintf(stderr, "ret: " WOLFSENTRY_ERROR_FMT, WOLFSENTRY_ERROR_FMT_ARGS(ret));
    else {
        fprintf(stderr,"exact_p=%d\n",exact_p);
        if (*found_route == NULL)
            fprintf(stderr, "*found_route == NULL!\n");
        else {
            fprintf(stderr,"matched: ");
            if (wolfsentry_route_render(WOLFSENTRY_CONTEXT_ARGS_OUT, *found_route, stderr) < 0) {}
            fputc('\n', stderr);
        }
    }
#endif

    WOLFSENTRY_ERROR_RERETURN(ret);
}

static wolfsentry_errcode_t wolfsentry_route_lookup_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route_table *table,
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    struct wolfsentry_event *parent_event,
    int exact_p,
    wolfsentry_route_flags_t *inexact_matches,
    struct wolfsentry_route **found_route,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
#ifdef WOLFSENTRY_NO_ALLOCA
    const size_t addr_buf_size = WOLFSENTRY_MAX_ADDR_BYTES * 2;
    struct {
        struct wolfsentry_route route;
        byte buf[WOLFSENTRY_MAX_ADDR_BYTES * 2];
    } target;
    #define LOOKUP_TARGET &target.route
#else
    const size_t addr_buf_size = WOLFSENTRY_BITS_TO_BYTES(remote->addr_len) + WOLFSENTRY_BITS_TO_BYTES(local->addr_len);
    struct wolfsentry_route *target;

    target = (struct wolfsentry_route *)alloca(sizeof(*target) + addr_buf_size);
    #define LOOKUP_TARGET target
#endif

    if ((ret = wolfsentry_route_init(parent_event, remote, local, flags, 0 /* data_addr_offset */, sizeof(struct wolfsentry_route) + addr_buf_size, LOOKUP_TARGET)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    /* fix any nonzero wildcard fields, to avoid spurious mismatches. */
    clamp_wildcard_fields_to_zero(LOOKUP_TARGET);

    ret = wolfsentry_route_lookup_0(WOLFSENTRY_CONTEXT_ARGS_OUT, table, LOOKUP_TARGET, exact_p, inexact_matches, found_route, action_results);
    WOLFSENTRY_ERROR_RERETURN(ret);
#undef LOOKUP_TARGET
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_main_table(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table **table)
{
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();

    *table = wolfsentry->routes;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_default_policy_set(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t default_policy)
{
    if (WOLFSENTRY_MASKOUT_BITS(default_policy, WOLFSENTRY_ROUTE_DEFAULT_POLICY_MASK) != WOLFSENTRY_ACTION_RES_NONE)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    WOLFSENTRY_MUTEX_OR_RETURN();
    table->default_policy = default_policy;
    WOLFSENTRY_ERROR_UNLOCK_AND_RETURN(OK);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_default_policy_set(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_action_res_t default_policy)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_route_table *table;
    WOLFSENTRY_MUTEX_OR_RETURN();
    ret = wolfsentry_route_get_main_table(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        &table);
    WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);
    ret = wolfsentry_route_table_default_policy_set(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        table,
        default_policy);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_default_policy_get(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *default_policy)
{
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
    *default_policy = table->default_policy;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_default_policy_get(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_action_res_t *default_policy)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_route_table *table;
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
    ret = wolfsentry_route_get_main_table(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        &table);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    WOLFSENTRY_ERROR_RERETURN(
        wolfsentry_route_table_default_policy_get(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            table,
            default_policy));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_max_purgeable_routes_get(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_hitcount_t *max_purgeable_routes)
{
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
    *max_purgeable_routes = WOLFSENTRY_ATOMIC_LOAD(table->max_purgeable_routes);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_max_purgeable_routes_set(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_hitcount_t max_purgeable_routes)
{
    int need_purge_now = 0;

    WOLFSENTRY_HAVE_MUTEX_OR_RETURN();

    if (WOLFSENTRY_ATOMIC_LOAD(table->max_purgeable_routes) > max_purgeable_routes) {
        if (table->purge_list.len > max_purgeable_routes)
            need_purge_now = 1;
    }

    WOLFSENTRY_ATOMIC_STORE(table->max_purgeable_routes, max_purgeable_routes);

    if (need_purge_now)
        WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_stale_purge(WOLFSENTRY_CONTEXT_ARGS_OUT, table, NULL /* action_results */));
    else
        WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_max_purgeable_idle_time_get(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_time_t *max_purgeable_idle_time)
{
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
    *max_purgeable_idle_time = WOLFSENTRY_ATOMIC_LOAD(table->max_purgeable_idle_time);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_max_purgeable_idle_time_set(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_time_t max_purgeable_idle_time)
{
    WOLFSENTRY_HAVE_MUTEX_OR_RETURN();

    WOLFSENTRY_ATOMIC_STORE(table->max_purgeable_idle_time, max_purgeable_idle_time);

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_reference(
    WOLFSENTRY_CONTEXT_ARGS_IN,
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

    WOLFSENTRY_SHARED_OR_RETURN();

    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event_label, event_label_len, &event)) < 0)
            WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    }
    ret = wolfsentry_route_lookup_1(WOLFSENTRY_CONTEXT_ARGS_OUT, table, remote, local, flags, event, exact_p, inexact_matches, (struct wolfsentry_route **)route, NULL /* action_results */);
    if (event != NULL)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event, NULL /* action_results */));
    WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);
    WOLFSENTRY_REFCOUNT_INCREMENT((*route)->header.refcount, ret);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

static wolfsentry_errcode_t wolfsentry_route_delete_0(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_event *trigger_event,
    struct wolfsentry_route *route,
    wolfsentry_action_res_t *action_results,
    int defer_p)
{
    wolfsentry_errcode_t ret;

    WOLFSENTRY_HAVE_MUTEX_OR_RETURN();

    /* if the route has a nonzero connection count, assume all connections are
     * in TIME_WAIT, set a GC timeout on the route, and defer actual deletion.
     * note that wolfsentry_route_stale_purge_1() calls
     * wolfsentry_route_delete_0() directly, intentionally bypassing this logic.
     */
    if (defer_p && (route->meta.connection_count > 0)) {
        wolfsentry_time_t tcp_fin_timeout, new_purge_after;
        wolfsentry_route_flags_t flags_before, flags_after;
        wolfsentry_route_update_flags_1(route, WOLFSENTRY_ROUTE_FLAG_PENDING_DELETE, WOLFSENTRY_ROUTE_FLAG_NONE, &flags_before, &flags_after);
        /* lwIP default TCP_FIN_WAIT_TIMEOUT is 20s, and Linux
         * net.ipv4.tcp_fin_timeout is 60s.
         */
        WOLFSENTRY_FROM_EPOCH_TIME(60 /* epoch_secs */, 0 /* epoch_nsecs */, &tcp_fin_timeout);
        new_purge_after = route->meta.last_hit_time + tcp_fin_timeout;
        if (route->meta.purge_after < new_purge_after) {
            if (route->meta.purge_after)
                wolfsentry_list_ent_delete(&route_table->purge_list, &route->purge_links);
            route->meta.purge_after = new_purge_after;
            wolfsentry_route_purge_list_insert(route_table, route);
        }
        WOLFSENTRY_SUCCESS_RETURN(DEFERRED);
    }

    {
        wolfsentry_route_flags_t flags_before, flags_after;
        wolfsentry_route_update_flags_1(route, WOLFSENTRY_ROUTE_FLAG_NONE, WOLFSENTRY_ROUTE_FLAG_IN_TABLE, &flags_before, &flags_after);
    }

    if ((ret = wolfsentry_table_ent_delete_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &route->header)) < 0) {
        wolfsentry_route_flags_t flags_before, flags_after;
        wolfsentry_route_update_flags_1(route, WOLFSENTRY_ROUTE_FLAG_IN_TABLE, WOLFSENTRY_ROUTE_FLAG_NONE, &flags_before, &flags_after);
        WOLFSENTRY_ERROR_RERETURN(ret);
    }

#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    if (route->flags & (WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK | WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK))
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_bitmask_matching_downref(route->sa_family, route_table));
#endif

    if (route->meta.purge_after)
        wolfsentry_list_ent_delete(&route_table->purge_list, &route->purge_links);

    if (route->parent_event && (wolfsentry_list_ent_get_len(&route->parent_event->delete_action_list.header) > 0)) {
        ret = wolfsentry_action_list_dispatch(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            caller_arg,
            route->parent_event,
            trigger_event,
            WOLFSENTRY_ACTION_TYPE_DELETE,
            NULL /* target_route */,
            route_table,
            route,
            action_results);
        if (ret < 0)
            WOLFSENTRY_WARN("wolfsentry_action_list_dispatch for wolfsentry_route_delete_0 returned " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
    }

    if (route_table->last_af_wildcard_route == route)
        route_table->last_af_wildcard_route = (struct wolfsentry_route *)route->header.prev;

    {
        wolfsentry_priority_t effective_priority = route->parent_event ? route->parent_event->priority : 0;
        if (effective_priority == route_table->highest_priority_route_in_table) {
            wolfsentry_priority_t new_highest_priority_route_in_table = MAX_UINT_OF(wolfsentry_priority_t);
            struct wolfsentry_cursor cursor;
            ret = wolfsentry_table_cursor_init(WOLFSENTRY_CONTEXT_ARGS_OUT, &cursor);
            if (WOLFSENTRY_IS_SUCCESS(ret)) {
                const struct wolfsentry_route *i;
                wolfsentry_table_cursor_seek_to_head(&route_table->header, &cursor);
                for (i = (struct wolfsentry_route *)wolfsentry_table_cursor_current(&cursor);
                     i;
                     i = (struct wolfsentry_route *)wolfsentry_table_cursor_next(&cursor))
                {
                    wolfsentry_priority_t i_effective_priority = i->parent_event ? i->parent_event->priority : 0;
                    if (i_effective_priority < new_highest_priority_route_in_table) {
                        new_highest_priority_route_in_table = i_effective_priority;
                        if (i_effective_priority <= route_table->highest_priority_route_in_table)
                            break;
                    }
                }
            } else
                WOLFSENTRY_WARN("wolfsentry_table_cursor_init() returned " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
            route_table->highest_priority_route_in_table = new_highest_priority_route_in_table;
        }
    }

    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(WOLFSENTRY_CONTEXT_ARGS_OUT, route, action_results));

    WOLFSENTRY_RETURN_OK;
}

static inline wolfsentry_errcode_t wolfsentry_route_delete_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
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

    WOLFSENTRY_HAVE_MUTEX_OR_RETURN();

    ret = wolfsentry_route_lookup_1(WOLFSENTRY_CONTEXT_ARGS_OUT, route_table, remote, local, flags, event, 1 /* exact_p */, NULL /* inexact_matches */, &route, NULL /* action_results */);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_route_delete_0(WOLFSENTRY_CONTEXT_ARGS_OUT, caller_arg, route_table, NULL /* trigger_event */, route, action_results, 1 /* defer_p */);
    if (WOLFSENTRY_IS_SUCCESS(ret))
        ++(*n_deleted);
    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_delete_from_table(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
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

    WOLFSENTRY_MUTEX_OR_RETURN();

    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event_label, event_label_len, &event)) < 0)
            WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    }

    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    *n_deleted = 0;
    ret = wolfsentry_route_delete_1(WOLFSENTRY_CONTEXT_ARGS_OUT, route_table ? route_table : wolfsentry->routes, caller_arg, remote, local, flags, event, action_results, n_deleted);
    if (event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event, NULL /* action_results */));
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_delete(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    const struct wolfsentry_sockaddr *remote,
    const struct wolfsentry_sockaddr *local,
    wolfsentry_route_flags_t flags,
    const char *event_label,
    int event_label_len,
    wolfsentry_action_res_t *action_results,
    int *n_deleted)
{
    WOLFSENTRY_ERROR_RERETURN(
        wolfsentry_route_delete_from_table(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            NULL,
            caller_arg,
            remote,
            local,
            flags,
            event_label,
            event_label_len,
            action_results,
            n_deleted));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_delete_by_id(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_ent_id_t id,
    const char *trigger_label,
    int trigger_label_len,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *trigger_event = NULL;
    struct wolfsentry_route *route;

    WOLFSENTRY_MUTEX_OR_RETURN();

    if (trigger_label) {
        if ((ret = wolfsentry_event_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, trigger_label, trigger_label_len, &trigger_event)) < 0)
            WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    }
    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);

    if ((ret = wolfsentry_table_ent_get_by_id(WOLFSENTRY_CONTEXT_ARGS_OUT, id, (struct wolfsentry_table_ent_header **)&route)) < 0)
        goto out;
    if (route->header.parent_table == NULL) {
        ret = WOLFSENTRY_ERROR_ENCODE(INTERNAL_CHECK_FATAL);
        goto out;
    }
    if (route->header.parent_table->ent_type != WOLFSENTRY_OBJECT_TYPE_ROUTE) {
        ret = WOLFSENTRY_ERROR_ENCODE(WRONG_OBJECT);
        goto out;
    }

    ret = wolfsentry_route_delete_0(WOLFSENTRY_CONTEXT_ARGS_OUT, caller_arg, (struct wolfsentry_route_table *)route->header.parent_table, trigger_event, route, action_results, 1 /* defer_p */);

  out:
    if (trigger_event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, trigger_event, NULL /* action_results */));
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

static wolfsentry_errcode_t wolfsentry_route_stale_purge_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *action_results,
    int mode,
    wolfsentry_time_t now);

static wolfsentry_errcode_t wolfsentry_route_event_dispatch_0(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_event *trigger_event,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    struct wolfsentry_route *target_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results
    )
{
    struct wolfsentry_event *parent_event;
    struct wolfsentry_eventconfig_internal *config;
    wolfsentry_route_flags_t current_rule_route_flags;
    wolfsentry_errcode_t ret;
    wolfsentry_time_t now;

    if (target_route == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (route_table == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (rule_route == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (action_results == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    /* doesn't make any sense to supply a bitmask with a target address. */
    if (target_route->flags & (WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK | WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    parent_event = rule_route->parent_event ? rule_route->parent_event : route_table->default_event;
    config = (parent_event && parent_event->config) ? parent_event->config : &wolfsentry->config;

    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();

    current_rule_route_flags = WOLFSENTRY_ATOMIC_LOAD(rule_route->flags);

    ret = WOLFSENTRY_GET_TIME(&now);
    if (ret < 0) {
        WOLFSENTRY_WARN_ON_FAILURE(ret);
        *action_results |= WOLFSENTRY_ACTION_RES_ERROR;
        now = 0;
    } else {
        rule_route->meta.last_hit_time = now;
    }

    if (rule_route->meta.purge_after) {
        wolfsentry_time_t purge_margin, new_purge_after;
        /* use the purge_margin to reduce mutex burden. */
        WOLFSENTRY_FROM_EPOCH_TIME(WOLFSENTRY_ROUTE_PURGE_MARGIN_SECONDS, 0 /* epoch_nsecs */, &purge_margin);
        new_purge_after = rule_route->meta.last_hit_time + config->config.route_idle_time_for_purge + purge_margin;
        /* note that the below read access to rule_route->meta.purge_after is
         * race-prone on 32 bit targets -- this is benign, because the code path
         * on a false positive is to obtain a mutex, whereafter all access is
         * coherent.
         */
        if (new_purge_after - rule_route->meta.purge_after >= purge_margin) {
#ifdef WOLFSENTRY_THREADSAFE
            if (WOLFSENTRY_IS_SUCCESS(wolfsentry_lock_have_mutex(&wolfsentry->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE)) ||
                WOLFSENTRY_IS_SUCCESS(wolfsentry_lock_shared2mutex(&wolfsentry->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE)))
#endif
            {
                rule_route->meta.purge_after = new_purge_after; /* coherent assignment */
                if (route_table->purge_list.tail != &rule_route->purge_links) {
                    wolfsentry_list_ent_delete(&route_table->purge_list, &rule_route->purge_links);
                    wolfsentry_route_purge_list_insert(route_table, rule_route);
                }
            }
        }
    }

    /* opportunistic garbage collection. */
    (void)wolfsentry_route_stale_purge_1(WOLFSENTRY_CONTEXT_ARGS_OUT, route_table, NULL /* action_results */, 2, now);

    if (trigger_event && (wolfsentry_list_ent_get_len(&trigger_event->post_action_list.header) > 0)) {
        /* for dynamic blocking, e.g. of a port scanner, one of the plugins in
         * trigger_event->action_list must call wolfsentry_route_set_wildcard(),
         * in addition to setting _ACTION_RES_INSERT.
         */
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_dispatch(
                                       WOLFSENTRY_CONTEXT_ARGS_OUT,
                                       caller_arg,
                                       trigger_event,
                                       trigger_event,
                                       WOLFSENTRY_ACTION_TYPE_POST,
                                       target_route,
                                       route_table,
                                       rule_route,
                                       action_results));
        WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP);
        current_rule_route_flags = WOLFSENTRY_ATOMIC_LOAD(rule_route->flags);
    }

    if (config->config.action_res_bits_to_add)
        WOLFSENTRY_SET_BITS(*action_results, config->config.action_res_bits_to_add);
    if (config->config.action_res_bits_to_clear)
        WOLFSENTRY_CLEAR_BITS(*action_results, config->config.action_res_bits_to_clear);

    /* if the rule_route still isn't in the table at this point, then switch to the fallthrough rule. */
    if ((! WOLFSENTRY_CHECK_BITS(current_rule_route_flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE)) && (route_table->fallthrough_route != NULL)) {
        rule_route = route_table->fallthrough_route;
        if (rule_route) {
            *action_results |= WOLFSENTRY_ACTION_RES_FALLTHROUGH;
            wolfsentry_route_increment_hitcount(WOLFSENTRY_CONTEXT_ARGS_OUT, rule_route, action_results);
        }
        parent_event = route_table->default_event;
    }

    if (parent_event && (wolfsentry_list_ent_get_len(&parent_event->match_action_list.header) > 0)) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_dispatch(
                                       WOLFSENTRY_CONTEXT_ARGS_OUT,
                                       caller_arg,
                                       parent_event,
                                       trigger_event,
                                       WOLFSENTRY_ACTION_TYPE_MATCH,
                                       target_route,
                                       route_table,
                                       rule_route,
                                       action_results));
        WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP);
        current_rule_route_flags = WOLFSENTRY_ATOMIC_LOAD(rule_route->flags);
    }

    /* if _RES_INSERTED signals that a side-effect route was created within this
     * dispatch, assume any counts were assigned to the new route, and ignore
     * them here.
     *
     * also inhibit counts if returning a fallthrough result.
     */
    if ((! WOLFSENTRY_CHECK_BITS(*action_results, WOLFSENTRY_ACTION_RES_INSERTED)) &&
        (! WOLFSENTRY_CHECK_BITS(*action_results, WOLFSENTRY_ACTION_RES_FALLTHROUGH)))
    {
        if (*action_results & WOLFSENTRY_ACTION_RES_DEROGATORY) {
            WOLFSENTRY_ATOMIC_INCREMENT_UNSIGNED_SAFELY_BY_ONE(rule_route->meta.derogatory_count, ret);
            (void)ret;
        }

        if (! (current_rule_route_flags & WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_CURRENT_CONNECTIONS)) {
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
            } else if (*action_results & WOLFSENTRY_ACTION_RES_DISCONNECT) {
                uint16_t new_connection_count;
                /* important to decrement safely, because untimely route
                 * deletions can lead to a decrement being assigned to a
                 * different route than the one originally incremented.
                 */
                WOLFSENTRY_ATOMIC_DECREMENT_UNSIGNED_SAFELY(rule_route->meta.connection_count, 1, new_connection_count);
                if (new_connection_count == MAX_UINT_OF(rule_route->meta.connection_count))
                    WOLFSENTRY_WARN("_RES_DISCONNECT for route #" WOLFSENTRY_ENT_ID_FMT ", whose connection_count is already zero.", rule_route->header.id);
            }
        }

        if (*action_results & WOLFSENTRY_ACTION_RES_COMMENDABLE) {
            WOLFSENTRY_ATOMIC_INCREMENT_UNSIGNED_SAFELY_BY_ONE(rule_route->meta.commendable_count, ret);
            (void)ret;
            if (config->config.flags & WOLFSENTRY_EVENTCONFIG_FLAG_COMMENDABLE_CLEARS_DEROGATORY)
                WOLFSENTRY_ATOMIC_STORE(rule_route->meta.derogatory_count, 0);
        }
    }

    if (((current_rule_route_flags & WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED)) &&
        WOLFSENTRY_CHECK_BITS(*action_results, WOLFSENTRY_ACTION_RES_COMMENDABLE) &&
        WOLFSENTRY_CHECK_BITS(config->config.flags, WOLFSENTRY_EVENTCONFIG_FLAG_COMMENDABLE_CLEARS_DEROGATORY))
    {
        wolfsentry_route_flags_t flags_before;
        WOLFSENTRY_WARN_ON_FAILURE(
            wolfsentry_route_update_flags(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                rule_route,
                WOLFSENTRY_ROUTE_FLAG_NONE,
                WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED,
                &flags_before,
                &current_rule_route_flags,
                action_results));
    }

    if (((current_rule_route_flags & WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED)) &&
        ((config->config.penaltybox_duration > 0) && (rule_route->meta.last_penaltybox_time != 0)))
    {
        if (WOLFSENTRY_DIFF_TIME(now, rule_route->meta.last_penaltybox_time) > config->config.penaltybox_duration) {
            wolfsentry_route_flags_t flags_before;
            WOLFSENTRY_WARN_ON_FAILURE(
                wolfsentry_route_update_flags(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    rule_route,
                    WOLFSENTRY_ROUTE_FLAG_NONE,
                    WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED,
                    &flags_before,
                    &current_rule_route_flags,
                    action_results));
        }
    }

    if (current_rule_route_flags & WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED) {
        *action_results |= WOLFSENTRY_ACTION_RES_REJECT;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        goto done;
    } else if ((config->config.derogatory_threshold_for_penaltybox > 0)
               && ((config->config.flags & WOLFSENTRY_EVENTCONFIG_FLAG_DEROGATORY_THRESHOLD_IGNORE_COMMENDABLE) ?
                   (WOLFSENTRY_ATOMIC_LOAD(rule_route->meta.derogatory_count)
                    >= config->config.derogatory_threshold_for_penaltybox)
                   :
                   (WOLFSENTRY_ATOMIC_LOAD(rule_route->meta.derogatory_count)
                    - WOLFSENTRY_ATOMIC_LOAD(rule_route->meta.commendable_count)
                    >= (int)config->config.derogatory_threshold_for_penaltybox)))
    {
        wolfsentry_route_flags_t flags_before;
        WOLFSENTRY_WARN_ON_FAILURE(
            ret = wolfsentry_route_update_flags(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                rule_route,
                WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED,
                WOLFSENTRY_ROUTE_FLAG_NONE,
                &flags_before,
                &current_rule_route_flags,
                action_results));
        if (WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
            /* once the penalty box threshold is reached, counting starts over
             * from zero.
             */
            WOLFSENTRY_ATOMIC_STORE(rule_route->meta.derogatory_count, 0);
            WOLFSENTRY_ATOMIC_STORE(rule_route->meta.commendable_count, 0);
        }
        *action_results |= WOLFSENTRY_ACTION_RES_REJECT;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        goto done;
    } else if ((current_rule_route_flags & WOLFSENTRY_ROUTE_FLAG_GREENLISTED)) {
        *action_results |= WOLFSENTRY_ACTION_RES_ACCEPT;
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
        goto done;
    }

    if (! WOLFSENTRY_MASKIN_BITS(*action_results, WOLFSENTRY_ACTION_RES_ACCEPT|WOLFSENTRY_ACTION_RES_REJECT))
        *action_results |= WOLFSENTRY_ACTION_RES_FALLTHROUGH | route_table->default_policy;

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  done:

    if ((*action_results & WOLFSENTRY_ACTION_RES_REJECT) &&
        (current_rule_route_flags & WOLFSENTRY_ROUTE_FLAG_PORT_RESET))
    {
        *action_results |= WOLFSENTRY_ACTION_RES_PORT_RESET;
    }

    if (WOLFSENTRY_CHECK_BITS(*action_results, WOLFSENTRY_ACTION_RES_UPDATE) &&
        parent_event && (wolfsentry_list_ent_get_len(&parent_event->update_action_list.header) > 0))
    {
        WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP);
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_dispatch(
                                       WOLFSENTRY_CONTEXT_ARGS_OUT,
                                       caller_arg,
                                       parent_event,
                                       trigger_event,
                                       WOLFSENTRY_ACTION_TYPE_UPDATE,
                                       target_route,
                                       route_table,
                                       rule_route,
                                       action_results));
        /* no need to refresh current_rule_route_flags */
    }

    if (parent_event && (wolfsentry_list_ent_get_len(&parent_event->decision_action_list.header) > 0)) {
        WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP);
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_dispatch(
                                       WOLFSENTRY_CONTEXT_ARGS_OUT,
                                       caller_arg,
                                       parent_event,
                                       trigger_event,
                                       WOLFSENTRY_ACTION_TYPE_DECISION,
                                       target_route,
                                       route_table,
                                       rule_route,
                                       action_results));
        /* no need to refresh current_rule_route_flags */
    }

    if (ret < 0)
        *action_results |= WOLFSENTRY_ACTION_RES_ERROR;

    WOLFSENTRY_ERROR_RERETURN(ret);
}

static wolfsentry_errcode_t wolfsentry_route_event_dispatch_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
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
    struct wolfsentry_route *target_route = NULL;
    struct {
        struct wolfsentry_route route;
        uint16_t addr_buf[16];
    } target_route_buf;
    struct wolfsentry_route *rule_route = NULL;
    struct wolfsentry_event *trigger_event = NULL;
    wolfsentry_errcode_t ret;

    if ((remote == NULL) ||
        (local == NULL) ||
        (action_results == NULL))
    {
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }

    WOLFSENTRY_SHARED_OR_RETURN();

    if (route_table == NULL)
        route_table = wolfsentry->routes;

    if (event_label) {
        if (((ret = wolfsentry_event_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event_label, event_label_len, &trigger_event)) < 0)
            && (! (flags & WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD)))
        {
            WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
        }
    }

    if (id)
        *id = WOLFSENTRY_ENT_ID_NONE;

    if ((WOLFSENTRY_BITS_TO_BYTES(remote->addr_len) <= 16) && (WOLFSENTRY_BITS_TO_BYTES(local->addr_len) <= 16)) {
        ret = wolfsentry_route_init(
            trigger_event,
            remote,
            local,
            flags,
            0 /* private data_addr_offset */,
            sizeof target_route_buf,
            &target_route_buf.route);
        if (ret < 0)
            goto just_free_resources;
        target_route = &target_route_buf.route;
    } else {
        if ((ret = wolfsentry_route_new(WOLFSENTRY_CONTEXT_ARGS_OUT, trigger_event, remote, local, flags, &target_route)) < 0)
            goto just_free_resources;
    }

    ret = wolfsentry_route_lookup_0(WOLFSENTRY_CONTEXT_ARGS_OUT, route_table, target_route, 0 /* exact_p */, inexact_matches, &rule_route, action_results);
    if (WOLFSENTRY_IS_SUCCESS(ret)) {
        /* continue */
    }
    else if ((trigger_event || route_table->default_event) &&
             (wolfsentry_list_ent_get_len(&((trigger_event ? trigger_event : route_table->default_event))->post_action_list.header) > 0)) {
        /*
         * the trigger or default event has post actions.
         *
         * this entails evaluating unmatched traffic for possible side-effects
         * (particularly dynamic route insertion), but is very inefficient
         * because an ephemeral rule has to be constructed.
         *
         * to avoid this overhead, trigger and default events should have empty
         * post action lists.  then unmatched traffic will immediately have the
         * default policy applied to it, and evaluation will end.
         */
    }
    else {
        /* nothing to do. */
        /* carry through ret from final wolfsentry_route_lookup_0(), and impose the default policy. */
        goto just_free_resources;
    }

    if (rule_route == NULL) {
        *action_results |= WOLFSENTRY_ACTION_RES_FALLTHROUGH;
        if ((ret = wolfsentry_route_clone(
                 WOLFSENTRY_CONTEXT_ARGS_OUT,
                 &target_route->header,
                 wolfsentry,
                 (struct wolfsentry_table_ent_header **)&rule_route,
                 WOLFSENTRY_CLONE_FLAG_NONE)) < 0)
            goto just_free_resources;
        if ((rule_route->parent_event == NULL) && (route_table->default_event != NULL)) {
            rule_route->parent_event = route_table->default_event;
            WOLFSENTRY_REFCOUNT_INCREMENT(rule_route->parent_event->header.refcount, ret);
            WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);
        }
    }

    ret = wolfsentry_route_event_dispatch_0(WOLFSENTRY_CONTEXT_ARGS_OUT, trigger_event ? trigger_event : route_table->default_event, caller_arg, target_route, route_table, rule_route, action_results);

    if (id && WOLFSENTRY_CHECK_BITS(rule_route->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE))
        *id = rule_route->header.id;

  just_free_resources:

    if ((rule_route != NULL) && (! WOLFSENTRY_CHECK_BITS(rule_route->flags, WOLFSENTRY_ROUTE_FLAG_IN_TABLE)))
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(WOLFSENTRY_CONTEXT_ARGS_OUT, rule_route, NULL /* action_results */));

    if ((target_route != NULL) && (target_route != &target_route_buf.route))
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(WOLFSENTRY_CONTEXT_ARGS_OUT, target_route, NULL /* action_results */));

    if (trigger_event != NULL)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, trigger_event, NULL /* action_results */));

    if (rule_route == NULL) {
        if (inexact_matches)
            *inexact_matches = WOLFSENTRY_ROUTE_WILDCARD_FLAGS | WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
        *action_results |= route_table->default_policy | WOLFSENTRY_ACTION_RES_FALLTHROUGH;
        WOLFSENTRY_SUCCESS_UNLOCK_AND_RETURN(USED_FALLBACK);
    }

    if (ret < 0)
        *action_results |= WOLFSENTRY_ACTION_RES_ERROR;

    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_with_table(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
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
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_event_dispatch_1(WOLFSENTRY_CONTEXT_ARGS_OUT, route_table, remote, local, flags, event_label, event_label_len, caller_arg, id, inexact_matches, action_results));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch(
    WOLFSENTRY_CONTEXT_ARGS_IN,
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
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_event_dispatch_1(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL, remote, local, flags, event_label, event_label_len, caller_arg, id, inexact_matches, action_results));
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

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_with_table_with_inited_result(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *route_table,
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
    wolfsentry_errcode_t ret = check_user_inited_result(*action_results);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_event_dispatch_1(WOLFSENTRY_CONTEXT_ARGS_OUT, route_table, remote, local, flags, event_label, event_label_len, caller_arg, id, inexact_matches, action_results));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_with_inited_result(
    WOLFSENTRY_CONTEXT_ARGS_IN,
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
    wolfsentry_errcode_t ret = check_user_inited_result(*action_results);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_event_dispatch_1(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL, remote, local, flags, event_label, event_label_len, caller_arg, id, inexact_matches, action_results));
}

static wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_id_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
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
    struct wolfsentry_route_table *route_table;

    WOLFSENTRY_SHARED_OR_RETURN();

    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event_label, event_label_len, &trigger_event)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
    }

    if ((ret = wolfsentry_table_ent_get_by_id(WOLFSENTRY_CONTEXT_ARGS_OUT, id, (struct wolfsentry_table_ent_header **)&route)) < 0)
        goto out;
    if (route->header.parent_table == NULL) {
        ret = WOLFSENTRY_ERROR_ENCODE(INTERNAL_CHECK_FATAL);
        goto out;
    }
    if (route->header.parent_table->ent_type != WOLFSENTRY_OBJECT_TYPE_ROUTE) {
        ret = WOLFSENTRY_ERROR_ENCODE(WRONG_OBJECT);
        goto out;
    }

    route_table = (struct wolfsentry_route_table *)route->header.parent_table;

    ret = wolfsentry_route_event_dispatch_0(WOLFSENTRY_CONTEXT_ARGS_OUT, trigger_event ? trigger_event : route_table->default_event, caller_arg, route /* target_route */, (struct wolfsentry_route_table *)route->header.parent_table, route /* rule_route */, action_results);

  out:
    if (trigger_event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, trigger_event, NULL /* action_results */));
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_id(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_ent_id_t id,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_action_res_t *action_results
    )
{
    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_event_dispatch_by_id_1(WOLFSENTRY_CONTEXT_ARGS_OUT, id, event_label, event_label_len, caller_arg, action_results));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_id_with_inited_result(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_ent_id_t id,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_action_res_t *action_results
    )
{
    wolfsentry_errcode_t ret = check_user_inited_result(*action_results);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_event_dispatch_by_id_1(WOLFSENTRY_CONTEXT_ARGS_OUT, id, event_label, event_label_len, caller_arg, action_results));
}

static wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_route_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_action_res_t *action_results
    )
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_event *trigger_event = NULL;
    struct wolfsentry_route_table *route_table;

    WOLFSENTRY_SHARED_OR_RETURN();

    if (event_label) {
        if ((ret = wolfsentry_event_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event_label, event_label_len, &trigger_event)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
    }

    if (route->header.parent_table->ent_type != WOLFSENTRY_OBJECT_TYPE_ROUTE) {
        ret = WOLFSENTRY_ERROR_ENCODE(WRONG_OBJECT);
        goto out;
    }

    route_table = (struct wolfsentry_route_table *)route->header.parent_table;

    ret = wolfsentry_route_event_dispatch_0(WOLFSENTRY_CONTEXT_ARGS_OUT, trigger_event ? trigger_event : route_table->default_event, caller_arg, route /* target_route */, (struct wolfsentry_route_table *)route->header.parent_table, route /* rule_route */, action_results);

  out:
    if (trigger_event)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, trigger_event, NULL /* action_results */));
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_route(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_action_res_t *action_results
    )
{
    WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_event_dispatch_by_route_1(WOLFSENTRY_CONTEXT_ARGS_OUT, route, event_label, event_label_len, caller_arg, action_results));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_event_dispatch_by_route_with_inited_result(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    const char *event_label,
    int event_label_len,
    void *caller_arg, /* passed to action callback(s) as the caller_arg. */
    wolfsentry_action_res_t *action_results
    )
{
    wolfsentry_errcode_t ret = check_user_inited_result(*action_results);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_event_dispatch_by_route_1(WOLFSENTRY_CONTEXT_ARGS_OUT, route, event_label, event_label_len, caller_arg, action_results));
}

/* purge_list: least stale at the head, most stale at the tail. */

WOLFSENTRY_LOCAL_VOID wolfsentry_route_purge_list_insert(struct wolfsentry_route_table *route_table, struct wolfsentry_route *route_to_insert) {
    struct wolfsentry_list_ent_header *point_ent;

    for (wolfsentry_list_ent_get_first(&route_table->purge_list, &point_ent); point_ent; point_ent = point_ent->next) {
        struct wolfsentry_route *point_route = WOLFSENTRY_ROUTE_PURGE_HEADER_TO_TABLE_ENT_HEADER(point_ent);
        if (point_route->meta.purge_after < route_to_insert->meta.purge_after)
            break;
    }
    wolfsentry_list_ent_insert_before(&route_table->purge_list, point_ent, &route_to_insert->purge_links);
    WOLFSENTRY_RETURN_VOID;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_purge_time_set(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    wolfsentry_time_t purge_after)
{
    WOLFSENTRY_HAVE_MUTEX_OR_RETURN();
    if (route->meta.purge_after)
        wolfsentry_list_ent_delete(&((struct wolfsentry_route_table *)route->header.parent_table)->purge_list, &route->purge_links);
    route->meta.purge_after = purge_after;
    if (route->meta.purge_after)
        wolfsentry_route_purge_list_insert((struct wolfsentry_route_table *)route->header.parent_table, route);
    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_stale_purge_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *action_results,
    int mode,
    wolfsentry_time_t now)
{
    wolfsentry_errcode_t ret;
    int n = 0;
    wolfsentry_action_res_t fallback_action_results = 0;
#ifdef WOLFSENTRY_THREADSAFE
    int have_mutex = 0;
    int got_lock = 0;
#endif

    if ((mode != 3) && (now == 0)) {
        if ((ret = WOLFSENTRY_GET_TIME(&now)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
    }

    if (table) {
        WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
        if ((! table->purge_list.tail) ||
            ((mode != 3) && (WOLFSENTRY_ROUTE_PURGE_HEADER_TO_TABLE_ENT_HEADER(table->purge_list.tail)->meta.purge_after > now)))
            WOLFSENTRY_ERROR_RETURN(ALREADY);
    }

    if (action_results == NULL)
        action_results = &fallback_action_results;

#ifdef WOLFSENTRY_THREADSAFE
    if (wolfsentry_lock_have_mutex(&wolfsentry->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE) < 0) {
        if (wolfsentry_lock_have_shared2mutex_reservation(&wolfsentry->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE) < 0) {
            if (thread == NULL) {
                if (mode == 2)
                    ret = wolfsentry_context_lock_mutex_timed(WOLFSENTRY_CONTEXT_ARGS_OUT, 0 /* max_wait */);
                else
                    ret = wolfsentry_context_lock_mutex_abstimed(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL);
                have_mutex = 1;
            } else {
                if (mode == 2)
                    ret = wolfsentry_context_lock_shared_with_reservation_timed(WOLFSENTRY_CONTEXT_ARGS_OUT, 0 /* max wait */);
                else
                    ret = wolfsentry_context_lock_shared_with_reservation_abstimed(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL);
            }
            WOLFSENTRY_RERETURN_IF_ERROR(ret);
            got_lock = 1;
        }
    } else
        have_mutex = 1;
#endif

    if (! table)
        table = wolfsentry->routes;

    while (table->purge_list.tail) {
        struct wolfsentry_route *route = WOLFSENTRY_ROUTE_PURGE_HEADER_TO_TABLE_ENT_HEADER(table->purge_list.tail);
        if (mode != 3) {
            if (route->meta.purge_after > now)
                break;
            if ((route->meta.connection_count > 0) &&
                (! (route->flags & WOLFSENTRY_ROUTE_FLAG_PENDING_DELETE)) &&
                ((table->max_purgeable_idle_time == 0) || (now - route->meta.last_hit_time > table->max_purgeable_idle_time)))
            {
                continue;
            }
        }
#ifdef WOLFSENTRY_THREADSAFE
        if (! have_mutex) {
            if (mode == 2)
                ret = wolfsentry_lock_shared2mutex_timed(&wolfsentry->lock, thread, 0 /* max_wait */, WOLFSENTRY_LOCK_FLAG_NONE);
            else
                ret = wolfsentry_lock_shared2mutex(&wolfsentry->lock, thread, WOLFSENTRY_LOCK_FLAG_NONE);
            if (ret < 0) {
                if (got_lock)
                    WOLFSENTRY_UNLOCK_AND_UNRESERVE_FOR_RETURN();
                WOLFSENTRY_ERROR_RERETURN(ret);
            }
            have_mutex = 1;
        }
#endif
        ret = wolfsentry_route_delete_0(WOLFSENTRY_CONTEXT_ARGS_OUT, NULL /* caller_arg */, table, NULL /* trigger_event */, route, action_results, 0 /* defer_p */);
        if (ret < 0) {
#ifdef WOLFSENTRY_THREADSAFE
            if (got_lock)
                WOLFSENTRY_UNLOCK_AND_UNRESERVE_FOR_RETURN();
#endif
            WOLFSENTRY_ERROR_RERETURN(ret);
        }
        WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP);
        ++n;
        if (mode >= 1)
             break;
    }
#ifdef WOLFSENTRY_THREADSAFE
    if (got_lock)
        WOLFSENTRY_UNLOCK_AND_UNRESERVE_FOR_RETURN();
#endif
    if (n > 0)
        WOLFSENTRY_RETURN_OK;
    else
        WOLFSENTRY_ERROR_RETURN(ALREADY);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_stale_purge(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *action_results)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_stale_purge_1(WOLFSENTRY_CONTEXT_ARGS_OUT, table, action_results, 0, 0));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_stale_purge_one(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *action_results)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_stale_purge_1(WOLFSENTRY_CONTEXT_ARGS_OUT, table, action_results, 1, 0));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_stale_purge_one_opportunistically(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *action_results)
{
    /* use "try" lock semantics. */
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_stale_purge_1(WOLFSENTRY_CONTEXT_ARGS_OUT, table, action_results, 2, 0));
}

static wolfsentry_errcode_t wolfsentry_route_stale_purge_one_unconditionally(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *action_results)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_route_stale_purge_1(WOLFSENTRY_CONTEXT_ARGS_OUT, table, action_results, 3, 0));
}

struct route_delete_filter_args {
    WOLFSENTRY_CONTEXT_ELEMENTS;
};

static wolfsentry_errcode_t wolfsentry_route_delete_for_filter(
    void *args,
    struct wolfsentry_table_ent_header *route,
    wolfsentry_action_res_t *action_results)
{
    WOLFSENTRY_CLEAR_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP);
    return wolfsentry_route_delete_0(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX2((struct route_delete_filter_args *)args),
        NULL /* caller_arg */,
        (struct wolfsentry_route_table *)route->parent_table,
        NULL /* trigger_event */,
        (struct wolfsentry_route *)route,
        action_results,
        0 /* defer_p */
        );
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_flush_table(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    wolfsentry_action_res_t *action_results)
{
    struct route_delete_filter_args args;
    wolfsentry_errcode_t ret;
    args.wolfsentry = wolfsentry;
#ifdef WOLFSENTRY_THREADSAFE
    args.thread = thread;
#endif
    WOLFSENTRY_MUTEX_OR_RETURN();
    ret = wolfsentry_table_map(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        &table->header,
        (wolfsentry_map_function_t)wolfsentry_route_delete_for_filter,
        &args,
        action_results);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

static wolfsentry_errcode_t wolfsentry_route_clear_insert_action_status(
    void *context,
    struct wolfsentry_table_ent_header *route,
    wolfsentry_action_res_t *action_results)
{
    (void)context;
    (void)action_results;
    if (WOLFSENTRY_CHECK_BITS(((struct wolfsentry_route *)route)->flags, WOLFSENTRY_ROUTE_FLAG_INSERT_ACTIONS_CALLED))
        WOLFSENTRY_CLEAR_BITS(((struct wolfsentry_route *)route)->flags, WOLFSENTRY_ROUTE_FLAG_INSERT_ACTIONS_CALLED);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_bulk_clear_insert_action_status(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    WOLFSENTRY_MUTEX_OR_RETURN();
    ret = wolfsentry_table_map(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        &wolfsentry->routes->header,
        wolfsentry_route_clear_insert_action_status,
        NULL /* context */, action_results);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

struct insert_action_args {
    WOLFSENTRY_CONTEXT_ELEMENTS;
};

static wolfsentry_errcode_t wolfsentry_route_call_insert_action(
    void *args,
    struct wolfsentry_table_ent_header *route,
    wolfsentry_action_res_t *action_results)
{
    if (((struct wolfsentry_route *)route)->parent_event && (wolfsentry_list_ent_get_len(&((struct wolfsentry_route *)route)->parent_event->insert_action_list.header) > 0)) {
        wolfsentry_errcode_t ret = wolfsentry_action_list_dispatch(
            WOLFSENTRY_CONTEXT_GET_ELEMENTS(*(struct insert_action_args *)args),
            NULL /* caller_arg */,
            ((struct wolfsentry_route *)route)->parent_event,
            NULL /* trigger_event */,
            WOLFSENTRY_ACTION_TYPE_INSERT,
            NULL /* target_route */,
            (struct wolfsentry_route_table *)route->parent_table,
            (struct wolfsentry_route *)route,
            action_results);
        if (WOLFSENTRY_ERROR_CODE_IS(ret, OK))
            WOLFSENTRY_ERROR_RERETURN(ret);
        else if (WOLFSENTRY_ERROR_CODE_IS(ret, ALREADY))
            WOLFSENTRY_RETURN_OK;
        else
            WOLFSENTRY_ERROR_RERETURN(ret);
    } else
        WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_bulk_insert_actions(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct insert_action_args args;
    WOLFSENTRY_MUTEX_OR_RETURN();
    WOLFSENTRY_CONTEXT_SET_ELEMENTS(args);
    ret = wolfsentry_table_map(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        &wolfsentry->routes->header,
        wolfsentry_route_call_insert_action,
        &args, action_results);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_private_data(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    void **private_data,
    size_t *private_data_size)
{
    struct wolfsentry_eventconfig_internal *config = (route->parent_event && route->parent_event->config) ? route->parent_event->config : &wolfsentry->config;
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    if (config->config.route_private_data_size == 0)
        WOLFSENTRY_ERROR_RETURN(DATA_MISSING);
    *private_data = (byte *)route->data + config->route_private_data_padding;
    if (private_data_size)
        *private_data_size = config->config.route_private_data_size - config->route_private_data_padding;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_flags(
    const struct wolfsentry_route *route,
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
    WOLFSENTRY_ATOMIC_UPDATE_FLAGS(route->flags, flags_to_set, flags_to_clear, flags_before, flags_after);
    WOLFSENTRY_RETURN_VOID;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_update_flags(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    wolfsentry_route_flags_t flags_to_set,
    wolfsentry_route_flags_t flags_to_clear,
    wolfsentry_route_flags_t *flags_before,
    wolfsentry_route_flags_t *flags_after,
    wolfsentry_action_res_t *action_results)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    if ((flags_to_set & (WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED|WOLFSENTRY_ROUTE_FLAG_GREENLISTED)) ==
        (WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED|WOLFSENTRY_ROUTE_FLAG_GREENLISTED))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((flags_to_set | flags_to_clear) & (WOLFSENTRY_ROUTE_FLAG_PENDING_DELETE | WOLFSENTRY_ROUTE_FLAG_IN_TABLE))
        WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);

    if ((route->flags & WOLFSENTRY_ROUTE_FLAG_IN_TABLE) && ((flags_to_set | flags_to_clear) & WOLFSENTRY_ROUTE_IMMUTABLE_FLAGS))
        WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);

    wolfsentry_route_update_flags_1(route, flags_to_set, flags_to_clear, flags_before, flags_after);
    if (action_results) {
        if (*flags_before != *flags_after)
            *action_results |= WOLFSENTRY_ACTION_RES_UPDATE;
    }
    if ((*flags_after & WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED) && (! (*flags_before & WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED)))
        WOLFSENTRY_WARN_ON_FAILURE(WOLFSENTRY_GET_TIME(&route->meta.last_penaltybox_time));
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_increment_derogatory_count(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    int count_to_add,
    int *new_derogatory_count_ptr)
{
    uint16_t new_derogatory_count;

    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;

    if (count_to_add > 0) {
        WOLFSENTRY_ATOMIC_INCREMENT_UNSIGNED_SAFELY(route->meta.derogatory_count, (unsigned)count_to_add, new_derogatory_count);
        if (new_derogatory_count == 0)
            WOLFSENTRY_ERROR_RETURN(OVERFLOW_AVERTED);
    } else {
        WOLFSENTRY_ATOMIC_DECREMENT_UNSIGNED_SAFELY(route->meta.derogatory_count, (unsigned)(-count_to_add), new_derogatory_count);
        if (new_derogatory_count == MAX_UINT_OF(route->meta.derogatory_count))
            WOLFSENTRY_ERROR_RETURN(OVERFLOW_AVERTED);
    }

    if (new_derogatory_count_ptr)
        *new_derogatory_count_ptr = (int)new_derogatory_count;

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_increment_commendable_count(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    int count_to_add,
    int *new_commendable_count_ptr)
{
    uint16_t new_commendable_count;

    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;

    if (count_to_add > 0) {
        WOLFSENTRY_ATOMIC_INCREMENT_UNSIGNED_SAFELY(route->meta.commendable_count, (unsigned)count_to_add, new_commendable_count);
        if (new_commendable_count == 0)
            WOLFSENTRY_ERROR_RETURN(OVERFLOW_AVERTED);
    } else {
        WOLFSENTRY_ATOMIC_DECREMENT_UNSIGNED_SAFELY(route->meta.commendable_count, (unsigned)(-count_to_add), new_commendable_count);
        if (new_commendable_count == MAX_UINT_OF(route->meta.commendable_count))
            WOLFSENTRY_ERROR_RETURN(OVERFLOW_AVERTED);
    }

    if (new_commendable_count_ptr)
        *new_commendable_count_ptr = (int)new_commendable_count;

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_reset_derogatory_count(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    int *old_derogatory_count_ptr)
{
    uint16_t old_derogatory_count;
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    WOLFSENTRY_ATOMIC_RESET(route->meta.derogatory_count, &old_derogatory_count);
    if (old_derogatory_count_ptr)
        *old_derogatory_count_ptr = (int)old_derogatory_count;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_reset_commendable_count(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route *route,
    int *old_commendable_count_ptr)
{
    uint16_t old_commendable_count;
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    WOLFSENTRY_ATOMIC_RESET(route->meta.commendable_count, &old_commendable_count);
    if (old_commendable_count_ptr)
        *old_commendable_count_ptr = (int)old_commendable_count;
    WOLFSENTRY_RETURN_OK;
}

/* only possible before route is inserted. */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_set_wildcard(
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

/* note copying .meta with a shared lock is racey.  if coherent results are
 * needed, a mutex is needed.  this caveat is particularly germane on 32 bit
 * targets, where the top and bottom halves of the wolfsentry_time_t's will (on
 * rare occasions) be mutually incoherent.
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_metadata(
    const struct wolfsentry_route *route,
    struct wolfsentry_route_metadata_exports *metadata)
{
    metadata->insert_time = route->meta.insert_time;
    if (sizeof(void *) == sizeof route->meta.last_hit_time) {
        metadata->last_hit_time = WOLFSENTRY_ATOMIC_LOAD(route->meta.last_hit_time);
        metadata->last_penaltybox_time = WOLFSENTRY_ATOMIC_LOAD(route->meta.last_penaltybox_time);
        metadata->purge_after = WOLFSENTRY_ATOMIC_LOAD(route->meta.purge_after);
    } else {
        /* avoid 64 bit atomic operations on 32 bit targets. */
        metadata->last_hit_time = route->meta.last_hit_time;
        metadata->last_penaltybox_time = route->meta.last_penaltybox_time;
        metadata->purge_after = route->meta.purge_after;
    }
    metadata->connection_count = WOLFSENTRY_ATOMIC_LOAD(route->meta.connection_count);
    metadata->derogatory_count = WOLFSENTRY_ATOMIC_LOAD(route->meta.derogatory_count);
    metadata->commendable_count = WOLFSENTRY_ATOMIC_LOAD(route->meta.commendable_count);
    metadata->hit_count = WOLFSENTRY_ATOMIC_LOAD(route->header.hitcount);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_reset_metadata_exports(struct wolfsentry_route_exports *route_exports) {
    route_exports->meta.purge_after = 0;
    route_exports->meta.connection_count = 0;
    route_exports->meta.derogatory_count = 0;
    route_exports->meta.commendable_count = 0;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_clear_default_event(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table)
{
    wolfsentry_errcode_t ret;
    WOLFSENTRY_MUTEX_OR_RETURN();
    if (table->default_event != NULL) {
        if ((ret = wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, table->default_event, NULL /* action_results */)) < 0)
            WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
        table->default_event = NULL;
    }
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_set_default_event(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    const char *event_label,
    int event_label_len)
{
    struct wolfsentry_event *event = NULL;
    wolfsentry_errcode_t ret;
    WOLFSENTRY_MUTEX_OR_RETURN();
    if ((ret = wolfsentry_event_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event_label, event_label_len, &event)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    if ((ret = wolfsentry_route_table_clear_default_event(WOLFSENTRY_CONTEXT_ARGS_OUT, table)) < 0) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, event, NULL /* action_results */));
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    }
    table->default_event = event;
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_get_default_event(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *table,
    char *event_label,
    int *event_label_len)
{
    if (table->default_event == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    WOLFSENTRY_SHARED_OR_RETURN();
    if (table->default_event->label_len >= *event_label_len)
        WOLFSENTRY_ERROR_UNLOCK_AND_RETURN(BUFFER_TOO_SMALL);
    memcpy(event_label, table->default_event->label, (size_t)(table->default_event->label_len + 1));
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_get_addrs(
    const struct wolfsentry_route *route,
    wolfsentry_addr_family_t *af,
    wolfsentry_addr_bits_t *local_addr_len,
    const byte **local_addr,
    wolfsentry_addr_bits_t *remote_addr_len,
    const byte **remote_addr)
{
    if (af)
        *af = route->sa_family;
    if (local_addr_len)
        *local_addr_len = WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(route);
    if (local_addr)
        *local_addr = WOLFSENTRY_ROUTE_LOCAL_ADDR(route);
    if (remote_addr_len)
        *remote_addr_len = WOLFSENTRY_ROUTE_REMOTE_ADDR_BITS(route);
    if (remote_addr)
        *remote_addr = WOLFSENTRY_ROUTE_REMOTE_ADDR(route);
    WOLFSENTRY_RETURN_OK;
}

/* note copying .flags and .meta with a shared lock is racey.  if coherent
 * results are needed, a mutex is needed.
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_export(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route *route,
    struct wolfsentry_route_exports *route_exports)
{
    wolfsentry_errcode_t ret;
    const struct wolfsentry_eventconfig_internal *config = (route->parent_event && route->parent_event->config) ? route->parent_event->config : &wolfsentry->config;
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    if (route->parent_event) {
        route_exports->parent_event_label = route->parent_event->label;
        route_exports->parent_event_label_len = route->parent_event->label_len;
    } else {
        route_exports->parent_event_label = NULL;
        route_exports->parent_event_label_len = 0;
    }
    route_exports->flags = WOLFSENTRY_ATOMIC_LOAD(route->flags);
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
        WOLFSENTRY_ERROR_RERETURN(ret);
    if (config->config.route_private_data_size == 0) {
        route_exports->private_data = NULL;
        route_exports->private_data_size = 0;
    } else {
        route_exports->private_data = (byte *)route->data + config->route_private_data_padding;
        route_exports->private_data_size = config->config.route_private_data_size - config->route_private_data_padding;
    }
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API const struct wolfsentry_event *wolfsentry_route_parent_event(const struct wolfsentry_route *route) {
    return route->parent_event;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_start(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor **cursor)
{
    int ret;
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
    if ((*cursor = (struct wolfsentry_cursor *)WOLFSENTRY_MALLOC(sizeof **cursor)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if ((ret = wolfsentry_table_cursor_init(WOLFSENTRY_CONTEXT_ARGS_OUT, *cursor)) < 0)
        goto out;
    wolfsentry_table_cursor_seek_to_head(&table->header, *cursor);
  out:
    if (ret < 0)
        WOLFSENTRY_FREE(*cursor);
    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_seek_to_head(
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor)
{
    wolfsentry_table_cursor_seek_to_head(&table->header, cursor);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_seek_to_tail(
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor)
{
    wolfsentry_table_cursor_seek_to_tail(&table->header, cursor);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_current(
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_route **route)
{
    (void)table;
    *route = (struct wolfsentry_route *)wolfsentry_table_cursor_current(cursor);
    if (*route == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_prev(
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_route **route)
{
    (void)table;
    *route = (struct wolfsentry_route *)wolfsentry_table_cursor_prev(cursor);
    if (*route == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_next(
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_route **route)
{
    (void)table;
    *route = (struct wolfsentry_route *)wolfsentry_table_cursor_next(cursor);
    if (*route == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_iterate_end(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor **cursor)
{
    (void)table;
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
    WOLFSENTRY_FREE(*cursor);
    *cursor = NULL;
    WOLFSENTRY_RETURN_OK;
}

static inline char hexdigit_ntoa(unsigned int d) {
    d &= 0xf;
    if (d < 10)
        return (char)('0' + d);
    else
        return (char)('a' + (d - 0xa));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_format_address(
    WOLFSENTRY_CONTEXT_ARGS_IN,
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
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                (wolfsentry_addr_family_t)sa_family,
                &formatter),
            OK))
    {
        wolfsentry_errcode_t ret = formatter(WOLFSENTRY_CONTEXT_ARGS_OUT, addr, addr_bits, buf, buflen);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        WOLFSENTRY_RETURN_OK;
    }

    if (sa_family == WOLFSENTRY_AF_LINK) {
        unsigned int i;
        if ((addr_bits >> 3) * 3 > (size_t)*buflen)
            WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
        for (i=0; i < (addr_bits >> 3); ++i) {
            if (i > 0)
                *buf++ = ':';
            *buf++ = hexdigit_ntoa(addr[i] >> 4);
            *buf++ = hexdigit_ntoa(addr[i]);
        }
        *buf = 0;
        *buflen = (int)(buf - buf_at_start);
        WOLFSENTRY_RETURN_OK;
    } else if (sa_family == WOLFSENTRY_AF_INET) {
        byte addr_buf[sizeof(struct in_addr)];
        memset(addr_buf, 0, sizeof addr_buf);
        memcpy(addr_buf, addr, WOLFSENTRY_BITS_TO_BYTES(addr_bits));
        if (inet_ntop(AF_INET, addr_buf, buf, (socklen_t)*buflen) == NULL)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FAILED);
        *buflen = (int)strlen(buf);
        WOLFSENTRY_RETURN_OK;
    } else if (sa_family == WOLFSENTRY_AF_INET6) {
        byte addr_buf[sizeof(struct in6_addr)];
        memset(addr_buf, 0, sizeof addr_buf);
        memcpy(addr_buf, addr, WOLFSENTRY_BITS_TO_BYTES(addr_bits));
        if (inet_ntop(AF_INET6, addr_buf, buf, (socklen_t)*buflen) == NULL)
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
    } else if (sa_family == WOLFSENTRY_AF_CAN) {
        unsigned int i;
        if (2 + (4 * 2) + 1 > (size_t)*buflen)
            WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
        *buf++ = '0';
        *buf++ = 'x';
        for (i=0; i < 4; ++i) {
            if (i < (addr_bits >> 3)) {
                *buf++ = hexdigit_ntoa(addr[i] >> 4);
                *buf++ = hexdigit_ntoa(addr[i]);
            } else {
                *buf++ = '0';
                *buf++ = '0';
            }
        }
        *buf = 0;
        *buflen = (int)(buf - buf_at_start);
        WOLFSENTRY_RETURN_OK;
    } else
        WOLFSENTRY_ERROR_RETURN(OP_NOT_SUPP_FOR_PROTO);
}

#if defined(WOLFSENTRY_PROTOCOL_NAMES) || defined(WOLFSENTRY_JSON_DUMP_UTILS) || !defined(WOLFSENTRY_NO_JSON)

struct wolfsentry_route_flag_name_map_ent {
    const wolfsentry_route_flags_t flag;
    const char *name;
};

static const struct wolfsentry_route_flag_name_map_ent wolfsentry_route_flag_names[] = {
    { WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD, "af-wild" },
    { WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD, "raddr-wild" },
    { WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD, "rport-wild" },
    { WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD, "laddr-wild" },
    { WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD, "lport-wild" },
    { WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD, "riface-wild" },
    { WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD, "liface-wild" },
    { WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS, "tcplike-port-numbers" },
    { WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN, "direction-in" },
    { WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT, "direction-out" },
    { WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED, "penalty-boxed" },
    { WOLFSENTRY_ROUTE_FLAG_GREENLISTED, "green-listed" },
    { WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_HITS, "dont-count-hits" },
    { WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_CURRENT_CONNECTIONS, "dont-count-current-connections" },
    { WOLFSENTRY_ROUTE_FLAG_PORT_RESET, "port-reset" }
};

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_flag_assoc_by_flag(wolfsentry_route_flags_t flag, const char **name) {
    const struct wolfsentry_route_flag_name_map_ent *i;
    for (i = wolfsentry_route_flag_names; i < end_ptr_of_array(wolfsentry_route_flag_names); ++i) {
        if (i->flag == flag) {
            *name = i->name;
            WOLFSENTRY_RETURN_OK;
        }
    }
    WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_flag_assoc_by_name(const char *name, int len, wolfsentry_route_flags_t *flag) {
    const struct wolfsentry_route_flag_name_map_ent *i;
    if (len < 0)
        len = (int)strlen(name);
    for (i = wolfsentry_route_flag_names; i < end_ptr_of_array(wolfsentry_route_flag_names); ++i) {
        if ((strncmp(i->name, name, (size_t)len) == 0) &&
            (i->name[len] == 0))
        {
            *flag = i->flag;
            WOLFSENTRY_RETURN_OK;
        }
    }
    WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
}

#endif /* WOLFSENTRY_PROTOCOL_NAMES || WOLFSENTRY_JSON_DUMP_UTILS || !WOLFSENTRY_NO_JSON */

/* note this rendering routine has no dependence on centijson and other
 * facilities implemented in src/json/, nor even on stdio -- it is available
 * even when defined(WOLFSENTRY_NO_JSON) and/or defined(WOLFSENTRY_NO_STDIO).
 */

#if !defined(WOLFSENTRY_NO_JSON) || defined(WOLFSENTRY_JSON_DUMP_UTILS)

static wolfsentry_errcode_t ws_itoa(int i, unsigned char **out, size_t *spc) {
    int out_chars;
    int digit_thresh;
    int neg;
    if (i < 0) {
        neg = 1;
        i = -i;
        out_chars = 2;
    } else {
        neg = 0;
        out_chars = 1;
    }
    for (digit_thresh = 10; ; digit_thresh *= 10) {
        if (i >= digit_thresh)
            ++out_chars;
        else {
            digit_thresh /= 10;
            break;
        }
        if (digit_thresh == 1000000000)
            break;
    }
    if (*spc < (size_t)out_chars)
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    (*spc) -= (size_t)out_chars;
    if (neg)
        *(*out)++ = '-';
    while (digit_thresh >= 1) {
        int quotient = i / digit_thresh;
        i %= digit_thresh;
        digit_thresh /= 10;
        *(*out)++ = (unsigned char)('0' + quotient);
    }
    WOLFSENTRY_RETURN_OK;
}

#define write_byte(b) do { if (*json_out_len == 0) { WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL); } *(*json_out)++ = (b); --(*json_out_len); } while (0)
#define write_bytes(b,l) do { size_t _l = (size_t)(l); if (*json_out_len < _l) { WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL); } memcpy(*json_out, b, _l); *json_out += _l; *json_out_len -= _l; } while (0)
#define write_string(s) do { size_t _l = strlen(s); if (*json_out_len < _l) { WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL); } memcpy(*json_out, s, _l); *json_out += _l; *json_out_len -= _l; } while (0)
#define unwrite_byte() do { --(*json_out); ++(*json_out_len); } while (0)
#define unwrite_bytes(l) do { size_t _l = (size_t)(l); (*json_out) -= _l; (*json_out_len) += _l; } while (0)

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_format_json(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route *r,
    unsigned char **json_out,
    size_t *json_out_len,
    wolfsentry_format_flags_t flags)
{
    wolfsentry_errcode_t ret;

    write_byte('{');
    if (r->parent_event) {
        write_string("\"parent-event\":\"");
        write_bytes(r->parent_event->label, r->parent_event->label_len);
        write_string("\",");
    }
    {
        const struct wolfsentry_route_flag_name_map_ent *i;
        for (i = wolfsentry_route_flag_names; i < end_ptr_of_array(wolfsentry_route_flag_names); ++i) {
            write_byte('"');
            write_string(i->name);
            write_string("\":");
            if (r->flags & i->flag)
                write_string("true");
            else
                write_string("false");
            write_byte(',');
        }
    }

#define have_r_attr(x) (! (r->flags & WOLFSENTRY_ROUTE_FLAG_ ## x ## _WILDCARD))

    if (have_r_attr(SA_FAMILY)) {
        int rendered_family = 0;
        write_string("\"family\":");
#ifdef WOLFSENTRY_PROTOCOL_NAMES
        if (! (flags & WOLFSENTRY_FORMAT_FLAG_ALWAYS_NUMERIC)) {
            struct wolfsentry_addr_family_bynumber *addr_family;
            const char *family_name;

            ret = wolfsentry_addr_family_ntop(WOLFSENTRY_CONTEXT_ARGS_OUT, r->sa_family, &addr_family, &family_name);
            if (WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
                size_t family_name_len = strlen(family_name);
                if (family_name_len + 2 > (size_t)*json_out_len)
                    ret = WOLFSENTRY_ERROR_ENCODE(BUFFER_TOO_SMALL);
                else {
                    write_byte('"');
                    write_bytes(family_name, family_name_len);
                    write_byte('"');
                    rendered_family = 1;
                }
                if (addr_family) {
                    wolfsentry_errcode_t drop_ret = wolfsentry_addr_family_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, addr_family, NULL /* action_results */ );
                    if (drop_ret < 0)
                        WOLFSENTRY_ERROR_RERETURN(drop_ret);
                }
                if (ret < 0)
                    WOLFSENTRY_ERROR_RERETURN(ret);
            }

        }
#endif
        if (! rendered_family)
            WOLFSENTRY_RERETURN_IF_ERROR(ws_itoa((int)r->sa_family, json_out, json_out_len));
        write_byte(',');
    }

    if (have_r_attr(SA_PROTO)) {
        int rendered_proto = 0;

        write_string("\"protocol\":");

#ifndef WOLFSENTRY_NO_GETPROTOBY
        if ((! (flags & WOLFSENTRY_FORMAT_FLAG_ALWAYS_NUMERIC)) &&
            ((r->sa_family == WOLFSENTRY_AF_INET) ||
             (r->sa_family == WOLFSENTRY_AF_INET6)))
        {
            char get_buf[256];
            struct protoent protoent, *p;
            /* note this is glibc-specific and non-standard; other libc
             * implementations have same name but different args.
             */
            if (getprotobynumber_r(r->sa_proto,
                                   &protoent,
                                   get_buf, sizeof get_buf,
                                   &p) == 0)
            {
                write_byte('"');
                write_string(protoent.p_name);
                write_byte('"');
                rendered_proto = 1;
            }
        }
#else
        (void)flags;
#endif /* !WOLFSENTRY_NO_GETPROTOBY */
        if (! rendered_proto)
            WOLFSENTRY_RERETURN_IF_ERROR(ws_itoa((int)r->sa_proto, json_out, json_out_len));
        write_byte(',');
    }

    if (have_r_attr(SA_REMOTE_ADDR) ||
        have_r_attr(SA_REMOTE_PORT) ||
        have_r_attr(REMOTE_INTERFACE))
    {
        write_string("\"remote\":{");

        if (have_r_attr(SA_REMOTE_ADDR)) {
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
            if (r->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK) {
                int len_in_out = (int)*json_out_len;
                write_string("\"address\":\"");
                ret = wolfsentry_route_format_address(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    r->sa_family,
                    WOLFSENTRY_ROUTE_REMOTE_ADDR(r),
                    WOLFSENTRY_ROUTE_REMOTE_ADDR_BITS(r) >> 1,
                    (char *)*json_out,
                    &len_in_out);
                WOLFSENTRY_RERETURN_IF_ERROR(ret);
                (*json_out) += len_in_out;
                *json_out_len -= (size_t)len_in_out;
                write_string("\",\"bitmask\":\"");
                len_in_out = (int)*json_out_len;
                ret = wolfsentry_route_format_address(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    r->sa_family,
                    WOLFSENTRY_ROUTE_REMOTE_ADDR(r) + WOLFSENTRY_BITS_TO_BYTES(WOLFSENTRY_ROUTE_REMOTE_ADDR_BITS(r) >> 1),
                    WOLFSENTRY_ROUTE_REMOTE_ADDR_BITS(r) >> 1,
                    (char *)*json_out,
                    &len_in_out);
                WOLFSENTRY_RERETURN_IF_ERROR(ret);
                (*json_out) += len_in_out;
                *json_out_len -= (size_t)len_in_out;
                write_string("\",");
            } else
#endif
            {
                int len_in_out = (int)*json_out_len;
                write_string("\"address\":\"");
                ret = wolfsentry_route_format_address(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    r->sa_family,
                    WOLFSENTRY_ROUTE_REMOTE_ADDR(r),
                    WOLFSENTRY_ROUTE_REMOTE_ADDR_BITS(r),
                    (char *)*json_out,
                    &len_in_out);
                WOLFSENTRY_RERETURN_IF_ERROR(ret);
                (*json_out) += len_in_out;
                *json_out_len -= (size_t)len_in_out;
                write_string("\",\"prefix-bits\":");
                WOLFSENTRY_RERETURN_IF_ERROR(ws_itoa(WOLFSENTRY_ROUTE_REMOTE_ADDR_BITS(r), json_out, json_out_len));
                write_byte(',');
            }
        }
        if (have_r_attr(SA_REMOTE_PORT)) {
            write_string("\"port\":");
            WOLFSENTRY_RERETURN_IF_ERROR(ws_itoa(WOLFSENTRY_ROUTE_REMOTE_PORT_GET(r, 0), json_out, json_out_len));
            write_byte(',');
        }
        if (have_r_attr(REMOTE_INTERFACE)) {
            write_string("\"interface\":");
            WOLFSENTRY_RERETURN_IF_ERROR(ws_itoa(r->remote.interface, json_out, json_out_len));
            write_byte(',');
        }
        unwrite_byte();
        write_string("},");
    }

    if (have_r_attr(SA_LOCAL_ADDR) ||
        have_r_attr(SA_LOCAL_PORT) ||
        have_r_attr(LOCAL_INTERFACE))
    {
        write_string("\"local\":{");

        if (have_r_attr(SA_LOCAL_ADDR)) {
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
            if (r->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK) {
                int len_in_out = (int)*json_out_len;
                write_string("\"address\":\"");
                ret = wolfsentry_route_format_address(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    r->sa_family,
                    WOLFSENTRY_ROUTE_LOCAL_ADDR(r),
                    WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(r) >> 1,
                    (char *)*json_out,
                    &len_in_out);
                WOLFSENTRY_RERETURN_IF_ERROR(ret);
                (*json_out) += len_in_out;
                *json_out_len -= (size_t)len_in_out;
                write_string("\",\"bitmask\":\"");
                len_in_out = (int)*json_out_len;
                ret = wolfsentry_route_format_address(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    r->sa_family,
                    WOLFSENTRY_ROUTE_LOCAL_ADDR(r) + WOLFSENTRY_BITS_TO_BYTES(WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(r) >> 1),
                    WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(r) >> 1,
                    (char *)*json_out,
                    &len_in_out);
                WOLFSENTRY_RERETURN_IF_ERROR(ret);
                (*json_out) += len_in_out;
                *json_out_len -= (size_t)len_in_out;
                write_string("\",");
            } else
#endif
            {
                int len_in_out = (int)*json_out_len;
                write_string("\"address\":\"");
                ret = wolfsentry_route_format_address(
                    WOLFSENTRY_CONTEXT_ARGS_OUT,
                    r->sa_family,
                    WOLFSENTRY_ROUTE_LOCAL_ADDR(r),
                    WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(r),
                    (char *)*json_out,
                    &len_in_out);
                WOLFSENTRY_RERETURN_IF_ERROR(ret);
                (*json_out) += len_in_out;
                *json_out_len -= (size_t)len_in_out;
                write_string("\",\"prefix-bits\":");
                WOLFSENTRY_RERETURN_IF_ERROR(ws_itoa(WOLFSENTRY_ROUTE_LOCAL_ADDR_BITS(r), json_out, json_out_len));
                write_byte(',');
            }
        }

        if (have_r_attr(SA_LOCAL_PORT)) {
            write_string("\"port\":");
            WOLFSENTRY_RERETURN_IF_ERROR(ws_itoa(WOLFSENTRY_ROUTE_LOCAL_PORT_GET(r, 0), json_out, json_out_len));
            write_byte(',');
        }
        if (have_r_attr(LOCAL_INTERFACE)) {
            write_string("\"interface\":");
            WOLFSENTRY_RERETURN_IF_ERROR(ws_itoa(r->local.interface, json_out, json_out_len));
            write_byte(',');
        }
        unwrite_byte();
        write_string("},");
    }

    unwrite_byte();
    write_string("}");

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_dump_json_start(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor **cursor,
    unsigned char **json_out,
    size_t *json_out_len,
    wolfsentry_format_flags_t flags)
{
    (void)flags;
    write_string("{\"wolfsentry-config-version\":1,\n\"routes\":[\n");
    WOLFSENTRY_RERETURN_IF_ERROR(
        wolfsentry_route_table_iterate_start(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            table,
            cursor));
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_dump_json_next(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor *cursor,
    unsigned char **json_out,
    size_t *json_out_len,
    wolfsentry_format_flags_t flags)
{
    struct wolfsentry_route *route;
    wolfsentry_errcode_t ret;
    unsigned char *json_out_start = *json_out;
    size_t json_out_len_start = *json_out_len;

    WOLFSENTRY_RERETURN_IF_ERROR(
        wolfsentry_route_table_iterate_current(
            table,
            cursor,
            &route));

    if (&route->header != wolfsentry_table_first(&table->header))
        write_string(",\n");

    ret = wolfsentry_route_format_json(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        route,
        json_out,
        json_out_len,
        flags);

    if (ret < 0) {
        if (WOLFSENTRY_ERROR_CODE_IS(ret, BUFFER_TOO_SMALL)) {
            *json_out = json_out_start;
            *json_out_len = json_out_len_start;
        }
    } else
      (void)wolfsentry_table_cursor_next(cursor);

    return ret;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_table_dump_json_end(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_route_table *table,
    struct wolfsentry_cursor **cursor,
    unsigned char **json_out,
    size_t *json_out_len,
    wolfsentry_format_flags_t flags)
{
    (void)flags;
    write_string("\n]}\n");
    WOLFSENTRY_RERETURN_IF_ERROR(
        wolfsentry_route_table_iterate_end(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            table,
            cursor));
    WOLFSENTRY_RETURN_OK;
}

#endif /* !WOLFSENTRY_NO_JSON || WOLFSENTRY_JSON_DUMP_UTILS */

#ifndef WOLFSENTRY_NO_STDIO_STREAMS

static wolfsentry_errcode_t wolfsentry_route_render_proto(int proto, wolfsentry_route_flags_t flags, FILE *f) {
    if (WOLFSENTRY_CHECK_BITS(flags, WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD)) {
        fprintf(f, ", proto = *");
        WOLFSENTRY_RETURN_OK;
    }
#ifdef WOLFSENTRY_NO_GETPROTOBY
    (void)flags;
#else
    if (WOLFSENTRY_CHECK_BITS(flags, WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS)) {
        char get_buf[256];
        struct protoent protoent, *p;

        if (getprotobynumber_r(
                proto,
                &protoent,
                get_buf, sizeof get_buf,
                &p) != 0)
        {
            p = NULL;
        }
        if (p)
            fprintf(f, ", proto = %s", p->p_name);
        else
            fprintf(f, ", proto = %d", proto);
    } else
#endif /* !WOLFSENTRY_NO_GETPROTOBY */
    {
        fprintf(f, ", proto = %d", proto);
    }
    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_render_address(WOLFSENTRY_CONTEXT_ARGS_IN, int sa_family, unsigned int addr_bits, const byte *addr, size_t addr_bytes, FILE *f) {
    char fmt_buf[256];
    wolfsentry_addr_family_formatter_t formatter;

    if (WOLFSENTRY_ERROR_CODE_IS(
            wolfsentry_addr_family_get_formatter(
                WOLFSENTRY_CONTEXT_ARGS_OUT,
                (wolfsentry_addr_family_t)sa_family,
                &formatter),
            OK))
    {
        int fmt_buf_len = (int)sizeof fmt_buf;
        wolfsentry_errcode_t ret = formatter(WOLFSENTRY_CONTEXT_ARGS_OUT, addr, addr_bits, fmt_buf, &fmt_buf_len);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        if (fwrite(fmt_buf, 1, (size_t)fmt_buf_len, f) != (size_t)fmt_buf_len)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
        WOLFSENTRY_RETURN_OK;
    }

    if (sa_family == WOLFSENTRY_AF_LINK) {
        unsigned int i;
        for (i=0; i < (addr_bits >> 3); ++i) {
            if (fprintf(f, "%s%02x", i ? ":" : "", (unsigned int)addr[i]) < 0)
                WOLFSENTRY_ERROR_RETURN(IO_FAILED);
        }
    } else if (sa_family == WOLFSENTRY_AF_INET) {
        byte addr_buf[4];
        if (addr_bytes > sizeof addr_buf)
            WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
        memset(addr_buf, 0, sizeof addr_buf);
        memcpy(addr_buf, addr, addr_bytes);
        if (inet_ntop(AF_INET, addr_buf, fmt_buf, sizeof fmt_buf) == NULL)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FAILED);
        if (fprintf(f, "%s/%u", fmt_buf, addr_bits) < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    } else if (sa_family == WOLFSENTRY_AF_INET6) {
        byte addr_buf[16];
        if (addr_bytes > sizeof addr_buf)
            WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
        memset(addr_buf, 0, sizeof addr_buf);
        memcpy(addr_buf, addr, addr_bytes);
        if (inet_ntop(AF_INET6, addr_buf, fmt_buf, sizeof fmt_buf) == NULL)
            WOLFSENTRY_ERROR_RETURN(SYS_OP_FAILED);
        if (fprintf(f, "[%s]/%u", fmt_buf, addr_bits) < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    } else if (sa_family == WOLFSENTRY_AF_LOCAL) {
        if (fprintf(f, "\"%.*s\"", (int)addr_bytes, addr) < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    } else if (sa_family == WOLFSENTRY_AF_CAN) {
        switch(WOLFSENTRY_BITS_TO_BYTES(addr_bits)) {
        case 4:
            if (fprintf(f, "\"0x%02x%02x%02x%02x\"", addr[0], addr[1], addr[2], addr[3]) < 0)
                WOLFSENTRY_ERROR_RETURN(IO_FAILED);
            break;
        case 3:
            if (fprintf(f, "\"0x%02x%02x%02x00\"", addr[0], addr[1], addr[2]) < 0)
                WOLFSENTRY_ERROR_RETURN(IO_FAILED);
            break;
        case 2:
            if (fprintf(f, "\"0x%02x%02x0000\"", addr[0], addr[1]) < 0)
                WOLFSENTRY_ERROR_RETURN(IO_FAILED);
            break;
        case 1:
            if (fprintf(f, "\"0x%02x000000\"", addr[0]) < 0)
                WOLFSENTRY_ERROR_RETURN(IO_FAILED);
            break;
        default:
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
        }
    } else
        WOLFSENTRY_ERROR_RETURN(OP_NOT_SUPP_FOR_PROTO);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_render_flags(wolfsentry_route_flags_t flags, FILE *f) {
    unsigned mask;
    wolfsentry_route_flags_t masked_flags;
    int already = 0;
    if (! flags) {
        if (fputs("{}", f) < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
        WOLFSENTRY_RETURN_OK;
    }
    if (fputs("{", f) < 0)
        WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    for (mask = 1; mask; mask <<= 1) {
        const char *rendername = NULL;
        masked_flags = flags & mask;
        if (! masked_flags)
            continue;
#define ROUTE_FLAG_CASE(enumname, renderval) case WOLFSENTRY_ROUTE_FLAG_ ## enumname: rendername = (renderval); break
        switch (masked_flags) {
            ROUTE_FLAG_CASE(SA_FAMILY_WILDCARD, "*F");
            ROUTE_FLAG_CASE(SA_REMOTE_ADDR_WILDCARD, "*RA");
            ROUTE_FLAG_CASE(SA_PROTO_WILDCARD, "*Pr");
            ROUTE_FLAG_CASE(SA_LOCAL_PORT_WILDCARD, "*LP");
            ROUTE_FLAG_CASE(SA_LOCAL_ADDR_WILDCARD, "*LA");
            ROUTE_FLAG_CASE(SA_REMOTE_PORT_WILDCARD, "*RP");
            ROUTE_FLAG_CASE(REMOTE_INTERFACE_WILDCARD, "*RI");
            ROUTE_FLAG_CASE(LOCAL_INTERFACE_WILDCARD, "*LI");
            ROUTE_FLAG_CASE(PARENT_EVENT_WILDCARD, "*E");
            ROUTE_FLAG_CASE(TCPLIKE_PORT_NUMBERS, "Tcplike");
            ROUTE_FLAG_CASE(DIRECTION_IN, "In");
            ROUTE_FLAG_CASE(DIRECTION_OUT, "Out");
            ROUTE_FLAG_CASE(REMOTE_ADDR_BITMASK, "BMR");
            ROUTE_FLAG_CASE(LOCAL_ADDR_BITMASK, "BML");
            ROUTE_FLAG_CASE(IN_TABLE, "Res");
            ROUTE_FLAG_CASE(PENDING_DELETE, "D");
            ROUTE_FLAG_CASE(INSERT_ACTIONS_CALLED, "Ins");
            ROUTE_FLAG_CASE(DELETE_ACTIONS_CALLED, "Da");
            ROUTE_FLAG_CASE(PENALTYBOXED, "Pbox");
            ROUTE_FLAG_CASE(GREENLISTED, "Glist");
            ROUTE_FLAG_CASE(DONT_COUNT_HITS, "NoHits");
            ROUTE_FLAG_CASE(DONT_COUNT_CURRENT_CONNECTIONS, "NoConnTrk");
            ROUTE_FLAG_CASE(PORT_RESET, "PortRst");
        case WOLFSENTRY_ROUTE_FLAG_NONE: /* silence -Wswitch */
            break;
        }
#undef ROUTE_FLAG_CASE
        if (already) {
            if (fputc(',', f) < 0)
                WOLFSENTRY_ERROR_RETURN(IO_FAILED);
        } else
            already = 1;
        if (rendername == NULL) {
            if (fprintf(stderr, "unk-0x%x", masked_flags) < 0)
                WOLFSENTRY_ERROR_RETURN(IO_FAILED);
        } else {
            if (fputs(rendername, f) < 0)
                WOLFSENTRY_ERROR_RETURN(IO_FAILED);
        }
    }
    if (fputs("}", f) < 0)
        WOLFSENTRY_ERROR_RETURN(IO_FAILED);

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_render_endpoint(WOLFSENTRY_CONTEXT_ARGS_IN, const struct wolfsentry_route *r, int sa_local_p, FILE *f) {
    const struct wolfsentry_route_endpoint *e = (sa_local_p ? &r->local : &r->remote);
    size_t addr_bytes = (size_t)(sa_local_p ? WOLFSENTRY_ROUTE_LOCAL_ADDR_BYTES(r) : WOLFSENTRY_ROUTE_REMOTE_ADDR_BYTES(r));
    const byte *addr = (sa_local_p ? WOLFSENTRY_ROUTE_LOCAL_ADDR(r) : WOLFSENTRY_ROUTE_REMOTE_ADDR(r));

    if (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD)) {
        if (fputs("*", stdout) < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    }
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    else if (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK) : (r->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK)) {
        wolfsentry_errcode_t ret = wolfsentry_route_render_address(WOLFSENTRY_CONTEXT_ARGS_OUT, r->sa_family, e->addr_len >> 1, addr, addr_bytes, f);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        if (fprintf(f, "&") < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
        ret = wolfsentry_route_render_address(WOLFSENTRY_CONTEXT_ARGS_OUT, r->sa_family, e->addr_len >> 1, addr + WOLFSENTRY_BITS_TO_BYTES(e->addr_len >> 1), addr_bytes, f);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
    }
#endif
    else {
        wolfsentry_errcode_t ret = wolfsentry_route_render_address(WOLFSENTRY_CONTEXT_ARGS_OUT, r->sa_family, e->addr_len, addr, addr_bytes, f);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
    }

    if (! (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD))) {
        if (fprintf(f, "%%%d", e->interface) < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    }

    if (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD)) {
        if (fprintf(f, ":*") < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    } else {
        if (fprintf(f, ":%d", (int)e->sa_port) < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    }

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_render(WOLFSENTRY_CONTEXT_ARGS_IN, const struct wolfsentry_route *r, FILE *f) {
    wolfsentry_errcode_t ret = wolfsentry_route_render_endpoint(WOLFSENTRY_CONTEXT_ARGS_OUT, r, 0 /* sa_local_p */, f);

#ifndef WOLFSENTRY_PROTOCOL_NAMES
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
#endif

    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    if (fprintf(f, " %s-%s ",
                (r->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT) ? "<" : "",
                (r->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN) ? ">" : "") < 0)
        WOLFSENTRY_ERROR_RETURN(IO_FAILED);

    if ((ret = wolfsentry_route_render_endpoint(WOLFSENTRY_CONTEXT_ARGS_OUT, r, 1 /* sa_local_p */, f)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    if (WOLFSENTRY_CHECK_BITS(r->flags, WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD)) {
        if (fprintf(f, ", AF = *") < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    } else {
#ifdef WOLFSENTRY_PROTOCOL_NAMES
        struct wolfsentry_addr_family_bynumber *addr_family;
        const char *family_name;
        ret = wolfsentry_addr_family_ntop(WOLFSENTRY_CONTEXT_ARGS_OUT, r->sa_family, &addr_family, &family_name);
        if (WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
            if (fprintf(f, ", AF = %s", family_name) < 0)
                ret = WOLFSENTRY_ERROR_ENCODE(IO_FAILED);
            if (addr_family) {
                wolfsentry_errcode_t drop_ret = wolfsentry_addr_family_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, addr_family, NULL /* action_results */ );
                if (drop_ret < 0)
                    WOLFSENTRY_ERROR_RERETURN(drop_ret);
            }
            if (ret < 0)
                WOLFSENTRY_ERROR_RERETURN(ret);
        } else
#endif
        {
            if (fprintf(f, ", AF = %d", r->sa_family) < 0)
                WOLFSENTRY_ERROR_RETURN(IO_FAILED);
        }
    }

    wolfsentry_route_render_proto(r->sa_proto, r->flags, f);

    if (r->parent_event != NULL) {
        if (fprintf(f, ", ev = \"%.*s\"%s", (int)r->parent_event->label_len, r->parent_event->label, WOLFSENTRY_CHECK_BITS(r->flags, WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD) ? "[*]" : "") < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    } else if (WOLFSENTRY_CHECK_BITS(r->flags, WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD)) {
        if (fprintf(f, ", ev = [*]") < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    } else {
        if (fprintf(f, ", ev = (none)") < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    }

    if (fputs(", flags=", f) < 0)
        WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    WOLFSENTRY_RERETURN_IF_ERROR(wolfsentry_route_render_flags(r->flags, f));

    if (fprintf(f, ", id=%u\n", (unsigned int)r->header.id) < 0)
        WOLFSENTRY_ERROR_RETURN(IO_FAILED);

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_route_exports_render_endpoint(WOLFSENTRY_CONTEXT_ARGS_IN, const struct wolfsentry_route_exports *r, int sa_local_p, FILE *f) {
    const struct wolfsentry_route_endpoint *e = (sa_local_p ? &r->local : &r->remote);
    size_t addr_bytes = (size_t)(sa_local_p ? WOLFSENTRY_ROUTE_LOCAL_ADDR_BYTES(r) : WOLFSENTRY_ROUTE_REMOTE_ADDR_BYTES(r));
    const byte *addr = (sa_local_p ? r->local_address : r->remote_address);

    if (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD)) {
        if (fputs("*", stdout) < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    }
#ifdef WOLFSENTRY_ADDR_BITMASK_MATCHING
    else if (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_ADDR_BITMASK) : (r->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_ADDR_BITMASK)) {
        wolfsentry_errcode_t ret = wolfsentry_route_render_address(WOLFSENTRY_CONTEXT_ARGS_OUT, r->sa_family, e->addr_len >> 1, addr, addr_bytes, f);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
        if (fprintf(f, "&") < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
        ret = wolfsentry_route_render_address(WOLFSENTRY_CONTEXT_ARGS_OUT, r->sa_family, e->addr_len >> 1, addr + WOLFSENTRY_BITS_TO_BYTES(e->addr_len >> 1), addr_bytes, f);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
    }
#endif
    else {
        wolfsentry_errcode_t ret = wolfsentry_route_render_address(WOLFSENTRY_CONTEXT_ARGS_OUT, r->sa_family, e->addr_len, addr, addr_bytes, f);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
    }

    if (! (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD))) {
        if (fprintf(f, "%%%d", e->interface) < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    }

    if (sa_local_p ? (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD) : (r->flags & WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD)) {
        if (fprintf(f, ":*") < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    } else {
        if (fprintf(f, ":%d", (int)e->sa_port) < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    }

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_route_exports_render(WOLFSENTRY_CONTEXT_ARGS_IN, const struct wolfsentry_route_exports *r, FILE *f) {
    wolfsentry_errcode_t ret = wolfsentry_route_exports_render_endpoint(WOLFSENTRY_CONTEXT_ARGS_OUT, r, 0 /* sa_local_p */, f);

#ifndef WOLFSENTRY_PROTOCOL_NAMES
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
#endif

    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    if (fprintf(f, " %s-%s ",
                (r->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT) ? "<" : "",
                (r->flags & WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN) ? ">" : "") < 0)
        WOLFSENTRY_ERROR_RETURN(IO_FAILED);

    if ((ret = wolfsentry_route_exports_render_endpoint(WOLFSENTRY_CONTEXT_ARGS_OUT, r, 1 /* sa_local_p */, f)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    if (WOLFSENTRY_CHECK_BITS(r->flags, WOLFSENTRY_ROUTE_FLAG_SA_FAMILY_WILDCARD)) {
        if (fprintf(f, ", AF = *") < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    } else {
#ifdef WOLFSENTRY_PROTOCOL_NAMES
        struct wolfsentry_addr_family_bynumber *addr_family;
        const char *family_name;
        ret = wolfsentry_addr_family_ntop(WOLFSENTRY_CONTEXT_ARGS_OUT, r->sa_family, &addr_family, &family_name);
        if (WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
            if (fprintf(f, ", AF = %s", family_name) < 0)
                WOLFSENTRY_ERROR_RETURN(IO_FAILED);
            if (addr_family) {
                if ((ret = wolfsentry_addr_family_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, addr_family, NULL /* action_results */ )) < 0)
                    WOLFSENTRY_ERROR_RERETURN(ret);
            }
        } else
#endif
        {
            if (fprintf(f, ", AF = %d", r->sa_family) < 0)
                WOLFSENTRY_ERROR_RETURN(IO_FAILED);
        }
    }

    wolfsentry_route_render_proto(r->sa_proto, r->flags, f);

    if (r->parent_event_label_len > 0) {
        if (fprintf(f, ", ev = \"%.*s\"%s", (int)r->parent_event_label_len, r->parent_event_label, WOLFSENTRY_CHECK_BITS(r->flags, WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD) ? "[*]" : "") < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    } else if (WOLFSENTRY_CHECK_BITS(r->flags, WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD)) {
        if (fprintf(f, ", ev = [*]") < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    } else {
        if (fprintf(f, ", ev = (none)") < 0)
            WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    }

    if (fputs(", flags=", f) < 0)
        WOLFSENTRY_ERROR_RETURN(IO_FAILED);
    WOLFSENTRY_RERETURN_IF_ERROR(wolfsentry_route_render_flags(r->flags, f));

    WOLFSENTRY_RETURN_OK;
}

#endif /* !WOLFSENTRY_NO_STDIO_STREAMS */

static wolfsentry_errcode_t wolfsentry_route_table_reset(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *table)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    WOLFSENTRY_TABLE_HEADER_RESET(*table);
    ((struct wolfsentry_route_table *)table)->last_af_wildcard_route = NULL;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_route_table_init(
    struct wolfsentry_route_table *route_table)
{
    WOLFSENTRY_TABLE_HEADER_RESET(route_table->header);
    route_table->header.cmp_fn = wolfsentry_route_key_cmp;
    route_table->header.reset_fn = wolfsentry_route_table_reset;
    route_table->header.free_fn = wolfsentry_route_drop_reference_generic;
    route_table->header.ent_type = WOLFSENTRY_OBJECT_TYPE_ROUTE;
    route_table->highest_priority_route_in_table = MAX_UINT_OF(wolfsentry_priority_t);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_route_table_clone_header(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags)
{
    wolfsentry_errcode_t ret;

    (void)wolfsentry;

    if (src_table->ent_type != WOLFSENTRY_OBJECT_TYPE_ROUTE)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    ((struct wolfsentry_route_table *)dest_table)->max_purgeable_routes =
        ((struct wolfsentry_route_table *)src_table)->max_purgeable_routes;
    ((struct wolfsentry_route_table *)dest_table)->default_policy =
        ((struct wolfsentry_route_table *)src_table)->default_policy;

    if (((struct wolfsentry_route_table *)src_table)->default_event != NULL) {
        struct wolfsentry_event *default_event;
        if (((struct wolfsentry_route_table *)dest_table)->default_event != NULL) {
            WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(
                                           WOLFSENTRY_CONTEXT_ARGS_OUT_EX(dest_context),
                                           ((struct wolfsentry_route_table *)dest_table)->default_event, NULL /* action_results */));
            ((struct wolfsentry_route_table *)dest_table)->default_event = NULL;
        }
        if ((ret = wolfsentry_event_get_reference(
                 dest_context,
#ifdef WOLFSENTRY_THREADSAFE
                 NULL /* thread_context */,
#endif
                 ((struct wolfsentry_route_table *)src_table)->default_event->label,
                 ((struct wolfsentry_route_table *)src_table)->default_event->label_len,
                 &default_event)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
        ((struct wolfsentry_route_table *)dest_table)->default_event = default_event;
    }

    if (((struct wolfsentry_route_table *)src_table)->fallthrough_route != NULL) {
        if (((struct wolfsentry_route_table *)dest_table)->fallthrough_route != NULL) {
            WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(
                                           WOLFSENTRY_CONTEXT_ARGS_OUT_EX(dest_context),
                                           ((struct wolfsentry_route_table *)dest_table)->fallthrough_route, NULL /* action_results */));
        }
        ((struct wolfsentry_route_table *)dest_table)->fallthrough_route = ((struct wolfsentry_route_table *)src_table)->fallthrough_route;
        WOLFSENTRY_REFCOUNT_INCREMENT(((struct wolfsentry_route_table *)dest_table)->fallthrough_route->header.refcount, ret);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
    }

    if (WOLFSENTRY_CHECK_BITS(flags, WOLFSENTRY_CLONE_FLAG_NO_ROUTES))
        WOLFSENTRY_RETURN_OK;

    ((struct wolfsentry_route_table *)dest_table)->highest_priority_route_in_table =
        ((struct wolfsentry_route_table *)src_table)->highest_priority_route_in_table;

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL_VOID wolfsentry_route_table_free(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table **route_table)
{
    if ((*route_table)->fallthrough_route != NULL) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_drop_reference_1(WOLFSENTRY_CONTEXT_ARGS_OUT, (*route_table)->fallthrough_route, NULL /* action_results */));
        (*route_table)->fallthrough_route = NULL;
    }
    if ((*route_table)->default_event != NULL) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_event_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, (*route_table)->default_event, NULL /* action_results */));
        (*route_table)->default_event = NULL;
    }

    WOLFSENTRY_FREE(*route_table);
    *route_table = NULL;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_route_copy_metadata(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_route_table *from_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_route_table *to_table)
{
    struct wolfsentry_route *from_i, *to_i;

    WOLFSENTRY_HAVE_MUTEX_OR_RETURN();
    WOLFSENTRY_HAVE_MUTEX_OR_RETURN_EX(dest_context);

    for (from_i = (struct wolfsentry_route *)from_table->header.head,
             to_i = (struct wolfsentry_route *)to_table->header.head;
         from_i && to_i;
         /* pointers are advanced inside the loop. */)
    {
        if (from_i->header.id == to_i->header.id) {
            to_i->flags = from_i->flags;
            to_i->meta = from_i->meta;
        } else {
            int cmpret = wolfsentry_route_key_cmp_1(from_i, to_i, 0 /* match_wildcards_p */, NULL /* inexact_matches */);
            if (cmpret < 0) {
                from_i = (struct wolfsentry_route *)(from_i->header.next);
                continue;
            } else if (cmpret > 0) {
                to_i = (struct wolfsentry_route *)(to_i->header.next);
                continue;
            }
            /* else identical routes have different IDs, which means the new
             * route was loaded from scratch and metadata shouldn't be
             * copied.
             */
        }

        from_i = (struct wolfsentry_route *)(from_i->header.next);
        to_i = (struct wolfsentry_route *)(to_i->header.next);
    }

    WOLFSENTRY_RETURN_OK;
}
