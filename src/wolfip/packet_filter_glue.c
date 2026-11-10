/*
 * wolfip/packet_filter_glue.c
 *
 * Copyright (C) 2024-2025 wolfSSL Inc.
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

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include <wolfsentry/wolfsentry.h>
#include <wolfsentry/wolfsentry_wolfip.h>

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_WOLFIP_PACKET_FILTER_GLUE_C

#ifndef __STRICT_ANSI__
    #define __F__ __FUNCTION__
#endif

#ifndef WOLFIP_CONFIG_HEADER
#define WOLFIP_CONFIG_HEADER "../../../wolfip/config.h"
#endif
#include WOLFIP_CONFIG_HEADER

#include <wolfip-filter.h>
#include <wolfip.h>

#if CONFIG_IPFILTER

static struct wolfsentry_context *wolfip_filter_context;
static uint32_t wolfip_mask_eth;
static uint32_t wolfip_mask_ip;
static uint32_t wolfip_mask_icmp;
static uint32_t wolfip_mask_tcp;
static uint32_t wolfip_mask_udp;
static int wolfip_cleanup_registered;

static int wolfip_filter_with_wolfsentry(void *arg, const struct wolfIP_filter_event *event);

#ifdef WOLFSENTRY_PACKET_FILTER_FAIL_OPEN
#define WOLFIP_FAIL_VERDICT 0
#define WOLFIP_FAIL_VERDICT_STR "passing"
#else
#define WOLFIP_FAIL_VERDICT (-WOLFIP_EACCES)
#define WOLFIP_FAIL_VERDICT_STR "denying"
#endif

#define WOLFIP_MAPPED_COMMON (WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING) | \
                              WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING) | \
                              WOLFIP_FILT_MASK(WOLFIP_FILT_INBOUND_ERR) | \
                              WOLFIP_FILT_MASK(WOLFIP_FILT_OUTBOUND_ERR))
#define WOLFIP_MAPPED_UNREACHABLE (WOLFIP_FILT_MASK(WOLFIP_FILT_ADDR_UNREACHABLE) | \
                                   WOLFIP_FILT_MASK(WOLFIP_FILT_PORT_UNREACHABLE))
#define WOLFIP_MAPPED_SOCKET (WOLFIP_FILT_MASK(WOLFIP_FILT_BINDING) | \
                              WOLFIP_FILT_MASK(WOLFIP_FILT_DISSOCIATE))
#define WOLFIP_MAPPED_LISTEN (WOLFIP_FILT_MASK(WOLFIP_FILT_LISTENING) | \
                              WOLFIP_FILT_MASK(WOLFIP_FILT_STOP_LISTENING))
#define WOLFIP_MAPPED_ETH WOLFIP_MAPPED_COMMON
#define WOLFIP_MAPPED_IP (WOLFIP_MAPPED_COMMON | WOLFIP_MAPPED_UNREACHABLE)
#define WOLFIP_MAPPED_ICMP (WOLFIP_MAPPED_COMMON | WOLFIP_MAPPED_UNREACHABLE | WOLFIP_MAPPED_SOCKET)
#define WOLFIP_MAPPED_UDP (WOLFIP_MAPPED_ICMP | WOLFIP_MAPPED_LISTEN)
#define WOLFIP_MAPPED_TCP (WOLFIP_MAPPED_COMMON | WOLFIP_MAPPED_SOCKET | WOLFIP_MAPPED_LISTEN | \
                           WOLFIP_FILT_MASK(WOLFIP_FILT_PORT_UNREACHABLE) | \
                           WOLFIP_FILT_MASK(WOLFIP_FILT_ACCEPTING) | \
                           WOLFIP_FILT_MASK(WOLFIP_FILT_CONNECTING) | \
                           WOLFIP_FILT_MASK(WOLFIP_FILT_REMOTE_RESET) | \
                           WOLFIP_FILT_MASK(WOLFIP_FILT_CLOSED) | \
                           WOLFIP_FILT_MASK(WOLFIP_FILT_CLOSE_WAIT))

#define WOLFIP_WARN_EXTRA_SLOTS 4U

/* values 0-255 (every reason, and the small ip_proto values) each get a bit;
 * others claim an exact-value slot, and once the slots run out, one line says so. */
struct wolfip_warn_latch {
    uint32_t bits[8];
    int extra[WOLFIP_WARN_EXTRA_SLOTS]; /* 0 marks a free slot; only values outside 0-255 land here. */
    uint32_t overflow_logged;
};

static struct wolfip_warn_latch wolfip_warned_eth;
static struct wolfip_warn_latch wolfip_warned_ip;
static struct wolfip_warn_latch wolfip_warned_tcp;
static struct wolfip_warn_latch wolfip_warned_udp;
static struct wolfip_warn_latch wolfip_warned_icmp;
static struct wolfip_warn_latch wolfip_warned_proto;

/* filter callbacks can run concurrently, so each claim is an atomic bit set, reads included. */
static int wolfip_warn_latch_claim(uint32_t *word, uint32_t bit)
{
#ifdef WOLFSENTRY_THREADSAFE
    uint32_t pre = WOLFSENTRY_ATOMIC_LOAD(*word);
    for (;;) {
        if (pre & bit)
            return 0;
        if (WOLFSENTRY_ATOMIC_CMPXCHG(word, &pre, pre | bit, 0 /* weak */, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
            return 1;
    }
#else
    if (*word & bit)
        return 0;
    *word |= bit;
    return 1;
#endif
}

/* a slot is written once, from free to its value, so every caller scanning in order agrees on it. */
static int wolfip_warn_slot_claim(int *slot, int value)
{
#ifdef WOLFSENTRY_THREADSAFE
    int expected = 0;
    return WOLFSENTRY_ATOMIC_CMPXCHG(slot, &expected, value, 0 /* weak */, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
#else
    if (*slot != 0)
        return 0;
    *slot = value;
    return 1;
#endif
}

/* reached only on wolfIP version skew, as install rejects unmapped mask bits;
 * warn once per value rather than once per packet.
 */
static int wolfip_unmapped_verdict(struct wolfip_warn_latch *warned, const char *what, int value)
{
    unsigned int i;
    int warn = 0;

    if ((value >= 0) && ((unsigned int)value < sizeof warned->bits * 8U))
        warn = wolfip_warn_latch_claim(&warned->bits[(unsigned int)value / 32U], 1U << ((unsigned int)value % 32U));
    else {
        for (i = 0; i < WOLFIP_WARN_EXTRA_SLOTS; ++i) {
            if (WOLFSENTRY_ATOMIC_LOAD(warned->extra[i]) == value)
                break;
            if (wolfip_warn_slot_claim(&warned->extra[i], value)) {
                warn = 1;
                break;
            }
            if (WOLFSENTRY_ATOMIC_LOAD(warned->extra[i]) == value)
                break;
        }
        if ((i == WOLFIP_WARN_EXTRA_SLOTS) && wolfip_warn_latch_claim(&warned->overflow_logged, 1U))
            WOLFSENTRY_WARN("wolfIP filter: further unmapped %s values are not logged\n", what);
    }
    if (warn)
        WOLFSENTRY_WARN("wolfIP filter: " WOLFIP_FAIL_VERDICT_STR " unmapped %s %d\n", what, value);
    return WOLFIP_FAIL_VERDICT;
}

static wolfsentry_errcode_t wolfip_apply_masks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t new_mask_eth,
    uint32_t new_mask_ip,
    uint32_t new_mask_icmp,
    uint32_t new_mask_tcp,
    uint32_t new_mask_udp);

static byte wolfip_if_idx_to_byte(unsigned int if_idx)
{
    return (if_idx > 0xffU) ? 0xffU : (byte)if_idx;
}

static int wolfip_is_direction_out(enum wolfIP_filter_reason reason)
{
    switch (reason) {
    case WOLFIP_FILT_SENDING:
    case WOLFIP_FILT_CONNECTING:
    case WOLFIP_FILT_DISSOCIATE:
    case WOLFIP_FILT_OUTBOUND_ERR:
    case WOLFIP_FILT_CLOSED:
        return 1;
    default:
        return 0;
    }
}

static void wolfip_set_ipv4_sockaddrs(
    struct wolfsentry_sockaddr *remote,
    struct wolfsentry_sockaddr *local,
    const struct wolfIP_filter_event *event,
    int outbound)
{
    uint32_t remote_ip = outbound ? event->meta.dst_ip : event->meta.src_ip;
    uint32_t local_ip = outbound ? event->meta.src_ip : event->meta.dst_ip;

    remote->sa_family = WOLFSENTRY_AF_INET;
    remote->addr_len = sizeof(remote_ip) * 8;
    memcpy(&remote->addr, &remote_ip, sizeof remote_ip);
    remote->sa_port = 0;
    remote->interface = wolfip_if_idx_to_byte(event->if_idx);

    local->sa_family = WOLFSENTRY_AF_INET;
    local->addr_len = sizeof(local_ip) * 8;
    memcpy(&local->addr, &local_ip, sizeof local_ip);
    local->sa_port = 0;
    local->interface = wolfip_if_idx_to_byte(event->if_idx);
}

static void wolfip_set_link_sockaddrs(
    struct wolfsentry_sockaddr *remote,
    struct wolfsentry_sockaddr *local,
    const struct wolfIP_filter_event *event,
    int outbound)
{
    const uint8_t *remote_mac = outbound ? event->meta.dst_mac : event->meta.src_mac;
    const uint8_t *local_mac = outbound ? event->meta.src_mac : event->meta.dst_mac;

    remote->sa_family = WOLFSENTRY_AF_LINK;
    remote->addr_len = sizeof(event->meta.src_mac) * 8;
    memcpy(&remote->addr, remote_mac, sizeof(event->meta.src_mac));
    remote->sa_port = 0;
    remote->sa_proto = event->meta.eth_type;
    remote->interface = wolfip_if_idx_to_byte(event->if_idx);

    local->sa_family = WOLFSENTRY_AF_LINK;
    local->addr_len = sizeof(event->meta.src_mac) * 8;
    memcpy(&local->addr, local_mac, sizeof(event->meta.src_mac));
    local->sa_port = 0;
    local->sa_proto = event->meta.eth_type;
    local->interface = wolfip_if_idx_to_byte(event->if_idx);
}

static int wolfip_action_rejects(wolfsentry_action_res_t action_results)
{
    if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT))
        return 1;
    if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_PORT_RESET))
        return 1;
    return 0;
}

static int wolfip_dispatch_event(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_route_flags_t route_flags,
    wolfsentry_action_res_t *action_results,
    struct wolfsentry_sockaddr *remote,
    struct wolfsentry_sockaddr *local,
    const struct wolfIP_filter_event *event)
{
    wolfsentry_errcode_t ws_ret;
    WOLFSENTRY_THREAD_HEADER_DECLS

    if (wolfsentry == NULL)
        return WOLFIP_FAIL_VERDICT;

    if (WOLFSENTRY_THREAD_HEADER_INIT(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        return -WOLFIP_EACCES;

    ws_ret = wolfsentry_route_event_dispatch_with_inited_result(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            remote,
            local,
            route_flags,
            NULL /* event_label */,
            0,
            (void *)event,
            NULL,
            NULL,
            action_results);

    WOLFSENTRY_WARN_ON_FAILURE(ws_ret);

    if (WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        return -WOLFIP_EACCES;

    /* fail closed: a failed dispatch leaves no trustworthy verdict. */
    if (WOLFSENTRY_IS_FAILURE(ws_ret))
        return -WOLFIP_EACCES;

    if (wolfip_action_rejects(*action_results))
        return -WOLFIP_EACCES;

    return 0;
}

static int wolfip_filter_ethernet(
    struct wolfsentry_context *wolfsentry,
    const struct wolfIP_filter_event *event)
{
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    int outbound = 0;
    int ret;
    WOLFSENTRY_STACKBUF(
        struct wolfsentry_sockaddr,
        addr,
        sizeof(event->meta.src_mac),
        remote);
    WOLFSENTRY_STACKBUF(
        struct wolfsentry_sockaddr,
        addr,
        sizeof(event->meta.src_mac),
        local);

    switch (event->reason) {
    case WOLFIP_FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_RECEIVED;
        break;
    case WOLFIP_FILT_SENDING:
        outbound = 1;
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SENDING;
        break;
    case WOLFIP_FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case WOLFIP_FILT_OUTBOUND_ERR:
        outbound = 1;
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    default:
        return wolfip_unmapped_verdict(&wolfip_warned_eth, "event reason", (int)event->reason);
    }

    wolfip_set_link_sockaddrs(&remote.remote, &local.local, event, outbound);
    ret = wolfip_dispatch_event(wolfsentry, route_flags, &action_results, &remote.remote, &local.local, event);
    return ret;
}

static int wolfip_filter_ipv4(
    struct wolfsentry_context *wolfsentry,
    const struct wolfIP_filter_event *event)
{
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    int outbound = 0;
    int ret;
    WOLFSENTRY_STACKBUF(
        struct wolfsentry_sockaddr,
        addr,
        sizeof(event->meta.src_ip),
        remote);
    WOLFSENTRY_STACKBUF(
        struct wolfsentry_sockaddr,
        addr,
        sizeof(event->meta.src_ip),
        local);
    switch (event->reason) {
    case WOLFIP_FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_RECEIVED;
        break;
    case WOLFIP_FILT_SENDING:
        outbound = 1;
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SENDING;
        break;
    case WOLFIP_FILT_ADDR_UNREACHABLE:
    case WOLFIP_FILT_PORT_UNREACHABLE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE;
        break;
    case WOLFIP_FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case WOLFIP_FILT_OUTBOUND_ERR:
        outbound = 1;
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    default:
        return wolfip_unmapped_verdict(&wolfip_warned_ip, "event reason", (int)event->reason);
    }

    wolfip_set_ipv4_sockaddrs(&remote.remote, &local.local, event, outbound);
    remote.remote.sa_proto = local.local.sa_proto = 0;
    ret = wolfip_dispatch_event(wolfsentry, route_flags, &action_results, &remote.remote, &local.local, event);
    return ret;
}

static int wolfip_filter_tcp(
    struct wolfsentry_context *wolfsentry,
    const struct wolfIP_filter_event *event)
{
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS |
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    int outbound = wolfip_is_direction_out(event->reason);
    int ret;
    WOLFSENTRY_STACKBUF(
        struct wolfsentry_sockaddr,
        addr,
        sizeof(event->meta.src_ip),
        remote);
    WOLFSENTRY_STACKBUF(
        struct wolfsentry_sockaddr,
        addr,
        sizeof(event->meta.src_ip),
        local);
    switch (event->reason) {
    case WOLFIP_FILT_ACCEPTING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_CONNECT;
        break;
    case WOLFIP_FILT_CONNECTING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_CONNECTING_OUT;
        break;
    case WOLFIP_FILT_REMOTE_RESET:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_DISCONNECT;
        break;
    case WOLFIP_FILT_CLOSED:
        route_flags |= outbound ? WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT :
                                  WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = outbound ? WOLFSENTRY_ACTION_RES_CLOSED :
                         WOLFSENTRY_ACTION_RES_DISCONNECT;
        break;
    case WOLFIP_FILT_CLOSE_WAIT:
        route_flags |= outbound ? WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT :
                                  WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_CLOSE_WAIT;
        break;
    case WOLFIP_FILT_PORT_UNREACHABLE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE |
                         WOLFSENTRY_ACTION_RES_DEROGATORY;
        break;
    case WOLFIP_FILT_BINDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        action_results = WOLFSENTRY_ACTION_RES_BINDING |
            WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES;
        break;
    case WOLFIP_FILT_LISTENING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        action_results = WOLFSENTRY_ACTION_RES_LISTENING |
            WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES;
        break;
    case WOLFIP_FILT_STOP_LISTENING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        action_results = WOLFSENTRY_ACTION_RES_STOPPED_LISTENING |
            WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES;
        break;
    case WOLFIP_FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_RECEIVED;
        break;
    case WOLFIP_FILT_SENDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SENDING;
        break;
    case WOLFIP_FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case WOLFIP_FILT_OUTBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case WOLFIP_FILT_DISSOCIATE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_CLOSED;
        break;
    default:
        return wolfip_unmapped_verdict(&wolfip_warned_tcp, "event reason", (int)event->reason);
    }

    wolfip_set_ipv4_sockaddrs(&remote.remote, &local.local, event, outbound);
    remote.remote.sa_proto = local.local.sa_proto = IPPROTO_TCP;

    if (event->meta.ip_proto == WOLFIP_FILTER_PROTO_TCP) {
        uint16_t remote_port = outbound ? ee16(event->meta.l4.tcp.dst_port) :
                                          ee16(event->meta.l4.tcp.src_port);
        uint16_t local_port = outbound ? ee16(event->meta.l4.tcp.src_port) :
                                         ee16(event->meta.l4.tcp.dst_port);
        remote.remote.sa_port = remote_port;
        local.local.sa_port = local_port;
    }

    ret = wolfip_dispatch_event(wolfsentry, route_flags, &action_results, &remote.remote, &local.local, event);
    return ret;
}

static int wolfip_filter_udp(
    struct wolfsentry_context *wolfsentry,
    const struct wolfIP_filter_event *event)
{
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    int outbound = wolfip_is_direction_out(event->reason);
    int ret;
    WOLFSENTRY_STACKBUF(
        struct wolfsentry_sockaddr,
        addr,
        sizeof(event->meta.src_ip),
        remote);
    WOLFSENTRY_STACKBUF(
        struct wolfsentry_sockaddr,
        addr,
        sizeof(event->meta.src_ip),
        local);
    switch (event->reason) {
    case WOLFIP_FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_RECEIVED;
        break;
    case WOLFIP_FILT_SENDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SENDING;
        break;
    case WOLFIP_FILT_PORT_UNREACHABLE:
    case WOLFIP_FILT_ADDR_UNREACHABLE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE;
        break;
    case WOLFIP_FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case WOLFIP_FILT_OUTBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case WOLFIP_FILT_BINDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        action_results = WOLFSENTRY_ACTION_RES_BINDING |
            WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES;
        break;
    case WOLFIP_FILT_LISTENING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        action_results = WOLFSENTRY_ACTION_RES_LISTENING |
            WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES;
        break;
    case WOLFIP_FILT_STOP_LISTENING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        action_results = WOLFSENTRY_ACTION_RES_STOPPED_LISTENING |
            WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES;
        break;
    case WOLFIP_FILT_DISSOCIATE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_CLOSED;
        break;
    default:
        return wolfip_unmapped_verdict(&wolfip_warned_udp, "event reason", (int)event->reason);
    }

    wolfip_set_ipv4_sockaddrs(&remote.remote, &local.local, event, outbound);
    remote.remote.sa_proto = local.local.sa_proto = IPPROTO_UDP;

    if (event->meta.ip_proto == WOLFIP_FILTER_PROTO_UDP) {
        uint16_t remote_port = outbound ? ee16(event->meta.l4.udp.dst_port) :
                                          ee16(event->meta.l4.udp.src_port);
        uint16_t local_port = outbound ? ee16(event->meta.l4.udp.src_port) :
                                         ee16(event->meta.l4.udp.dst_port);
        remote.remote.sa_port = remote_port;
        local.local.sa_port = local_port;
    }

    ret = wolfip_dispatch_event(wolfsentry, route_flags, &action_results, &remote.remote, &local.local, event);
    return ret;
}

static int wolfip_filter_icmp(
    struct wolfsentry_context *wolfsentry,
    const struct wolfIP_filter_event *event)
{
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    int outbound = wolfip_is_direction_out(event->reason);
    int ret;
    WOLFSENTRY_STACKBUF(
        struct wolfsentry_sockaddr,
        addr,
        sizeof(event->meta.src_ip),
        remote);
    WOLFSENTRY_STACKBUF(
        struct wolfsentry_sockaddr,
        addr,
        sizeof(event->meta.src_ip),
        local);

    switch (event->reason) {
    case WOLFIP_FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_RECEIVED;
        break;
    case WOLFIP_FILT_SENDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SENDING;
        break;
    case WOLFIP_FILT_ADDR_UNREACHABLE:
    case WOLFIP_FILT_PORT_UNREACHABLE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_UNREACHABLE;
        break;
    case WOLFIP_FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case WOLFIP_FILT_OUTBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_SOCK_ERROR;
        break;
    case WOLFIP_FILT_BINDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        action_results = WOLFSENTRY_ACTION_RES_BINDING |
            WOLFSENTRY_ACTION_RES_EXCLUDE_REJECT_ROUTES;
        /* socket lifecycle events carry the local endpoint in src_ip; orient
         * the sockaddrs as locally originated so the bound address lands in
         * local, while route_flags keeps the inbound binding semantics. */
        outbound = 1;
        break;
    case WOLFIP_FILT_DISSOCIATE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        action_results = WOLFSENTRY_ACTION_RES_CLOSED;
        break;
    default:
        return wolfip_unmapped_verdict(&wolfip_warned_icmp, "event reason", (int)event->reason);
    }

    wolfip_set_ipv4_sockaddrs(&remote.remote, &local.local, event, outbound);
    remote.remote.sa_proto = local.local.sa_proto = IPPROTO_ICMP;

    ret = wolfip_dispatch_event(wolfsentry, route_flags, &action_results, &remote.remote, &local.local, event);
    return ret;
}

static int wolfip_filter_with_wolfsentry(void *arg, const struct wolfIP_filter_event *event)
{
    struct wolfsentry_context *wolfsentry = (struct wolfsentry_context *)arg;

    if (event == NULL)
        return 0;
    if (wolfsentry == NULL)
        return WOLFIP_FAIL_VERDICT;

    switch (event->meta.ip_proto) {
    case WOLFIP_FILTER_PROTO_ETH:
        return wolfip_filter_ethernet(wolfsentry, event);
    case WOLFIP_FILTER_PROTO_IP:
        return wolfip_filter_ipv4(wolfsentry, event);
    case WOLFIP_FILTER_PROTO_TCP:
        return wolfip_filter_tcp(wolfsentry, event);
    case WOLFIP_FILTER_PROTO_UDP:
        return wolfip_filter_udp(wolfsentry, event);
    case WOLFIP_FILTER_PROTO_ICMP:
        return wolfip_filter_icmp(wolfsentry, event);
    default:
        return wolfip_unmapped_verdict(&wolfip_warned_proto, "protocol", (int)event->meta.ip_proto);
    }
}

static wolfsentry_errcode_t wolfip_apply_masks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t new_mask_eth,
    uint32_t new_mask_ip,
    uint32_t new_mask_icmp,
    uint32_t new_mask_tcp,
    uint32_t new_mask_udp)
{
    uint32_t combined = new_mask_eth | new_mask_ip | new_mask_icmp |
        new_mask_tcp | new_mask_udp;
    wolfsentry_errcode_t ret = WOLFSENTRY_ERROR_ENCODE(OK);

    /* validate ownership before mutating any shared state, so a rejected call
     * cannot perturb the owning context's masks or callback (fail-open). the
     * check applies on the disable path too. */
    if ((wolfip_filter_context != NULL) && (wolfip_filter_context != wolfsentry))
        return WOLFSENTRY_ERROR_ENCODE(INCOMPATIBLE_STATE);

    if ((new_mask_eth & ~(uint32_t)WOLFIP_MAPPED_ETH) ||
        (new_mask_ip & ~(uint32_t)WOLFIP_MAPPED_IP) ||
        (new_mask_icmp & ~(uint32_t)WOLFIP_MAPPED_ICMP) ||
        (new_mask_tcp & ~(uint32_t)WOLFIP_MAPPED_TCP) ||
        (new_mask_udp & ~(uint32_t)WOLFIP_MAPPED_UDP))
    {
        return WOLFSENTRY_ERROR_ENCODE(INVALID_ARG);
    }

    if (combined) {
        if (! wolfip_cleanup_registered) {
            ret = wolfsentry_cleanup_push(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry_cleanup_wolfip_filter_callbacks, NULL);
            if (ret < 0)
                return ret;
            wolfip_cleanup_registered = 1;
        }
    }

    wolfip_mask_eth = new_mask_eth;
    wolfip_mask_ip = new_mask_ip;
    wolfip_mask_icmp = new_mask_icmp;
    wolfip_mask_tcp = new_mask_tcp;
    wolfip_mask_udp = new_mask_udp;

    if (combined) {
        wolfip_filter_context = wolfsentry;
        wolfIP_filter_set_callback(wolfip_filter_with_wolfsentry, wolfsentry);
    } else {
        wolfIP_filter_set_callback(NULL, NULL);
        wolfip_filter_context = NULL;
        /* release ownership of the cleanup registration so the next context to
         * install receives its own cleanup hook rather than relying on a stale
         * flag bound to a context that may since be torn down. */
        wolfip_cleanup_registered = 0;
    }

    wolfIP_filter_set_eth_mask(wolfip_mask_eth);
    wolfIP_filter_set_ip_mask(wolfip_mask_ip);
    wolfIP_filter_set_icmp_mask(wolfip_mask_icmp);
    wolfIP_filter_set_tcp_mask(wolfip_mask_tcp);
    wolfIP_filter_set_udp_mask(wolfip_mask_udp);

    return ret;
}

WOLFSENTRY_API_VOID wolfsentry_cleanup_wolfip_filter_callbacks(WOLFSENTRY_CONTEXT_ARGS_IN, void *cleanup_arg)
{
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    (void)cleanup_arg;
    /* a cleanup hook fires when its registering context is destroyed; only tear
     * down the shared filter state if that context still owns it, so destroying
     * a non-owner cannot silently disable a surviving owner's filtering. */
    if ((wolfip_filter_context != NULL) && (wolfip_filter_context != wolfsentry))
        return;
    wolfip_mask_eth = wolfip_mask_ip = wolfip_mask_icmp = wolfip_mask_tcp = wolfip_mask_udp = 0;
    wolfip_cleanup_registered = 0;
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
    wolfIP_filter_set_ip_mask(0);
    wolfIP_filter_set_icmp_mask(0);
    wolfIP_filter_set_tcp_mask(0);
    wolfIP_filter_set_udp_mask(0);
    wolfip_filter_context = NULL;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_ethernet_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t ethernet_mask)
{
    wolfsentry_errcode_t ret;

    WOLFSENTRY_MUTEX_OR_RETURN();
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    ret = wolfip_apply_masks(WOLFSENTRY_CONTEXT_ARGS_OUT,
        ethernet_mask, wolfip_mask_ip, wolfip_mask_icmp, wolfip_mask_tcp,
        wolfip_mask_udp);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_ip4_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t ip_mask)
{
    wolfsentry_errcode_t ret;

    WOLFSENTRY_MUTEX_OR_RETURN();
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    ret = wolfip_apply_masks(WOLFSENTRY_CONTEXT_ARGS_OUT,
        wolfip_mask_eth, ip_mask, wolfip_mask_icmp, wolfip_mask_tcp,
        wolfip_mask_udp);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_icmp_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t icmp_mask)
{
    wolfsentry_errcode_t ret;

    WOLFSENTRY_MUTEX_OR_RETURN();
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    ret = wolfip_apply_masks(WOLFSENTRY_CONTEXT_ARGS_OUT,
        wolfip_mask_eth, wolfip_mask_ip, icmp_mask, wolfip_mask_tcp,
        wolfip_mask_udp);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

static uint32_t wolfip_normalize_tcp_mask(uint32_t tcp_mask)
{
    /* an accept is counted as a connection, so when accepts are requested also
     * deliver the close and reset events that release it; teardown-only masks
     * must not turn on accept counting. */
    if (tcp_mask & WOLFIP_FILT_MASK(WOLFIP_FILT_ACCEPTING))
        tcp_mask |= WOLFIP_FILT_MASK(WOLFIP_FILT_CLOSED) |
            WOLFIP_FILT_MASK(WOLFIP_FILT_REMOTE_RESET);
    return tcp_mask;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_tcp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t tcp_mask)
{
    wolfsentry_errcode_t ret;

    WOLFSENTRY_MUTEX_OR_RETURN();
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    ret = wolfip_apply_masks(WOLFSENTRY_CONTEXT_ARGS_OUT,
        wolfip_mask_eth, wolfip_mask_ip, wolfip_mask_icmp,
        wolfip_normalize_tcp_mask(tcp_mask), wolfip_mask_udp);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_udp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t udp_mask)
{
    wolfsentry_errcode_t ret;

    WOLFSENTRY_MUTEX_OR_RETURN();
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    ret = wolfip_apply_masks(WOLFSENTRY_CONTEXT_ARGS_OUT,
        wolfip_mask_eth, wolfip_mask_ip, wolfip_mask_icmp, wolfip_mask_tcp,
        udp_mask);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t ethernet_mask,
    uint32_t ip_mask,
    uint32_t icmp_mask,
    uint32_t tcp_mask,
    uint32_t udp_mask)
{
    wolfsentry_errcode_t ret;

    WOLFSENTRY_MUTEX_OR_RETURN();
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    ret = wolfip_apply_masks(WOLFSENTRY_CONTEXT_ARGS_OUT,
        ethernet_mask, ip_mask, icmp_mask, wolfip_normalize_tcp_mask(tcp_mask),
        udp_mask);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

#else /* !CONFIG_IPFILTER */

WOLFSENTRY_API_VOID wolfsentry_cleanup_wolfip_filter_callbacks(WOLFSENTRY_CONTEXT_ARGS_IN, void *cleanup_arg)
{
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    (void)cleanup_arg;
    (void)wolfsentry;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_ethernet_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t ethernet_mask)
{
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    (void)wolfsentry;
    if (ethernet_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_ip4_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t ip_mask)
{
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    (void)wolfsentry;
    if (ip_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_icmp_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t icmp_mask)
{
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    (void)wolfsentry;
    if (icmp_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_tcp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t tcp_mask)
{
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    (void)wolfsentry;
    if (tcp_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_udp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t udp_mask)
{
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    (void)wolfsentry;
    if (udp_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t ethernet_mask,
    uint32_t ip_mask,
    uint32_t icmp_mask,
    uint32_t tcp_mask,
    uint32_t udp_mask)
{
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    (void)wolfsentry;
    if (ethernet_mask || ip_mask || icmp_mask || tcp_mask || udp_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    WOLFSENTRY_RETURN_OK;
}

#endif /* CONFIG_IPFILTER */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_ip6_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t ip_mask)
{
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    (void)wolfsentry;
    if (ip_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_icmp6_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t icmp_mask)
{
    WOLFSENTRY_CONTEXT_ARGS_THREAD_NOT_USED;
    (void)wolfsentry;
    if (icmp_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    WOLFSENTRY_RETURN_OK;
}
