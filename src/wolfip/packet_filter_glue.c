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

static wolfsentry_errcode_t wolfip_apply_masks(WOLFSENTRY_CONTEXT_ARGS_IN);

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
        return 0;

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
        return 0;
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
        return 0;
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
        action_results = WOLFSENTRY_ACTION_RES_DEROGATORY;
        break;
    default:
        return 0;
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
    default:
        return 0;
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
    default:
        return 0;
    }

    wolfip_set_ipv4_sockaddrs(&remote.remote, &local.local, event, outbound);
    remote.remote.sa_proto = local.local.sa_proto = IPPROTO_ICMP;

    ret = wolfip_dispatch_event(wolfsentry, route_flags, &action_results, &remote.remote, &local.local, event);
    return ret;
}

static int wolfip_filter_with_wolfsentry(void *arg, const struct wolfIP_filter_event *event)
{
    struct wolfsentry_context *wolfsentry = (struct wolfsentry_context *)arg;

    if ((wolfsentry == NULL) || (event == NULL))
        return 0;

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
        return 0;
    }
}

static wolfsentry_errcode_t wolfip_apply_masks(WOLFSENTRY_CONTEXT_ARGS_IN)
{
    uint32_t combined = wolfip_mask_eth | wolfip_mask_ip | wolfip_mask_icmp |
        wolfip_mask_tcp | wolfip_mask_udp;
    wolfsentry_errcode_t ret = WOLFSENTRY_ERROR_ENCODE(OK);

    if (combined) {
        if (wolfip_filter_context && (wolfip_filter_context != wolfsentry))
            return WOLFSENTRY_ERROR_ENCODE(INCOMPATIBLE_STATE);
        if (!wolfip_cleanup_registered) {
            ret = wolfsentry_cleanup_push(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry_cleanup_wolfip_filter_callbacks, NULL);
            if (ret < 0)
                return ret;
            wolfip_cleanup_registered = 1;
        }
        wolfip_filter_context = wolfsentry;
        wolfIP_filter_set_callback(wolfip_filter_with_wolfsentry, wolfsentry);
    } else {
        wolfIP_filter_set_callback(NULL, NULL);
        wolfip_filter_context = NULL;
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
    (void)wolfsentry;
    (void)thread;
    (void)cleanup_arg;
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
    (void)thread;
    wolfip_mask_eth = ethernet_mask;
    ret = wolfip_apply_masks(WOLFSENTRY_CONTEXT_ARGS_OUT);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_ip4_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t ip_mask)
{
    wolfsentry_errcode_t ret;

    WOLFSENTRY_MUTEX_OR_RETURN();
    (void)thread;
    wolfip_mask_ip = ip_mask;
    ret = wolfip_apply_masks(WOLFSENTRY_CONTEXT_ARGS_OUT);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_icmp_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t icmp_mask)
{
    wolfsentry_errcode_t ret;

    WOLFSENTRY_MUTEX_OR_RETURN();
    (void)thread;
    wolfip_mask_icmp = icmp_mask;
    ret = wolfip_apply_masks(WOLFSENTRY_CONTEXT_ARGS_OUT);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_tcp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t tcp_mask)
{
    wolfsentry_errcode_t ret;

    WOLFSENTRY_MUTEX_OR_RETURN();
    (void)thread;
    if (tcp_mask & (WOLFIP_FILT_MASK(WOLFIP_FILT_ACCEPTING) |
                    WOLFIP_FILT_MASK(WOLFIP_FILT_CLOSED) |
                    WOLFIP_FILT_MASK(WOLFIP_FILT_REMOTE_RESET)))
        tcp_mask |= WOLFIP_FILT_MASK(WOLFIP_FILT_ACCEPTING) |
            WOLFIP_FILT_MASK(WOLFIP_FILT_CLOSED) |
            WOLFIP_FILT_MASK(WOLFIP_FILT_REMOTE_RESET);
    wolfip_mask_tcp = tcp_mask;
    ret = wolfip_apply_masks(WOLFSENTRY_CONTEXT_ARGS_OUT);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_udp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t udp_mask)
{
    wolfsentry_errcode_t ret;

    WOLFSENTRY_MUTEX_OR_RETURN();
    (void)thread;
    wolfip_mask_udp = udp_mask;
    ret = wolfip_apply_masks(WOLFSENTRY_CONTEXT_ARGS_OUT);
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
    (void)thread;
    wolfip_mask_eth = ethernet_mask;
    wolfip_mask_ip = ip_mask;
    wolfip_mask_icmp = icmp_mask;
    wolfip_mask_tcp = tcp_mask;
    wolfip_mask_udp = udp_mask;
    ret = wolfip_apply_masks(WOLFSENTRY_CONTEXT_ARGS_OUT);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

#else /* !CONFIG_IPFILTER */

WOLFSENTRY_API_VOID wolfsentry_cleanup_wolfip_filter_callbacks(WOLFSENTRY_CONTEXT_ARGS_IN, void *cleanup_arg)
{
    (void)thread;
    (void)cleanup_arg;
    (void)wolfsentry;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_ethernet_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t ethernet_mask)
{
    (void)thread;
    (void)wolfsentry;
    if (ethernet_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_ip4_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t ip_mask)
{
    (void)thread;
    (void)wolfsentry;
    if (ip_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_icmp_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t icmp_mask)
{
    (void)thread;
    (void)wolfsentry;
    if (icmp_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_tcp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t tcp_mask)
{
    (void)thread;
    (void)wolfsentry;
    if (tcp_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_udp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t udp_mask)
{
    (void)thread;
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
    (void)thread;
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
    (void)thread;
    (void)wolfsentry;
    if (ip_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_icmp6_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t icmp_mask)
{
    (void)thread;
    (void)wolfsentry;
    if (icmp_mask)
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
    WOLFSENTRY_RETURN_OK;
}
