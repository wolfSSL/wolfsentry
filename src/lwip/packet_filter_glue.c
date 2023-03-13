/*
 * lwip/packet_filter_glue.c
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

#include <wolfsentry/wolfsentry.h>
#include <wolfsentry/wolfsentry_lwip.h>

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_LWIP_PACKET_FILTER_GLUE_C

#if LWIP_PACKET_FILTER_API

#if LWIP_TCP

#include "lwip/tcp.h"

static err_t tcp_filter_wolfsentry(
    void *arg,
    struct packet_filter_event *event,
    ip_addr_t *laddr,
    u16_t lport,
    ip_addr_t *raddr,
    u16_t rport)
{
    err_t ret;
    wolfsentry_errcode_t ws_ret;
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS |
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    const char *event_name = NULL;
    struct {
        struct wolfsentry_sockaddr sa;
#if LWIP_IPV6
        ip6_addr_t addr_buf; /* note, includes extra byte for zone. */
#else
        ip4_addr_t addr_buf;
#endif
    }
    remote, local;
    static_assert((void *)&remote.sa.addr == (void *)&remote.addr_buf, "unexpected layout in struct wolfsentry_sockaddr.");
    struct wolfsentry_context *wolfsentry = (struct wolfsentry_context *)arg;
    WOLFSENTRY_THREAD_HEADER_DECLS;

    if (wolfsentry == NULL)
        return ERR_OK;

    switch(event->reason) {
    case FILT_ACCEPTING:
        action_results = WOLFSENTRY_ACTION_RES_CONNECT; /* lets wolfSentry increment the connection count for this peer. */
        route_flags |=
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        event_name = "connect";
        break;
    case FILT_REMOTE_RESET:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        /* fall through */
    case FILT_CLOSED:
        if (event->pcb.tcp_pcb->flags & TF_ACCEPTED) {
            route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
            action_results = WOLFSENTRY_ACTION_RES_DISCONNECT; /* lets wolfSentry decrement the connection count for this peer. */
            event_name = "disconnect";
        } else {
            route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
            event_name = "disconnect";
            /* connection wasn't accepted -- don't debit on disconnect. */
        }
        break;
    case FILT_ADDR_UNREACHABLE:
    case FILT_PORT_UNREACHABLE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN | WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD;
        action_results |= WOLFSENTRY_ACTION_RES_DEROGATORY;
        event_name = "unreachable";
        /* fall through */
    case FILT_BINDING:
        route_flags |=
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        event_name = "bind";
        break;
    case FILT_LISTENING:
        route_flags |=
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        event_name = "listen";
        break;
    case FILT_STOP_LISTENING:
        event_name = "stop-listening";
        route_flags |=
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        break;
    case FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        event_name = "receive";
        break;
    case FILT_CONNECTING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        event_name = "connect";
        break;
    case FILT_SENDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        event_name = "send";
        break;
    case FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        event_name = "error";
        break;
    case FILT_OUTBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        event_name = "error";
        break;
    case FILT_DISSOCIATE: /* can't happen. */
        return ERR_OK;
    }

#if LWIP_IPV6
    if (laddr->type == IPADDR_TYPE_V6) {
        remote.sa.sa_family = WOLFSENTRY_AF_INET6;
        remote.sa.addr_len = 128; /* ip6_addr_t includes an extra byte for the zone. */
        ip6_addr_set_hton((struct ip6_addr *)&remote.addr_buf, ip_2_ip6(raddr));

        local.sa.sa_family = WOLFSENTRY_AF_INET6;
        local.sa.addr_len = 128; /* ip6_addr_t includes an extra byte for the zone. */
        ip6_addr_set_hton((struct ip6_addr *)&local.addr_buf, ip_2_ip6(laddr));
    } else {
#endif
        remote.sa.sa_family = WOLFSENTRY_AF_INET;
        remote.sa.addr_len = sizeof(ip4_addr_t) * 8;
        ip4_addr_set_hton((struct ip4_addr *)&remote.addr_buf, ip_2_ip4(raddr));

        local.sa.sa_family = WOLFSENTRY_AF_INET;
        local.sa.addr_len = sizeof(ip4_addr_t) * 8;
        ip4_addr_set_hton((struct ip4_addr *)&local.addr_buf, ip_2_ip4(laddr));
#if LWIP_IPV6
    }
#endif

    remote.sa.sa_proto = IPPROTO_TCP;
    remote.sa.sa_port = rport;

    local.sa.sa_proto = IPPROTO_TCP;
    local.sa.sa_port = lport;

    if (event->netif)
        remote.sa.interface = local.sa.interface = netif_get_index(event->netif);
    else {
        remote.sa.interface = local.sa.interface = NETIF_NO_INDEX;
        route_flags |= WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD | WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD;
    }

    WOLFSENTRY_THREAD_HEADER_INIT(WOLFSENTRY_THREAD_FLAG_NONE);
    if (WOLFSENTRY_THREAD_GET_ERROR < 0)
        return ERR_MEM;

    ws_ret = wolfsentry_route_event_dispatch_with_inited_result(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            &remote.sa,
            &local.sa,
            route_flags,
            event_name,
            -1,
            (void *)&event,
            NULL,
            NULL,
            &action_results);

    if (ws_ret < 0)
        ret = ERR_OK;
    else {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT))
            ret = ERR_ABRT;
        else
            ret = ERR_OK;
    }

    if (WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        return ERR_MEM;

    return ret;
}

#endif /* LWIP_TCP */

#if LWIP_UDP

#include "lwip/udp.h"

static err_t udp_filter_wolfsentry(
    void *arg,
    struct packet_filter_event *event,
    const ip_addr_t *laddr,
    u16_t lport,
    const ip_addr_t *raddr,
    u16_t rport)
{
    err_t ret;
    wolfsentry_errcode_t ws_ret;
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_TCPLIKE_PORT_NUMBERS |
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    const char *event_name = NULL;
    struct {
        struct wolfsentry_sockaddr sa;
#if LWIP_IPV6
        ip6_addr_t addr_buf; /* note, includes extra byte for zone. */
#else
        ip4_addr_t addr_buf;
#endif
    } remote, local;
    struct wolfsentry_context *wolfsentry = (struct wolfsentry_context *)arg;
    WOLFSENTRY_THREAD_HEADER_DECLS;

    if (wolfsentry == NULL)
        return ERR_OK;

    switch(event->reason) {
    case FILT_BINDING:
        route_flags |=
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        event_name = "bind";
        break;
    case FILT_CONNECTING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN | WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        event_name = "connect";
        break;
    case FILT_DISSOCIATE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN | WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        event_name = "disconnect";
        break;
    case FILT_CLOSED:
        route_flags |=
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD |
            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD;
        event_name = "unbind";
        break;
    case FILT_ADDR_UNREACHABLE:
    case FILT_PORT_UNREACHABLE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN | WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD;
        action_results |= WOLFSENTRY_ACTION_RES_DEROGATORY;
        event_name = "unreachable";
        /* fall through */
    case FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        event_name = "receive";
        break;
    case FILT_SENDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        event_name = "send";
        break;
    case FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        event_name = "error";
        break;
    case FILT_OUTBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        event_name = "error";
        break;
    case FILT_ACCEPTING:
    case FILT_REMOTE_RESET:
    case FILT_LISTENING:
    case FILT_STOP_LISTENING:
        /* can't happen. */
        return ERR_OK;
    }

#if LWIP_IPV6
    if (laddr->type == IPADDR_TYPE_V6) {
        remote.sa.sa_family = WOLFSENTRY_AF_INET6;
        remote.sa.addr_len = 128; /* ip6_addr_t includes an extra byte for the zone. */
        ip6_addr_set_hton((struct ip6_addr *)&remote.addr_buf, ip_2_ip6(raddr));

        local.sa.sa_family = WOLFSENTRY_AF_INET6;
        local.sa.addr_len = 128; /* ip6_addr_t includes an extra byte for the zone. */
        ip6_addr_set_hton((struct ip6_addr *)&local.addr_buf, ip_2_ip6(laddr));
    } else {
#endif
        remote.sa.sa_family = WOLFSENTRY_AF_INET;
        remote.sa.addr_len = sizeof(ip4_addr_t) * 8;
        ip4_addr_set_hton((struct ip4_addr *)&remote.addr_buf, ip_2_ip4(raddr));

        local.sa.sa_family = WOLFSENTRY_AF_INET;
        local.sa.addr_len = sizeof(ip4_addr_t) * 8;
        ip4_addr_set_hton((struct ip4_addr *)&local.addr_buf, ip_2_ip4(laddr));
#if LWIP_IPV6
    }
#endif

    remote.sa.sa_proto = IPPROTO_UDP;
    remote.sa.sa_port = rport;

    local.sa.sa_proto = IPPROTO_UDP;
    local.sa.sa_port = lport;

    if (event->netif)
        remote.sa.interface = local.sa.interface = netif_get_index(event->netif);
    else {
        remote.sa.interface = local.sa.interface = NETIF_NO_INDEX;
        route_flags |= WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD | WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD;
    }

    if (WOLFSENTRY_THREAD_HEADER_INIT(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        return ERR_MEM;

    ws_ret = wolfsentry_route_event_dispatch_with_inited_result(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            &remote.sa,
            &local.sa,
            route_flags,
            event_name,
            -1,
            (void *)event,
            NULL,
            NULL,
            &action_results);

    if (ws_ret >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT))
            ret = ERR_ABRT;
        else
            ret = ERR_OK;
    } else
        ret = ERR_OK;

    if (WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        return ERR_MEM;

  return ret;
}

#endif /* LWIP_UDP */

#if LWIP_ICMP

#include "lwip/icmp.h"

static err_t icmp4_filter_wolfsentry(
    void *arg,
    struct packet_filter_event *event,
    const ip4_addr_t *laddr,
    const ip4_addr_t *raddr,
    u8_t icmp4_type)
{
    err_t ret;
    wolfsentry_errcode_t ws_ret;
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    const char *event_name = NULL;
    struct {
        struct wolfsentry_sockaddr sa;
        ip4_addr_t addr_buf;
    } remote, local;
    struct wolfsentry_context *wolfsentry = (struct wolfsentry_context *)arg;
    WOLFSENTRY_THREAD_HEADER_DECLS;

    if (wolfsentry == NULL)
        return ERR_OK;

    switch(event->reason) {
    case FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        event_name = "receive";
        break;
    case FILT_SENDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        event_name = "send";
        break;
    case FILT_ADDR_UNREACHABLE:
    case FILT_PORT_UNREACHABLE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN | WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD;
        action_results |= WOLFSENTRY_ACTION_RES_DEROGATORY;
        event_name = "unreachable";
        /* fall through */
    case FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        event_name = "error";
        break;
    case FILT_OUTBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        event_name = "error";
        break;
    case FILT_BINDING:
    case FILT_CONNECTING:
    case FILT_DISSOCIATE:
    case FILT_CLOSED:
    case FILT_ACCEPTING:
    case FILT_REMOTE_RESET:
    case FILT_LISTENING:
    case FILT_STOP_LISTENING:
        /* can't happen. */
        return ERR_OK;
    }

    remote.sa.sa_family = WOLFSENTRY_AF_INET;
    remote.sa.addr_len = sizeof(ip4_addr_t) * 8;
    ip4_addr_set_hton(&remote.addr_buf, raddr);

    local.sa.sa_family = WOLFSENTRY_AF_INET;
    local.sa.addr_len = sizeof(ip4_addr_t) * 8;
    ip4_addr_set_hton(&local.addr_buf, laddr);

    remote.sa.sa_proto = IPPROTO_ICMP;
    remote.sa.sa_port = 0;

    local.sa.sa_proto = IPPROTO_ICMP;
    local.sa.sa_port = icmp4_type;

    if (event->netif)
        remote.sa.interface = local.sa.interface = netif_get_index(event->netif);
    else {
        remote.sa.interface = local.sa.interface = NETIF_NO_INDEX;
        route_flags |= WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD | WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD;
    }

    if (WOLFSENTRY_THREAD_HEADER_INIT(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        return ERR_MEM;

    ws_ret = wolfsentry_route_event_dispatch_with_inited_result(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            &remote.sa,
            &local.sa,
            route_flags,
            event_name,
            -1,
            (void *)event,
            NULL,
            NULL,
            &action_results);

    if (ws_ret >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT))
            ret = ERR_ABRT;
        else
            ret = ERR_OK;
    } else
        ret = ERR_OK;

    if (WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        return ERR_MEM;

    return ret;
}

#endif /* LWIP_ICMP */

#if LWIP_ICMP6

#include "lwip/icmp6.h"

static err_t icmp6_filter_wolfsentry(
    void *arg,
    struct packet_filter_event *event,
    const ip6_addr_t *laddr,
    const ip6_addr_t *raddr,
    u8_t icmp6_type)
{
    err_t ret;
    wolfsentry_errcode_t ws_ret;
    wolfsentry_route_flags_t route_flags =
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    const char *event_name = NULL;
    struct {
        struct wolfsentry_sockaddr sa;
        ip6_addr_t addr_buf; /* note, includes extra byte for zone. */
    } remote, local;
    struct wolfsentry_context *wolfsentry = (struct wolfsentry_context *)arg;
    WOLFSENTRY_THREAD_HEADER_DECLS;

    if (wolfsentry == NULL)
        return ERR_OK;

    switch(event->reason) {
    case FILT_RECEIVING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        event_name = "receive";
        break;
    case FILT_SENDING:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        event_name = "send";
        break;
    case FILT_ADDR_UNREACHABLE:
    case FILT_PORT_UNREACHABLE:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN | WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD;
        action_results |= WOLFSENTRY_ACTION_RES_DEROGATORY;
        event_name = "unreachable";
        /* fall through */
    case FILT_INBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN;
        event_name = "error";
        break;
    case FILT_OUTBOUND_ERR:
        route_flags |= WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT;
        event_name = "error";
        break;
    case FILT_BINDING:
    case FILT_CONNECTING:
    case FILT_DISSOCIATE:
    case FILT_CLOSED:
    case FILT_ACCEPTING:
    case FILT_REMOTE_RESET:
    case FILT_LISTENING:
    case FILT_STOP_LISTENING:
        /* can't happen. */
        return ERR_OK;
    }

    remote.sa.sa_family = WOLFSENTRY_AF_INET6;
    remote.sa.addr_len = 128; /* ip6_addr_t includes an extra byte for the zone. */
    ip6_addr_set_hton(&remote.addr_buf, raddr);

    local.sa.sa_family = WOLFSENTRY_AF_INET6;
    local.sa.addr_len = 128; /* ip6_addr_t includes an extra byte for the zone. */
    ip6_addr_set_hton(&local.addr_buf, laddr);

    remote.sa.sa_proto = IPPROTO_ICMP;
    remote.sa.sa_port = 0;

    local.sa.sa_proto = IPPROTO_ICMP;
    local.sa.sa_port = icmp6_type;

    if (event->netif)
        remote.sa.interface = local.sa.interface = netif_get_index(event->netif);
    else {
        remote.sa.interface = local.sa.interface = NETIF_NO_INDEX;
        route_flags |= WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD | WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD;
    }

    if (WOLFSENTRY_THREAD_HEADER_INIT(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        return ERR_MEM;

    ws_ret = wolfsentry_route_event_dispatch_with_inited_result(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            &remote.sa,
            &local.sa,
            route_flags,
            event_name,
            -1,
            (void *)event,
            NULL,
            NULL,
            &action_results);

    if (ws_ret >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT))
            ret = ERR_ABRT;
        else
            ret = ERR_OK;
    } else
        ret = ERR_OK;

    if (WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE) < 0)
        return ERR_MEM;

  return ret;
}

#endif /* LWIP_ICMP6 */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_callbacks(struct wolfsentry_context *wolfsentry, packet_filter_event_mask_t tcp_mask, packet_filter_event_mask_t udp_mask, packet_filter_event_mask_t icmp_mask) {
#if LWIP_TCP
    tcp_filter(tcp_filter_wolfsentry);
    /* make sure wolfSentry sees the close/reset event associated with an
     * earlier accept, for concurrent-connection accounting purposes.
     */
    if (tcp_mask & FILT_MASK(ACCEPTING))
        tcp_mask |= FILT_MASK(CLOSED) | FILT_MASK(REMOTE_RESET);
    tcp_filter_mask(tcp_mask);
    tcp_filter_arg((void *)wolfsentry);
#else
    (void)tcp_mask;
#endif /* LWIP_TCP */
#if LWIP_UDP
    udp_filter(udp_filter_wolfsentry);
    udp_filter_mask(udp_mask);
    udp_filter_arg((void *)wolfsentry);
#else
    (void)udp_mask;
#endif /* LWIP_UDP */
#if LWIP_ICMP
    icmp_filter(icmp4_filter_wolfsentry);
    icmp_filter_mask(icmp_mask);
    icmp_filter_arg((void *)wolfsentry);
#else
    (void)icmp_mask;
#endif /* LWIP_ICMP */
#if LWIP_ICMP6
    icmp6_filter(icmp6_filter_wolfsentry);
    icmp6_filter_mask(icmp_mask);
    icmp6_filter_arg((void *)wolfsentry);
#else
    (void)icmp_mask;
#endif /* LWIP_ICMP6 */
    WOLFSENTRY_RETURN_OK;
}

#endif /* LWIP_PACKET_FILTER_API */
