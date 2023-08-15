/*
 * wolfsentry/wolfsentry_lwip.h
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

#ifndef WOLFSENTRY_LWIP_H
#define WOLFSENTRY_LWIP_H

#include "lwip/init.h"

#if LWIP_PACKET_FILTER_API

#include "lwip/filter.h"

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_ethernet_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t ethernet_mask);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_ip_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t ip_mask);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_icmp_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t icmp_mask);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_tcp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t tcp_mask);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_udp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t udp_mask);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t ethernet_mask,
    packet_filter_event_mask_t ip_mask,
    packet_filter_event_mask_t icmp_mask,
    packet_filter_event_mask_t tcp_mask,
    packet_filter_event_mask_t udp_mask);

WOLFSENTRY_API_VOID wolfsentry_cleanup_lwip_filter_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *arg);

#endif /* LWIP_PACKET_FILTER_API */

#endif /* WOLFSENTRY_LWIP_H */
