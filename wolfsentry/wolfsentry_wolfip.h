/*
 * wolfsentry_wolfip.h
 *
 * Copyright (C) 2025 wolfSSL Inc.
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

/*! @file wolfsentry_wolfip.h
 *  \brief Prototypes for wolfIP callback installation functions.
 */

#ifndef WOLFSENTRY_WOLFIP_H
#define WOLFSENTRY_WOLFIP_H

#include <stdint.h>

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_ethernet_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t ethernet_mask);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_ip4_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t ip_mask);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_ip6_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t ip_mask);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_icmp_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t icmp_mask);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_icmp6_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t icmp_mask);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_tcp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t tcp_mask);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_udp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t udp_mask);

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_wolfip_filter_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    uint32_t ethernet_mask,
    uint32_t ip_mask,
    uint32_t icmp_mask,
    uint32_t tcp_mask,
    uint32_t udp_mask);

WOLFSENTRY_API_VOID wolfsentry_cleanup_wolfip_filter_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *cleanup_arg);

#endif /* WOLFSENTRY_WOLFIP_H */
