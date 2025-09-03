/*
 * wolfsentry/wolfsentry_netxduo.h
 *
 * Copyright (C) 2021-2025 wolfSSL Inc.
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

#ifndef _WOLFSENTRY_NETXDUO_H
#define _WOLFSENTRY_NETXDUO_H

#ifdef NEED_THREADX_TYPES
#include "types.h"
#endif
#include "nx_api.h"

#ifndef AF_INET
#define AF_INET  2 /* IPv4 socket (UDP, TCP, etc) */
#endif
#ifndef AF_INET6
#define AF_INET6 3 /* IPv6 socket (UDP, TCP, etc) */
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6  /* TCP Socket */
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17 /* TCP Socket */
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP  1
#endif

#ifndef in_addr
struct nx_bsd_in_addr {
    ULONG           s_addr; /* Internet address (32 bits) */
};
#define in_addr nx_bsd_in_addr
#endif

#ifndef in6_addr
struct nx_bsd_in6_addr {
    union {
        UCHAR _S6_u8[16];
        ULONG _S6_u32[4];
    } _S6_un;
};
#define in6_addr nx_bsd_in6_addr
#endif

#ifndef socklen_t
typedef ULONG nx_bsd_socklen_t;
#define socklen_t nx_bsd_socklen_t
#endif

#endif /* _WOLFSENTRY_NETXDUO_H */
