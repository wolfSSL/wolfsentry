/*
 * FreeRTOS/include/lwipopts.h
 *
 * Copyright (C) 2022-2023 wolfSSL Inc.
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

#ifndef __LWIPOPTS_H__
#define __LWIPOPTS_H__

#define TCP_MSS                      1500
#define TCP_WND                     65535
#define NO_SYS                          0
/* #define LWIP_NOASSERT                   1 */
/* #define SYS_LIGHTWEIGHT_PROT            1 */
#define SYS_LIGHTWEIGHT_PROT            0

#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEM_USE_POOLS                   0
#define LWIP_ALLOW_MEM_FREE_FROM_OTHER_CONTEXT 1

#define LWIP_ETHERNET                   1
#define LWIP_IPV4                       1
#define LWIP_IPV6                       1
#define LWIP_TCP                        1
#define LWIP_UDP                        1
#define LWIP_ARP                        1
#define LWIP_ICMP                       1
#define LWIP_ICMP6                      1
#define IP_FRAG                         1

#define LWIP_DEBUG			0
#define ECHO_DEBUG                      LWIP_DBG_ON
/* #define IP4_DEBUG                       LWIP_DBG_ON */
/* #define NETIF_DEBUG                     LWIP_DBG_ON */
/* #define TCP_DEBUG                       LWIP_DBG_ON */
/* #define ETHARP_DEBUG                    LWIP_DBG_ON */

#define PPP_SUPPORT                     0
#define LWIP_SOCKET                     1
#define LWIP_NETCONN                    1
#define LWIP_RAW                        1
#define LWIP_COMPAT_SOCKETS             0
#define LWIP_TIMEVAL_PRIVATE            0
#define LWIP_STATS                      0

#define LWIP_CHECKSUM_CTRL_PER_NETIF    1

/* #define LWIP_PROVIDE_ERRNO 1 */
#undef LWIP_PROVIDE_ERRNO

#define TCPIP_THREAD_PRIO               3
#define MEM_ALIGNMENT                   4
#define MEM_SIZE                   262144
#define MEMP_NUM_PBUF                  20
#define MEMP_NUM_UDP_PCB               16
#define MEMP_NUM_TCP_PCB               10
#define MEMP_NUM_TCP_PCB_LISTEN         4
#define MEMP_NUM_TCP_SEG               20
#define MEMP_NUM_SYS_TIMEOUT            8

/* sequential API stuff */
#define MEMP_NUM_NETBUF                 4
#define MEMP_NUM_NETCONN                4
#define MEMP_NUM_API_MSG                8
/* #define MEMP_NUM_TCPIP_MSG              8 */

#define MEM_RECLAIM                     1
#define MEMP_RECLAIM                    1
#define PBUF_POOL_SIZE                  4
#define PBUF_POOL_BUFSIZE            1500
#define PBUF_LINK_HLEN                 16
#define TCP_TTL                       255
#define TCP_QUEUE_OOSEQ                 1
#define TCP_SND_BUF                  65535 /* "For maximum throughput, set this to the same value as TCP_WND" */
#define TCP_SND_QUEUELEN                (6 * TCP_SND_BUF/TCP_MSS)
#define TCP_MAXRTX                     12
#define TCP_SYNMAXRTX                   4
#define ARP_TABLE_SIZE                 32
#define ARP_QUEUEING                    1
#define IP_FORWARD                      1
#define IP_OPTIONS                      1
#define ICMP_TTL                      255
#define LWIP_DHCP                       0
#define DHCP_DOES_ARP_CHECK             1
#define UDP_TTL                       255

/* #define STATS */
#undef STATS

#ifdef STATS
#define LINK_STATS                      1
#define IP_STATS                        1
#define ICMP_STATS                      1
#define ICMP6_STATS                     1
#define UDP_STATS                       1
#define TCP_STATS                       1
#define MEM_STATS                       1
#define MEMP_STATS                      1
#define PBUF_STATS                      1
#define SYS_STATS                       1
#endif /* STATS */

#define LWIP_PACKET_FILTER_API 1

#define LWIP_TCPIP_CORE_LOCKING    1

#if !NO_SYS
void sys_check_core_locking(void);
#define LWIP_ASSERT_CORE_LOCKED()  sys_check_core_locking()
#endif

#endif /* __LWIPOPTS_H__ */
