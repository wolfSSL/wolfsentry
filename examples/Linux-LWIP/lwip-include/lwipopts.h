// SPDX-License-Identifier: GPL-2.0-or-later

#define TCP_MSS                         1500
#define TCP_WND                         65535
#define NO_SYS                          0
#define SYS_LIGHTWEIGHT_PROT            0

#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEM_USE_POOLS                   0
#define LWIP_ALLOW_MEM_FREE_FROM_OTHER_CONTEXT 1

#define LWIP_ETHERNET                   1
#define LWIP_IPV4                       1
#define LWIP_TCP                        1
#define LWIP_ARP                        1
#define LWIP_ICMP                       1
#define IP_FRAG                         1

#define LWIP_DEBUG                      0
#define ECHO_DEBUG                      LWIP_DBG_ON
//#define IP4_DEBUG                       LWIP_DBG_ON
//#define NETIF_DEBUG                     LWIP_DBG_ON
//#define TCP_DEBUG                       LWIP_DBG_ON
//#define ETHARP_DEBUG                    LWIP_DBG_ON

#define PPP_SUPPORT                     0
#define LWIP_SOCKET                     1
#define LWIP_NETCONN                    1
#define LWIP_RAW                        1
#define LWIP_COMPAT_SOCKETS             0
#define LWIP_STATS                      0

#define LWIP_CHECKSUM_CTRL_PER_NETIF    1

