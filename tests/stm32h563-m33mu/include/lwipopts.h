/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef WOLFSENTRY_M33MU_LWIPOPTS_H
#define WOLFSENTRY_M33MU_LWIPOPTS_H

#define NO_SYS                          0
#define SYS_LIGHTWEIGHT_PROT            1
#define MEM_ALIGNMENT                   4
#define MEM_SIZE                        (48 * 1024)
#define MEM_LIBC_MALLOC                 0
#define MEMP_MEM_MALLOC                 0
#define MEMP_NUM_PBUF                   16
#define MEMP_NUM_RAW_PCB                4
#define MEMP_NUM_TCP_PCB                8
#define MEMP_NUM_TCP_PCB_LISTEN         4
#define MEMP_NUM_TCP_SEG                16
#define MEMP_NUM_SYS_TIMEOUT            8
#define MEMP_NUM_TCPIP_MSG_API          8
#define MEMP_NUM_TCPIP_MSG_INPKT        8
#define MEMP_NUM_NETBUF                 4
#define MEMP_NUM_NETCONN                4
#define MEMP_NUM_API_MSG                8
#define PBUF_POOL_SIZE                  8
#define PBUF_POOL_BUFSIZE               1536

#define LWIP_IPV4                       1
#define LWIP_IPV6                       0
#define LWIP_ETHERNET                   1
#define LWIP_ARP                        1
#define LWIP_ICMP                       1
#define LWIP_RAW                        1
#define LWIP_TCP                        1
#define LWIP_UDP                        1
#define LWIP_DHCP                       0
#define LWIP_SOCKET                     1
#define LWIP_NETCONN                    1
#define LWIP_STATS                      0
#define LWIP_CHECKSUM_CTRL_PER_NETIF    1
#define LWIP_PACKET_FILTER_API          1
#define LWIP_COMPAT_SOCKETS             0
#define LWIP_ERRNO_STDINCLUDE           1
#define LWIP_TIMEVAL_PRIVATE             0
#define TCPIP_THREAD_NAME               "tcpip"
#define TCPIP_THREAD_STACKSIZE          2048
#define TCPIP_THREAD_PRIO               3
#define TCPIP_MBOX_SIZE                 16
#define TCP_MSS                         1460
#define TCP_WND                         (4 * TCP_MSS)
#define TCP_SND_BUF                     (4 * TCP_MSS)
#define TCP_SND_QUEUELEN                16
#define TCP_QUEUE_OOSEQ                 1
#define TCP_TTL                         255
#define ICMP_TTL                        255
#define ARP_TABLE_SIZE                  8
#define ARP_QUEUEING                    1
unsigned int lwip_port_rand(void);
#define LWIP_RAND() lwip_port_rand()

#endif /* WOLFSENTRY_M33MU_LWIPOPTS_H */
