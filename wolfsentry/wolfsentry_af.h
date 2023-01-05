/*
 * wolfsentry_af.h
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

#ifndef WOLFSENTRY_AF_H
#define WOLFSENTRY_AF_H

/* per Linux kernel 5.12, include/linux/socket.h */

#define WOLFSENTRY_AF_UNSPEC       0
#define WOLFSENTRY_AF_UNIX         1       /* Unix domain sockets          */
#define WOLFSENTRY_AF_LOCAL        1       /* POSIX name for WOLFSENTRY_AF_UNIX       */
#define WOLFSENTRY_AF_INET         2       /* Internet IP Protocol         */
#define WOLFSENTRY_AF_AX25         3       /* Amateur Radio AX.25          */
#define WOLFSENTRY_AF_IPX          4       /* Novell IPX                   */
#define WOLFSENTRY_AF_APPLETALK    5       /* AppleTalk DDP                */
#define WOLFSENTRY_AF_NETROM       6       /* Amateur Radio NET/ROM        */
#define WOLFSENTRY_AF_BRIDGE       7       /* Multiprotocol bridge         */
#define WOLFSENTRY_AF_ATMPVC       8       /* ATM PVCs                     */
#define WOLFSENTRY_AF_X25          9       /* Reserved for X.25 project    */
#define WOLFSENTRY_AF_INET6        10      /* IP version 6                 */
#define WOLFSENTRY_AF_ROSE         11      /* Amateur Radio X.25 PLP       */
#define WOLFSENTRY_AF_DECnet       12      /* Reserved for DECnet project  */
#define WOLFSENTRY_AF_NETBEUI      13      /* Reserved for 802.2LLC project*/
#define WOLFSENTRY_AF_SECURITY     14      /* Security callback pseudo AF */
#define WOLFSENTRY_AF_KEY          15      /* PF_KEY key management API */
#define WOLFSENTRY_AF_NETLINK      16
#define WOLFSENTRY_AF_ROUTE        WOLFSENTRY_AF_NETLINK /* Alias to emulate 4.4BSD */
#define WOLFSENTRY_AF_PACKET       17      /* Packet family                */
#define WOLFSENTRY_AF_ASH          18      /* Ash                          */
#define WOLFSENTRY_AF_ECONET       19      /* Acorn Econet                 */
#define WOLFSENTRY_AF_ATMSVC       20      /* ATM SVCs                     */
#define WOLFSENTRY_AF_RDS          21      /* RDS sockets                  */
#define WOLFSENTRY_AF_SNA          22      /* Linux SNA Project (nutters!) */
#define WOLFSENTRY_AF_IRDA         23      /* IRDA sockets                 */
#define WOLFSENTRY_AF_PPPOX        24      /* PPPoX sockets                */
#define WOLFSENTRY_AF_WANPIPE      25      /* Wanpipe API Sockets */
#define WOLFSENTRY_AF_LLC          26      /* Linux LLC                    */
#define WOLFSENTRY_AF_IB           27      /* Native InfiniBand address    */
#define WOLFSENTRY_AF_MPLS         28      /* MPLS */
#define WOLFSENTRY_AF_CAN          29      /* Controller Area Network      */
#define WOLFSENTRY_AF_TIPC         30      /* TIPC sockets                 */
#define WOLFSENTRY_AF_BLUETOOTH    31      /* Bluetooth sockets            */
#define WOLFSENTRY_AF_IUCV         32      /* IUCV sockets                 */
#define WOLFSENTRY_AF_RXRPC        33      /* RxRPC sockets                */
#define WOLFSENTRY_AF_ISDN         34      /* mISDN sockets                */
#define WOLFSENTRY_AF_PHONET       35      /* Phonet sockets               */
#define WOLFSENTRY_AF_IEEE802154   36      /* IEEE802154 sockets           */
#define WOLFSENTRY_AF_CAIF         37      /* CAIF sockets                 */
#define WOLFSENTRY_AF_ALG          38      /* Algorithm sockets            */
#define WOLFSENTRY_AF_NFC          39      /* NFC sockets                  */
#define WOLFSENTRY_AF_VSOCK        40      /* vSockets                     */
#define WOLFSENTRY_AF_KCM          41      /* Kernel Connection Multiplexor*/
#define WOLFSENTRY_AF_QIPCRTR      42      /* Qualcomm IPC Router          */
#define WOLFSENTRY_AF_SMC          43      /* smc sockets: reserve number for
                                 * PF_SMC protocol family that
                                 * reuses WOLFSENTRY_AF_INET address family
                                 */
#define WOLFSENTRY_AF_XDP          44      /* XDP sockets                  */

#define WOLFSENTRY_AF_BSD_OFFSET 100

/* from FreeBSD at commit a56e5ad6 */
#define WOLFSENTRY_AF_IMPLINK      (WOLFSENTRY_AF_BSD_OFFSET + 3)          /* arpanet imp addresses */
#define WOLFSENTRY_AF_PUP          (WOLFSENTRY_AF_BSD_OFFSET + 4)          /* pup protocols: e.g. BSP */
#define WOLFSENTRY_AF_CHAOS        (WOLFSENTRY_AF_BSD_OFFSET + 5)          /* mit CHAOS protocols */
#define WOLFSENTRY_AF_NETBIOS      (WOLFSENTRY_AF_BSD_OFFSET + 6)          /* SMB protocols */
#define WOLFSENTRY_AF_ISO          (WOLFSENTRY_AF_BSD_OFFSET + 7)          /* ISO protocols */
#define WOLFSENTRY_AF_OSI          WOLFSENTRY_AF_ISO
#define WOLFSENTRY_AF_ECMA         (WOLFSENTRY_AF_BSD_OFFSET + 8)          /* European computer manufacturers */
#define WOLFSENTRY_AF_DATAKIT      (WOLFSENTRY_AF_BSD_OFFSET + 9)          /* datakit protocols */
#define WOLFSENTRY_AF_DLI          (WOLFSENTRY_AF_BSD_OFFSET + 13)         /* DEC Direct data link interface */
#define WOLFSENTRY_AF_LAT          (WOLFSENTRY_AF_BSD_OFFSET + 14)         /* LAT */
#define WOLFSENTRY_AF_HYLINK       (WOLFSENTRY_AF_BSD_OFFSET + 15)         /* NSC Hyperchannel */
#define WOLFSENTRY_AF_LINK         (WOLFSENTRY_AF_BSD_OFFSET + 18)         /* Link layer interface */
#define WOLFSENTRY_AF_COIP         (WOLFSENTRY_AF_BSD_OFFSET + 20)         /* connection-oriented IP, aka ST II */
#define WOLFSENTRY_AF_CNT          (WOLFSENTRY_AF_BSD_OFFSET + 21)         /* Computer Network Technology */
#define WOLFSENTRY_AF_SIP          (WOLFSENTRY_AF_BSD_OFFSET + 24)         /* Simple Internet Protocol */
#define WOLFSENTRY_AF_SLOW         (WOLFSENTRY_AF_BSD_OFFSET + 33)         /* 802.3ad slow protocol */
#define WOLFSENTRY_AF_SCLUSTER     (WOLFSENTRY_AF_BSD_OFFSET + 34)         /* Sitara cluster protocol */
#define WOLFSENTRY_AF_ARP          (WOLFSENTRY_AF_BSD_OFFSET + 35)
#define WOLFSENTRY_AF_IEEE80211    (WOLFSENTRY_AF_BSD_OFFSET + 37)         /* IEEE 802.11 protocol */
#define WOLFSENTRY_AF_INET_SDP     (WOLFSENTRY_AF_BSD_OFFSET + 40)         /* OFED Socket Direct Protocol ipv4 */
#define WOLFSENTRY_AF_INET6_SDP    (WOLFSENTRY_AF_BSD_OFFSET + 42)         /* OFED Socket Direct Protocol ipv6 */
#define WOLFSENTRY_AF_HYPERV       (WOLFSENTRY_AF_BSD_OFFSET + 43)         /* HyperV sockets */

#define WOLFSENTRY_AF_USER_OFFSET 256

#endif /* WOLFSENTRY_AF_H */
