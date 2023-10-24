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

/*! @file wolfsentry_af.h
    \brief Definitions for address families.

    Included by `wolfsentry.h`.
 */

#ifndef WOLFSENTRY_AF_H
#define WOLFSENTRY_AF_H

/*! \addtogroup wolfsentry_addr_family
 *  @{
 */

/* per Linux kernel 5.12, include/linux/socket.h */

#define WOLFSENTRY_AF_UNSPEC       0
#define WOLFSENTRY_AF_UNIX         1       /*!< \brief Unix domain sockets */
#define WOLFSENTRY_AF_LOCAL        1       /*!< \brief POSIX name for WOLFSENTRY_AF_UNIX */
#define WOLFSENTRY_AF_INET         2       /*!< \brief Internet IP Protocol */
#define WOLFSENTRY_AF_AX25         3       /*!< \brief Amateur Radio AX.25 */
#define WOLFSENTRY_AF_IPX          4       /*!< \brief Novell IPX */
#define WOLFSENTRY_AF_APPLETALK    5       /*!< \brief AppleTalk DDP */
#define WOLFSENTRY_AF_NETROM       6       /*!< \brief Amateur Radio NET/ROM */
#define WOLFSENTRY_AF_BRIDGE       7       /*!< \brief Multiprotocol bridge */
#define WOLFSENTRY_AF_ATMPVC       8       /*!< \brief ATM PVCs */
#define WOLFSENTRY_AF_X25          9       /*!< \brief Reserved for X.25 project */
#define WOLFSENTRY_AF_INET6        10      /*!< \brief IP version 6 */
#define WOLFSENTRY_AF_ROSE         11      /*!< \brief Amateur Radio X.25 PLP */
#define WOLFSENTRY_AF_DECnet       12      /*!< \brief Reserved for DECnet project */
#define WOLFSENTRY_AF_NETBEUI      13      /*!< \brief Reserved for 802.2LLC project*/
#define WOLFSENTRY_AF_SECURITY     14      /*!< \brief Security callback pseudo AF */
#define WOLFSENTRY_AF_KEY          15      /*!< \brief PF_KEY key management API */
#define WOLFSENTRY_AF_NETLINK      16
#define WOLFSENTRY_AF_ROUTE        WOLFSENTRY_AF_NETLINK /*!< \brief Alias to emulate 4.4BSD */
#define WOLFSENTRY_AF_PACKET       17      /*!< \brief Packet family */
#define WOLFSENTRY_AF_ASH          18      /*!< \brief Ash */
#define WOLFSENTRY_AF_ECONET       19      /*!< \brief Acorn Econet */
#define WOLFSENTRY_AF_ATMSVC       20      /*!< \brief ATM SVCs */
#define WOLFSENTRY_AF_RDS          21      /*!< \brief RDS sockets */
#define WOLFSENTRY_AF_SNA          22      /*!< \brief Linux SNA Project (nutters!) */
#define WOLFSENTRY_AF_IRDA         23      /*!< \brief IRDA sockets */
#define WOLFSENTRY_AF_PPPOX        24      /*!< \brief PPPoX sockets */
#define WOLFSENTRY_AF_WANPIPE      25      /*!< \brief Wanpipe API Sockets */
#define WOLFSENTRY_AF_LLC          26      /*!< \brief Linux LLC */
#define WOLFSENTRY_AF_IB           27      /*!< \brief Native InfiniBand address */
#define WOLFSENTRY_AF_MPLS         28      /*!< \brief MPLS */
#define WOLFSENTRY_AF_CAN          29      /*!< \brief Controller Area Network */
#define WOLFSENTRY_AF_TIPC         30      /*!< \brief TIPC sockets */
#define WOLFSENTRY_AF_BLUETOOTH    31      /*!< \brief Bluetooth sockets */
#define WOLFSENTRY_AF_IUCV         32      /*!< \brief IUCV sockets */
#define WOLFSENTRY_AF_RXRPC        33      /*!< \brief RxRPC sockets */
#define WOLFSENTRY_AF_ISDN         34      /*!< \brief mISDN sockets */
#define WOLFSENTRY_AF_PHONET       35      /*!< \brief Phonet sockets */
#define WOLFSENTRY_AF_IEEE802154   36      /*!< \brief IEEE802154 sockets */
#define WOLFSENTRY_AF_CAIF         37      /*!< \brief CAIF sockets */
#define WOLFSENTRY_AF_ALG          38      /*!< \brief Algorithm sockets */
#define WOLFSENTRY_AF_NFC          39      /*!< \brief NFC sockets */
#define WOLFSENTRY_AF_VSOCK        40      /*!< \brief vSockets */
#define WOLFSENTRY_AF_KCM          41      /*!< \brief Kernel Connection Multiplexor*/
#define WOLFSENTRY_AF_QIPCRTR      42      /*!< \brief Qualcomm IPC Router */
#define WOLFSENTRY_AF_SMC          43      /*!< \brief smc sockets: reserve number for PF_SMC protocol family that reuses WOLFSENTRY_AF_INET address family */
#define WOLFSENTRY_AF_XDP          44      /*!< \brief XDP sockets */

#define WOLFSENTRY_AF_BSD_OFFSET 100

/*!< \brief from FreeBSD at commit a56e5ad6, except WOLFSENTRY_AF_LINK64, added here. */
#define WOLFSENTRY_AF_IMPLINK      (WOLFSENTRY_AF_BSD_OFFSET + 3)          /*!< \brief arpanet imp addresses */
#define WOLFSENTRY_AF_PUP          (WOLFSENTRY_AF_BSD_OFFSET + 4)          /*!< \brief pup protocols: e.g. BSP */
#define WOLFSENTRY_AF_CHAOS        (WOLFSENTRY_AF_BSD_OFFSET + 5)          /*!< \brief mit CHAOS protocols */
#define WOLFSENTRY_AF_NETBIOS      (WOLFSENTRY_AF_BSD_OFFSET + 6)          /*!< \brief SMB protocols */
#define WOLFSENTRY_AF_ISO          (WOLFSENTRY_AF_BSD_OFFSET + 7)          /*!< \brief ISO protocols */
#define WOLFSENTRY_AF_OSI          WOLFSENTRY_AF_ISO
#define WOLFSENTRY_AF_ECMA         (WOLFSENTRY_AF_BSD_OFFSET + 8)          /*!< \brief European computer manufacturers */
#define WOLFSENTRY_AF_DATAKIT      (WOLFSENTRY_AF_BSD_OFFSET + 9)          /*!< \brief datakit protocols */
#define WOLFSENTRY_AF_DLI          (WOLFSENTRY_AF_BSD_OFFSET + 13)         /*!< \brief DEC Direct data link interface */
#define WOLFSENTRY_AF_LAT          (WOLFSENTRY_AF_BSD_OFFSET + 14)         /*!< \brief LAT */
#define WOLFSENTRY_AF_HYLINK       (WOLFSENTRY_AF_BSD_OFFSET + 15)         /*!< \brief NSC Hyperchannel */
#define WOLFSENTRY_AF_LINK48       (WOLFSENTRY_AF_BSD_OFFSET + 18)         /*!< \brief Link layer interface, explicit EUI-48 */
#define WOLFSENTRY_AF_LINK         WOLFSENTRY_AF_LINK48                    /*!< \brief Link layer interface, implicit EUI-48 */
#define WOLFSENTRY_AF_LINK64       (WOLFSENTRY_AF_BSD_OFFSET + 19)         /*!< \brief Link layer interface, explicit EUI-64 */
#define WOLFSENTRY_AF_COIP         (WOLFSENTRY_AF_BSD_OFFSET + 20)         /*!< \brief connection-oriented IP, aka ST II */
#define WOLFSENTRY_AF_CNT          (WOLFSENTRY_AF_BSD_OFFSET + 21)         /*!< \brief Computer Network Technology */
#define WOLFSENTRY_AF_SIP          (WOLFSENTRY_AF_BSD_OFFSET + 24)         /*!< \brief Simple Internet Protocol */
#define WOLFSENTRY_AF_SLOW         (WOLFSENTRY_AF_BSD_OFFSET + 33)         /*!< \brief 802.3ad slow protocol */
#define WOLFSENTRY_AF_SCLUSTER     (WOLFSENTRY_AF_BSD_OFFSET + 34)         /*!< \brief Sitara cluster protocol */
#define WOLFSENTRY_AF_ARP          (WOLFSENTRY_AF_BSD_OFFSET + 35)
#define WOLFSENTRY_AF_IEEE80211    (WOLFSENTRY_AF_BSD_OFFSET + 37)         /*!< \brief IEEE 802.11 protocol */
#define WOLFSENTRY_AF_INET_SDP     (WOLFSENTRY_AF_BSD_OFFSET + 40)         /*!< \brief OFED Socket Direct Protocol ipv4 */
#define WOLFSENTRY_AF_INET6_SDP    (WOLFSENTRY_AF_BSD_OFFSET + 42)         /*!< \brief OFED Socket Direct Protocol ipv6 */
#define WOLFSENTRY_AF_HYPERV       (WOLFSENTRY_AF_BSD_OFFSET + 43)         /*!< \brief HyperV sockets */

#define WOLFSENTRY_AF_USER_OFFSET 256

/*! @} (end wolfsentry_addr_family) */

#endif /* WOLFSENTRY_AF_H */
