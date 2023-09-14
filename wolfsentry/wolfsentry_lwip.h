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

/*! @file wolfsentry_lwip.h
 *  \brief Prototypes for lwIP callback installation functions, for use in lwIP applications.
 *
 * `packet_filter_event_mask_t` is passed to lwIP via the callback installation routines, to designate which events are of interest.  It is set to a bitwise-OR of values from `packet_filter_event_t`, defined in `src/include/lwip/filter.h` in the lwIP source tree after applying `lwip/LWIP_PACKET_FILTER_API.patch`.  The values are:
 *
 * `FILT_BINDING` -- Call into wolfSentry (filter) on binding events<br>
 * `FILT_DISSOCIATE` -- Call into wolfSentry on socket dissociation events<br>
 * `FILT_LISTENING` -- Call into wolfSentry at initiation of socket listening<br>
 * `FILT_STOP_LISTENING` -- Call into wolfSentry when listening is shut down<br>
 * `FILT_CONNECTING` -- Call into wolfSentry (filter) when connecting out<br>
 * `FILT_ACCEPTING` -- Call into wolfSentry (filter) when accepting an inbound connection<br>
 * `FILT_CLOSED` -- Call into wolfSentry when socket is closed<br>
 * `FILT_REMOTE_RESET` -- Call into wolfSentry when a connection was reset by the remote peer<br>
 * `FILT_RECEIVING` -- Call into wolfSentry (filter) for each regular inbound packet of data<br>
 * `FILT_SENDING` -- Call into wolfSentry (filter) for each regular outbound packet of data<br>
 * `FILT_ADDR_UNREACHABLE` -- Call into wolfSentry when inbound traffic attempts to reach an unknown address<br>
 * `FILT_PORT_UNREACHABLE` -- Call into wolfSentry when inbound traffic attempts to reach an unlistened/unbound port<br>
 * `FILT_INBOUND_ERR` -- Call into wolfSentry when inbound traffic results in detection of an error by lwIP<br>
 * `FILT_OUTBOUND_ERR` -- Call into wolfSentry when outbound traffic results in detection of an error by lwIP<br>
 */

#ifndef WOLFSENTRY_LWIP_H
#define WOLFSENTRY_LWIP_H

/*! \addtogroup wolfsentry_lwip
 * @{
 */

#include "lwip/init.h"

#if LWIP_PACKET_FILTER_API

#include "lwip/filter.h"

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_ethernet_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t ethernet_mask);
    /*!< \brief Install wolfSentry callbacks into lwIP for ethernet (layer 2) filtering. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_ip_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t ip_mask);
    /*!< \brief Install wolfSentry callbacks into lwIP for IPv4/IPv6 (layer 3) filtering. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_icmp_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t icmp_mask);
    /*!< \brief Install wolfSentry callbacks into lwIP for ICMP filtering. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_tcp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t tcp_mask);
    /*!< \brief Install wolfSentry callbacks into lwIP for TCP (layer 4) filtering. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_udp_callback(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t udp_mask);
    /*!< \brief Install wolfSentry callbacks into lwIP for UDP (layer 4) filtering. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_install_lwip_filter_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    packet_filter_event_mask_t ethernet_mask,
    packet_filter_event_mask_t ip_mask,
    packet_filter_event_mask_t icmp_mask,
    packet_filter_event_mask_t tcp_mask,
    packet_filter_event_mask_t udp_mask);
    /*!< \brief Install wolfSentry callbacks for all layers/protocols enabled by the supplied masks. */

WOLFSENTRY_API_VOID wolfsentry_cleanup_lwip_filter_callbacks(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *arg);
    /*!< \brief Disables any wolfSentry callbacks previously installed in lwIP. */

#endif /* LWIP_PACKET_FILTER_API */

/*! @} */

#endif /* WOLFSENTRY_LWIP_H */
