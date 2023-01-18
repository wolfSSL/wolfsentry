/*
 * sentry.h
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

#ifndef __SENTRY_H__
#define __SENTRY_H__

#include <wolfsentry/wolfsentry.h>
#include <wolfsentry/wolfsentry_util.h>
#include <wolfsentry/wolfsentry_json.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/certs_test.h>
#include <wolfssl/ssl.h>

#ifdef BUILD_FOR_FREERTOS_LWIP

#include "lwip/tcp.h"
#include "lwip/sockets.h"
#include <netif/etharp.h>
#include "lwip/etharp.h"

#elif defined(BUILD_FOR_LINUX) || defined(BUILD_FOR_MACOSX)

#include <inttypes.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef uint8_t u8_t;
typedef uint32_t u32_t;
#define ip_addr_t struct in_addr

#else

#error only know how to build for FreeRTOS-LWIP and Linux

#endif

#include <stdbool.h>

typedef enum {
    SENTRY_ACTION_NONE,
    SENTRY_ACTION_CONNECT,
    SENTRY_ACTION_DISCONNECT
} sentry_action_type;

int sentry_init(
    WOLFSSL_CTX *wolfssl_ctx,
    struct wolfsentry_host_platform_interface *hpi,
    const unsigned char *json_config);

extern struct wolfsentry_context *global_wolfsentry;
#ifdef WOLFSENTRY_THREADSAFE
/* currently log_server is single-threaded, so a single thread object is used for the entire process. */
extern struct wolfsentry_thread_context *global_thread;
#endif

int sentry_action(ip_addr_t *local_ip, ip_addr_t *remote_ip, in_port_t local_port, in_port_t remote_port, sentry_action_type action);

struct wolfsentry_data {
    WOLFSENTRY_SOCKADDR(128) remote;
    WOLFSENTRY_SOCKADDR(128) local;
    wolfsentry_route_flags_t flags;
    wolfsentry_action_res_t action_results;
    wolfsentry_ent_id_t rule_route_id;
    struct wolfsentry_route *rule_route;
    int ssl_error;
    void *heap;
    int alloctype;
};

int wolfsentry_store_endpoints(
    WOLFSSL *ssl,
    struct sockaddr_in *remote,
    struct sockaddr_in *local,
    int proto,
    wolfsentry_route_flags_t flags,
    struct wolfsentry_data **wolfsentry_data_out);

#ifdef BUILD_FOR_FREERTOS_LWIP
int sentry_action_ping(const ip_addr_t *addr, u8_t type);
int sentry_action_mac(struct eth_addr *addr);
#endif

#endif
