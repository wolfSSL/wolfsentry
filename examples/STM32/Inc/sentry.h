// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef __SENTRY_H__
#define __SENTRY_H__
#include "lwip/tcp.h"
#include <netif/etharp.h>
#include <stdbool.h>

typedef enum
{
    SENTRY_ACTION_NONE,
    SENTRY_ACTION_CONNECT,
    SENTRY_ACTION_DISCONNECT
} sentry_action_type;

int sentry_init(void);
int sentry_action(struct tcp_pcb *pcb, sentry_action_type action);
int sentry_action_ping(const ip_addr_t *addr, u8_t type);
int sentry_action_mac(struct eth_addr *addr);
#endif
