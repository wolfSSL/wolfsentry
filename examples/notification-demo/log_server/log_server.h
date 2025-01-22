/*
 * log_server.h
 *
 * Copyright (C) 2022-2025 wolfSSL Inc.
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

#ifndef __ECHO_H__
#define __ECHO_H__

#define ECHO_DEBUG LWIP_DBG_ON

#include <stdint.h>

struct pbuf;
struct tcp_pcb;
struct tcp_hdr;

struct circlog_message;
extern wolfsentry_errcode_t circlog_init(size_t size);
extern wolfsentry_errcode_t circlog_shutdown(void);
extern wolfsentry_errcode_t circlog_dequeue_one(struct circlog_message **msg);
extern wolfsentry_errcode_t circlog_enqueue_one(size_t msg_len, char **msg_buf);
extern wolfsentry_errcode_t circlog_iterate(struct circlog_message **msg);
typedef wolfsentry_errcode_t (*circlog_format_fn_t)(struct circlog_message *msg, char **out, size_t *out_space);
extern wolfsentry_errcode_t circlog_format_one(struct circlog_message *msg, char **out, size_t *out_space);
extern wolfsentry_errcode_t circlog_reset(void);

int echo_init(void);
int sentry_tcp_inpkt(struct tcp_pcb *pcb, struct tcp_hdr *hdr, uint16_t optlen, uint16_t opt1len, uint8_t *opt2, struct pbuf *p);
int echo_ssl(void);
void echo_msgclose(struct tcp_pcb *pcb);

#endif
