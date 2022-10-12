// SPDX-License-Identifier: GPL-2.0-or-later

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


int echo_init();
int sentry_tcp_inpkt(struct tcp_pcb *pcb, struct tcp_hdr *hdr, uint16_t optlen, uint16_t opt1len, uint8_t *opt2, struct pbuf *p);
int echo_ssl();
void echo_msgclose(struct tcp_pcb *pcb);

#endif
