// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __ECHO_H__
#define __ECHO_H__

#include <stdint.h>

struct pbuf;
struct tcp_pcb;
struct tcp_hdr;

int echo_init(void);
int sentry_tcp_inpkt(struct tcp_pcb *pcb, struct tcp_hdr *hdr, uint16_t optlen, uint16_t opt1len, uint8_t *opt2, struct pbuf *p);

#endif
