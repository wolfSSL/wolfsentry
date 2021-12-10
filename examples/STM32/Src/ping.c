// SPDX-License-Identifier: GPL-2.0-or-later

#include "lwip/debug.h"

#include "ping.h"
#include "sentry.h"
#include "lwip/raw.h"
#include "lwip/icmp.h"

/* ICMP message received. Return 0 to let lwIP process it and 1 to eat the
 * packet */
static u8_t ping_recv(void *arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr)
{
  struct icmp_echo_hdr *iecho;
  LWIP_UNUSED_ARG(arg);
  LWIP_ASSERT("p != NULL", p != NULL);

  /* If the message is long enough, get the header */
  if (p->tot_len >= (PBUF_IP_HLEN + sizeof(struct icmp_echo_hdr))) {

      iecho = (struct icmp_echo_hdr *)(p->payload + PBUF_IP_HLEN);
      /* Extract the ICMP message type (8 is a PING received), wolfSentry
       * will accept or reject the ICMP message */
      if (sentry_action_ping(addr, iecho->type) != 0)
      {
          /* RAW recv needs to free if not returning 0 */
          pbuf_free(p);
          printf("Ping rejected from %s\n", ipaddr_ntoa(addr));
          return 1;
      }
  }

  printf("Ping accepted from %s\n", ipaddr_ntoa(addr));
  return 0;
}

/* Initialise the ICMP hooks */
int ping_init(void)
{
  struct raw_pcb *ping_pcb;
  /* Create a new listener instance for ICMP messages */
  ping_pcb = raw_new(IP_PROTO_ICMP);
  LWIP_ASSERT("ping_pcb != NULL", ping_pcb != NULL);

  /* Callback to ping_recv in ICMP message received */
  raw_recv(ping_pcb, ping_recv, NULL);
  /* Bind to ICMP on any address */
  raw_bind(ping_pcb, IP_ADDR_ANY);

  return 0;
}
