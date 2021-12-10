// SPDX-License-Identifier: GPL-2.0-or-later

#include "lwip/debug.h"

#include "lwip/stats.h"

#include "echo.h"
#include "sentry.h"
#include "lwip/tcp.h"
#include "lwip/prot/tcp.h"

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <time.h>

/* Called by echo_msgrecv() when it effectively gets an EOF */
static void echo_msgclose(struct tcp_pcb *pcb)
{
    printf("Closing connection from: %s\n", ipaddr_ntoa(&(pcb->remote_ip)));
    /* Tell sentry_action() that this is a disconnect event which decrements
     * the connection count */
    sentry_action(&pcb->local_ip, &pcb->remote_ip, pcb->local_port, pcb->remote_port, SENTRY_ACTION_DISCONNECT);

    /* Remove all the callbacks and shutdown the connection */
    tcp_arg(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_arg(pcb, NULL);
    tcp_close(pcb);
}

/* Message received callback */
static err_t echo_msgrecv(void *arg, struct tcp_pcb *pcb, struct pbuf *p,
                          err_t err)
{
    if (err == ERR_OK && p != NULL)
    {
        struct pbuf *q;

        for (q = p; q != NULL; q = q->next)
        {
            printf("Got: %.*s\n", q->len, q->payload);
        }
    }
    else if (err == ERR_OK && p == NULL)
    {
        echo_msgclose(pcb);
    }

    return ERR_OK;
}

/* TCP error callback handler */
static void echo_msgerr(void *arg, err_t err)
{
    LWIP_DEBUGF(ECHO_DEBUG, ("echo_msgerr: %s (%i)\n", lwip_strerr(err), err));
    printf("Err: %s\n", lwip_strerr(err));
}

/* TCP accept connection callback handler */
static err_t echo_msgaccept(void *arg, struct tcp_pcb *pcb, err_t err)
{
    /* Accepted new connection */
    LWIP_PLATFORM_DIAG(("echo_msgaccept called\n"));

    printf("Connect from: %s port: %d\n", ipaddr_ntoa(&(pcb->remote_ip)), pcb->remote_port);

    /* The below is an alternative hook to check for incoming connections. The
     * down side of this is that it will only trigger after the initial SYN/ACK
     */
    /*
    if (sentry_action(pcb, SENTRY_ACTION_CONNECT) != 0)
    {
        printf("Sentry rejected connection\n");
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    */

    /* Set an arbitrary pointer for callbacks. We don't use this right now */
    //tcp_arg(pcb, esm);

    /* Set TCP receive packet callback. */
    tcp_recv(pcb, echo_msgrecv);

    /* Set an error callback. */
    tcp_err(pcb, echo_msgerr);

    return ERR_OK;
}

/* Init the TCP listener */
int echo_init(void)
{
    struct tcp_pcb *pcb;

    /* Create lwIP TCP instance */
    pcb = tcp_new();
    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: pcb: %x\n", pcb));
    /* Bind port 11111 */
    int r = tcp_bind(pcb, IP_ADDR_ANY, 11111);
    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: tcp_bind: %d\n", r));
    /* Enable listening */
    pcb = tcp_listen(pcb);
    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: listen-pcb: %x\n", pcb));
    /* Set accept connection callback */
    tcp_accept(pcb, echo_msgaccept);

    return 0;
}

/* Hook to incoming TCP packet. We catch incoming connections here because the
 * tcp_accept() hook is triggered after the first ACK
 */
int sentry_tcp_inpkt(struct tcp_pcb *pcb, struct tcp_hdr *hdr, uint16_t optlen,
        uint16_t opt1len, uint8_t *opt2, struct pbuf *p)
{
    /* First incoming packet is in a LISTEN state */
    if (pcb->state == LISTEN)
    {
        /* The tcp_pcb struct does is not filled in with the IP/port details
         * yet, that happens immediately after this callback, so we get these
         * details from other sources. The same sources that are about to fill
         * in the details into the sruct */
        printf("Incomming connection from: %s\n",
                ipaddr_ntoa(ip_current_src_addr()));
        if (sentry_action(ip_current_dest_addr(), ip_current_src_addr(),
                    pcb->local_port, hdr->src , SENTRY_ACTION_CONNECT) != 0)
        {
            printf("Sentry rejected connection from: %s\n",
                    ipaddr_ntoa(ip_current_src_addr()));
            return ERR_ABRT;
        }
    }
    return ERR_OK;
}
