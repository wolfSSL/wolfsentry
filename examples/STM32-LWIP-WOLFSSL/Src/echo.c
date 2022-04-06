// SPDX-License-Identifier: GPL-2.0-or-later

#include "cmsis_os.h"
#include "lwip/debug.h"
#include "lwip/tcp.h"
#include "lwip/prot/tcp.h"
#include "lwip/stats.h"

#include "echo.h"
#include "sentry.h"


#define USE_CERT_BUFFERS_2048
#include <wolfssl/certs_test.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <time.h>

WOLFSSL_CTX* wolf_ctx = NULL;
QueueHandle_t connQueue;

struct thread_data {
	WOLFSSL *ssl;
	struct tcp_pcb *pcb;
};

const char cert[] = "-----BEGIN CERTIFICATE-----"
"MIIB2TCCAX+gAwIBAgIUclisQ2ZFuLig1QRSSpfRgt7F3jswCgYIKoZIzj0EAwIw"
"QjELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEcMBoGA1UECgwT"
"RGVmYXVsdCBDb21wYW55IEx0ZDAeFw0yMjAzMjgxNjE5MjFaFw0yMzAzMjgxNjE5"
"MjFaMEIxCzAJBgNVBAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAaBgNV"
"BAoME0RlZmF1bHQgQ29tcGFueSBMdGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC"
"AAQERlfGhvecebosgalSR6hmUTRIWB7FZ6jt3JcapCYmFjAhpNtkYBeqqz1paRil"
"hBxttla7S2YmGAO3wjn2vROyo1MwUTAdBgNVHQ4EFgQU10K/RQqcUiFItOJCo0ru"
"/oi+DVswHwYDVR0jBBgwFoAU10K/RQqcUiFItOJCo0ru/oi+DVswDwYDVR0TAQH/"
"BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAovdAAdctkSOQnwsqcdOiYwxjwS6z"
"lVmbi+AeY3ZjiYQCIAy/eYMMhFGMnIukdTMIP/Qf3KqfcBvlpLqiI3OaBZw4"
"-----END CERTIFICATE-----";

const char key[] = "-----BEGIN EC PARAMETERS-----"
"BggqhkjOPQMBBw=="
"-----END EC PARAMETERS-----"
"-----BEGIN EC PRIVATE KEY-----"
"MHcCAQEEIMFl+x1zSTy9H0P8iv3h4uFYtcr/Ad1gvAROSrqOMiYEoAoGCCqGSM49"
"AwEHoUQDQgAEBEZXxob3nHm6LIGpUkeoZlE0SFgexWeo7dyXGqQmJhYwIaTbZGAX"
"qqs9aWkYpYQcbbZWu0tmJhgDt8I59r0Tsg=="
"-----END EC PRIVATE KEY-----";

/* Called by echo_msgrecv() when it effectively gets an EOF */
void echo_msgclose(struct tcp_pcb *pcb)
{
    printf("Closing connection from: %s\n", ipaddr_ntoa(&(pcb->remote_ip)));
    /* Tell sentry_action() that this is a disconnect event which decrements
     * the connection count */
    //sentry_action(&pcb->local_ip, &pcb->remote_ip, pcb->local_port, pcb->remote_port, SENTRY_ACTION_DISCONNECT);

    /* Remove all the callbacks and shutdown the connection */
    tcp_arg(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_close(pcb);
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
	WOLFSSL *ssl;
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

    struct thread_data tdata;
    tdata.pcb = pcb;
    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(wolf_ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    tdata.ssl = ssl;
    wolfSSL_SetIO_LwIP(ssl, pcb, NULL, NULL, NULL);
    if( xQueueSendFromISR( connQueue, ( void * ) &tdata,0 ) != pdPASS )
    {
    	fprintf(stderr, "Error adding to queue\r\n");
        tcp_abort(pcb);
        return ERR_ABRT;
    }

    return ERR_OK;
}

/* Init the TCP listener */
int echo_ssl()
{
	int ret;

    wolfSSL_Init();
    wolfSSL_Debugging_ON();
    /* Create and initialize WOLFSSL_CTX */
    if ((wolf_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return -1;
    }

    /* Load server certificates into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_use_certificate_buffer(wolf_ctx, cert,
    		strlen(cert), WOLFSSL_FILETYPE_PEM))
        != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load certificate buffer.\n");
        return -1;
    }

    /* Load server key into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_use_PrivateKey_buffer(wolf_ctx, key,
    		strlen(key), WOLFSSL_FILETYPE_PEM))
        != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load key buffer.\n");
        return -1;
    }
    return 0;
}
void echo_init()
{
	struct tcp_pcb *pcb;
    /* Create lwIP TCP instance */
    pcb = tcp_new();
    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: pcb: %x\n", pcb));
    /* Bind port 11111 */
    int r = tcp_bind(pcb, IP_ADDR_ANY, 8080);
    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: tcp_bind: %d\n", r));
    /* Enable listening */
    tcp_arg(pcb, NULL);
    pcb = tcp_listen(pcb);
    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: listen-pcb: %x\n", pcb));
    /* Set accept connection callback */
    tcp_accept(pcb, echo_msgaccept);
    fprintf(stderr, "Accept ready!\n");
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
        //fprintf(stderr, "Incomming connection from: %s\n",
        //        ipaddr_ntoa(ip_current_src_addr()));

        if (sentry_action(ip_current_dest_addr(), ip_current_src_addr(),
                    pcb->local_port, hdr->src , SENTRY_ACTION_CONNECT) != 0)
        {
            fprintf(stderr, "Sentry rejected connection from: %s\n",
                    ipaddr_ntoa(ip_current_src_addr()));
            return ERR_ABRT;
        }
    }
    return ERR_OK;
}
