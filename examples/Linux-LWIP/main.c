// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>

#include <pcap/pcap.h>

#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/ethip6.h>
#include <netif/etharp.h>
#include <lwip/udp.h>
#include <lwip/mld6.h>
#include <lwip/timeouts.h>

#include "echo.h"
#include "ping.h"
#include "sentry.h"

/* Callback to send a raw lwIP packet via PCAP */
static err_t pcap_output(struct netif *netif, struct pbuf *p)
{
    pcap_t *pcap = netif->state;
    //printf("Sending packet with length %d\n", p->tot_len);

    /* Just fire the raw packet data down PCAP */
    int r = pcap_sendpacket(pcap, (uint8_t *)p->payload, p->tot_len);

    if (r != 0)
    {
        printf("Error sending packet\n");
        printf("Error: %s\n", pcap_geterr(pcap));
        fflush(stdout);
        return ERR_IF;
    }

    return ERR_OK;
}

/* Raw input packet callback used for MAC address filtering */
static err_t filter_input(struct pbuf *p, struct netif *inp)
{
    /* Start of payload will have an Ethernet header */
    struct eth_hdr *ethhdr = (struct eth_hdr *)p->payload;
    struct eth_addr *ethaddr = &ethhdr->src;

    /* "src" contains the source hardware address from the packet */
    if (sentry_action_mac(ethaddr) != 0)
    {
        printf("Sentry rejected MAC address %02X:%02X:%02X:%02X:%02X:%02X\n",
                ethaddr->addr[0], ethaddr->addr[1], ethaddr->addr[2],
                ethaddr->addr[3], ethaddr->addr[4], ethaddr->addr[5]);
        fflush(stdout);
        /* Basically drop the packet */
        return ERR_ABRT;
    }
    printf("Sentry accepted MAC address %02X:%02X:%02X:%02X:%02X:%02X\n",
            ethaddr->addr[0], ethaddr->addr[1], ethaddr->addr[2],
            ethaddr->addr[3], ethaddr->addr[4], ethaddr->addr[5]);
    fflush(stdout);
    /* We passed the MAC filter, so pass the packet to the regular internal
     * lwIP input callback */
    return netif_input(p, inp);
}

/* The lwIP network interface init callback */
static err_t init_callback(struct netif *netif)
{
    netif->name[0] = 't';
    netif->name[1] = 'p';
    /* Raw packet is ready to be transmitted, use the callback above */
    netif->linkoutput = pcap_output;
    /* Use the normal lwIP internal callback for preparing a packet
     * header for transmission */
    netif->output = etharp_output;
    /* Use the input callback above for packets coming in */
    netif->input = filter_input;

    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;

    netif_set_link_up(netif);

    return ERR_OK;
}

int main(size_t argc, char **argv)
{
    /* Open PCAP on eth0 */
    pcap_t *pcap = pcap_open_live("eth0", 65536, 1, 100, NULL);
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Create a lwIP network interface struct and give it a MAC */
    struct netif netif;
    memset(&netif, 0, sizeof netif);
    netif.hwaddr_len = 6;
    memcpy(netif.hwaddr, "\xaa\x00\x00\x00\x00\x01", 6);

    /* This is the hard-coded listen IP iaddress */
    ip4_addr_t ip, mask, gw;
    IP4_ADDR(&ip, 172, 20, 20, 5);
    IP4_ADDR(&mask, 255, 255, 0, 0);
    IP4_ADDR(&gw, 172, 20, 20, 1);

    /* Add the lwIP network interface to PCAP with a couple of callbacks */
    netif_add(&netif, &ip, &mask, &gw, pcap, init_callback, ethernet_input);
    netif_set_up(&netif);

    NETIF_SET_CHECKSUM_CTRL(&netif, 0x00FF);

    /* Initialize wolfSentry */
    if (sentry_init() != 0)
    {
        printf("Sentry init failure\n");
        fflush(stdout);
        return -1;
    }

    /* Initialize TCP listener */
    if (echo_init() != 0)
    {
        printf("TCP init failure\n");
        fflush(stdout);
        return -1;
    }

    /* Initialize ICMP listener */
    if (ping_init() != 0)
    {
        printf("ICMP init failure\n");
        fflush(stdout);
        return -1;
    }

    struct pcap_pkthdr *hdr = NULL;
    const unsigned char *data = NULL;

    while (1)
    {
        /* Get next PCAP message (blocking) */
        int r = pcap_next_ex(pcap, &hdr, &data);

        switch (r)
        {
            case 0:
                // Timeout
                continue;

            case -1:
                printf("Error: %s\n", pcap_geterr(pcap));
                fflush(stdout);
                continue;

            case 1:
                break;

            default:
                printf("Unknown result: %d\n", r);
                fflush(stdout);
                continue;
        }

        /* Copy the packet to lwIP's packet buffer and trigger a lwIP packet
         * input */
        //printf("Packet length: %d / %d\n", hdr->len, hdr->caplen);
        struct pbuf *pbuf = pbuf_alloc(PBUF_RAW, hdr->len, PBUF_RAM);
        memcpy(pbuf->payload, data, hdr->len);
        netif.input(pbuf, &netif);
    }

    return 0;
}

