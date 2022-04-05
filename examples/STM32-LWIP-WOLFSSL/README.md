# wolfSentry STM32 LWIP wolfSSL Example

This is a demo application that starts a very basic HTTPS server. It is designed to accept HTTPS connections on port 8080 from a specific IP. Connections from other IPs will be blocked. On the wolfSSL side the native LWIP code is used to send/receive data.

This example is designed to be used with STM32CubeIDE.

## STM32CubeMX Setup

When creating a project in STM32CubeMX enable FREERTOS and LWIP, you will also need to configure the `ETH` Connectivity option as appropriate for your hardware.

**NOTES:**
1. It is recommended that in FREERTOS "Tasks and Queues" you increase the `defaultTask` stack size, especially if you are doing DHCP in LWIP. 8KB should work fine.

2. It is recommended you use CMSISv1 and do not use multi-threaded support with STM32Cube's version of LWIP. Alternative configurations can have stability issues.

## Copying Files

1. Copy the wolfsentry git checkout (or make a new clone) at the base of the project.
2. Copy the files in the `Src` directory next to this README to the `Core/Src` directory of the project.
3. Copy the files in the `Inc` directory next to this README to the `Core/Inc` directory of the project.

## STM32CubeIDE Setup

In STM32CubeIDE click on "Project" -> "Properties". From here go to "C/C++ General" -> "Paths and Symbols". Now click on the "Source Location" tab and click on "Add Folder". There will be "wolfsentry" available to select which will add wolfSentry to the build chain. Once added click on "Edit Filter", click on "Add..." and add the following:

```
**/unittests.c
**/examples
```

This is so that the unittests do not build as part of your application, causing a conflict for `main()`.

## Code Changes

### wolfsentry_options.h

In `wolfsentry/wolfsentry` create the file `wolfsentry_options.h`:

```c
#ifndef WOLFSENTRY_OPTIONS_H
#define WOLFSENTRY_OPTIONS_H

#define FREERTOS
#define WOLFSENTRY_SINGLETHREADED
#define WOLFSENTRY_LWIP
#define WOLFSENTRY_NO_PROTOCOL_NAMES
#define WOLFSENTRY_NO_POSIX_MEMALIGN
#endif /* WOLFSENTRY_OPTIONS_H */
```

### main.c

In `main()` add the following as needed, use the comment blocks to locate where to place the code.

Near the top of the file:

```c
/* USER CODE BEGIN Includes */

#include "echo.h"
#include "sentry.h"
```

In `StartDefaultTask()`:

```c
  /* USER CODE BEGIN 5 */
  printf("Start!\r\n");
  printf("Sentry init\n");
  sentry_init();
  printf("Echo init\n");
  echo_ssl();

  connQueue = xQueueCreate( 10, sizeof( struct thread_data* ) );
  echo_init();

  /* Infinite loop */
  for(;;)
  {
		BaseType_t qRet = pdFALSE;
		struct thread_data tdata;
		while (qRet != pdTRUE) {
		  qRet = xQueueReceive( connQueue, &( tdata ), ( TickType_t ) 10 );
		}
		char buff[256];
		int ret;
		int retry = 10;
		struct tcp_pcb *pcb = tdata.pcb;
		WOLFSSL *ssl = tdata.ssl;

		fprintf(stderr, "Queue item running\r\n");
		do {
			if (pcb->state == CLOSE_WAIT) {
				fprintf(stderr, "Client immediately hung-up\n");
				goto close_wait;
			}
			ret = wolfSSL_accept(ssl);
			if ((wolfSSL_want_read(ssl) || wolfSSL_want_write(ssl))) {
				osDelay(500);
				retry--;
			} else {
				retry = 0;
			}
		} while (retry);
		if (ret != WOLFSSL_SUCCESS) {
			fprintf(stderr, "wolfSSL_accept ret = %d, error = %d\n",
				ret, wolfSSL_get_error(ssl, ret));
			goto ssl_shutdown;
		} else {
			fprintf(stderr, "Handshake done!\n");
		}

		memset(buff, 0, sizeof(buff));
		if (ret == WOLFSSL_SUCCESS) {
			retry = 10;
			do {
				ret = wolfSSL_read(ssl, buff, sizeof(buff));
				if ((wolfSSL_want_read(ssl) || wolfSSL_want_write(ssl))) {
					osDelay(500);
					retry--;
				} else {
					retry = 0;
				}
			} while (retry);
			if (ret == -1) {
				fprintf(stderr, "ERROR: failed to read\n");
				goto ssl_shutdown;
			}
			else
			{
				fprintf(stderr, "Sending response\n");
				if ((ret = wolfSSL_write(ssl, response, strlen(response))) != strlen(response)) {
					fprintf(stderr, "ERROR: failed to write\n");
				}
			}
		}

ssl_shutdown:
		retry = 10;
		do {
			ret = wolfSSL_shutdown(ssl);
			if (ret == SSL_SHUTDOWN_NOT_DONE) {
				osDelay(500);
				retry--;
			} else {
				break;
			}
		} while (retry);

close_wait:
		fprintf(stderr, "Connection closed\n");
		wolfSSL_free(ssl);
  }
  /* USER CODE END 5 */
```

### sentry.c

The sentry configuration is at the top of the file. Edit the addresses / prefix ranges as needed.

### ethernetif.c

Changes to this file are needed for MAC address filtering. You do not need to do these changes if you do not wish to do MAC address filtering.

This file can be found in `LWIP/Target`. Near the top of the code add:

```c
/* USER CODE BEGIN 0 */
#include "sentry.h"
/* Raw input packet callback used for MAC address filtering */
static err_t filter_input(struct pbuf *p, struct netif *inp)
{
    /* Start of payload will have an Ethernet header */
    struct eth_hdr *ethhdr = (struct eth_hdr *)p->payload;
    struct eth_addr *ethaddr = &ethhdr->src;

    /* "src" contains the source hardware address from the packet */
    if (sentry_action_mac(&ethhdr->src) != 0)
    {
        //printf("Sentry rejected MAC address %02X:%02X:%02X:%02X:%02X:%02X\n",
                ethaddr->addr[0], ethaddr->addr[1], ethaddr->addr[2],
                ethaddr->addr[3], ethaddr->addr[4], ethaddr->addr[5]);

        /* Basically drop the packet */
        return ERR_ABRT;
    }

    printf("Sentry accepted MAC address %02X:%02X:%02X:%02X:%02X:%02X\n",
        ethaddr->addr[0], ethaddr->addr[1], ethaddr->addr[2],
        ethaddr->addr[3], ethaddr->addr[4], ethaddr->addr[5]);

    /* We passed the MAC filter, so pass the packet to the regular internal
     * lwIP input callback */
    return netif_input(p, inp);
}
```

Find the function `ethernetif_init()` and below `#if LWIP_ARP` add:

```c
    netif->input = filter_input;
```

Note that the last edit above will be erased if you regenerate the code using STM32CubeMX.

Finally open `lwipopts.h` in the same directory and add the following inside the `USER CODE BEGIN 0` section:

```c
#include "echo.h"
#define LWIP_HOOK_TCP_INPACKET_PCB sentry_tcp_inpkt
```

## Using the Application

Once running you should be able to TCP connect on port 8080 using an HTTP client. If it is blocked then you will get a timeout and the UART will show details. Otherwise an SSL handshake will happen and an HTTP response will be provided.
