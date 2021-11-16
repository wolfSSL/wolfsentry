# wolfSentry STM32 LWIP Example

The is a demo application which is very similar to the Linux example in this codebase. It allows filtering on TCP echo, ICMP ping and MAC address. It uses STM32 with FreeRTOS for the OS and LWIP for the network stack.

This example is designed to be used with STM32CubeMX and STM32CubeIDE.

## STM32CubeMX Setup

When creating a project in STM32CubeMX enable FREERTOS and LWIP, you will also need to configure the `ETH` Connectivity option as appropriate for your hardware. If you wish to do ICMP ping filtering, go into the "Key Options", select "Show Advanced Parameters" and enable `LWIP_RAW`.

**NOTES:**
1. It is recommended that in FREERTOS "Tasks and Queues" you increase the `defaultTask` stack size, especially if you are doing DHCP in LWIP. 8KB should work fine.

2. It is recommended you use CMSISv1 and do not use multi-threaded support with STM32Cube's version of LWIP. This can have stability issues.

## Copying Files

1. Copy the wolfsentry git checkout (or make a new clone) at the base of the project.
2. Copy the files in the `Src` directory next to this README to the `Core/Src` directory of the project.
3. Copy the files in the `Inc` directory next to this README to the `Core/Inc` directory of the project.

## STM32CubeIDE Setup

In STM32CubeIDE click on "Project" -> "Properties". From here go to "C/C++ General" -> "Paths and Symbols". Now click on the "Source Location" tab and click on "Add Folder". There will be "wolfsentry" available to select which will add wolfSentry to the build chain. Once added click on "Edit Filter", click on "Add..." and add the following:

```
**/unittests.c
**/Examples
```

This is so that the unittests do not build as part of your application, causing a conflict for `main()`.

## Code Changes

### wolfsentry_options.h

In `wolfsentry/wolfsentry` create the file `wolfsentry_options.h`:

```c
#ifndef WOLFSENTRY_OPTIONS_H
#define WOLFSENTRY_OPTIONS_H

#define FREERTOS
//#define WOLFSENTRY_SINGLETHREADED
#define WOLFSENTRY_LWIP
#define WOLFSENTRY_NO_PROTOCOL_NAMES
#define WOLFSENTRY_NO_POSIX_MEMALIGN
#endif /* WOLFSENTRY_OPTIONS_H */
```

Uncomment the `WOLFSENTRY_SINGLETHREADED` if you are using single threaded as this will remove the need for semaphores.

### main.c

In `main()` add the following as needed, use the comment blocks to locate where to place the code.

Near the top of the file:

```c
/* USER CODE BEGIN Includes */

#include "echo.h"
#include "ping.h"
```

In `StartDefaultTask()`:

```c
  /* USER CODE BEGIN 5 */
  printf("Sentry init\n");
  sentry_init();
  printf("Echo init\n");
  echo_init();
  printf("Ping init\n");
  ping_init();
```

### sentry.c

The sentry configuration is at the top of the file. You can see configurations for ping, TCP and MAC address. Edit these addresses / prefix ranges as needed.

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

    /* "src" contains the source hardware address from the packet */
    if (sentry_action_mac(&ethhdr->src) != 0)
    {
        //printf("Sentry rejected MAC address\n");
        /* Basically drop the packet */
        return ERR_ABRT;
    }

    printf("Sentry accepted MAC address\n");
    /* We passed the MAC filter, so pass the packet to the regular internal
     * lwIP input callback */
    return netif_input(p, inp);
```

Find the function `ethernet_init()` and below `#if LWIP_ARP` add:

```c
    netif->input = filter_input;
```

Note that the last edit above will be erased if you regenerate the code using STM32CubeMX.

## Using the Application

Once running you should be able to TCP connect on port 11111 and anything sent to that will be echoed via `printf()` (if it is not blocked). The filtering will also apply to pings and incoming packets will be filtered based on MAC address.
