/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef WOLFSENTRY_M33MU_LWIP_ARCH_CC_H
#define WOLFSENTRY_M33MU_LWIP_ARCH_CC_H

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#ifndef inet_ntop
#define inet_ntop lwip_inet_ntop
#endif
#ifndef inet_pton
#define inet_pton lwip_inet_pton
#endif
#define LWIP_PLATFORM_DIAG(message) do { printf message; } while (0)
#define LWIP_PLATFORM_ASSERT(message) do { \
    printf("lwIP assertion: %s\n", message); \
    m33mu_fail(); \
} while (0)

void m33mu_fail(void);

#endif /* WOLFSENTRY_M33MU_LWIP_ARCH_CC_H */
