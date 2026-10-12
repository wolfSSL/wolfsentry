/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "lwip/etharp.h"

#include "sentry.h"
#include "echo.h"
#if !defined(M33MU_EXAMPLE_TLS)
    #include "ping.h"
#endif

#if defined(M33MU_EXAMPLE_TLS)
    #define EXAMPLE_REMOTE_A 192
    #define EXAMPLE_REMOTE_B 168
    #define EXAMPLE_REMOTE_C 4
    #define EXAMPLE_REMOTE_D 85
#else
    #define EXAMPLE_REMOTE_A 192
    #define EXAMPLE_REMOTE_B 168
    #define EXAMPLE_REMOTE_C 103
    #define EXAMPLE_REMOTE_D 2
#endif

static volatile int tcpip_ready;
static volatile int example_network_ready;
static volatile int example_network_status;
static uint32_t random_state = 0x6d33336dUL;

static void tcpip_initialized(void *argument)
{
    (void)argument;
    tcpip_ready = 1;
}

static void example_network_init(void *argument)
{
    (void)argument;
#if defined(M33MU_EXAMPLE_TLS)
    echo_init();
    example_network_status = 0;
#else
    example_network_status = echo_init();
    if (example_network_status == 0)
        example_network_status = ping_init();
#endif
    example_network_ready = 1;
}

unsigned int lwip_port_rand(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}

int m33mu_random_block(unsigned char *output, unsigned int size)
{
    unsigned int i;

    if (output == NULL)
        return -1;
    for (i = 0; i < size; ++i)
        output[i] = (unsigned char)lwip_port_rand();
    return 0;
}

void m33mu_fail(void)
{
    printf("FAIL: STM32H563 M33MU example\n");
    __asm volatile("bkpt 0x01");
    for (;;) {
    }
}

void m33mu_assert(const char *file, unsigned long line)
{
    printf("FreeRTOS assertion: %s:%lu\n", file, line);
    __asm volatile("bkpt 0x02");
    for (;;) {
    }
}

void vApplicationMallocFailedHook(void)
{
    printf("FreeRTOS allocation failed\n");
    __asm volatile("bkpt 0x03");
    for (;;) {
    }
}

void vApplicationStackOverflowHook(TaskHandle_t task, char *name)
{
    (void)task;
    printf("FreeRTOS stack overflow: %s\n", name);
    __asm volatile("bkpt 0x04");
    for (;;) {
    }
}

static void require_result(int condition, const char *message)
{
    if (!condition) {
        printf("failed: %s\n", message);
        __asm volatile("bkpt 0x07");
        for (;;) {
        }
    }
}

static void run_policy_checks(void)
{
    ip_addr_t local;
    ip_addr_t allowed;
    ip_addr_t rejected;
    struct eth_addr allowed_mac;
    struct eth_addr rejected_mac;

    IP4_ADDR(ip_2_ip4(&local), 192, 168, 0, 10);
    IP4_ADDR(ip_2_ip4(&allowed), EXAMPLE_REMOTE_A, EXAMPLE_REMOTE_B,
        EXAMPLE_REMOTE_C, EXAMPLE_REMOTE_D);
    IP4_ADDR(ip_2_ip4(&rejected), EXAMPLE_REMOTE_A, EXAMPLE_REMOTE_B,
        EXAMPLE_REMOTE_C, EXAMPLE_REMOTE_D + 1);

    allowed_mac.addr[0] = 0xde;
    allowed_mac.addr[1] = 0xc0;
    allowed_mac.addr[2] = 0xde;
    allowed_mac.addr[3] = 0x03;
    allowed_mac.addr[4] = 0x02;
    allowed_mac.addr[5] = 0x7f;
    rejected_mac.addr[0] = 0xde;
    rejected_mac.addr[1] = 0xc0;
    rejected_mac.addr[2] = 0xde;
    rejected_mac.addr[3] = 0x03;
    rejected_mac.addr[4] = 0x03;
    rejected_mac.addr[5] = 0x01;

    require_result(sentry_action(&local, &allowed, 11111, 49152,
        SENTRY_ACTION_CONNECT) == 0, "allowed TCP route");
    require_result(sentry_action(&local, &rejected, 11111, 49152,
        SENTRY_ACTION_CONNECT) != 0, "rejected TCP route");
    require_result(sentry_action_ping(&allowed, 8) == 0,
        "allowed ICMP route");
    require_result(sentry_action_ping(&rejected, 8) != 0,
        "rejected ICMP route");
    require_result(sentry_action_mac(&allowed_mac) == 0,
        "allowed Ethernet route");
    require_result(sentry_action_mac(&rejected_mac) != 0,
        "rejected Ethernet route");
}

static void example_task(void *argument)
{
    (void)argument;
    printf("M33MU: FreeRTOS task started\n");

    tcpip_init(tcpip_initialized, NULL);
    while (!tcpip_ready)
        vTaskDelay(pdMS_TO_TICKS(1));
    printf("M33MU: lwIP TCP/IP task started\n");

    require_result(sentry_init() == 0, "wolfSentry initialization");
#if defined(M33MU_EXAMPLE_TLS)
    require_result(echo_ssl() == 0, "wolfSSL TLS initialization");
#endif
    require_result(tcpip_callback(example_network_init, NULL) == ERR_OK,
        "lwIP example callback");
    while (!example_network_ready)
        vTaskDelay(pdMS_TO_TICKS(1));
    require_result(example_network_status == 0, "lwIP example initialization");
    run_policy_checks();

#if defined(M33MU_EXAMPLE_TLS)
    printf("PASS: STM32-LWIP-WOLFSSL on FreeRTOS/lwIP under M33MU\n");
#else
    printf("PASS: STM32-LWIP on FreeRTOS/lwIP under M33MU\n");
#endif
    __asm volatile("bkpt 0x7f");
    for (;;) {
    }
}

int main(void)
{
    BaseType_t status;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("M33MU: STM32H563 booted\n");
    status = xTaskCreate(example_task, "example", 8192, NULL, 2, NULL);
    if (status != pdPASS) {
        __asm volatile("bkpt 0x05");
        for (;;) {
        }
    }
    vTaskStartScheduler();
    __asm volatile("bkpt 0x06");
    for (;;) {
    }
    return 1;
}
