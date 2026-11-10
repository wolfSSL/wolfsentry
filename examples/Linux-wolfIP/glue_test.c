/*
 * examples/Linux-wolfIP/glue_test.c
 *
 * Copyright (C) 2024-2025 wolfSSL Inc.
 *
 * This file is part of wolfSentry.
 *
 * wolfSentry is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSentry is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <wolfsentry/wolfsentry.h>
#include <wolfsentry/wolfsentry_wolfip.h>

#include "wolfip/config.h"

#include <wolfip.h>
#include <wolfip-filter.h>

/* stand-ins for wolfIP's filter registration, so the glue can be driven directly. */
static wolfIP_filter_cb stub_cb;
static void *stub_arg;
static uint32_t stub_masks[5];

enum { LAYER_ETH, LAYER_IP, LAYER_ICMP, LAYER_TCP, LAYER_UDP, N_LAYERS };

void wolfIP_filter_set_callback(wolfIP_filter_cb cb, void *arg)
{
    stub_cb = cb;
    stub_arg = arg;
}

void wolfIP_filter_set_eth_mask(uint32_t mask) { stub_masks[LAYER_ETH] = mask; }
void wolfIP_filter_set_ip_mask(uint32_t mask) { stub_masks[LAYER_IP] = mask; }
void wolfIP_filter_set_icmp_mask(uint32_t mask) { stub_masks[LAYER_ICMP] = mask; }
void wolfIP_filter_set_tcp_mask(uint32_t mask) { stub_masks[LAYER_TCP] = mask; }
void wolfIP_filter_set_udp_mask(uint32_t mask) { stub_masks[LAYER_UDP] = mask; }

#define M(r) WOLFIP_FILT_MASK(WOLFIP_FILT_ ## r)
#define COMMON (M(RECEIVING) | M(SENDING) | M(INBOUND_ERR) | M(OUTBOUND_ERR))
#define UNREACH (M(ADDR_UNREACHABLE) | M(PORT_UNREACHABLE))

/* written out from the reason list, independently of the glue's own masks. */
static const uint32_t allowed[N_LAYERS] = {
    COMMON,
    COMMON | UNREACH,
    COMMON | UNREACH | M(BINDING) | M(DISSOCIATE),
    COMMON | M(BINDING) | M(DISSOCIATE) | M(LISTENING) | M(STOP_LISTENING) | M(PORT_UNREACHABLE) |
        M(ACCEPTING) | M(CONNECTING) | M(REMOTE_RESET) | M(CLOSED) | M(CLOSE_WAIT),
    COMMON | UNREACH | M(BINDING) | M(DISSOCIATE) | M(LISTENING) | M(STOP_LISTENING)
};

/* the library build records the posture in wolfsentry_options.h, which wolfsentry.h includes. */
#ifdef WOLFSENTRY_PACKET_FILTER_FAIL_OPEN
#define EXPECTED_FAIL_VERDICT 0
#else
#define EXPECTED_FAIL_VERDICT (-WOLFIP_EACCES)
#endif

static int failures;

#define CHECK(cond) do { if (! (cond)) { fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

static wolfsentry_errcode_t install_layer(struct wolfsentry_context *ctx, int layer, uint32_t mask)
{
    switch (layer) {
    case LAYER_ETH:
        return wolfsentry_install_wolfip_filter_ethernet_callback(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(ctx, NULL), mask);
    case LAYER_IP:
        return wolfsentry_install_wolfip_filter_ip4_callbacks(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(ctx, NULL), mask);
    case LAYER_ICMP:
        return wolfsentry_install_wolfip_filter_icmp_callbacks(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(ctx, NULL), mask);
    case LAYER_TCP:
        return wolfsentry_install_wolfip_filter_tcp_callback(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(ctx, NULL), mask);
    default:
        return wolfsentry_install_wolfip_filter_udp_callback(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(ctx, NULL), mask);
    }
}

static wolfsentry_errcode_t install_all(struct wolfsentry_context *ctx, const uint32_t *masks)
{
    return wolfsentry_install_wolfip_filter_callbacks(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(ctx, NULL),
        masks[LAYER_ETH], masks[LAYER_IP], masks[LAYER_ICMP], masks[LAYER_TCP], masks[LAYER_UDP]);
}

/* every reason bit, per layer: mapped bits install, the rest are refused without side effects. */
static void test_masks(struct wolfsentry_context *ctx)
{
    uint32_t before[N_LAYERS], bad[N_LAYERS], expected;
    unsigned int bit;
    int layer;
    wolfsentry_errcode_t ret;

    CHECK(install_all(ctx, allowed) >= 0);
    CHECK(memcmp(stub_masks, allowed, sizeof stub_masks) == 0);
    CHECK((stub_cb != NULL) && (stub_arg == ctx));

    for (layer = 0; layer < N_LAYERS; ++layer) {
        for (bit = 0; bit < 32; ++bit) {
            memcpy(before, stub_masks, sizeof before);
            ret = install_layer(ctx, layer, 1U << bit);
            if (allowed[layer] & (1U << bit)) {
                expected = 1U << bit;
                if ((layer == LAYER_TCP) && (bit == WOLFIP_FILT_ACCEPTING))
                    expected |= M(CLOSED) | M(REMOTE_RESET);
                CHECK(ret >= 0);
                CHECK(stub_masks[layer] == expected);
            } else {
                CHECK(WOLFSENTRY_ERROR_CODE_IS(ret, INVALID_ARG));
                CHECK(memcmp(stub_masks, before, sizeof before) == 0);
                CHECK((stub_cb != NULL) && (stub_arg == ctx));
            }
        }
    }

    /* the combined installer refuses the whole update if any layer is bad. */
    CHECK(install_all(ctx, allowed) >= 0);
    for (layer = 0; layer < N_LAYERS; ++layer) {
        memcpy(bad, allowed, sizeof bad);
        bad[layer] |= ~allowed[layer];
        CHECK(WOLFSENTRY_ERROR_CODE_IS(install_all(ctx, bad), INVALID_ARG));
        CHECK(memcmp(stub_masks, allowed, sizeof stub_masks) == 0);
    }
}

static int dispatch(void *arg, enum wolfIP_filter_reason reason, uint16_t ip_proto)
{
    struct wolfIP_filter_event event;
    memset(&event, 0, sizeof event);
    event.reason = reason;
    event.meta.ip_proto = ip_proto;
    return stub_cb(arg, &event);
}

/* run fn with stderr captured into out, for counting the glue's warning lines. */
static int capture_stderr(struct wolfsentry_context *ctx, void (*fn)(struct wolfsentry_context *), char *out, size_t out_size)
{
    size_t len;
    int saved;
    FILE *capture = tmpfile();

    if (capture == NULL)
        return -1;
    fflush(stderr);
    saved = dup(STDERR_FILENO);
    dup2(fileno(capture), STDERR_FILENO);
    fn(ctx);
    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    rewind(capture);
    len = fread(out, 1, out_size - 1, capture);
    out[len] = 0;
    fclose(capture);
    return 0;
}

static int count_lines(const char *text, const char *needle)
{
    int n = 0;
    while ((text = strstr(text, needle)) != NULL) {
        ++n;
        text += strlen(needle);
    }
    return n;
}

static void unmapped_events(struct wolfsentry_context *ctx)
{
    unsigned int i;
    /* the same unmapped reason and protocol, repeatedly, plus distinct large protocols. */
    for (i = 0; i < 3; ++i) {
        CHECK(dispatch(ctx, WOLFIP_FILT_ACCEPTING, WOLFIP_FILTER_PROTO_ETH) == EXPECTED_FAIL_VERDICT);
        CHECK(dispatch(ctx, WOLFIP_FILT_RECEIVING, 0x86dd) == EXPECTED_FAIL_VERDICT);
        CHECK(dispatch(ctx, WOLFIP_FILT_RECEIVING, 0x00ee) == EXPECTED_FAIL_VERDICT);
    }
    for (i = 0; i < 6; ++i)
        CHECK(dispatch(ctx, WOLFIP_FILT_RECEIVING, (uint16_t)(0x9000 + i)) == EXPECTED_FAIL_VERDICT);
}

#define RACERS 8

#ifdef WOLFSENTRY_THREADSAFE

static int race_started;

static void *race_one(void *ctx)
{
    while (! __atomic_load_n(&race_started, __ATOMIC_ACQUIRE))
        (void)sched_yield();
    (void)dispatch(ctx, WOLFIP_FILT_RECEIVING, 0xa0a0);
    return NULL;
}

/* first sightings of one large value, all at once, must still log it once. */
static void race_events(struct wolfsentry_context *ctx)
{
    pthread_t racers[RACERS];
    int i, created;

    for (created = 0; created < RACERS; ++created) {
        if (pthread_create(&racers[created], NULL, race_one, ctx) != 0)
            break;
    }
    CHECK(created == RACERS);
    /* released even after a failed create, so the threads that did start can be joined. */
    __atomic_store_n(&race_started, 1, __ATOMIC_RELEASE);
    for (i = 0; i < created; ++i)
        CHECK(pthread_join(racers[i], NULL) == 0);
}

#else

/* a single-threaded library is never called concurrently, so the same sightings arrive in turn. */
static void race_events(struct wolfsentry_context *ctx)
{
    int i;
    for (i = 0; i < RACERS; ++i)
        (void)dispatch(ctx, WOLFIP_FILT_RECEIVING, 0xa0a0);
}

#endif

int main(void)
{
    struct wolfsentry_context *ctx = NULL;
    wolfsentry_errcode_t ret;
    static char log[4096];

    ret = wolfsentry_init(wolfsentry_build_settings, WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(NULL /* hpi */, NULL /* thread */), NULL, &ctx);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry_init failed: " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        return EXIT_FAILURE;
    }

    test_masks(ctx);

    /* no context attached: the build-selected verdict. */
    CHECK(dispatch(NULL, WOLFIP_FILT_RECEIVING, WOLFIP_FILTER_PROTO_ETH) == EXPECTED_FAIL_VERDICT);

    CHECK(capture_stderr(ctx, race_events, log, sizeof log) == 0);
    CHECK(count_lines(log, "wolfIP filter:") == 1);
    CHECK(count_lines(log, "unmapped protocol 41120\n") == 1);

    /* one line per distinct value until the four large-value slots fill (0xa0a0 holds one), then one line for the rest. */
    CHECK(capture_stderr(ctx, unmapped_events, log, sizeof log) == 0);
    CHECK(count_lines(log, "wolfIP filter:") == 6);
    CHECK(count_lines(log, "unmapped event reason 5\n") == 1);
    CHECK(count_lines(log, "unmapped protocol 238\n") == 1);
    CHECK(count_lines(log, "unmapped protocol 34525\n") == 1);
    CHECK(count_lines(log, "unmapped protocol 36865\n") == 1);
    CHECK(count_lines(log, "unmapped protocol 36866\n") == 0);
    CHECK(count_lines(log, "further unmapped protocol values are not logged") == 1);
    CHECK(capture_stderr(ctx, unmapped_events, log, sizeof log) == 0);
    CHECK(count_lines(log, "wolfIP filter:") == 0);

    ret = wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(&ctx, NULL));
    CHECK(ret >= 0);
    CHECK(stub_cb == NULL);

    if (failures) {
        fprintf(stderr, "wolfIP glue test: %d failures\n", failures);
        return EXIT_FAILURE;
    }
#ifdef WOLFSENTRY_THREADSAFE
    printf("wolfIP glue test passed (%s posture, threadsafe).\n", EXPECTED_FAIL_VERDICT ? "deny" : "pass");
#else
    printf("wolfIP glue test passed (%s posture, single-threaded).\n", EXPECTED_FAIL_VERDICT ? "deny" : "pass");
#endif
    return EXIT_SUCCESS;
}
