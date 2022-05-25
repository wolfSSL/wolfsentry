// SPDX-License-Identifier: GPL-2.0-or-later

#include <wolfsentry/wolfsentry.h>
#include <wolfsentry/wolfsentry_util.h>
#include <wolfsentry/wolfsentry_json.h>
#include "lwip/sockets.h"
#include "lwip/etharp.h"
#include "lwip/tcp.h"
#include "sentry.h"

static const char *wolfsentry_config_path = "echo-config.json";
static struct wolfsentry_context *wolfsentry = NULL;

/* Callback that is fired when an action is taken, this can be used for
 * debugging for now */
static wolfsentry_errcode_t test_action(
    struct wolfsentry_context *wolfsentry,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *target_route,
    struct wolfsentry_route_table *route_table,
    const struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    const struct wolfsentry_event *parent_event = wolfsentry_route_parent_event(rule_route);
    (void)wolfsentry;
    (void)handler_arg;
    (void)route_table;
    (void)action_results;

    /*fprintf(stderr, "action callback: a=\"%s\" parent_event=\"%s\" trigger=\"%s\" t=%u r_id=%u caller_arg=%p\n",
           wolfsentry_action_get_label(action),
           wolfsentry_event_get_label(parent_event),
           wolfsentry_event_get_label(trigger_event),
           action_type,
           wolfsentry_get_object_id(route),
           caller_arg);*/
    return 0;
}

/* Initialize wolfSentry with a config file */
int sentry_init()
{
    wolfsentry_errcode_t ret;
    wolfsentry_ent_id_t id;

    struct wolfsentry_eventconfig config = { .route_private_data_size = 32, .route_private_data_alignment = 16 };
    ret =  wolfsentry_init(NULL /* hpi */, &config,
                           &wolfsentry);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry_init() returned " WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
        fprintf(stderr, "unable to initialize wolfSentry");
    }

    /* Insert the possible actions into wolfSentry */
    wolfsentry_action_insert(      wolfsentry,
                                   "handle-insert",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   test_action,
                                   NULL,
                                   &id);

    wolfsentry_action_insert(
                                   wolfsentry,
                                   "handle-delete",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   test_action,
                                   NULL,
                                   &id);

    wolfsentry_action_insert(
                                   wolfsentry,
                                   "handle-match",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   test_action,
                                   NULL,
                                   &id);

    wolfsentry_action_insert(
                                   wolfsentry,
                                   "notify-on-match",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   test_action,
                                   NULL,
                                   &id);

    wolfsentry_action_insert(
                                   wolfsentry,
                                   "handle-connect",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   test_action,
                                   NULL,
                                   &id);

    wolfsentry_action_insert(
                                   wolfsentry,
                                   "handle-connect2",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   test_action,
                                   NULL,
                                   &id);


    char buf[512], err_buf[512];
    struct wolfsentry_json_process_state *jps;

    /* Open the config file */
    FILE *f = fopen(wolfsentry_config_path, "r");

    if (f == NULL) {
        fprintf(stderr, "fopen(%s): %s\n",wolfsentry_config_path,strerror(errno));
        fprintf(stderr, "unable to open wolfSentry config file");
    }

    /* Initalize the wolfSentry JSON parser */
    if ((ret = wolfsentry_config_json_init(
             wolfsentry,
             WOLFSENTRY_CONFIG_LOAD_FLAG_NONE,
             &jps)) < 0) {
        fprintf(stderr, "wolfsentry_config_json_init() returned "
                WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
        fprintf(stderr, "error while initializing wolfSentry config parser");
    }

    /* wolfSentry uses a streaming reader/parser for the config file */
    for (;;) {
        /* Read some data from the config file */
        size_t n = fread(buf, 1, sizeof buf, f);
        if ((n < sizeof buf) && ferror(f)) {
            fprintf(stderr, "fread(%s): %s\n",wolfsentry_config_path, strerror(errno));
            fprintf(stderr, "error while reading wolfSentry config file");
        }

        /* Send the read data into the JSON parser */
        ret = wolfsentry_config_json_feed(jps, buf, n, err_buf, sizeof err_buf);
        if (ret < 0) {
            fprintf(stderr, "%.*s\n", (int)sizeof err_buf, err_buf);
            fprintf(stderr, "error while loading wolfSentry config file");
        }
        if ((n < sizeof buf) && feof(f))
            break;
    }
    fclose(f);

    /* Clean up the JSON parser */
    if ((ret = wolfsentry_config_json_fini(&jps, err_buf, sizeof err_buf)) < 0) {
        fprintf(stderr, "%.*s\n", (int)sizeof err_buf, err_buf);
        fprintf(stderr, "error while loading wolfSentry config file");
    }

    return 0;
}

/* Check a TCP connection with wolfSentry. This is called for connect and
 * disconnect so wolfSentry can count the simultaneous connections */
int sentry_action(ip_addr_t *local_ip, ip_addr_t *remote_ip, in_port_t local_port, in_port_t remote_port, sentry_action_type action)
{
    wolfsentry_errcode_t ret;
    wolfsentry_action_res_t action_results;
    /* Note that sa.addr is 0 bytes, addr_buf essentially enlarges this to the correct size */
    struct {
        struct wolfsentry_sockaddr sa;
        byte addr_buf[4];
    } remote, local;
    u32_t remoteip = remote_ip->addr;
    u32_t localip = local_ip->addr;

    /* Connect will increment the connection count in wolfSentry, disconnect
     * will decrement it */
    switch(action) {
        case SENTRY_ACTION_CONNECT:
            action_results = WOLFSENTRY_ACTION_RES_CONNECT;
            break;
        case SENTRY_ACTION_DISCONNECT:
            action_results = WOLFSENTRY_ACTION_RES_DISCONNECT;
            break;
        case SENTRY_ACTION_NONE:
        default:
            break;
    }

    /* Setup sockaddr information to send to wolfSentry */
    remote.sa.sa_family = WOLFSENTRY_AF_INET;
    remote.sa.sa_proto = IPPROTO_TCP;
    remote.sa.sa_port = remote_port;
    /* Essentially a prefix size, wolfSentry uses the lesser of this and the
     * rule in JSON as to how much of the IP address to compare */
    remote.sa.addr_len = 32; // prefix size
    remote.sa.interface = 0;
    memcpy(remote.sa.addr, &remoteip, 4);

    local.sa.sa_family = WOLFSENTRY_AF_INET;
    local.sa.sa_proto = IPPROTO_TCP;
    local.sa.sa_port = local_port;
    local.sa.addr_len = 32;
    local.sa.interface = 0;
    memcpy(local.sa.addr, &localip, 4);

    /* Send the details of this to wolfSentry and get the result */
    ret = wolfsentry_route_event_dispatch_with_inited_result(
            wolfsentry,
            &remote.sa,
            &local.sa,
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
            "call-in-from-echo",
            strlen("call-in-from-echo"),
            NULL,
            NULL,
            NULL,
            &action_results);

    fprintf(stderr, "TCP Sentry action returned " WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(ret));

    /* Check the result, if it contains "reject" then notify the caller */
    if (WOLFSENTRY_ERROR_DECODE_ERROR_CODE(ret) >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT)) {
            return -1;
        }
    }

    return 0;
}

/* Check / validate ICMP traffic */
int sentry_action_ping(const ip_addr_t *addr, u8_t type)
{
    wolfsentry_errcode_t ret;
    wolfsentry_action_res_t action_results;
    /* As above, pad the struct to make addr 4 bytes */
    struct {
        struct wolfsentry_sockaddr sa;
        byte addr_buf[4];
    } remote;

    /* ICMP protocol check. The ICMP packet type is the port number for this
     * check */
    remote.sa.sa_family = WOLFSENTRY_AF_INET;
    remote.sa.sa_proto = IPPROTO_ICMP;
    remote.sa.sa_port = type;
    remote.sa.addr_len = 32;
    remote.sa.interface = 0;
    memcpy(remote.sa.addr, &addr->addr, 4);

    ret = wolfsentry_route_event_dispatch(
            wolfsentry,
            &remote.sa,
            &remote.sa, // Reuse for now
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
            "call-in-from-echo",
            strlen("call-in-from-echo"),
            NULL,
            NULL,
            NULL,
            &action_results);
    fprintf(stderr, "PING Sentry action returned " WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
    if (WOLFSENTRY_ERROR_DECODE_ERROR_CODE(ret) >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT)) {
            return -1;
        }
    }

    return 0;
}

/* Check MAC address */
int sentry_action_mac(struct eth_addr *addr)
{
    wolfsentry_errcode_t ret;
    wolfsentry_action_res_t action_results;
    /* Pad addr to 6 bytes for the hardware address */
    struct {
        struct wolfsentry_sockaddr sa;
        byte addr_buf[6];
    } remote;

    /* We only really care about the data and length, the family is AF_LINK */
    remote.sa.sa_family = WOLFSENTRY_AF_LINK;
    remote.sa.addr_len = 48;
    remote.sa.interface = 0;
    // MAC addresses are 6 bytes (48 bits)
    memcpy(remote.sa.addr, &addr->addr, 6);

    ret = wolfsentry_route_event_dispatch(
            wolfsentry,
            &remote.sa,
            &remote.sa, // Reuse for now
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
            "call-in-from-echo",
            strlen("call-in-from-echo"),
            NULL,
            NULL,
            NULL,
            &action_results);

    fprintf(stderr, "MAC Sentry action returned " WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
    if (WOLFSENTRY_ERROR_DECODE_ERROR_CODE(ret) >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT)) {
            return -1;
        }
    }

    return 0;
}

