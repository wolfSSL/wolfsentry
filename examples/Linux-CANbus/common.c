/* common.c
 *
 * Copyright (C) 2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "common.h"

volatile int keep_running = 1;

static isotp_wolfssl_ctx isotp_ctx;
static struct wolfsentry_context *wolfsentry = NULL;

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
    (void)target_route;

    printf("action callback: a=\"%s\" parent_event=\"%s\" trigger=\"%s\" t=%u r_id=%u caller_arg=%p\n",
           wolfsentry_action_get_label(action),
           wolfsentry_event_get_label(parent_event),
           wolfsentry_event_get_label(trigger_event),
           action_type,
           wolfsentry_get_object_id(rule_route),
           caller_arg);
    return 0;
}


int sentry_init(byte local_addr, byte remote_addr)
{
    wolfsentry_errcode_t ret;
    wolfsentry_ent_id_t id;
    wolfsentry_action_res_t action_results;
    wolfsentry_route_flags_t flags;
    wolfsentry_action_res_t default_policy;
    struct wolfsentry_route_table *static_routes;

    struct {
        struct wolfsentry_sockaddr sa;
        byte addr_buf;
    } remote, local;

    struct wolfsentry_eventconfig config = { .route_private_data_size = 32, .route_private_data_alignment = 16 };
    ret =  wolfsentry_init(NULL /* hpi */, &config, &wolfsentry);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry_init() returned " WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
    }

    flags = WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN | WOLFSENTRY_ROUTE_FLAG_GREENLISTED;
    default_policy = WOLFSENTRY_ACTION_RES_REJECT|WOLFSENTRY_ACTION_RES_STOP;
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

    ret = wolfsentry_route_get_table_static(wolfsentry, &static_routes);
    if (ret < 0) {
        fprintf(stderr, "Couldn't get static routes\n");
    }
    ret = wolfsentry_route_table_default_policy_set(wolfsentry, static_routes, default_policy);
    if (ret < 0) {
        fprintf(stderr, "Couldn't set default policy\n");
    }

    remote.sa.sa_family = local.sa.sa_family = WOLFSENTRY_AF_CAN;
    remote.sa.sa_proto = local.sa.sa_proto = CAN_RAW;
    remote.sa.sa_port = local.sa.sa_port = 0;
    remote.sa.addr_len = local.sa.addr_len = 8;
    remote.sa.interface = local.sa.interface = 0;
    memcpy(remote.sa.addr, &remote_addr, 1);
    memcpy(local.sa.addr, &local_addr, 1);

    wolfsentry_event_insert(wolfsentry, "call-in-from-can", -1, 10, NULL, WOLFSENTRY_EVENT_FLAG_NONE, &id);

    wolfsentry_route_insert_static(wolfsentry, NULL, &remote.sa, &local.sa, flags, "call-in-from-can", strlen("call-in-from-can"), &id, &action_results);
    return 0;
}

/* Check a TCP connection with wolfSentry. This is called for connect and
 * disconnect so wolfSentry can count the simultaneous connections */
static int sentry_action(byte local_addr, byte remote_addr)
{
    wolfsentry_errcode_t ret;
    wolfsentry_action_res_t action_results;
    /* Note that sa.addr is 0 bytes, addr_buf essentially enlarges this to the correct size */
    struct {
        struct wolfsentry_sockaddr sa;
        byte addr_buf;
    } remote, local;

    /* Setup sockaddr information to send to wolfSentry */
    remote.sa.sa_family = WOLFSENTRY_AF_CAN;
    remote.sa.sa_proto = CAN_RAW;
    remote.sa.sa_port = 0;
    /* Essentially a prefix size, wolfSentry uses the lesser of this and the
     * rule in JSON as to how much of the IP address to compare */
    remote.sa.addr_len = 8; // prefix size
    remote.sa.interface = 0;
    memcpy(remote.sa.addr, &remote_addr, 1);

    local.sa.sa_family = WOLFSENTRY_AF_CAN;
    local.sa.sa_proto = CAN_RAW;
    local.sa.sa_port = 0;
    local.sa.addr_len = 8;
    local.sa.interface = 0;
    memcpy(local.sa.addr, &local_addr, 1);

    /* Send the details of this to wolfSentry and get the result */
    ret = wolfsentry_route_event_dispatch(
            wolfsentry,
            &remote.sa,
            &local.sa,
            WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
            "call-in-from-can",
            strlen("call-in-from-can"),
            NULL,
            NULL,
            NULL,
            &action_results);

    /* Check the result, if it contains "reject" then notify the caller */
    if (WOLFSENTRY_ERROR_DECODE_ERROR_CODE(ret) >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT)) {
            fprintf(stderr, "wolfSentry rejected packet, local: 0x%x, remote: 0x%x!\n", local_addr, remote_addr);
            return -1;
        }
    }
    fprintf(stderr, "wolfSentry accepted packet, local: 0x%x, remote: 0x%x \n", local_addr, remote_addr);

    return 0;
}


struct can_info {
    int sock;
    canid_t arbitration;
    canid_t remote_arbitration;
};

struct can_info can_con_info;

/* Function callback for wolfSSL to add delays to messages when a receiver
 * requests it*/
void can_delay(int microseconds)
{
    usleep(microseconds);
}

void sig_handle(int dummy);

/* Function callback for wolfSSL to send a CAN bus frame of up to 8 bytes */
int can_receive(struct isotp_can_data *data, void *arg, int timeout) {
    int nbytes;
    int ret;
    struct can_info *info = ((struct can_info*)arg);
    struct can_frame frame;
    struct pollfd p[1];
    byte local, remote;

    p[0].fd = info->sock;
    p[0].events = POLLIN;

    /* Poll for new data */
    ret = poll(p, 1, timeout);

    if (ret <= 0) {
        return ret;
    }

    /* Read in the frame data */
    nbytes = read(info->sock, &frame, sizeof(struct can_frame));
    if (nbytes <= 0) {
       return nbytes;
    }
    local = frame.can_id & 0xff;
    remote = (frame.can_id & 0xff00) >> 8;
    ret = sentry_action(local, remote);
    if (ret != 0) {
        return -1;
    }

    memcpy(data->data, frame.data, frame.can_dlc);
    data->length = frame.can_dlc;
    return nbytes;
}

/* Function callback for wolfSSL to send a CAN bus frame of up to 8 bytes */
int can_send(struct isotp_can_data *data, void *arg)
{
    struct can_info *info = ((struct can_info*)arg);
    struct can_frame frame;
    memcpy(frame.data, data->data, data->length);
    frame.can_dlc = data->length;
    frame.can_id = info->arbitration;
    return write(info->sock, &frame, sizeof(struct can_frame));
}


/* Connect to the CAN bus */
int can_connect(const char *address)
{
    struct sockaddr_can addr;
    struct ifreq ifr;
    int sock = -1;


    if ((sock = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
       perror("Socket open error\n");
       return -1;
    }

    strcpy(ifr.ifr_name, address);
    ioctl(sock, SIOCGIFINDEX, &ifr);

    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
       perror("Bind error\n");
       return -1;
    }

    return sock;
}

void can_close()
{
    close(can_con_info.sock);
}

void close_ssl(WOLFSSL_CTX *ctx, WOLFSSL *ssl)
{
    if (ssl) {
        int ret = WOLFSSL_SHUTDOWN_NOT_DONE;
        while (ret == WOLFSSL_SHUTDOWN_NOT_DONE) {
            ret = wolfSSL_shutdown(ssl);
        }
        if (ret != WOLFSSL_SUCCESS) {
            char buffer[ERR_MSG_LEN];
            int err = wolfSSL_get_error(ssl, ret);
            fprintf(stderr, "Error shutting down TLS connection: %d, %s",
                    err, wolfSSL_ERR_error_string(err, buffer));
            return;
        }
    }
    can_close();

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
}

void sig_handle(int dummy)
{
    (void) dummy;
    keep_running = 0;
}

int setup_connection(const char *interface, int local_id, int remote_id)
{
    int sock;
    struct sigaction sa = { .sa_handler = sig_handle, /* .sa_flags = 0 */ };
    sigaction(SIGINT, &sa, 0);

    wolfSSL_Init();

    /* Connect to CAN bus provided on command line, filter out everything
     * except for the remote CAN ID */
    sock = can_connect(interface);
    if (sock < 1) {
        return -1;
    }
    can_con_info.sock = sock;
    can_con_info.arbitration = 0x18da0000 | (local_id << 8) | remote_id | CAN_EFF_FLAG;
    return 0;
}

int setup_ssl(enum service_type type, WOLFSSL_CTX **new_ctx,
        WOLFSSL_METHOD **new_method, WOLFSSL **new_ssl)
{
    int ret;
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL_METHOD* method = NULL;
    WOLFSSL* ssl = NULL;
    char *receive_buffer = malloc(ISOTP_DEFAULT_BUFFER_SIZE);

    if (type == SERVICE_TYPE_CLIENT) {
        method = wolfTLSv1_3_client_method();
    } else {
        method = wolfTLSv1_3_server_method();
    }

    if (!method) {
        fprintf(stderr, "Could not init wolfSSL method\n");
        return -1;
    }

    ctx = wolfSSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "Could not init wolfSSL context\n");
        close_ssl(NULL, NULL);
        return -1;
    }

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

    if (type == SERVICE_TYPE_CLIENT) {
        ret = wolfSSL_CTX_load_verify_locations(ctx, "client.pem", NULL);
    } else {
        ret = wolfSSL_CTX_use_certificate_file(ctx, "server.pem",
                WOLFSSL_FILETYPE_PEM);
    }

    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load cert, "
                "please check the file.\n");
        close_ssl(ctx, NULL);
        return -1;
    }

    if (type == SERVICE_TYPE_SERVER) {
        if ((ret = wolfSSL_CTX_use_PrivateKey_file(ctx, "server.key",
                        WOLFSSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "ERROR: failed to load key file, "
                    "please check the file.\n");
            close_ssl(ctx, NULL);
            return -1;
        }
    }

    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Could not init wolfSSL\n");
        close_ssl(ctx, NULL);
        return -1;
    }

    wolfSSL_SetIO_ISOTP(ssl, &isotp_ctx, can_receive, can_send, can_delay, 0,
            receive_buffer, ISOTP_DEFAULT_BUFFER_SIZE, &can_con_info);

    if (type == SERVICE_TYPE_CLIENT) {
        ret = wolfSSL_connect(ssl);
    } else {
        ret = wolfSSL_accept(ssl);
    }

    wolfSSL_set_using_nonblock(ssl, 1);

    if (ret != WOLFSSL_SUCCESS) {
        char buffer[ERR_MSG_LEN];
        int err = wolfSSL_get_error(ssl, ret);
        fprintf(stderr, "ERROR: failed to connect using wolfSSL: %d, %s\n",
                err, wolfSSL_ERR_error_string(err, buffer));
        close_ssl(ctx, ssl);
        return -1;
    }
    *new_ctx = ctx;
    *new_method = method;
    *new_ssl = ssl;

    printf("SSL handshake done!\n");

    return 0;
}
