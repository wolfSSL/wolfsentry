/*
 * udp_to_dbus.c
 *
 * Copyright (C) 2022 wolfSSL Inc.
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

/*
 * This is a demonstration application daemon that pairs with
 * ../wolfssl-wolfsentry_notify_via_UDP_JSON.patch, which adds corresponding
 * functionality to libwolfssl's example server application.
 *
 * The patched wolfssl server transmits JSON-encoded UDP datagrams with event
 * descriptions to udp_to_dbus.  udp_to_dbus decodes and formats the
 * JSON-encoded messages, and sends the resulting messages to the local dbus,
 * producing a pop-up message.
 * 
 *
 * Building the demo:
 *
 * Modern Linux and Gnu toolchain are assumed throughout. glib-2.0 and
 * gdk-pixbuf-2.0, with header files, are also needed.  We've tested with
 * glib-2.72.3 and gdk-pixbuf-2.42.
 *
 * Set up a top level source tree with wolfSSL 5.4.0 or later in ./wolfssl/, and
 * this release of wolfSentry at ./wolfsentry/.
 *
 * Starting in the top level source tree:
 *
 *   pushd wolfsentry
 *   make -j test
 *   cd examples/notification-demo/udp_to_dbus/
 *   make
 *   popd
 *
 * Alternatively, to install wolfSentry and target that installation with the
 * udp_to_dbus build, use
 *
 *   pushd wolfsentry
 *   make -j install INSTALL_DIR={the_install_top}
 *   cd examples/notification-demo/udp_to_dbus/
 *   make WOLFSENTRY_ROOT={the_install_top}
 *   popd
 *
 * Now build libwolfssl with the patched example client and server applications:
 *
 *   pushd wolfssl
 *   patch -p1 < ../wolfsentry/examples/notification-demo/wolfssl-wolfsentry_notify_via_UDP_JSON.patch
 *   [optional: autoreconf --install --force]
 *   ./configure --quiet --enable-all --enable-wolfsentry --with-wolfsentry=../wolfsentry/install_image
 *   make -j
 *   popd
 *
 * At this point, all executables should be built and ready for use.
 *
 *
 * Running the demo:
 *
 * Run the message daemon in terminal #1:
 *
 *   pushd wolfsentry/examples/notification-demo/udp_to_dbus
 *   ./udp_to_dbus
 *
 * Run the example server in a terminal #2:
 *
 *   pushd wolfssl
 *   ./examples/server/server -x -i -v 4 -b -g --wolfsentry-config ../wolfsentry/tests/test-config.json
 *
 * Run the example client from a third terminal, and try various target addresses to exercise the ruleset:
 *
 *   pushd wolfssl
 *   ./examples/client/client -v 4 localhost
 *       [should succeed]
 *   ./examples/client/client -v 4 192.168.0.1
 *       [if 192.168.0.1 is a configured address of your local workstation, this
 *              will be blocked by wolfSentry, else it will time out eventually]
 *
 * Note that the example client is also calling wolfSentry for the outbound
 * connections, but by default it won't load the JSON config.
 *
 * If instead you issue
 *
 *   ./examples/client/client -v 4 localhost --wolfsentry-config ../wolfsentry/tests/test-config.json
 *
 * Then the example client will also generate notifications.  In fact, if the
 * connection succeeds, it will generate two, because the test client both calls
 * wolfsentry_route_event_dispatch() directly before connecting, and also
 * installs a callback in the wolfSSL library that calls
 * wolfsentry_route_event_dispatch() at the start of the TLS negotiation
 * process.  Obviously this is for demonstration purposes -- a production
 * wolfSentry-aware application would always filter outbound connections at the
 * earliest opportunity, and in any case, before establishing a network
 * connection.
 *
 *
 * tests/test-config.json has these clauses in its "user-values" section to
 * support coordination of the notification pipeline:
 *
 *      "notification-dest-addr" : "127.0.0.1",
 *      "notification-dest-port" : 55555
 *
 * If these values aren't suitable -- e.g., to experiment with sending
 * notifications over a LAN connection -- modify the values to suit, and pass
 * the path of the modified file in the above commands.
 *
 *
 * New rules can also be added to test-config.json, e.g. to allow 192.168.*.*,
 * inbound and outbound, add this rule to the "static-routes-insert" array:
 * 
 *
 *      {
 *          "parent-event" : "static-route-parent",
 *          "direction-in" : true,
 *          "direction-out" : true,
 *          "green-listed" : true,
 *          "family" : "inet",
 *          "protocol" : "tcp",
 *          "remote" : {
 *              "address" : "192.168.0.0",
 *              "prefix-bits" : 16,
 *              "interface" : 1
 *          },
 *      }
 *
 */

#define _GNU_SOURCE

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_USER_BASE

#include <wolfsentry/wolfsentry_json.h>

#ifndef WOLFSENTRY_HAVE_JSON_DOM
#error wolfSentry built without WOLFSENTRY_HAVE_JSON_DOM
#endif

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/signal.h>
#include <setjmp.h>

#include <libnotify/notify.h>

#include <wolfsentry/centijson_dom.h>
#include <wolfsentry/centijson_value.h>

static int notnormal = 0;

static int notify(JSON_CONFIG *centijson_config, const char *json_message, size_t json_message_len) {
    VALUE p_root;
    VALUE *action_v = NULL,
        *rule_id_v = NULL,
        *rule_hitcount_v = NULL,
        *af_v = NULL,
        *proto_v = NULL,
        *remote_addr_v = NULL,
        *remote_port_v = NULL,
        *local_addr_v = NULL,
        *local_port_v = NULL,
        *decision_array_v = NULL,
        *decision_string_v = NULL;
    JSON_INPUT_POS json_pos;

    NotifyNotification *notify = NULL;
    const char *summary = NULL;
    const char *body = NULL;
    const char *type = NULL;
    const char *app_name = NULL;
    const char *icon_str = NULL;
    gint notification_id = 0;
    NotifyUrgency urgency = NOTIFY_URGENCY_NORMAL;
    glong expire_timeout = 10000 /*NOTIFY_EXPIRES_DEFAULT*/ /* ms */;
    GError *error = NULL;
    gboolean retval;
    int ret;

    if ((ret = json_dom_parse(json_message, json_message_len, centijson_config,
                              0 /* dom_flags */, &p_root, &json_pos) < 0)) {
        if (WOLFSENTRY_ERROR_DECODE_SOURCE_ID(ret) == WOLFSENTRY_SOURCE_ID_UNSET)
            fprintf(stderr,
                    "json_dom_parse failed at offset " SIZET_FMT ", L%u, col %u, with centijson code %d: %s\n",
                    json_pos.offset,
                    json_pos.line_number,
                    json_pos.column_number,
                    ret,
                    json_error_str(ret));
        else
            fprintf(stderr,
                    "json_dom_parse failed at offset " SIZET_FMT ", L%u, col %u, with " WOLFSENTRY_ERROR_FMT "\n",
                    json_pos.offset,
                    json_pos.line_number,
                    json_pos.column_number,
                    WOLFSENTRY_ERROR_FMT_ARGS(ret));
        return -1;
    }

    do {
        /* {
             "action" : "notify-on-decision",
             "trigger" : "(null)",
             "parent" : "(null)",
             "af" : "INET",
             "proto" : "6",
             "remote" : {
               "address" : "108.65.49.10",
               "port" : 36558
             },
             "local" : {
               "address" : "108.65.49.10",
               "port" : 11111
             },
             "decision" : ["reject"]
           }
        */
        const char *action, *af, *remote_addr, *local_addr;
        char msgbuf[1024], *msgbuf_ptr = msgbuf;
        ssize_t msgbuf_len_left = sizeof msgbuf;
        int proto, remote_port, local_port;
        uint32_t rule_id, rule_hitcount;
        size_t n_decisions;

        action_v = value_path(&p_root, "action");
        rule_id_v = value_path(&p_root, "rule-id");
        rule_hitcount_v = value_path(&p_root, "rule-hitcount");
        af_v = value_path(&p_root, "af");
        proto_v = value_path(&p_root, "proto");
        remote_addr_v = value_path(&p_root, "remote/address");
        remote_port_v = value_path(&p_root, "remote/port");
        local_addr_v = value_path(&p_root, "local/address");
        local_port_v = value_path(&p_root, "local/port");
        decision_array_v = value_path(&p_root, "decision");

        action = value_string(action_v);
        rule_id = value_uint32(rule_id_v);
        rule_hitcount = value_uint32(rule_hitcount_v);
        af = value_string(af_v);
        proto = value_int32(proto_v);
        remote_addr = value_string(remote_addr_v);
        remote_port = value_int32(remote_port_v);
        local_addr = value_string(local_addr_v);
        local_port = value_int32(local_port_v);
        n_decisions = value_array_size(decision_array_v);

#define snprintf_msgptr(ptr, ptr_len_left, fmt, args...) {                      \
            int _len = snprintf((ptr), (size_t)(ptr_len_left), (fmt), ## args); \
            if ((_len < 0) || ((size_t)_len >= (ptr_len_left))) {               \
                (ptr_len_left) = -1;                                            \
                break;                                                          \
            }                                                                   \
            (ptr) += _len;                                                      \
        }

        snprintf_msgptr(msgbuf_ptr, msgbuf_len_left, "%s/%d from %s:%d to %s:%d\n",
                        af,
                        proto,
                        remote_addr,
                        remote_port,
                        local_addr,
                        local_port);

        snprintf_msgptr(msgbuf_ptr, msgbuf_len_left, "rule %u, %u hits\ndecision: [",
                        rule_id,
                        rule_hitcount);

        for (int i = 0; i < n_decisions; ++i) {
            const char *decision_string;
            decision_string_v = value_array_get(decision_array_v, i);
            if (decision_string_v == NULL)
                continue;
            decision_string = value_string(decision_string_v);
            if (decision_string == NULL)
                continue;
            snprintf_msgptr(msgbuf_ptr, msgbuf_len_left, "%s%s", i>0 ? "," : "", decision_string);
            value_fini(decision_string_v);
            decision_string_v = NULL;
        }

        if (msgbuf_len_left < 0)
            break;

        snprintf_msgptr(msgbuf_ptr, msgbuf_len_left, "]");

        /* xxx note that dbus notification daemons expect fragments of basic
         * HTML as input, so msgbuf needs rewriting to escape HTML entities.
         */

        summary = action;
        body = msgbuf;
        type = "type";
        app_name = "wolfsentry_udp_to_dbus";
        icon_str = "icon_str";

        notify = g_object_new (NOTIFY_TYPE_NOTIFICATION,
                               "summary", summary,
                               "body", body,
                               "icon-name", icon_str,
                               "id", notification_id,
                               NULL);
    } while(0);

    value_fini(action_v);
    value_fini(rule_id_v);
    value_fini(rule_hitcount_v);
    value_fini(af_v);
    value_fini(proto_v);
    value_fini(remote_addr_v);
    value_fini(remote_port_v);
    value_fini(local_addr_v);
    value_fini(local_port_v);
    value_fini(decision_array_v);

    value_fini(&p_root);

    if (notify == NULL)
        return -1;

    notify_notification_set_category (notify, type);
    notify_notification_set_urgency (notify, urgency);
    notify_notification_set_timeout (notify, expire_timeout);
    notify_notification_set_app_name (notify, app_name);

    notify_notification_set_hint (notify, "transient",
                                              g_variant_new_boolean (TRUE));

    retval = notify_notification_show (notify, &error);
    if (! retval) {
        fprintf (stderr, "%s\n", error->message);
        g_clear_error (&error);
    }

    return 0;
}

static wolfsentry_errcode_t my_addr_family_parser(
    struct wolfsentry_context *wolfsentry,
    const char *addr_text,
    const int addr_text_len,
    byte *addr_internal,
    wolfsentry_addr_bits_t *addr_internal_len)
{
    uint32_t a[3];
    char abuf[32];
    int n_octets, parsed_len = 0, i;

    (void)wolfsentry;

    if (snprintf(abuf,sizeof abuf,"%.*s",addr_text_len,addr_text) >= (int)sizeof abuf)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
    if ((n_octets = sscanf(abuf,"%o/%o/%o%n",&a[0],&a[1],&a[2],&parsed_len)) < 1)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    if (parsed_len != addr_text_len) {
        if ((n_octets = sscanf(abuf,"%o/%o/%n",&a[0],&a[1],&parsed_len)) < 1)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    }
    if (parsed_len != addr_text_len) {
        if ((n_octets = sscanf(abuf,"%o/%n",&a[0],&parsed_len)) < 1)
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    }
    if (parsed_len != addr_text_len)
        WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
    for (i = 0; i < n_octets; ++i) {
        if (a[i] > MAX_UINT_OF(byte))
            WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_VALUE);
        addr_internal[i] = (byte)a[i];
    }
    *addr_internal_len = (wolfsentry_addr_bits_t)(n_octets * 8);
    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t my_addr_family_formatter(
    struct wolfsentry_context *wolfsentry,
    const byte *addr_internal,
    const unsigned int addr_internal_len,
    char *addr_text,
    int *addr_text_len)
{
    int out_len;
    int ret;

    (void)wolfsentry;

    if (addr_internal_len <= 8)
        out_len = snprintf(addr_text, (size_t)*addr_text_len, "%o/",
                           (unsigned int)addr_internal[0]);
    else if (addr_internal_len <= 16)
        out_len = snprintf(addr_text, (size_t)*addr_text_len, "%o/%o/",
                           (unsigned int)addr_internal[0],
                           (unsigned int)addr_internal[1]);
    else
        out_len = snprintf(addr_text, (size_t)*addr_text_len, "%o/%o/%o",
                           (unsigned int)addr_internal[0],
                           (unsigned int)addr_internal[1],
                           (unsigned int)addr_internal[2]);
    if (out_len >= *addr_text_len)
        ret = WOLFSENTRY_ERROR_ENCODE(BUFFER_TOO_SMALL);
    else
        ret = WOLFSENTRY_ERROR_ENCODE(OK);
    *addr_text_len = out_len;
    return ret;
}

static jmp_buf interrupt_jmp_buf;
static void handle_interrupt(int sig) {
    (void)sig;
    longjmp(interrupt_jmp_buf, 1);
}

int main(int argc, char **argv) {
    wolfsentry_errcode_t ret;
    int wolfsentry_config_fd = -1;
    struct stat wolfsentry_config_st;
    const char *wolfsentry_config_map = MAP_FAILED;
    char buf[1024];
    int inbound_fd = -1;
    struct sockaddr_in inbound_sa;
    const char *wolfsentry_configfile = "../../../tests/test-config.json";
    uint64_t notification_dest_port;
    const char *notification_dest_addr;
    int notification_dest_addr_len;
    struct wolfsentry_kv_pair_internal *notification_dest_addr_record = NULL;
    int pton_ret;
    ssize_t recv_ret;

    JSON_CONFIG centijson_config = {
        2000,  /* max_total_len */
        100,  /* max_total_values */
        20,  /* max_number_len */
        255,  /* max_string_len */
        WOLFSENTRY_MAX_LABEL_BYTES,  /* max_key_len */
        6,  /* max_nesting_level */
        JSON_NOSCALARROOT   /* flags */
    };

    struct wolfsentry_context *wolfsentry;

    if (argc > 1)
        wolfsentry_configfile = argv[1];

    g_set_prgname (argv[0]);
    g_log_set_always_fatal (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);

    if (! notify_init("udp_to_dbus"))
        exit(1);

    if (wolfsentry_init(NULL /* HPI */, NULL /* config */, &wolfsentry) < 0)
        exit(1);

    if (wolfsentry_addr_family_handler_install(
            wolfsentry,
            WOLFSENTRY_AF_USER_OFFSET,
            "my_AF",
            WOLFSENTRY_LENGTH_NULL_TERMINATED,
            my_addr_family_parser,
            my_addr_family_formatter,
            24 /* max_addr_bits */) < 0)
        exit(1);

    if ((wolfsentry_config_fd = open(wolfsentry_configfile, O_RDONLY)) < 0) {
        perror(wolfsentry_configfile);
        exit(1);
    }

    if (fstat(wolfsentry_config_fd, &wolfsentry_config_st) < 0) {
        perror(wolfsentry_configfile);
        exit(1);
    }

    if ((wolfsentry_config_map = mmap(NULL,
                                      wolfsentry_config_st.st_size,
                                      PROT_READ,
                                      MAP_SHARED|MAP_POPULATE,
                                      wolfsentry_config_fd,
                                      0))
        == MAP_FAILED)
    {
        perror(wolfsentry_configfile);
        exit(1);
    }

    if (wolfsentry_config_json_oneshot(
            wolfsentry,
            wolfsentry_config_map,
            wolfsentry_config_st.st_size,
            WOLFSENTRY_CONFIG_LOAD_FLAG_NO_ROUTES_OR_EVENTS,
            buf,
            sizeof buf) < 0) {
        fprintf(stderr,"%s\n",buf);
        exit(1);
    }

    ret = wolfsentry_user_value_get_uint(
        wolfsentry,
        "notification-dest-port",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        &notification_dest_port);

    if (ret < 0)
        exit(1);

    ret = wolfsentry_user_value_get_string(
        wolfsentry,
        "notification-dest-addr",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        &notification_dest_addr,
        &notification_dest_addr_len,
        &notification_dest_addr_record);

    if (ret < 0)
        exit(1);

    pton_ret = inet_pton(AF_INET, notification_dest_addr, &inbound_sa.sin_addr);

    ret = wolfsentry_user_value_release_record(wolfsentry, &notification_dest_addr_record);

    if (ret < 0)
        exit(1);

    switch (pton_ret) {
    case 1:
        break;
    case 0:
        exit(1);
    case -1:
    default:
        exit(1);
    }

    inbound_sa.sin_family = AF_INET;
    inbound_sa.sin_port = htons(notification_dest_port);

    centijson_config.wolfsentry_context = wolfsentry;

    inbound_fd = socket(AF_INET, SOCK_DGRAM, 17 /* UDP */);
    if (inbound_fd < 0) {
        perror("socket(AF_INET, SOCK_DGRAM, UDP");
        exit(1);
    }

    if (bind(inbound_fd, &inbound_sa, sizeof inbound_sa) < 0) {
        perror("bind");
        exit(1);
    }

    if (setjmp(interrupt_jmp_buf))
        goto done;

    if (signal(SIGINT,handle_interrupt) == SIG_ERR) {
        perror("signal(SIGINT)");
        exit(1);
    }
    if (signal(SIGTERM,handle_interrupt) == SIG_ERR) {
        perror("signal(SIGTERM)");
        exit(1);
    }
    if (signal(SIGHUP,handle_interrupt) == SIG_ERR) {
        perror("signal(SIGHUP)");
        exit(1);
    }

    for (;;) {
        recv_ret = recv(inbound_fd, buf, sizeof buf, MSG_TRUNC);
        if (recv_ret > sizeof buf) {
            notnormal = 1;
            fprintf(stderr,"received overlong packet %zd (max %zu)\n", recv_ret, sizeof buf);
            continue;
        }
        if (recv_ret < 0) {
            notnormal = 1;
            perror("recv");
            break;
        }

        if (notify(&centijson_config,buf,recv_ret) < 0)
            notnormal = 1;
    }

done:

    notify_uninit();

    if (wolfsentry_shutdown(&wolfsentry) < 0) {
            fprintf(stderr, "wolfsentry_shutdown: " WOLFSENTRY_ERROR_FMT,
                    WOLFSENTRY_ERROR_FMT_ARGS(ret));
            notnormal = 1;
    }

    if (! notnormal)
        printf("\nnormal exit.\n");
    else
        fprintf(stderr,"\nexiting with warnings or errors.\n");
    exit(0);
}
