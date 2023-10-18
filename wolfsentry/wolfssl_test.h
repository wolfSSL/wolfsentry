/*
 * wolfssl_test.h
 *
 * Copyright (C) 2021-2023 wolfSSL Inc.
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

/*! @file wolfssl_test.h
    \brief Macros and helper functions for wolfSSL --enable-wolfsentry.

    This file is included by wolfssl/test.h when defined(WOLFSSL_WOLFSENTRY_HOOKS).
 */

#ifndef WOLFSENTRY_WOLFSSL_TEST_H
#define WOLFSENTRY_WOLFSSL_TEST_H

#include <wolfsentry/wolfsentry_util.h>

#if !defined(NO_FILESYSTEM) && !defined(WOLFSENTRY_NO_JSON)
#include <wolfsentry/wolfsentry_json.h>
#endif

#if defined(WOLFSENTRY_VERSION_GE)
#if WOLFSENTRY_VERSION_GE(0, 8, 0)
#define HAVE_WOLFSENTRY_API_0v8
#endif
#endif

#ifndef HAVE_WOLFSENTRY_API_0v8
#define WOLFSENTRY_CONTEXT_ARGS_OUT_EX(x) (x)
#define WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(x, y) (x)
#endif

struct wolfsentry_data {
    WOLFSENTRY_SOCKADDR(128) remote;
    WOLFSENTRY_SOCKADDR(128) local;
    wolfsentry_route_flags_t flags;
    void *heap;
    int alloctype;
};

static void free_wolfsentry_data(struct wolfsentry_data *data) {
    XFREE(data, data->heap, data->alloctype);
}

static struct wolfsentry_context *wolfsentry = NULL;

static int wolfsentry_data_index = -1;

static WC_INLINE int wolfsentry_store_endpoints(
    WOLFSSL *ssl,
    SOCKADDR_IN_T *remote,
    SOCKADDR_IN_T *local,
    int proto,
    wolfsentry_route_flags_t flags,
    struct wolfsentry_data **wolfsentry_data_out)
{
    struct wolfsentry_data *wolfsentry_data = (struct wolfsentry_data *)XMALLOC(
        sizeof *wolfsentry_data, NULL, DYNAMIC_TYPE_SOCKADDR);
    if (wolfsentry_data == NULL)
        return WOLFSSL_FAILURE;

    wolfsentry_data->heap = NULL;
    wolfsentry_data->alloctype = DYNAMIC_TYPE_SOCKADDR;

#ifdef TEST_IPV6
    if ((sizeof wolfsentry_data->remote.addr < sizeof remote->sin6_addr) ||
        (sizeof wolfsentry_data->local.addr < sizeof local->sin6_addr))
        return WOLFSSL_FAILURE;
    wolfsentry_data->remote.sa_family = wolfsentry_data->local.sa_family = remote->sin6_family;
    wolfsentry_data->remote.sa_port = ntohs(remote->sin6_port);
    wolfsentry_data->local.sa_port = ntohs(local->sin6_port);
    if (WOLFSENTRY_MASKIN_BITS(flags, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD)) {
        wolfsentry_data->remote.addr_len = 0;
        XMEMSET(wolfsentry_data->remote.addr, 0, sizeof remote->sin6_addr);
    } else {
        wolfsentry_data->remote.addr_len = sizeof remote->sin6_addr * BITS_PER_BYTE;
        XMEMCPY(wolfsentry_data->remote.addr, &remote->sin6_addr, sizeof remote->sin6_addr);
    }
    if (WOLFSENTRY_MASKIN_BITS(flags, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD)) {
        wolfsentry_data->local.addr_len = 0;
        XMEMSET(wolfsentry_data->local.addr, 0, sizeof local->sin6_addr);
    } else {
        wolfsentry_data->local.addr_len = sizeof local->sin6_addr * BITS_PER_BYTE;
        XMEMCPY(wolfsentry_data->local.addr, &local->sin6_addr, sizeof local->sin6_addr);
    }
#else
    if ((sizeof wolfsentry_data->remote.addr < sizeof remote->sin_addr) ||
        (sizeof wolfsentry_data->local.addr < sizeof local->sin_addr))
        return WOLFSSL_FAILURE;
    wolfsentry_data->remote.sa_family = wolfsentry_data->local.sa_family = remote->sin_family;
    wolfsentry_data->remote.sa_port = ntohs(remote->sin_port);
    wolfsentry_data->local.sa_port = ntohs(local->sin_port);
    if (WOLFSENTRY_MASKIN_BITS(flags, WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD)) {
        wolfsentry_data->remote.addr_len = 0;
        XMEMSET(wolfsentry_data->remote.addr, 0, sizeof remote->sin_addr);
    } else {
        wolfsentry_data->remote.addr_len = sizeof remote->sin_addr * BITS_PER_BYTE;
        XMEMCPY(wolfsentry_data->remote.addr, &remote->sin_addr, sizeof remote->sin_addr);
    }
    if (WOLFSENTRY_MASKIN_BITS(flags, WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD)) {
        wolfsentry_data->local.addr_len = 0;
        XMEMSET(wolfsentry_data->local.addr, 0, sizeof local->sin_addr);
    } else {
        wolfsentry_data->local.addr_len = sizeof local->sin_addr * BITS_PER_BYTE;
        XMEMCPY(wolfsentry_data->local.addr, &local->sin_addr, sizeof local->sin_addr);
    }
#endif
    wolfsentry_data->remote.sa_proto = wolfsentry_data->local.sa_proto = proto;
    wolfsentry_data->remote.interface = wolfsentry_data->local.interface = 0;
    wolfsentry_data->flags = flags;

    if (wolfSSL_set_ex_data_with_cleanup(
            ssl, wolfsentry_data_index, wolfsentry_data,
            (wolfSSL_ex_data_cleanup_routine_t)free_wolfsentry_data) !=
        WOLFSSL_SUCCESS) {
        free_wolfsentry_data(wolfsentry_data);
        return WOLFSSL_FAILURE;
    }

    if (wolfsentry_data_out != NULL)
        *wolfsentry_data_out = wolfsentry_data;

    return WOLFSSL_SUCCESS;
}

static int wolfSentry_NetworkFilterCallback(
    WOLFSSL *ssl,
    struct wolfsentry_context *_wolfsentry,
    wolfSSL_netfilter_decision_t *decision)
{
    struct wolfsentry_data *data;
    char inet_ntop_buf[INET6_ADDRSTRLEN], inet_ntop_buf2[INET6_ADDRSTRLEN];
    wolfsentry_errcode_t ret;
    wolfsentry_action_res_t action_results;

#if defined(WOLFSENTRY_THREADSAFE) && defined(HAVE_WOLFSENTRY_API_0v8)
    WOLFSENTRY_THREAD_HEADER(WOLFSENTRY_THREAD_FLAG_NONE);
    if (WOLFSENTRY_THREAD_GET_ERROR < 0) {
        fprintf(stderr, "wolfsentry thread init error: "
                WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(WOLFSENTRY_THREAD_GET_ERROR));
        return WOLFSSL_FAILURE;
    }
#endif /* WOLFSENTRY_THREADSAFE && HAVE_WOLFSENTRY_API_0v8 */

    if ((data = wolfSSL_get_ex_data(ssl, wolfsentry_data_index)) == NULL)
        return WOLFSSL_FAILURE;

    ret = wolfsentry_route_event_dispatch(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(_wolfsentry),
        (const struct wolfsentry_sockaddr *)&data->remote,
        (const struct wolfsentry_sockaddr *)&data->local,
        data->flags,
        NULL /* event_label */,
        0 /* event_label_len */,
        NULL /* caller_context */,
        NULL /* id */,
        NULL /* inexact_matches */,
        &action_results);

    if (ret >= 0) {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT))
            *decision = WOLFSSL_NETFILTER_REJECT;
        else if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT))
            *decision = WOLFSSL_NETFILTER_ACCEPT;
        else
            *decision = WOLFSSL_NETFILTER_PASS;
    } else {
        fprintf(stderr, "wolfsentry_route_event_dispatch error "
               WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        *decision = WOLFSSL_NETFILTER_PASS;
    }

    printf("wolfSentry got network filter callback: family=%d proto=%d rport=%d"
           " lport=%d raddr=%s laddr=%s interface=%d; decision=%d (%s)\n",
           data->remote.sa_family,
           data->remote.sa_proto,
           data->remote.sa_port,
           data->local.sa_port,
           inet_ntop(data->remote.sa_family, data->remote.addr, inet_ntop_buf,
                     sizeof inet_ntop_buf),
           inet_ntop(data->local.sa_family, data->local.addr, inet_ntop_buf2,
                     sizeof inet_ntop_buf2),
           data->remote.interface,
           *decision,
           *decision == WOLFSSL_NETFILTER_REJECT ? "REJECT" :
           *decision == WOLFSSL_NETFILTER_ACCEPT ? "ACCEPT" :
           *decision == WOLFSSL_NETFILTER_PASS ? "PASS" :
           "???");

#if defined(WOLFSENTRY_THREADSAFE) && defined(HAVE_WOLFSENTRY_API_0v8)
    ret = WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry thread exit error: "
               WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
    }
#endif

    return WOLFSSL_SUCCESS;
}

static int wolfsentry_setup(
    struct wolfsentry_context **_wolfsentry,
    const char *_wolfsentry_config_path,
    wolfsentry_route_flags_t route_flags)
{
    wolfsentry_errcode_t ret;

#ifdef HAVE_WOLFSENTRY_API_0v8
#ifdef WOLFSENTRY_THREADSAFE
    WOLFSENTRY_THREAD_HEADER(WOLFSENTRY_THREAD_FLAG_NONE);
    if (WOLFSENTRY_THREAD_GET_ERROR < 0) {
        fprintf(stderr, "wolfsentry thread init error: "
                WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(WOLFSENTRY_THREAD_GET_ERROR));
        err_sys("unable to initialize wolfSentry thread context");
    }
#endif
    ret =  wolfsentry_init(wolfsentry_build_settings,
                           WOLFSENTRY_CONTEXT_ARGS_OUT_EX(NULL /* hpi */),
                           NULL /* default config */,
                           _wolfsentry);
#else
    ret =  wolfsentry_init(NULL /* hpi */, NULL /* default config */,
                           _wolfsentry);
#endif
    if (ret < 0) {
        fprintf(stderr, "wolfsentry_init() returned " WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err_sys("unable to initialize wolfSentry");
    }

    if (wolfsentry_data_index < 0)
        wolfsentry_data_index = wolfSSL_get_ex_new_index(0, NULL, NULL, NULL,
                                                         NULL);

#if !defined(NO_FILESYSTEM) && !defined(WOLFSENTRY_NO_JSON)
    if (_wolfsentry_config_path != NULL) {
        unsigned char buf[512];
        char err_buf[512];
        struct wolfsentry_json_process_state *jps;

        FILE *f = fopen(_wolfsentry_config_path, "r");

        if (f == NULL) {
            fprintf(stderr, "fopen(%s): %s\n",_wolfsentry_config_path,strerror(errno));
            err_sys("unable to open wolfSentry config file");
        }

        if ((ret = wolfsentry_config_json_init(
                 WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*_wolfsentry),
                 WOLFSENTRY_CONFIG_LOAD_FLAG_NONE,
                 &jps)) < 0) {
            fprintf(stderr, "wolfsentry_config_json_init() returned "
                    WOLFSENTRY_ERROR_FMT "\n",
                    WOLFSENTRY_ERROR_FMT_ARGS(ret));
            err_sys("error while initializing wolfSentry config parser");
        }

        for (;;) {
            size_t n = fread(buf, 1, sizeof buf, f);
            if ((n < sizeof buf) && ferror(f)) {
                fprintf(stderr,"fread(%s): %s\n",_wolfsentry_config_path, strerror(errno));
                err_sys("error while reading wolfSentry config file");
            }

            ret = wolfsentry_config_json_feed(jps, buf, n, err_buf, sizeof err_buf);
            if (ret < 0) {
                fprintf(stderr, "%.*s\n", (int)sizeof err_buf, err_buf);
                err_sys("error while loading wolfSentry config file");
            }
            if ((n < sizeof buf) && feof(f))
                break;
        }
        fclose(f);

        if ((ret = wolfsentry_config_json_fini(&jps, err_buf, sizeof err_buf)) < 0) {
            fprintf(stderr, "%.*s\n", (int)sizeof err_buf, err_buf);
            err_sys("error while loading wolfSentry config file");
        }

    } else
#endif /* !NO_FILESYSTEM && !WOLFSENTRY_NO_JSON */
    {
        struct wolfsentry_route_table *table;

#ifdef WOLFSENTRY_THREADSAFE
        ret = WOLFSENTRY_SHARED_EX(*_wolfsentry);
        if (ret < 0) {
            fprintf(stderr, "wolfsentry shared lock op failed: "
                    WOLFSENTRY_ERROR_FMT ".\n",
                    WOLFSENTRY_ERROR_FMT_ARGS(ret));
            return ret;
        }
#endif

        if ((ret = wolfsentry_route_get_main_table(
                 WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*_wolfsentry),
                 &table)) < 0)
        {
            fprintf(stderr, "wolfsentry_route_get_main_table() returned "
                    WOLFSENTRY_ERROR_FMT "\n",
                    WOLFSENTRY_ERROR_FMT_ARGS(ret));
#ifdef WOLFSENTRY_THREADSAFE
            WOLFSENTRY_WARN_ON_FAILURE(
                wolfsentry_context_unlock(
                    WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*_wolfsentry)));
#endif
            return ret;
        }

        if (WOLFSENTRY_MASKIN_BITS(route_flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT)) {
            WOLFSENTRY_SOCKADDR(128) remote, local;
            wolfsentry_ent_id_t id;
            wolfsentry_action_res_t action_results;

            if ((ret = wolfsentry_route_table_default_policy_set(
                     WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*_wolfsentry),
                     table,
                     WOLFSENTRY_ACTION_RES_ACCEPT))
                < 0) {
                fprintf(stderr,
                        "wolfsentry_route_table_default_policy_set() returned "
                        WOLFSENTRY_ERROR_FMT "\n",
                        WOLFSENTRY_ERROR_FMT_ARGS(ret));
#ifdef WOLFSENTRY_THREADSAFE
                WOLFSENTRY_WARN_ON_FAILURE(
                    wolfsentry_context_unlock(
                        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*_wolfsentry)));
#endif
                return ret;
            }

            XMEMSET(&remote, 0, sizeof remote);
            XMEMSET(&local, 0, sizeof local);
#ifdef TEST_IPV6
            remote.sa_family = local.sa_family = AF_INET6;
            remote.addr_len = 128;
            XMEMCPY(remote.addr, "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\001", 16);
#else
            remote.sa_family = local.sa_family = AF_INET;
            remote.addr_len = 32;
            XMEMCPY(remote.addr, "\177\000\000\001", 4);
#endif

            if ((ret = wolfsentry_route_insert
                 (WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*_wolfsentry),
                  NULL /* caller_context */,
                  (const struct wolfsentry_sockaddr *)&remote,
                  (const struct wolfsentry_sockaddr *)&local,
                  route_flags                                    |
                  WOLFSENTRY_ROUTE_FLAG_GREENLISTED              |
                  WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD    |
                  WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD|
                  WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD |
                  WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD   |
                  WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD        |
                  WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD  |
                  WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD,
                  0 /* event_label_len */, 0 /* event_label */, &id,
                  &action_results)) < 0) {
                fprintf(stderr, "wolfsentry_route_insert() returned "
                        WOLFSENTRY_ERROR_FMT "\n",
                        WOLFSENTRY_ERROR_FMT_ARGS(ret));
#ifdef WOLFSENTRY_THREADSAFE
                WOLFSENTRY_WARN_ON_FAILURE(
                    wolfsentry_context_unlock(
                        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*_wolfsentry)));
#endif
                return ret;
            }
        } else if (WOLFSENTRY_MASKIN_BITS(route_flags, WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN)) {
            WOLFSENTRY_SOCKADDR(128) remote, local;
            wolfsentry_ent_id_t id;
            wolfsentry_action_res_t action_results;

            if ((ret = wolfsentry_route_table_default_policy_set(
                     WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*_wolfsentry), table,
                     WOLFSENTRY_ACTION_RES_REJECT|WOLFSENTRY_ACTION_RES_STOP))
                < 0) {
                fprintf(stderr,
                        "wolfsentry_route_table_default_policy_set() returned "
                        WOLFSENTRY_ERROR_FMT "\n",
                        WOLFSENTRY_ERROR_FMT_ARGS(ret));
#ifdef WOLFSENTRY_THREADSAFE
                WOLFSENTRY_WARN_ON_FAILURE(
                    wolfsentry_context_unlock(
                        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*_wolfsentry)));
#endif
                return ret;
            }

            XMEMSET(&remote, 0, sizeof remote);
            XMEMSET(&local, 0, sizeof local);
#ifdef TEST_IPV6
            remote.sa_family = local.sa_family = AF_INET6;
            remote.addr_len = 128;
            XMEMCPY(remote.addr, "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\001", 16);
#else
            remote.sa_family = local.sa_family = AF_INET;
            remote.addr_len = 32;
            XMEMCPY(remote.addr, "\177\000\000\001", 4);
#endif

            if ((ret = wolfsentry_route_insert
                 (WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*_wolfsentry),
                  NULL /* caller_context */,
                  (const struct wolfsentry_sockaddr *)&remote,
                  (const struct wolfsentry_sockaddr *)&local,
                  route_flags                                    |
                  WOLFSENTRY_ROUTE_FLAG_GREENLISTED              |
                  WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD    |
                  WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD|
                  WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD |
                  WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD   |
                  WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD        |
                  WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD  |
                  WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD,
                  0 /* event_label_len */, 0 /* event_label */, &id,
                  &action_results)) < 0) {
                fprintf(stderr, "wolfsentry_route_insert() returned "
                        WOLFSENTRY_ERROR_FMT "\n",
                        WOLFSENTRY_ERROR_FMT_ARGS(ret));
#ifdef WOLFSENTRY_THREADSAFE
                WOLFSENTRY_WARN_ON_FAILURE(
                    wolfsentry_context_unlock(
                        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*_wolfsentry)));
#endif
                return ret;
            }
        }
#ifdef WOLFSENTRY_THREADSAFE
        WOLFSENTRY_WARN_ON_FAILURE(
            wolfsentry_context_unlock(
                WOLFSENTRY_CONTEXT_ARGS_OUT_EX(*_wolfsentry)));
#endif
    }

#if defined(WOLFSENTRY_THREADSAFE) && defined(HAVE_WOLFSENTRY_API_0v8)
    ret = WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry thread exit error: "
               WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
    }
#endif

    return 0;
}

static WC_INLINE int tcp_connect_with_wolfSentry(
    SOCKET_T* sockfd,
    const char* ip,
    word16 port,
    int udp,
    int sctp,
    WOLFSSL* ssl,
    struct wolfsentry_context *_wolfsentry)
{
    SOCKADDR_IN_T remote_addr;
    struct wolfsentry_data *wolfsentry_data;
    char inet_ntop_buf[INET6_ADDRSTRLEN], inet_ntop_buf2[INET6_ADDRSTRLEN];
    wolfsentry_errcode_t ret;
    wolfsentry_action_res_t action_results;
    wolfSSL_netfilter_decision_t decision;

#if defined(WOLFSENTRY_THREADSAFE) && defined(HAVE_WOLFSENTRY_API_0v8)
    WOLFSENTRY_THREAD_HEADER(WOLFSENTRY_THREAD_FLAG_NONE);
    if (WOLFSENTRY_THREAD_GET_ERROR < 0) {
        fprintf(stderr, "wolfsentry thread init error: "
                WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(WOLFSENTRY_THREAD_GET_ERROR));
        err_sys("unable to initialize wolfSentry thread context");
    }
#endif

    build_addr(&remote_addr, ip, port, udp, sctp);

    {
        SOCKADDR_IN_T local_addr;
#ifdef TEST_IPV6
        local_addr.sin6_port = 0;
#else
        local_addr.sin_port = 0;
#endif
        ((struct sockaddr *)&local_addr)->sa_family = ((struct sockaddr *)&remote_addr)->sa_family;

        if (wolfsentry_store_endpoints(
                ssl, &remote_addr, &local_addr,
                udp ? IPPROTO_UDP : IPPROTO_TCP,
                WOLFSENTRY_ROUTE_FLAG_DIRECTION_OUT|
                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD|
                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD, &wolfsentry_data) != WOLFSSL_SUCCESS)
            return WOLFSSL_FAILURE;
    }

    ret = wolfsentry_route_event_dispatch(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(_wolfsentry),
        (const struct wolfsentry_sockaddr *)&wolfsentry_data->remote,
        (const struct wolfsentry_sockaddr *)&wolfsentry_data->local,
        wolfsentry_data->flags,
        NULL /* event_label */,
        0    /* event_label_len */,
        NULL /* caller_context */,
        NULL /* id */,
        NULL /* inexact_matches */,
        &action_results);

    if (ret < 0) {
        fprintf(stderr, "wolfsentry_route_event_dispatch error "
               WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        decision = WOLFSSL_NETFILTER_PASS;
    } else {
        if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT))
            decision = WOLFSSL_NETFILTER_REJECT;
        else if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_ACCEPT))
            decision = WOLFSSL_NETFILTER_ACCEPT;
        else
            decision = WOLFSSL_NETFILTER_PASS;
    }

    printf("wolfSentry callin from tcp_connect_with_wolfSentry: family=%d proto=%d rport=%d"
           " lport=%d raddr=%s laddr=%s interface=%d; decision=%d (%s)\n",
           wolfsentry_data->remote.sa_family,
           wolfsentry_data->remote.sa_proto,
           wolfsentry_data->remote.sa_port,
           wolfsentry_data->local.sa_port,
           inet_ntop(wolfsentry_data->remote.sa_family, wolfsentry_data->remote.addr, inet_ntop_buf,
                     sizeof inet_ntop_buf),
           inet_ntop(wolfsentry_data->local.sa_family, wolfsentry_data->local.addr, inet_ntop_buf2,
                     sizeof inet_ntop_buf2),
           wolfsentry_data->remote.interface,
           decision,
           decision == WOLFSSL_NETFILTER_REJECT ? "REJECT" :
           decision == WOLFSSL_NETFILTER_ACCEPT ? "ACCEPT" :
           decision == WOLFSSL_NETFILTER_PASS ?   "PASS" :
           "???");

    if (decision == WOLFSSL_NETFILTER_REJECT)
        return SOCKET_FILTERED_E;

    if (udp) {
        wolfSSL_dtls_set_peer(ssl, &remote_addr, sizeof(remote_addr));
    }
    tcp_socket(sockfd, udp, sctp);

    if (!udp) {
        if (connect(*sockfd, (const struct sockaddr*)&remote_addr, sizeof(remote_addr)) != 0)
            err_sys_with_errno("tcp connect failed");
    }

#if defined(WOLFSENTRY_THREADSAFE) && defined(HAVE_WOLFSENTRY_API_0v8)
    ret = WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry thread exit error: "
               WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
    }
#endif

    return WOLFSSL_SUCCESS;
}

#define tcp_connect(sockfd, ip, port, udp, sctp, ssl) \
    tcp_connect_with_wolfSentry(sockfd, ip, port, udp, sctp, ssl, wolfsentry)

#endif /* !WOLFSENTRY_WOLFSSL_TEST_H */
