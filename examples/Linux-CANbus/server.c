/* server.c
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

#define RECV_MSG_LEN 64

extern volatile int keep_running;

int main(int argc, char *argv[])
{
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL_METHOD* method = NULL;
    WOLFSSL* ssl = NULL;
    int ret;
    uint8_t local;
    uint8_t remote;

    if (argc != 4) {
        printf("Usage: ./server <CAN interface> <local ID> <remote ID>\n");
        return -1;
    }

    local = strtoul(argv[2], NULL, 16);
    remote = strtoul(argv[3], NULL, 16);

    sentry_init(local, remote);
    ret = setup_connection(argv[1], local, remote);
    if (ret) {
        return ret;
    }

    ret = setup_ssl(SERVICE_TYPE_SERVER, &ctx, &method, &ssl);
    if (ret) {
        return ret;
    }

    while(keep_running) {
        int input;
        char reply[RECV_MSG_LEN];
        memset(reply, 0, RECV_MSG_LEN);
        input = wolfSSL_read(ssl, reply, RECV_MSG_LEN);
        if (input > 0) {
            printf("Got message: %s\n", reply);
        }
    }

    close_ssl(ctx, ssl);

    return 0;
}
