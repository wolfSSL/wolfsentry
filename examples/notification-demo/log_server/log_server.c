/*
 * log_server.c
 *
 * Copyright (C) 2022-2023 wolfSSL Inc.
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

//#define DEBUG_HTTP
//#define DEBUG_HTTP_IO
#define DEBUG_TLS
//#define DEBUG_WOLFSENTRY

//#define HTTP_NONBLOCKING /* not tested */
#define HTTP_MAX_NB_TRIES 10
#define HTTP_BUF_SZ 1024

#define WOLFSENTRY_SOURCE_ID (WOLFSENTRY_SOURCE_ID_USER_BASE+1)

#define SERVER_PRIME256V1
//#define SERVER_SECP384R1

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#if defined(HAVE_POLL) || defined(BUILD_FOR_LINUX) || defined(BUILD_FOR_MACOSX)
#include <poll.h>
#undef  HAVE_POLL
#define HAVE_POLL
#elif defined(HAVE_SELECT)
#include <sys/select.h>
#elif defined(NO_IO_TIMEOUTS)
#else
#error must set HAVE_POLL, HAVE_SELECT, or NO_IO_TIMEOUTS
#endif

#include "sentry.h"
#include "log_server.h"

#define USE_CERT_BUFFERS_2048

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#if !defined(WOLFSSL_WOLFSENTRY_HOOKS) || !defined(HAVE_EX_DATA) || !defined(HAVE_EX_DATA_CLEANUP_HOOKS)
#error Please build and install wolfSSL using --enable-wolfsentry
#endif

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/certs_test.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

/* this is an internal routine with strange argument type that's immediately
 * cast back to int in the implementation.
 */
#define wolfSSL_ERR_reason_error_string(x) wolfSSL_ERR_reason_error_string((unsigned long)(x))

#ifndef OPENSSL_EXTRA
#error log_server requires that wolfSSL be built with --enable-opensslextra
#endif

static WOLFSSL_CTX* wolf_ctx = NULL;
static int log_server_data_index = -1;

#ifdef SERVER_SECP384R1

/* certs/server-ecc384-cert.pem */
static const char server_cert[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDnzCCAyagAwIBAgICEAEwCgYIKoZIzj0EAwMwgZcxCzAJBgNVBAYTAlVTMRMw\n\
EQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0dGxlMRAwDgYDVQQKDAd3\n\
b2xmU1NMMRQwEgYDVQQLDAtEZXZlbG9wbWVudDEYMBYGA1UEAwwPd3d3LndvbGZz\n\
c2wuY29tMR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdvbGZzc2wuY29tMCAXDTI0MTIx\n\
ODIxMjUyOVoYDzIwNTQxMjExMjEyNTI5WjCBljELMAkGA1UEBhMCVVMxEzARBgNV\n\
BAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxETAPBgNVBAoMCEVsbGlw\n\
dGljMRIwEAYDVQQLDAlFQ0MzODRTcnYxGDAWBgNVBAMMD3d3dy53b2xmc3NsLmNv\n\
bTEfMB0GCSqGSIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTB2MBAGByqGSM49AgEG\n\
BSuBBAAiA2IABOrPk08sCbs5FA9WZMNAtN8OY67lcUsAzASX/+HpOJa7X5Gyasy1\n\
OV+PcFnxAfZaKwFsaAvPVSWvbZhICqh0yakXoAzD+9MjaP4EPGNQiDu5T3xnNPc7\n\
qXPnG8NRXiIY7KOCAUAwggE8MAkGA1UdEwQCMAAwEQYJYIZIAYb4QgEBBAQDAgZA\n\
MB0GA1UdDgQWBBSCO/JlL/O0AMa8Bv15QnVLZdHOvDCB1wYDVR0jBIHPMIHMgBSr\n\
4MMmTBjUcrvShIycCgWSgBJTUqGBnaSBmjCBlzELMAkGA1UEBhMCVVMxEzARBgNV\n\
BAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxEDAOBgNVBAoMB3dvbGZT\n\
U0wxFDASBgNVBAsMC0RldmVsb3BtZW50MRgwFgYDVQQDDA93d3cud29sZnNzbC5j\n\
b20xHzAdBgkqhkiG9w0BCQEWEGluZm9Ad29sZnNzbC5jb22CFFaBUbnOIn1WJzbB\n\
88oeB5Z04brGMA4GA1UdDwEB/wQEAwIDqDATBgNVHSUEDDAKBggrBgEFBQcDATAK\n\
BggqhkjOPQQDAwNnADBkAjAYATAj5pIDNH3L+oUwPS8ur+j7nhcf+T3/4/EywRUY\n\
C/cZR0DTEPUTTJP3AOgkC74CMGuLTpj9RxsUyhnVbHMRDEMmCFO04ewoLYSs129j\n\
OKguYwcZubpKZ42SE1meXjmZOA==\n\
-----END CERTIFICATE-----\n\
";

/* certs/server-ecc384-key.pem */
static const char server_key[] =
"-----BEGIN PRIVATE KEY-----\n\
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCk5QboBhY+q4n4YEPA\n\
YCXbunv+GTUIVWV24tzgAYtraN/Pb4ASznk36yuce8RoHHShZANiAATqz5NPLAm7\n\
ORQPVmTDQLTfDmOu5XFLAMwEl//h6TiWu1+RsmrMtTlfj3BZ8QH2WisBbGgLz1Ul\n\
r22YSAqodMmpF6AMw/vTI2j+BDxjUIg7uU98ZzT3O6lz5xvDUV4iGOw=\n\
-----END PRIVATE KEY-----\n\
";

#endif /* SERVER_SECP384R1 */

#ifdef SERVER_PRIME256V1

/* certs/server-ecc.pem */
static const char server_cert[] =
"-----BEGIN CERTIFICATE-----\n\
MIICojCCAkigAwIBAgIBAzAKBggqhkjOPQQDAjCBlzELMAkGA1UEBhMCVVMxEzAR\n\
BgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxEDAOBgNVBAoMB3dv\n\
bGZTU0wxFDASBgNVBAsMC0RldmVsb3BtZW50MRgwFgYDVQQDDA93d3cud29sZnNz\n\
bC5jb20xHzAdBgkqhkiG9w0BCQEWEGluZm9Ad29sZnNzbC5jb20wHhcNMjQxMjE4\n\
MjEyNTMwWhcNMjcwOTE0MjEyNTMwWjCBkDELMAkGA1UEBhMCVVMxEzARBgNVBAgM\n\
Cldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxETAPBgNVBAoMCEVsbGlwdGlj\n\
MQwwCgYDVQQLDANFQ0MxGDAWBgNVBAMMD3d3dy53b2xmc3NsLmNvbTEfMB0GCSqG\n\
SIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\n\
A0IABLszrEwnUErGSqUEwzzenzbbci3OlOor+ssgCTksFuhhAumvTdMCk5oxW5eS\n\
IX/wzxjakRECNIboIFgzC4A0idijgYkwgYYwHQYDVR0OBBYEFF1dJu+sfjb5m3YV\n\
K0olAiPvsokwMB8GA1UdIwQYMBaAFFaOmsPwQt4YuUVVbvmTz+rD86UhMAwGA1Ud\n\
EwEB/wQCMAAwDgYDVR0PAQH/BAQDAgOoMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBEG\n\
CWCGSAGG+EIBAQQEAwIGQDAKBggqhkjOPQQDAgNIADBFAiEAi4Kl0vbKhLqtLd42\n\
6SpN7ksgRrqrTtAQbuswtn7Yr4wCIAZ0QGqpMVT+IJ3GbSvfHapj2vyXUIeSae5j\n\
V7bs4un6\n\
-----END CERTIFICATE-----\n\
";

/* certs/ecc-key.pem */

static const char server_key[] =
"ASN1 OID: prime256v1\n\
-----BEGIN EC PARAMETERS-----\n\
BggqhkjOPQMBBw==\n\
-----END EC PARAMETERS-----\n\
-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIEW2aQJznGyFoThbcujox6zEA41TNQT6bCjcNI3hqAmMoAoGCCqGSM49\n\
AwEHoUQDQgAEuzOsTCdQSsZKpQTDPN6fNttyLc6U6iv6yyAJOSwW6GEC6a9N0wKT\n\
mjFbl5Ihf/DPGNqREQI0huggWDMLgDSJ2A==\n\
-----END EC PRIVATE KEY-----\n\
";

#endif /* SERVER_PRIME256V1 */

struct ca_cert {
    const char *pem;
    char *subject;
    unsigned long subjectHash;
    const int can_issue_admin_certs;
};

struct ca_cert ca_certs[] = {

    {
/* wolfssl/certs/ca-ecc384-cert.pem */
.pem =
"-----BEGIN CERTIFICATE-----\n\
MIIC0jCCAligAwIBAgIUTghnnSlhRz4qI4LNz8tTKrgCIlcwCgYIKoZIzj0EAwMw\n\
gZcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdT\n\
ZWF0dGxlMRAwDgYDVQQKDAd3b2xmU1NMMRQwEgYDVQQLDAtEZXZlbG9wbWVudDEY\n\
MBYGA1UEAwwPd3d3LndvbGZzc2wuY29tMR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdv\n\
bGZzc2wuY29tMB4XDTI0MTIxODIxMjUyOVoXDTI3MDkxNDIxMjUyOVowgZcxCzAJ\n\
BgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0dGxl\n\
MRAwDgYDVQQKDAd3b2xmU1NMMRQwEgYDVQQLDAtEZXZlbG9wbWVudDEYMBYGA1UE\n\
AwwPd3d3LndvbGZzc2wuY29tMR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdvbGZzc2wu\n\
Y29tMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7oLUOZqxJ4L01+rGvAMdTYNh9AOu\n\
fr3YWqW58I6ipdrOhztaq0QWnPWfYt32IM2cdjxAsT+XF99Z9s3ezUY1wO1eLki2\n\
ZpFxdLcMP7mat4O9kz9fUC1wP941JeGQO4bgo2MwYTAdBgNVHQ4EFgQUq+DDJkwY\n\
1HK70oSMnAoFkoASU1IwHwYDVR0jBBgwFoAUq+DDJkwY1HK70oSMnAoFkoASU1Iw\n\
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwMDaAAw\n\
ZQIwHT+SArJGVO6eDZADc2qrBFpB/vQb/daZzHps/VLaLk54/u95dBJeBJ0s5Oca\n\
TdMeAjEAtzToTGlw2/0aSMXcju8VyhPu+E8nX9I6agZ98zKndZcnbWDtop+ffmZD\n\
+RUdZV1J\n\
-----END CERTIFICATE-----\n\
",
.can_issue_admin_certs = 1

    },

    {
.pem =
/* wolfssl/certs/ca-cert.pem */
"-----BEGIN CERTIFICATE-----\n\
MIIE/zCCA+egAwIBAgIUa5twxvGjlGUZoQhY76eNK3qDwdowDQYJKoZIhvcNAQEL\n\
BQAwgZQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIDAdNb250YW5hMRAwDgYDVQQHDAdC\n\
b3plbWFuMREwDwYDVQQKDAhTYXd0b290aDETMBEGA1UECwwKQ29uc3VsdGluZzEY\n\
MBYGA1UEAwwPd3d3LndvbGZzc2wuY29tMR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdv\n\
bGZzc2wuY29tMB4XDTI0MTIxODIxMjUyOVoXDTI3MDkxNDIxMjUyOVowgZQxCzAJ\n\
BgNVBAYTAlVTMRAwDgYDVQQIDAdNb250YW5hMRAwDgYDVQQHDAdCb3plbWFuMREw\n\
DwYDVQQKDAhTYXd0b290aDETMBEGA1UECwwKQ29uc3VsdGluZzEYMBYGA1UEAwwP\n\
d3d3LndvbGZzc2wuY29tMR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdvbGZzc2wuY29t\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvwzKLRSyHoRCW804H0ry\n\
TXUQ8bY1n9/KfQOY06zeA2buKvHYsH1uB1QLEJghTYDLEiDnzE/eRX3Jcncy6sqQ\n\
u2lSEAMvqPOVxfGLYlYb72dvpBBBla0Km+OlwLDScHZQMFuo6AgsfO2nonqNOCkc\n\
rMft8nyVsJWCfUlcOM13Je+9gHVTlDw9ymNbnxW10x0TLxnRPNt2Osy4fcnlwtfa\n\
QG/YIdxzG0ItU5z+Gvx9q3o2P5jehHwFZ85qFDiHqfGMtWjLaH9xICv1oGP1Vi+j\n\
JtK3b7FaF9c4mQj+k1hv/sMTSQgWC6dNZwBSMWcjTpjtUUUduQTZC+zYKLNLve02\n\
eQIDAQABo4IBRTCCAUEwHQYDVR0OBBYEFCeOZxF0wyYdP+0zY7Ok2B0w5ejVMIHU\n\
BgNVHSMEgcwwgcmAFCeOZxF0wyYdP+0zY7Ok2B0w5ejVoYGapIGXMIGUMQswCQYD\n\
VQQGEwJVUzEQMA4GA1UECAwHTW9udGFuYTEQMA4GA1UEBwwHQm96ZW1hbjERMA8G\n\
A1UECgwIU2F3dG9vdGgxEzARBgNVBAsMCkNvbnN1bHRpbmcxGDAWBgNVBAMMD3d3\n\
dy53b2xmc3NsLmNvbTEfMB0GCSqGSIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbYIU\n\
a5twxvGjlGUZoQhY76eNK3qDwdowDAYDVR0TBAUwAwEB/zAcBgNVHREEFTATggtl\n\
eGFtcGxlLmNvbYcEfwAAATAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\n\
DQYJKoZIhvcNAQELBQADggEBAHc7PWZ0vJf+QBbmuqXV0YQIiWlPiA1Xqe+Mw5dS\n\
yL2Lokk7t/ddHtYUf7KAM9qgitPhL9W8M5/qWnIk5fi4S7PfYpA7qCHvJ0J1vGAC\n\
jjc1meujKPJlTP96+I7MI23lav4iWtmyT0fH4K6Y75Sstk9hgSmO4XksRvzpGsOW\n\
HxmTZC6fN3LF5JNOYV84jq7oORnml6iR1CN+HtLQU+zMrKAd0LfdsbcBLpbNhSfg\n\
50fiwcEA9pTfd+f6xu+KwHxnvP+gfJQ7fYZCrz2DMe4qO3vwLJ5v6cQHgSTaBXBN\n\
3QmunnK4IQ6MsquqTEkQ93b5tQ1sINPfegYyjSkfKB2NJjM=\n\
-----END CERTIFICATE-----\n\
",

.can_issue_admin_certs = 0

    }
};

/* implement a pre-allocated circular log that maintains wolfsentry_time_t-sized
 * alignment of the start of each message.
 */

struct circlog_message {
    wolfsentry_time_t when;
    uint16_t len;
    char msg_buf[];
};

static char *circlog = NULL;
static size_t circlog_size = 0, circlog_head = 0, circlog_tail = 0, circlog_nents = 0;

wolfsentry_errcode_t circlog_init(size_t size) {
    if (circlog != NULL) {
        if (size == circlog_size)
            WOLFSENTRY_ERROR_RETURN(ALREADY);
        else
            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    }
    circlog = (char *)malloc(size);
    if (circlog == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    circlog_size = size;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t circlog_shutdown(void) {
    if (circlog == NULL)
        WOLFSENTRY_ERROR_RETURN(ALREADY);
    free(circlog);
    circlog_size = circlog_head = circlog_tail = circlog_nents = 0;
    WOLFSENTRY_RETURN_OK;
}

static inline size_t circlog_ent_size_from_msg_len(size_t msg_len) {
    return ((sizeof(struct circlog_message) + msg_len) | (sizeof(wolfsentry_time_t) - 1)) + 1;
}

static inline size_t circlog_ent_size_from_ent(struct circlog_message *msg) {
    return ((sizeof *msg + (size_t)msg->len) | (sizeof(wolfsentry_time_t) - 1)) + 1;
}

wolfsentry_errcode_t circlog_dequeue_one(struct circlog_message **msg) {
    struct circlog_message *old_msg;

again:
    if (circlog_head == circlog_tail) {
        if (circlog_head)
            circlog_head = circlog_tail = 0;
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    }
    old_msg = (struct circlog_message *)(void *)(circlog + circlog_head);
    if (old_msg->len == 0) {
        circlog_head = 0;
        goto again;
    }
    --circlog_nents;
    circlog_head += circlog_ent_size_from_ent(old_msg);
    if (circlog_head + circlog_ent_size_from_msg_len(0) >= circlog_size)
        circlog_head = 0;
    if (msg)
        *msg = old_msg;
    WOLFSENTRY_RETURN_OK;
}

/* note msg_buf is not initialized -- undefined contents until caller writes to it. */
wolfsentry_errcode_t circlog_enqueue_one(size_t msg_len, char **msg_buf) {
    size_t new_ent_size;
    size_t new_msg_start;
    wolfsentry_errcode_t ret;
    struct circlog_message *new_ent;

    if ((msg_len == 0) || (msg_len > MAX_UINT_OF(new_ent->len)))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    new_ent_size = circlog_ent_size_from_msg_len(msg_len);
    if (new_ent_size > circlog_size)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (circlog_tail + new_ent_size > circlog_size) {
        /* if the new ent will wrap, old ents need to be cleared out to the end, and a skip ent inserted. */
        if (circlog_tail + circlog_ent_size_from_msg_len(0) < circlog_size) {
            while (circlog_head > circlog_tail) {
                ret = circlog_dequeue_one(NULL);
                if (ret < 0) {
                    if (WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND))
                        break;
                    return ret;
                }
            }
            /* write a skip ent. */
            new_ent = (struct circlog_message *)(void *)(circlog + circlog_tail);
            new_ent->when = 0;
            new_ent->len = 0;
        }
        new_msg_start = 0;
    } else {
        new_msg_start = circlog_tail;
    }

    /* discard any ents that would be overwritten.
     *
     * note that <= (versus <) in the 2nd inequality is needed because without
     * the =, circlog_tail could be incremented below to equal circlog_head,
     * which is defined to be an empty queue.
     */
    while ((circlog_head > new_msg_start) &&
           (circlog_head <= new_msg_start + new_ent_size))
    {
        ret = circlog_dequeue_one(NULL);
        if (ret < 0)
            return ret;
    }

    new_ent = (struct circlog_message *)(void *)(circlog + new_msg_start);
    ret = wolfsentry_time_now_plus_delta(global_wolfsentry, 0 /* td */, &new_ent->when);
    new_ent->len = (uint16_t)msg_len;
    *msg_buf = new_ent->msg_buf;
    circlog_tail = new_msg_start + new_ent_size;
    ++circlog_nents;

    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t circlog_iterate(struct circlog_message **msg) {
    size_t next_msg_offset;
    struct circlog_message *next_msg;

    if (*msg) {
        next_msg_offset = (size_t)((ptrdiff_t)(*msg) - (ptrdiff_t)circlog) + circlog_ent_size_from_ent(*msg);
        if (next_msg_offset + circlog_ent_size_from_msg_len(0) >= circlog_size)
            next_msg_offset = 0;
        else {
            if (next_msg_offset == circlog_tail) {
                *msg = NULL;
                WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
            }
            next_msg = (struct circlog_message *)(void *)(circlog + next_msg_offset);
            if (next_msg->len == 0) /* found a skip ent. */
                next_msg_offset = 0;
        }
        next_msg = (struct circlog_message *)(void *)(circlog + next_msg_offset);
    } else
        next_msg_offset = circlog_head;

    if (next_msg_offset == circlog_tail) {
        *msg = NULL;
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    }

    *msg = (struct circlog_message *)(void *)(circlog + next_msg_offset);
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t circlog_format_one(struct circlog_message *msg, char **out, size_t *out_space) {
    if (out == NULL) {
        *out_space = msg->len;
        WOLFSENTRY_RETURN_OK;
    }

    if ((size_t)msg->len + 1 >= *out_space)
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    memcpy(*out, msg->msg_buf, msg->len);
    *out += msg->len;
    *out_space -= msg->len;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t circlog_reset(void) {
    if (circlog == NULL)
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);
    circlog_head = circlog_tail = circlog_nents = 0;
    WOLFSENTRY_RETURN_OK;
}


struct log_server_data {
    struct ca_cert *issuer_cert;
    int error_code;
};


static int myVerifyCheck(int preverify, WOLFSSL_X509_STORE_CTX* store) {
    struct log_server_data *app_data = NULL;
    const char* issuerName = NULL;
    unsigned long issuerHash = 0;
#if defined(DEBUG_TLS) && defined(OPENSSL_EXTRA)
    const char *subjectCN;
    const char* subjectName;
    unsigned long subjectHash = 0;
#endif
    struct ca_cert *ca_certs_i;

    /* check incoming validation of cert 1=okay, 0=failed */
    if (preverify != 1) {
        fprintf(stderr, "ERROR: %s L%d pre-verify check failed! %d\n",
            __FILE__,__LINE__, preverify);
        return preverify;
    }

    if (store == NULL) {
        fprintf(stderr, "ERROR: %s L%d null store!\n", __FILE__,__LINE__);
        return WOLFSSL_FAILURE;
    }

    app_data = (struct log_server_data *)store->userCtx;
    if (app_data == NULL) {
        fprintf(stderr, "ERROR: %s L%d null store->userCtx!\n", __FILE__,__LINE__);
        return WOLFSSL_FAILURE;
    }

    app_data->error_code = NO_PEER_CERT; /* default error code */

    if (store->current_cert == NULL) {
        fprintf(stderr, "ERROR: %s L%d null store->current_cert\n", __FILE__,__LINE__);
        return WOLFSSL_FAILURE;
    }

    if (store->error != 0) {
#ifdef DEBUG_TLS
        fprintf(stderr, "%s L%d depth=%d ->error=%d (%s)\n", __FILE__,__LINE__,
            store->error_depth,store->error,
                wolfSSL_ERR_reason_error_string(store->error));
#endif
        app_data->error_code = store->error;
        return WOLFSSL_FAILURE;
    }

    if (store->error_depth != 0) /* "0=peer, >1 intermediates" */ {
        app_data->error_code = 0;
        return WOLFSSL_SUCCESS;
    }

#ifdef OPENSSL_EXTRA
    issuerHash = wolfSSL_X509_issuer_name_hash(store->current_cert);
    issuerName = wolfSSL_X509_NAME_oneline(
            wolfSSL_X509_get_issuer_name(store->current_cert), 0, 0);

    #ifdef DEBUG_TLS
    subjectCN = wolfSSL_X509_get_subjectCN(store->current_cert);
    subjectHash = wolfSSL_X509_subject_name_hash(store->current_cert);
    subjectName = wolfSSL_X509_NAME_oneline(
            wolfSSL_X509_get_subject_name(store->current_cert), 0, 0);
    fprintf(stderr, "CN=%s subjectName->name=\"%s\" subject_hash=%lu\n",
        subjectCN, subjectName, subjectHash);
    fprintf(stderr, "issuerName->name=\"%s\" issuer_hash=%lu\n", issuerName, issuerHash);
    #endif
#endif

    for (ca_certs_i = ca_certs;
         ca_certs_i < &ca_certs[sizeof(ca_certs) / sizeof(ca_certs[0])];
         ++ca_certs_i)
    {
        if ( /* (issuerHash == ca_certs_i->subjectHash) && */
                (!strncmp(issuerName, ca_certs_i->subject, WC_ASN_NAME_MAX))) {
            app_data->issuer_cert = ca_certs_i;
            break;
        }
    }
    if (app_data->issuer_cert == NULL) {
        fprintf(stderr, "ERROR: %s L%d app_data->issuer_cert NULL.\n",__FILE__,__LINE__);
        return WOLFSSL_FAILURE;
    }

    app_data->error_code = 0;

    return WOLFSSL_SUCCESS;
}

/* matches logic in wolfSSL_X509_issuer_name_hash() and MakeWordFromHash(). */
static unsigned long cert_subject_name_hash(DecodedCert *cert) {
    unsigned long ret = 0;
    int retHash = NOT_COMPILED_IN;
    byte digest[WC_MAX_DIGEST_SIZE];

    if (cert == NULL) {
        return ret;
    }

#ifndef NO_SHA
    retHash = wc_ShaHash((const byte*)cert->subject,
                         (word32)strnlen(cert->subject, WC_ASN_NAME_MAX) + 1, digest);
#elif !defined(NO_SHA256)
    retHash = wc_Sha256Hash((const byte*)cert->subject,
                            (word32)strnlen(cert->subject, WC_ASN_NAME_MAX) + 1, digest);
#endif
    if (retHash == 0) {
        ret = ((word32)digest[0] << 24) | ((word32)digest[1] << 16) |
            ((word32)digest[2] <<  8) |  (word32)digest[3];
    }
    return ret;
}

struct io_ctx {
    int timeout;
};

#ifndef NO_IO_TIMEOUTS

#ifdef HAVE_POLL
static int read_timed(WOLFSSL* ssl, char *buf, int sz, const struct io_ctx *ctx) {
    int ret;
        struct pollfd pollfd;

        pollfd.fd = wolfSSL_get_fd(ssl);
        if (pollfd.fd < 0) {
#if defined(DEBUG_HTTP_IO) || defined(DEBUG_TLS)
            fprintf(stderr,"ERROR: %s L%d wolfSSL_get_fd(): %s\n",
                    __FILE__, __LINE__, wolfSSL_ERR_reason_error_string(pollfd.fd));
#endif
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        pollfd.events = POLLIN;
        pollfd.revents = 0;
        ret = poll(&pollfd, 1, ctx->timeout);
        if (ret < 0) {
#ifdef DEBUG_HTTP_IO
            fprintf(stderr,"ERROR: %s L%d poll(): %s\n",
                __FILE__, __LINE__, strerror(errno));
#endif
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        if (pollfd.revents & (POLLERR|POLLHUP|POLLNVAL)) {
#ifdef DEBUG_HTTP_IO
            fprintf(stderr,"ERROR: %s L%d pollfd.revents error bits: 0%o\n",
                __FILE__, __LINE__, pollfd.revents);
#endif
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        if (! (pollfd.revents & POLLIN)) {
#ifdef DEBUG_HTTP_IO
            fprintf(stderr,"ERROR: %s L%d poll() returned without POLLIN set: 0%o\n",
                __FILE__, __LINE__, pollfd.revents);
#endif
            return WOLFSSL_CBIO_ERR_TIMEOUT /* WOLFSSL_CBIO_ERR_WANT_READ */;
        }
#ifdef DEBUG_HTTP_IO
        {
            int bytes_available = -1;
            (void)ioctl(pollfd.fd,FIONREAD,&bytes_available);
            fprintf(stderr, "read left poll() with .revents=0%o, bytes_available=%d\n",
                pollfd.revents, bytes_available);
        }
#endif

        ret = (int)read(pollfd.fd, buf, (size_t)sz);
        if (ret <= 0)
            return WOLFSSL_CBIO_ERR_GENERAL;
        else
            return ret;
}

static int write_timed(WOLFSSL* ssl, char *buf, int sz, const struct io_ctx *ctx) {
    ssize_t total_written = 0;
    struct pollfd pollfd;

    if (sz == 0)
        return 0;

    pollfd.fd = wolfSSL_get_fd(ssl);
    if (pollfd.fd < 0) {
#if defined(DEBUG_HTTP_IO) || defined(DEBUG_TLS)
        fprintf(stderr,"ERROR: %s L%d wolfSSL_get_fd() error: %s\n",
                __FILE__, __LINE__, wolfSSL_ERR_reason_error_string(pollfd.fd));
#endif
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    for (;;) {
        int ret;
        ssize_t this_written;
        pollfd.events = POLLOUT;
        pollfd.revents = 0;
        ret = poll(&pollfd, 1, ctx->timeout);
        if (ret < 0) {
#ifdef DEBUG_HTTP_IO
            fprintf(stderr,"ERROR: %s L%d poll(): %s\n",
                __FILE__, __LINE__, strerror(errno));
#endif
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        if (pollfd.revents & (POLLERR|POLLHUP|POLLNVAL)) {
#ifdef DEBUG_HTTP_IO
            fprintf(stderr,"ERROR: %s L%d pollfd.revents error bits: 0%o\n",
                __FILE__, __LINE__, pollfd.revents);
#endif
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        if (! (pollfd.revents & POLLOUT)) {
#ifdef DEBUG_HTTP_IO
            fprintf(stderr,"ERROR: %s L%d poll() returned without POLLOUT set: 0%o\n",
                __FILE__, __LINE__, pollfd.revents);
#endif
            return WOLFSSL_CBIO_ERR_TIMEOUT;
        }
#ifdef DEBUG_HTTP_IO
        fprintf(stderr, "write left poll() with .revents=0%o\n",pollfd.revents);
#endif

        this_written = send(pollfd.fd, buf + total_written,
                            (size_t)(sz - total_written), MSG_DONTWAIT);
        if (this_written <= 0)
            return WOLFSSL_CBIO_ERR_GENERAL;
        total_written += this_written;
#ifdef DEBUG_HTTP_IO
        fprintf(stderr, "wrote %zd bytes, %zu to go\n",
            this_written, (size_t)sz - total_written);
#endif
        if (total_written == sz)
            break;
    }
    return (int)total_written;
}
#endif /* HAVE_POLL */

#ifdef HAVE_SELECT
static int read_timed(WOLFSSL* ssl, char *buf, int sz, const struct io_ctx *ctx) {
    int ret;
    fd_set readfds, writefds, exceptfds;
    struct timeval timeout;
    int fd;

    fd = wolfSSL_get_fd(ssl);
    if (fd < 0) {
#if defined(DEBUG_HTTP_IO) || defined(DEBUG_TLS)
        fprintf(stderr,"ERROR: %s L%d wolfSSL_get_fd(): %s\n",
                __FILE__, __LINE__, wolfSSL_ERR_reason_error_string(fd));
#endif
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);

    FD_SET(fd, &readfds);
    FD_SET(fd, &exceptfds);

    timeout.tv_sec = ctx->timeout / 1000;
    timeout.tv_usec = (ctx->timeout % 1000) * 1000;

    ret = select(fd+1, &readfds, &writefds, &exceptfds, &timeout);
    if (ret < 0) {
#ifdef DEBUG_HTTP_IO
        fprintf(stderr,"ERROR: %s L%d select(): %s\n",
            __FILE__, __LINE__, strerror(errno));
#endif
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    if (FD_ISSET(fd, &exceptfds)) {
#ifdef DEBUG_HTTP_IO
        fprintf(stderr,"ERROR: %s L%d fd exception\n", __FILE__, __LINE__);
#endif
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    if (! FD_ISSET(fd, &readfds)) {
#ifdef DEBUG_HTTP_IO
        fprintf(stderr,"ERROR: %s L%d poll() returned with fd not readable\n",
            __FILE__, __LINE__);
#endif
        return WOLFSSL_CBIO_ERR_TIMEOUT /* WOLFSSL_CBIO_ERR_WANT_READ */;
    }

    ret = (int)read(fd, buf, sz);
    if (ret <= 0)
        return WOLFSSL_CBIO_ERR_GENERAL;
    else
        return ret;
}

static int write_timed(WOLFSSL* ssl, char *buf, int sz, const struct io_ctx *ctx) {
    ssize_t total_written = 0;
    if (sz == 0)
        return 0;
    fd_set readfds, writefds, exceptfds;
    struct timeval timeout;
    int fd;

    fd = wolfSSL_get_fd(ssl);
    if (fd < 0) {
#if defined(DEBUG_HTTP_IO) || defined(DEBUG_TLS)
        fprintf(stderr,"ERROR: %s L%d wolfSSL_get_fd(): %s\n",
                __FILE__, __LINE__, wolfSSL_ERR_reason_error_string(fd));
#endif
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    for (;;) {
        int ret;
        ssize_t this_written;

        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);

        FD_SET(fd, &writefds);
        FD_SET(fd, &exceptfds);

        timeout.tv_sec = ctx->timeout / 1000;
        timeout.tv_usec = (ctx->timeout % 1000) * 1000;

        ret = select(fd+1, &readfds, &writefds, &exceptfds, &timeout);
        if (ret < 0) {
#ifdef DEBUG_HTTP_IO
            fprintf(stderr,"ERROR: %s L%d select(): %s\n",
                __FILE__, __LINE__, strerror(errno));
#endif
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }

        if (FD_ISSET(fd, &exceptfds)) {
#ifdef DEBUG_HTTP_IO
            fprintf(stderr,"ERROR: %s L%d fd exception\n", __FILE__, __LINE__);
#endif
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        if (! FD_ISSET(fd, &writefds)) {
#ifdef DEBUG_HTTP_IO
            fprintf(stderr,"ERROR: %s L%d poll() returned with fd not writable\n",
                __FILE__, __LINE__);
#endif
            return WOLFSSL_CBIO_ERR_TIMEOUT /* WOLFSSL_CBIO_ERR_WANT_READ */;
        }

        this_written = send(fd, buf + total_written, sz - total_written,
            MSG_DONTWAIT);
        if (this_written <= 0)
            return WOLFSSL_CBIO_ERR_GENERAL;
        total_written += this_written;
#ifdef DEBUG_HTTP_IO
        fprintf(stderr, "wrote %zd bytes, %zu to go\n",
            this_written, (size_t)sz - total_written);
#endif
        if (total_written == sz)
            break;
    }
    return (int)total_written;
}
#endif /* HAVE_SELECT */

#else /* NO_IO_TIMEOUTS */

static int read_timed(WOLFSSL* ssl, char *buf, int sz, const struct io_ctx *ctx) {
    int ret;
    int fd = wolfSSL_get_fd(ssl);

    (void)ctx;

    if (fd < 0) {
#if defined(DEBUG_HTTP_IO) || defined(DEBUG_TLS)
        fprintf(stderr,"ERROR: %s L%d wolfSSL_get_fd(): %s\n",
            __FILE__, __LINE__, wolfSSL_ERR_reason_error_string(fd));
#endif
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    ret = (int)read(fd, buf, sz);
    if (ret <= 0)
        return WOLFSSL_CBIO_ERR_GENERAL;
    else
        return ret;
}

static int write_timed(WOLFSSL* ssl, char *buf, int sz, const struct io_ctx *ctx) {
    ssize_t total_written = 0;
    if (sz == 0)
        return 0;
    int fd;

    (void)ctx;

    fd = wolfSSL_get_fd(ssl);
    if (fd < 0) {
#if defined(DEBUG_HTTP_IO) || defined(DEBUG_TLS)
        fprintf(stderr,"ERROR: %s L%d wolfSSL_get_fd(): %s\n",
            __FILE__, __LINE__, wolfSSL_ERR_reason_error_string(fd));
#endif
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    for (;;) {
        ssize_t this_written;

        this_written = send(fd, buf + total_written, sz - total_written, 0 /* flags */);
        if (this_written <= 0)
            return WOLFSSL_CBIO_ERR_GENERAL;
        total_written += this_written;
#ifdef DEBUG_HTTP_IO
        fprintf(stderr, "wrote %zd bytes, %zu to go\n",
            this_written, (size_t)sz - total_written);
#endif
        if (total_written == sz)
            break;
    }
    return (int)total_written;
}

#endif /* NO_IO_TIMEOUTS */

/* Init the TCP listener */
static int ssl_init(void)
{
    int ret;
    struct ca_cert *ca_certs_i;

    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    if (log_server_data_index < 0) {
        log_server_data_index = wolfSSL_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_X509,
            NULL, NULL, NULL, NULL);
        if (log_server_data_index < 0) {
            fprintf(stderr,
                "ERROR: wolfSSL_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_X509, ...) returned %d\n",
                log_server_data_index);
            return -1;
        }
    }

    /* Create and initialize WOLFSSL_CTX */
    if ((wolf_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return -1;
    }

    wolfSSL_CTX_SetIORecv(wolf_ctx, (CallbackIORecv)read_timed);
    wolfSSL_CTX_SetIOSend(wolf_ctx, (CallbackIOSend)write_timed);

    /* Load server certificates into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_use_certificate_buffer(wolf_ctx, (const unsigned char *)server_cert,
                strlen(server_cert), WOLFSSL_FILETYPE_PEM))
        != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load certificate buffer.\n");
        return -1;
    }

    /* Load server key into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_use_PrivateKey_buffer(wolf_ctx, (const unsigned char *)server_key,
                strlen(server_key), WOLFSSL_FILETYPE_PEM))
        != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: %s L%d: failed to load key buffer: %s\n",
            __FILE__, __LINE__, wolfSSL_ERR_reason_error_string(ret));
        return -1;
    }

    for (ca_certs_i = ca_certs;
        ca_certs_i < &ca_certs[sizeof(ca_certs) / sizeof(ca_certs[0])];
        ++ca_certs_i)
    {
        if ((ret = wolfSSL_CTX_load_verify_buffer(wolf_ctx,
            (const unsigned char *)ca_certs_i->pem, (long)strlen(ca_certs_i->pem),
                WOLFSSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS)
        {
            fprintf(stderr, "ERROR: %s L%d: failed to load verify buffer: %s\n",
                __FILE__, __LINE__, wolfSSL_ERR_reason_error_string(ret));
            return -1;
        }

        {
            DerBuffer    *der;
            DecodedCert cert;
            int keyFormat = 0;

            if ((ret = wc_PemToDer((const unsigned char *)ca_certs_i->pem,
                (long)strlen(ca_certs_i->pem), CA_TYPE, &der,
                NULL /* heap */, NULL /* EncryptedInfo */, &keyFormat))
                != 0)
            {
                fprintf(stderr, "ERROR: %s L%d: wc_PemToDer() failed: %s\n",
                    __FILE__, __LINE__, wolfSSL_ERR_reason_error_string(ret));
                return -1;
            }

            wc_InitDecodedCert(&cert, der->buffer, der->length, NULL /* heap */);
            if ((ret = wc_ParseCert(&cert, CA_TYPE, NO_VERIFY, NULL /* cm */))
                != 0)
            {
                fprintf(stderr, "ERROR: %s L%d: wc_ParseCert() failed: %s\n",
                    __FILE__, __LINE__, wolfSSL_ERR_reason_error_string(ret));
                free(der);
                return -1;
            }

            /* make sure the subject is unique */
            for (struct ca_cert *ca_certs_j = ca_certs; ca_certs_j < ca_certs_i; ++ca_certs_j) {
                if (strncmp(ca_certs_j->subject, cert.subject, WC_ASN_NAME_MAX) == 0) {
                    fprintf(stderr, "ERROR: %s L%d CA subject \"%s\" repeats at array offset %zu.\n",
                        __FILE__,__LINE__,ca_certs_j->subject,
                        ((ptrdiff_t)ca_certs_i - (ptrdiff_t)ca_certs) /
                            (ptrdiff_t)sizeof ca_certs[0]);
                    wc_FreeDecodedCert(&cert);
                    free(der);
                    return -1;
                }
            }

            ca_certs_i->subject = strndup(cert.subject, WC_ASN_NAME_MAX);
            ca_certs_i->subjectHash = cert_subject_name_hash(&cert);

            wc_FreeDecodedCert(&cert);
            free(der);
        }
    }

    wolfSSL_CTX_set_verify(wolf_ctx,
        (WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT),
        myVerifyCheck);

    return 0;
}


#if defined(BUILD_FOR_LINUX) || defined(BUILD_FOR_MACOSX)

static int inbound_fd = -1;

static int log_server_init(void) {
    int ret;

    const char *admin_listen_addr;
    int admin_listen_addr_len;
    struct wolfsentry_kv_pair_internal *admin_listen_addr_record = NULL;

    struct sockaddr_in inbound_sa;
    uint64_t admin_listen_port;
    int pton_ret;

    ret = wolfsentry_user_value_get_uint(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(global_wolfsentry, global_thread),
        "admin-listen-port",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        &admin_listen_port);

    if (ret < 0) {
        fprintf(stderr, "ERROR: wolfsentry_user_value_get_uint(\"admin-listen-port\") returned "
                WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
        exit(1);
    }

    if (admin_listen_port > MAX_UINT_OF(inbound_sa.sin_port)) {
        fprintf(stderr, "ERROR: \"admin-listen-port\" value %lu is too big.\n", admin_listen_port);
        exit(1);
    }

    ret = wolfsentry_user_value_get_string(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(global_wolfsentry, global_thread),
        "admin-listen-addr",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        &admin_listen_addr,
        &admin_listen_addr_len,
        &admin_listen_addr_record);

    if (ret < 0) {
        fprintf(stderr, "ERROR: wolfsentry_user_value_get_string(\"admin-listen-addr\") returned "
                WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
        exit(1);
    }

    pton_ret = inet_pton(AF_INET, admin_listen_addr, &inbound_sa.sin_addr);

    ret = wolfsentry_user_value_release_record(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(global_wolfsentry, global_thread), &admin_listen_addr_record);

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

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("signal(SIGPIPE, SIG_IGN)");
        exit(1);
    }

    inbound_sa.sin_family = AF_INET;
    inbound_sa.sin_port = htons((wolfsentry_port_t)admin_listen_port);

    inbound_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (inbound_fd < 0) {
        perror("socket(AF_INET, SOCK_STREAM, IPPROTO_TCP");
        exit(1);
    }

    {
        int optval = 1;
        if (setsockopt(inbound_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&optval,(int)sizeof optval)<0) {
            perror("setsockopt(..., SO_REUSEADDR, ...)");
            exit(1);
        }
    }

    if (bind(inbound_fd, (const struct sockaddr *)&inbound_sa, sizeof inbound_sa) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(inbound_fd, 5) < 0) {
        perror("listen");
        exit(1);
    }

    return 0;
}

static int http_write_header(WOLFSSL *ssl, char *http_buf, size_t http_buf_size, int http_code, ssize_t content_length, const char *content_type, const char *body) {
    time_t now = time(NULL);
    struct tm now_tm;
    char now_formatted[32];
    size_t now_formatted_len;
    int i;
    const char *http_code_description = NULL, *http_code_explanation = NULL;
    int resp_len, ret;

    static const struct { int code; const char *description; const char *explanation; } http_codes[] = {
        { 200, "OK", "Operation succeeded\n" },
        { 403, "Forbidden", "Authorization denied.\n" },
        { 404, "Not Found", "Requested path not recognized.\n" },
        { 500, "Internal Server Error", "Internal server error.\n" }
    };

    for (i = 0; i < (int)(sizeof http_codes / sizeof http_codes[0]); ++i) {
        if (http_codes[i].code == http_code) {
            http_code_description = http_codes[i].description;
            http_code_explanation = http_codes[i].explanation;
            break;
        }
    }
    if (http_code_description == NULL)
        http_code_description = "Unknown code";

    if (gmtime_r(&now, &now_tm) == NULL) {
        fprintf(stderr, "ERROR: gmtime_r failed\n");
        return -1;
    }

    now_formatted_len = strftime(now_formatted, sizeof now_formatted, "%a, %d %h %Y %H:%M:%S %Z", &now_tm);
    if (now_formatted_len == 0) {
        fprintf(stderr, "ERROR: strftime failed\n");
        return -1;
    }

    if ((content_length < 0) && body)
        content_length = (ssize_t)strlen(body);

    if ((content_length == 0) && http_code_explanation) {
        content_type = "text/plain";
        content_length = (ssize_t)strlen(http_code_explanation);
        body = http_code_explanation;
    } else if (! body)
        body = "";

    resp_len = snprintf(http_buf, http_buf_size, "HTTP/1.0 %d %s\r\n" \
        "Date: %.*s\r\nServer: LogServer\r\nContent-Length: %zu%s%s\r\n\r\n%s",
                        http_code,
                        http_code_description,
                        (int)now_formatted_len,
                        now_formatted,
                        content_length,
                        content_type ? "\r\nContent-Type: " : "",
                        content_type ? content_type : "",
                        body);
    if (resp_len > (int)http_buf_size) {
        fprintf(stderr, "ERROR: overrun averted while formatting header, " \
            "http_buf_size = %zu, needed = %d\n", http_buf_size, resp_len);
        return -1;
    }
    if ((ret = wolfSSL_write(ssl, http_buf, resp_len)) != resp_len) {
        fprintf(stderr, "ERROR: failed to write: %s\n",
            wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl, ret)));
        return -1;
    }
    return 0;
}

#ifndef NO_FILESYSTEM
/* reads file size, allocates buffer, reads into buffer, returns buffer */
#include <stdio.h>
static int load_file(const char* fname, unsigned char** buf, size_t* bufLen)
{
    int ret;
    long int fileSz;
    FILE* lFile;

    if (fname == NULL || buf == NULL || bufLen == NULL) {
        return -1;
    }

    /* set defaults */
    *buf = NULL;
    *bufLen = 0;

    /* open file (read-only binary) */
    lFile = fopen(fname, "rb");
    if (!lFile) {
        fprintf(stderr, "ERROR: while loading %s: %s\n", fname, strerror(errno));
        return -1;
    }

    fseek(lFile, 0, SEEK_END);
    fileSz = (int)ftell(lFile);
    rewind(lFile);
    if (fileSz  > 0) {
        *bufLen = (size_t)fileSz;
        *buf = (unsigned char*)malloc(*bufLen);
        if (*buf == NULL) {
            ret = MEMORY_E;
            fprintf(stderr,
                    "ERROR: while allocating %lu bytes: %s\n", (unsigned long)*bufLen, strerror(errno));
        }
        else {
            size_t readLen = fread(*buf, *bufLen, 1, lFile);

            /* check response code */
            ret = (readLen > 0) ? 0 : -1;
        }
    }
    else {
        ret = -1;
    }
    fclose(lFile);

    return ret;
}
#else
    /* for wolfsentry_config_data */
    #include "../notify-config.h"
#endif

static volatile int running = 0;
static int peer_fd = -1;
static void handle_interrupt(int sig) {
    (void)sig;
    if (running)
        running = 0;
    if (inbound_fd > 0) {
        (void)close(inbound_fd);
        inbound_fd = -1;
    }
    if (peer_fd > 0) {
        (void)close(peer_fd);
        peer_fd = -1;
    }
}

int main(int argc, char **argv) {
    wolfsentry_errcode_t ret;
    char *http_buf = NULL;
    size_t http_buf_size = 0, http_buf_len;
    static const struct io_ctx io_ctx = { 1000 }; /* timeout = 1 second */
    int i;
    const char *wolfsentry_configfile = "../notify-config.json";
    uint64_t circlog_size_uint64;
#ifndef NO_FILESYSTEM
    unsigned char* wolfsentry_config_data = NULL;
    size_t wolfsentry_config_data_sz = 0;
#endif
    int notnormal = 0;
    WOLFSSL *ssl = NULL;
    struct log_server_data *app_data = NULL;
    int handshake_done = 0, transaction_successful = 0;

    http_buf_size = HTTP_BUF_SZ;
    http_buf = (char *)malloc(http_buf_size);
    if (http_buf == NULL) {
        perror("malloc");
        exit(1);
    }

#ifdef DEBUG_TLS
    fprintf(stderr, "log_server SSL init\n");
#endif
    if (ssl_init() < 0)
        exit(1);

#ifdef DEBUG_HTTP
    fprintf(stderr, "Sentry init\n");
#endif

    ret = wolfsentry_user_source_string_set(WOLFSENTRY_SOURCE_ID, __FILE__);
    if (ret < 0) {
        fprintf(stderr, "ERROR: wolfsentry_user_source_string_set() failed: " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        exit(1);
    }

    /* load configuration */
    for (i=1; i<argc; i+=2) {
        if (argc < i+2) {
            fprintf(stderr,"ERROR: %s: missing argument to \"%s\"\n", argv[0], argv[i]);
            exit(1);
        }
        if (! strcmp(argv[i],"--config")) {
            wolfsentry_configfile = argv[i+1];
        }
        else if (! strcmp(argv[i],"--kv-string")) {
        }
        else if (! strcmp(argv[i],"--kv-int")) {
        }
        else if (! strcmp(argv[i],"--greenlist")) {
        }
        else if (! strcmp(argv[i],"--redlist")) {
        }
        else {
            fprintf(stderr,"ERROR: %s: unrecognized argument \"%s\"\n",argv[0],argv[i]);
            exit(1);
        }
    }

#ifndef NO_FILESYSTEM
    printf("Loading configuration file %s\n", wolfsentry_configfile);
    if (load_file(wolfsentry_configfile, &wolfsentry_config_data, &wolfsentry_config_data_sz) != 0) {
        fprintf(stderr, "ERROR: while loading configuration file %s\n", wolfsentry_configfile);
        exit(1);
    }
    (void)wolfsentry_config_data_sz;
#else
    printf("Loading configuration from test-config.h\n");
#endif

    if (sentry_init(wolf_ctx, NULL /* hpi */, wolfsentry_config_data) < 0) {
    #ifndef NO_FILESYSTEM
        free(wolfsentry_config_data);
    #endif
        exit(1);
    }
#ifndef NO_FILESYSTEM
    free(wolfsentry_config_data);
    wolfsentry_config_data = NULL;
#endif

    /* parse other arguments */
    for (i=1; i<argc; i+=2) {
        if (argc < i+2) {
            fprintf(stderr,"ERROR: %s: missing argument to \"%s\"\n",argv[0],argv[i]);
            exit(1);
        }

        if (! strcmp(argv[i],"--kv-string")) {
            char *cp = strchr(argv[i+1], '=');
            if (cp == NULL) {
                fprintf(stderr,"ERROR: %s: missing '=' in argument to %s\n",argv[0],argv[i]);
                exit(1);
            }
            fprintf(stderr, "\tOverride string assignment loaded: %s\n", argv[i+1]);
            ret = wolfsentry_user_value_store_string(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(global_wolfsentry, global_thread), argv[i+1],
                (int)(cp - argv[i+1]), cp + 1, WOLFSENTRY_LENGTH_NULL_TERMINATED, 1 /* overwrite_p */);
            if (ret < 0) {
                fprintf(stderr, "ERROR: wolfsentry_user_value_store_string(): " \
                    WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
                exit(1);
            }
        }
        else if (! strcmp(argv[i],"--kv-int")) {
            char *cp = strchr(argv[i+1], '=');
            uint64_t the_int;
            char *end_of_the_int;
            if (cp == NULL) {
                fprintf(stderr,"ERROR: %s: missing '=' in argument to %s\n",argv[0],argv[i]);
                exit(1);
            }
            the_int = strtoul(cp+1, &end_of_the_int, 0);
            if ((*end_of_the_int != 0) || (end_of_the_int == cp+1)) {
                fprintf(stderr,"ERROR: %s: bad numeric argument to %s: \"%s\"\n",argv[0],cp+1,argv[i]);
                exit(1);
            }
            fprintf(stderr, "\tOverride int assignment loaded: %s (%llu)\n", argv[i+1], (unsigned long long int)the_int);
            ret = wolfsentry_user_value_store_uint(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(global_wolfsentry, global_thread), argv[i+1], (int)(cp - argv[i+1]), the_int, 1 /* overwrite_p */);
            if (ret < 0) {
                fprintf(stderr, "ERROR: wolfsentry_user_value_store_string(): " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
                exit(1);
            }
        }
        else if (! strcmp(argv[i],"--greenlist")) {
            char *cp = strchr(argv[i+1], '/');
            unsigned char json_buf[512];
            int json_len;
            char err_buf[1024];
            if (cp == NULL) {
                fprintf(stderr,"ERROR: %s: missing '/' (prefix length introducer) in argument to %s\n",argv[0],argv[i]);
                exit(1);
            }
            json_len = snprintf((char *)json_buf, sizeof(json_buf),
                "{\n"
                "  \"wolfsentry-config-version\" : 1,\n"
                "  \"static-routes-insert\" : [\n"
                "    {\n"
                "       \"parent-event\" : \"static-route-parent\",\n"
                "       \"direction-in\" : true,\n"
                "       \"direction-out\" : true,\n"
                "       \"penalty-boxed\" : false,\n"
                "       \"green-listed\" : true,\n"
                "       \"dont-count-hits\" : false,\n"
                "       \"dont-count-current-connections\" : true,\n"
                "       \"family\" : 2,\n"
                "       \"protocol\" : 6,\n"
                "       \"remote\" : {\n"
                "       \"address\" : \"%.*s\",\n"
                "       \"prefix-bits\" : %s\n"
                "       }\n"
                "   }\n"
                "  ]\n"
                "}\n"
                                , (int)(cp - argv[i+1]), argv[i+1], cp+1);

            ret = wolfsentry_config_json_oneshot(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(global_wolfsentry, global_thread),
                                                json_buf,
                                                 (size_t)json_len,
                                                WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH,
                                                err_buf,
                                                sizeof err_buf);

            if (ret < 0) {
                fprintf(stderr, "ERROR: wolfsentry_config_json_oneshot(): %s\n",err_buf);
                return ret;
            }
        }
        else if (! strcmp(argv[i],"--redlist")) {
            char *cp = strchr(argv[i+1], '/');
            unsigned char json_buf[512];
            int json_len;
            char err_buf[1024];
            if (cp == NULL) {
                fprintf(stderr,"ERROR: %s: missing '/' (prefix length introducer) in argument to %s\n",argv[0],argv[i]);
                exit(1);
            }
            json_len = snprintf((char *)json_buf, sizeof json_buf,
                "{\n"
                "  \"wolfsentry-config-version\" : 1,\n"
                "  \"static-routes-insert\" : [\n"
                "    {\n"
                "       \"parent-event\" : \"static-route-parent\",\n"
                "       \"direction-in\" : true,\n"
                "       \"direction-out\" : true,\n"
                "       \"penalty-boxed\" : true,\n"
                "       \"green-listed\" : false,\n"
                "       \"dont-count-hits\" : false,\n"
                "       \"dont-count-current-connections\" : true,\n"
                "       \"family\" : 2,\n"
                "       \"protocol\" : 6,\n"
                "       \"remote\" : {\n"
                "       \"address\" : \"%.*s\",\n"
                "       \"prefix-bits\" : %s\n"
                "       }\n"
                "   }\n"
                "  ]\n"
                "}\n",
                (int)(cp - argv[i+1]), argv[i+1], cp+1);

            ret = wolfsentry_config_json_oneshot(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(global_wolfsentry, global_thread),
                                                 json_buf,
                                                 (size_t)json_len,
                                                 WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH,
                                                 err_buf,
                                                 sizeof err_buf);

            if (ret < 0) {
                fprintf(stderr, "ERROR: wolfsentry_config_json_oneshot(): %s\n",err_buf);
                return ret;
            }
        }
    } /* for */

    ret = wolfsentry_user_value_get_uint(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(global_wolfsentry, global_thread),
        "circlog-size",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        &circlog_size_uint64);
    if (ret < 0) {
        fprintf(stderr, "ERROR: %s L%d: wolfsentry_user_value_get_string(\"circlog-size\") returned "
                WOLFSENTRY_ERROR_FMT "\n",
                __FILE__, __LINE__,
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
        exit(1);
    }

    ret = circlog_init((size_t)circlog_size_uint64);
    if (ret < 0) {
        fprintf(stderr, "ERROR: circlog_init() failed: " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        exit(1);
    }

#ifdef CIRCLOG_UNIT_TEST
{
    char *msg_buf;
    struct circlog_message *msg;
    int i;

    static const char text_s[] = "I'm a little teapot short and stout.";

    ret = circlog_enqueue_one(strlen(text_s), &msg_buf);
    if (ret < 0) {
        fprintf(stderr, "ERROR: %s L%d circlog failed: " WOLFSENTRY_ERROR_FMT "\n", __FILE__, __LINE__, WOLFSENTRY_ERROR_FMT_ARGS(ret));
        exit(1);
    }

    memcpy(msg_buf, text_s, strlen(text_s));

    ret = circlog_dequeue_one(&msg);
    if (ret < 0) {
        fprintf(stderr, "ERROR: %s L%d circlog failed: " WOLFSENTRY_ERROR_FMT "\n", __FILE__, __LINE__, WOLFSENTRY_ERROR_FMT_ARGS(ret));
        exit(1);
    }

    fprintf(stderr, "%.*s\n",(int)msg->len,msg->msg_buf);

    fprintf(stderr,"circlog_head=%zu circlog_tail=%zu\n",circlog_head,circlog_tail);

    for (i = 0; i < 3 * (circlog_size / circlog_ent_size_from_msg_len(strlen(text_s))); ++i) {
        size_t circlog_head_after_enqueue,circlog_tail_after_enqueue;

        ret = circlog_enqueue_one(strlen(text_s), &msg_buf);
        if (ret < 0) {
            fprintf(stderr, "ERROR: %s L%d circlog failed: " WOLFSENTRY_ERROR_FMT "\n", __FILE__, __LINE__, WOLFSENTRY_ERROR_FMT_ARGS(ret));
            exit(1);
        }

        circlog_head_after_enqueue = circlog_head;
        circlog_tail_after_enqueue = circlog_tail;

        memcpy(msg_buf, text_s, strlen(text_s));

        ret = circlog_dequeue_one(&msg);
        if (ret < 0) {
            fprintf(stderr, "ERROR: %s L%d circlog failed: " WOLFSENTRY_ERROR_FMT "\n", __FILE__, __LINE__, WOLFSENTRY_ERROR_FMT_ARGS(ret));
            exit(1);
        }

        if (((size_t)msg->len != strlen(text_s)) || (memcmp(msg->msg_buf, text_s, msg->len) != 0)) {
            fprintf(stderr, "ERROR: circlog msg doesn't match what went in, i=%d msg->len=%u circlog_head_after_enqueue=%zu circlog_tail_after_enqueue=%zu circlog_head=%zu circlog_tail=%zu.\n",i,msg->len,circlog_head_after_enqueue,circlog_tail_after_enqueue,circlog_head,circlog_tail);
            exit(1);
        }
    }

    fprintf(stderr,"circlog_head=%zu circlog_tail=%zu\n",circlog_head,circlog_tail);
}
#endif /* CIRCLOG_UNIT_TEST */

    log_server_init();

    running = 1;

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

    while (running) {
        struct sockaddr_in server_addr;
        socklen_t server_len;
        struct sockaddr_in client_addr;
        socklen_t client_len;
        struct wolfsentry_data *wolfsentry_data = NULL;
#ifdef HTTP_NONBLOCKING
        int retry;
#endif
        char *url, *url_end;

        transaction_successful = 0;

        client_len = sizeof client_addr;
        peer_fd = accept(inbound_fd, (struct sockaddr*)&client_addr,
                         &client_len);
        if (! running)
            goto ssl_shutdown;

        if (peer_fd < 0) {
            perror("accept");
            notnormal = 1;
            break;
        }

        if ((ssl = wolfSSL_new(wolf_ctx)) == NULL) {
            fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
            notnormal = 1;
            break;
        }

        app_data = (struct log_server_data *)XMALLOC(sizeof *app_data, NULL /* heap */, DYNAMIC_TYPE_TMP_BUFFER);
        if (app_data == NULL) {
            fprintf(stderr,"ERROR: %s L%d: XMALLOC(%zu) failed: %s\n", __FILE__, __LINE__, sizeof *app_data, strerror(errno));
            notnormal = 1;
            running = 0;
            goto ssl_shutdown;
        }
        memset(app_data, 0, sizeof *app_data);
        app_data->error_code = INCOMPLETE_DATA;
        wolfSSL_SetCertCbCtx(ssl, (void *)app_data);

        ret = wolfSSL_set_fd(ssl, peer_fd);
        if (ret != WOLFSSL_SUCCESS) {
            fprintf(stderr,"ERROR: SSL_set_fd() failed: %s\n", wolfSSL_ERR_reason_error_string(ret));
            notnormal = 1;
            running = 0;
            goto ssl_shutdown;
        }

        /* note a custom read ctx can only be set after wolfSSL_set_fd(), because
         * the latter sets it to &ssl->rfd.
         */
        wolfSSL_SetIOReadCtx(ssl, (void *)&io_ctx);
        wolfSSL_SetIOWriteCtx(ssl, (void *)&io_ctx);

        server_len = sizeof server_addr;
        if (getsockname(peer_fd, (struct sockaddr *)&server_addr, &server_len) < 0) {
            perror("getsockname");
            notnormal = 1;
            running = 0;
            goto ssl_shutdown;
        }

        ret = wolfsentry_store_endpoints(ssl, &client_addr, &server_addr, IPPROTO_TCP,
                                         WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN, &wolfsentry_data);
        if (ret < 0) {
            fprintf(stderr, "ERROR: wolfsentry_store_endpoints() failed: " WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
            notnormal = 1;
            running = 0;
            goto ssl_shutdown;
        }

#ifdef HTTP_NONBLOCKING
        retry = HTTP_MAX_NB_TRIES;
        do {
            ret = wolfSSL_accept(ssl);
            if ((wolfSSL_want_read(ssl) || wolfSSL_want_write(ssl))) {
                usleep(100000);
                retry--;
            } else {
                retry = 0;
            }
        } while (retry);
#else
        ret = wolfSSL_accept(ssl);
#endif /* HTTP_NONBLOCKING */
        if (! running)
            goto ssl_shutdown;

        if (ret != WOLFSSL_SUCCESS) {
            wolfsentry_data->ssl_error = wolfSSL_get_error(ssl, ret);
            fprintf(stderr, "ERROR: wolfSSL_accept ret = %d, error = %d (%s), sub-error = %d (%s)\n",
                    ret, wolfSSL_get_error(ssl, ret), wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl, ret)),
                    app_data->error_code, wolfSSL_ERR_reason_error_string(app_data->error_code));
            goto ssl_shutdown;
        }

        /* sanity check */
        if (app_data->issuer_cert == NULL) {
            fprintf(stderr, "ERROR: %s L%d app_data->issuer_cert is null!\n",__FILE__,__LINE__);
            goto ssl_shutdown;
        }

        handshake_done = 1;
#if defined(DEBUG_HTTP) || defined(DEBUG_TLS)
        fprintf(stderr, "Handshake done\n");
#endif

        http_buf_len = 0;
#ifdef HTTP_NONBLOCKING
        retry = 0;
#endif
        for (;;) {
            if (http_buf_len >= http_buf_size - 1) {
                fprintf(stderr, "ERROR: overlong client payload\n");
                goto ssl_shutdown;
            }
            ret = wolfSSL_read(ssl, http_buf + http_buf_len, (int)(http_buf_size - http_buf_len - 1));
            if (! running)
                goto ssl_shutdown;
            if (ret < 0) {
#ifdef DEBUG_HTTP
                fprintf(stderr,"\nL%d\n%.*s\n",__LINE__,(int)http_buf_len, http_buf);
#endif
                break;
            }
            http_buf_len += (size_t)ret;
#ifdef HTTP_NONBLOCKING
            if ((wolfSSL_want_read(ssl) || wolfSSL_want_write(ssl))) {
                if (retry == HTTP_MAX_NB_TRIES-1) {
                    fprintf(stderr, "giving up on client payload read after %d retries.\n", retry);
                    break;
                }
                usleep(100000);
                retry++;
#ifdef DEBUG_HTTP
                fprintf(stderr,"%s L%d retry %d\n",__FILE__,__LINE__,retry);
#endif
            }
            else
#endif /* HTTP_NONBLOCKING */
            {
                if ((http_buf_len >= 4) && (! strncmp(http_buf + http_buf_len - 4, "\r\n\r\n", 4)))
                    break;
                if ((http_buf_len >= 2) && (! strncmp(http_buf + http_buf_len - 2, "\n\n", 2)))
                    break;
            }
        }

        /* add null string termination to make string calls inherently safe. */
        http_buf[http_buf_len] = 0;

        if (ret < 0) {
            fprintf(stderr, "ERROR: failed to read: %s\n", wolfSSL_ERR_reason_error_string(ret));
            goto ssl_shutdown;
        }

#ifdef DEBUG_HTTP
        fprintf(stderr,"\n%.*s\n",(int)http_buf_len, http_buf);
#endif

        if (strncmp(http_buf, "GET ", 4) != 0) {
#ifdef DEBUG_HTTP
            fprintf(stderr, "ERROR: %s L%d non-GET request\n", __FILE__, __LINE__);
#endif
            goto ssl_shutdown;
        }

        url_end = memchr(http_buf + 4, ' ', http_buf_len - 4);
        if ((url_end == NULL) || (url_end == http_buf + 4)) {
#ifdef DEBUG_HTTP
            fprintf(stderr, "ERROR: %s L%d malformed request\n", __FILE__, __LINE__);
#endif
            goto ssl_shutdown;
        }

        url = http_buf + 4;

        if (strncmp(url_end+1, "HTTP/", 5) != 0) {
#ifdef DEBUG_HTTP
            fprintf(stderr, "ERROR: %s L%d unexpected protocol\n", __FILE__, __LINE__);
#endif
            goto ssl_shutdown;
        }

        *url_end = 0;

        if (strcmp(url, "/reset-log") == 0) {

            if (! app_data->issuer_cert->can_issue_admin_certs) {
                (void)http_write_header(ssl, http_buf, http_buf_size, 403, 0, NULL, NULL);
                goto ssl_shutdown;
            }

            ret = circlog_reset();
            if (ret < 0)
                (void)http_write_header(ssl, http_buf, http_buf_size, 500, 0, NULL, NULL);
            else
                (void)http_write_header(ssl, http_buf, http_buf_size, 200, 0, NULL, NULL);

            transaction_successful = 1;

            goto ssl_shutdown;
        }

        if (strcmp(url, "/kill-server") == 0) {

            if (! app_data->issuer_cert->can_issue_admin_certs) {
                (void)http_write_header(ssl, http_buf, http_buf_size, 403, 0, NULL, NULL);
                goto ssl_shutdown;
            }

            (void)http_write_header(ssl, http_buf, http_buf_size, 200, 0, NULL, NULL);

            transaction_successful = 1;

            running = 0;

            goto ssl_shutdown;
        }

#if 0
        /* not yet implemented */
        if (strncmp(url, "/reset-host", strlen("/reset-host"))) {
            const char *host_to_reset = url + strlen("/reset-host");

            if (! app_data->issuer_cert->can_issue_admin_certs) {
                (void)http_write_header(ssl, http_buf, http_buf_size, 403, 0, NULL, NULL);
                goto ssl_shutdown;
            }

            /* get the host to clear from the URL-encoded args, parse it, and call
             * wolfsentry_route_delete().  note this requires an exact match with
             * the rule inserted dynamically by sentry.c:handle_derogatory().
             */

            transaction_successful = 1;
        }
#endif

        if ((strncmp(url, "/show-log", strlen("/show-log")) == 0) &&
            ((url[strlen("/show-log")] == 0) ||
             (url[strlen("/show-log")] == '?')))
        {
            int resp_len;
            struct circlog_message *msg_i = NULL;
            size_t total_msg_len;
            char *show_log_args = url + strlen("/show-log");

            (void)show_log_args; /* arg processing not yet implemented. */

            total_msg_len = 2; /* "[\n" */
            for (ret = circlog_iterate(&msg_i); ret >= 0; ret = circlog_iterate(&msg_i)) {
                size_t this_out_len;
                ret = circlog_format_one(msg_i, NULL /* char **out */, &this_out_len);
                if (ret < 0) {
                    fprintf(stderr, "ERROR: %s L%d circlog_format_one() for size failed: " WOLFSENTRY_ERROR_FMT "\n", __FILE__, __LINE__, WOLFSENTRY_ERROR_FMT_ARGS(ret));
                    goto ssl_shutdown;
                }
                total_msg_len += this_out_len + 2; /* +2 for the ",\n" or "\n]" */
            }
            total_msg_len += 1; /* "\n" */

#ifdef DEBUG_HTTP
            fprintf(stderr, "Sending response\n");
#endif

            transaction_successful = 1;

            if (http_write_header(ssl, http_buf, http_buf_size, 200, (ssize_t)total_msg_len, "application/json", NULL) < 0)
                goto ssl_shutdown;

            /* option to dump rule counts? */
            {
                char *out_ptr = http_buf;
                size_t out_space = http_buf_size;
                int is_first;

                for (ret = circlog_iterate(&msg_i), is_first = 1; ret >= 0; ret = circlog_iterate(&msg_i)) {
                    int printed_this_sep = 0;
                    for (;;) {
                        if (printed_this_sep) {
                        } else if (is_first) {
                            memcpy(out_ptr, "[\n", strlen("[\n"));
                            out_ptr += strlen("[\n");
                            out_space -= strlen("[\n");
                            is_first = 0;
                            printed_this_sep = 1;
                        } else {
                            if (out_space < strlen(",\n"))
                                goto flush_now;
                            memcpy(out_ptr, ",\n", strlen(",\n"));
                            out_ptr += strlen(",\n");
                            out_space -= strlen(",\n");
                            printed_this_sep = 1;
                        }
                        ret = circlog_format_one(msg_i, &out_ptr, &out_space);
                        if (ret < 0) {
                            if (WOLFSENTRY_ERROR_CODE_IS(ret, BUFFER_TOO_SMALL)) {
                                if (http_buf_size - out_space <= strlen(",\n")) {
                                    fprintf(stderr,"ERROR: %s L%d msg won't fit in http_buf!\n",__FILE__,__LINE__);
                                    goto ssl_shutdown;
                                }
                            flush_now:
                                resp_len = (int)(http_buf_size - out_space);
                                if ((ret = wolfSSL_write(ssl, http_buf, resp_len)) != resp_len) {
                                    fprintf(stderr, "ERROR: failed to write: %s\n",wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl, ret)));
                                    goto ssl_shutdown;
                                }
                                out_ptr = http_buf;
                                out_space = http_buf_size;
                                continue;
                            } else {
                                fprintf(stderr, "ERROR: %s L%d circlog_format_one() failed: " WOLFSENTRY_ERROR_FMT "\n", __FILE__, __LINE__, WOLFSENTRY_ERROR_FMT_ARGS(ret));
                                goto ssl_shutdown;
                            }
                        }
                        break;
                    }

                }
                if (out_ptr != http_buf) {
                    resp_len = (int)(http_buf_size - out_space);
                    if ((ret = wolfSSL_write(ssl, http_buf, resp_len)) != resp_len) {
                        fprintf(stderr, "ERROR: failed to write: %s\n",wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl, ret)));
                        goto ssl_shutdown;
                    }
                }

                if ((ret = wolfSSL_write(ssl, "\n]\n", strlen("\n]\n"))) != strlen("\n]\n")) {
                    fprintf(stderr, "ERROR: failed to write: %s\n",wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl, ret)));
                    goto ssl_shutdown;
                }
            }

            goto ssl_shutdown;
        }

        (void)http_write_header(ssl, http_buf, http_buf_size, 404, 0, NULL, NULL);

        /* don't dock client */
        transaction_successful = 1;

    ssl_shutdown:

        /* if ssl_error != SOCKET_FILTERED_E, then pass in an appropriate event for the endpoint -- no-cert, bad-cert, transaction-forbidden. */

        if (wolfsentry_data) {
            if (wolfsentry_data->action_results & WOLFSENTRY_ACTION_RES_FALLTHROUGH)
                fprintf(stderr, "%s L%d WOLFSENTRY_ACTION_RES_FALLTHROUGH\n",__FILE__,__LINE__);

#ifdef DEBUG_WOLFSENTRY
            {
                struct wolfsentry_route_metadata_exports m;
                wolfsentry_time_t now;
                struct timespec age, purge_after;
                WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_route_get_metadata(wolfsentry_data->rule_route, &m));
                WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_time_now_plus_delta(global_wolfsentry, 0 /* td */, &now));
                WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_time_to_timespec(global_wolfsentry, now - m.insert_time, &age));
                if (m.purge_after)
                    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_time_to_timespec(global_wolfsentry, m.purge_after - now, &purge_after));
                else
                    purge_after.tv_sec = 0;
                fprintf(stderr,"%s L%d wolfsentry_data->rule_route_id = %u, derog = %u, commend = %u, hits = %u, age = %lds, purge_after=+%lds\n", __FILE__, __LINE__,
                        wolfsentry_data->rule_route_id,
                        m.derogatory_count,
                        m.commendable_count,
                        m.hit_count,
                        age.tv_sec,
                        purge_after.tv_sec
                    );
            }
#endif

            if (! (wolfsentry_data->action_results & WOLFSENTRY_ACTION_RES_FALLTHROUGH)) {
                wolfsentry_action_res_t action_results;
                if (transaction_successful) {
                    ret = wolfsentry_route_event_dispatch_by_route(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(global_wolfsentry, global_thread),
                                                                   wolfsentry_data->rule_route, "transaction-successful",
                                                                   WOLFSENTRY_LENGTH_NULL_TERMINATED, wolfsentry_data, &action_results);
                    if (ret < 0) {
                        fprintf(stderr, "ERROR: wolfsentry_route_event_dispatch_by_id() returned "
                                WOLFSENTRY_ERROR_FMT "\n",
                                WOLFSENTRY_ERROR_FMT_ARGS(ret));
                    }
                } else if (handshake_done)
                    ret = wolfsentry_route_event_dispatch_by_route(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(global_wolfsentry, global_thread),
                                                                   wolfsentry_data->rule_route, "transaction-failed",
                                                                   WOLFSENTRY_LENGTH_NULL_TERMINATED, wolfsentry_data, &action_results);
                else {
                    if (wolfsentry_data->ssl_error != SOCKET_FILTERED_E)
                        ret = wolfsentry_route_event_dispatch_by_route(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(global_wolfsentry, global_thread),
                                                                       wolfsentry_data->rule_route, "handshake-failed",
                                                                       WOLFSENTRY_LENGTH_NULL_TERMINATED, wolfsentry_data, &action_results);
                }
            }

            if (app_data != NULL) {
                if (wolfsentry_data->rule_route != NULL) {
                    wolfsentry_action_res_t action_results = 0;
                    ret = wolfsentry_route_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(global_wolfsentry, global_thread),
                                                          wolfsentry_data->rule_route, &action_results);
#ifdef DEBUG_WOLFSENTRY
                    fprintf(stderr,"%s L%d drop_reference rule_route=%p rule_route_id=%u action_results=0%o\n",
                            __FILE__, __LINE__, wolfsentry_data->rule_route, wolfsentry_data->rule_route_id, action_results);
#endif
                    if (ret < 0) {
                        fprintf(stderr, "ERROR: wolfsentry_route_drop_reference() returned "
                                WOLFSENTRY_ERROR_FMT "\n",
                                WOLFSENTRY_ERROR_FMT_ARGS(ret));
                        exit(1);
                    }
                }
                XFREE(app_data, NULL /* heap */, DYNAMIC_TYPE_TMP_BUFFER);
                app_data = NULL;
            }

            wolfsentry_data = NULL;
        }

        if (handshake_done) {
            handshake_done = 0;
#ifdef HTTP_NONBLOCKING
            retry = HTTP_MAX_NB_TRIES;
            do {
                ret = wolfSSL_shutdown(ssl);
                if (ret == SSL_SHUTDOWN_NOT_DONE) {
                    usleep(500);
                    retry--;
                } else {
                    break;
                }
            } while (retry);
#else
            ret = wolfSSL_shutdown(ssl);
#endif /* HTTP_NONBLOCKING */

            if (ret < 0) {
                fprintf(stderr, "ERROR: wolfSSL_shutdown() returned code %d %s\n",
                        ret, wolfSSL_ERR_reason_error_string(ret));
            }
        }

        if (ssl) {
            wolfSSL_free(ssl);
            ssl = NULL;
        }

        if (peer_fd > 0) {
            (void)close(peer_fd);
            peer_fd = -1;
#ifdef DEBUG_HTTP
            fprintf(stderr, "Connection closed\n");
#endif
        }
    }

    ret = wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(&global_wolfsentry, global_thread));
    if (ret < 0) {
        fprintf(stderr, "ERROR: wolfsentry_shutdown: " WOLFSENTRY_ERROR_FMT,
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
        notnormal = 1;
    }

#ifdef WOLFSENTRY_THREADSAFE
    ret = wolfsentry_destroy_thread_context(global_thread, WOLFSENTRY_THREAD_FLAG_NONE);
    if (ret < 0) {
        fprintf(stderr, "ERROR: %s: thread shutdown failed: " WOLFSENTRY_ERROR_FMT "\n", argv[0], WOLFSENTRY_ERROR_FMT_ARGS(ret));
        notnormal = 1;
    }
#endif

    if (! notnormal) {
        printf("\nnormal exit.\n");
        exit(0);
    } else {
        fprintf(stderr,"\nexiting with warnings or errors.\n");
        exit(1);
    }
}

#else

#error only know how to build for Linux and MacOSX

#endif
