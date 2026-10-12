/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef WOLFSENTRY_M33MU_WOLFSSL_USER_SETTINGS_H
#define WOLFSENTRY_M33MU_WOLFSSL_USER_SETTINGS_H

#define WOLFSSL_LWIP_NATIVE
#define WOLFSSL_TLS13
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define HAVE_ECC
#define ECC_USER_CURVES
#define HAVE_AESGCM
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_SMALL
#if !defined(__ASSEMBLER__)
    #ifndef FREERTOS
        #define FREERTOS
    #endif
#endif
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_NO_SOCK
#define NO_DEV_RANDOM
#define WOLFSSL_NO_GETPID
#define NO_DH
#define NO_RSA
#define CUSTOM_RAND_GENERATE_BLOCK m33mu_random_block
#define ECC_TIMING_RESISTANT

#if !defined(__ASSEMBLER__)
int m33mu_random_block(unsigned char *output, unsigned int size);
#endif

#endif /* WOLFSENTRY_M33MU_WOLFSSL_USER_SETTINGS_H */
