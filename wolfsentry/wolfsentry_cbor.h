/*
 * wolfsentry_cbor.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfSentry.
 *
 * wolfSentry is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*! @file wolfsentry_cbor.h
    \brief Loading wolfSentry configuration from CBOR using wolfCOSE.
 */

#ifndef WOLFSENTRY_CBOR_H
#define WOLFSENTRY_CBOR_H

#include "wolfsentry.h"
#include "wolfsentry_config.h"

#ifndef WOLFSENTRY_MAX_CBOR_NESTING
#define WOLFSENTRY_MAX_CBOR_NESTING 16U
#endif
#if WOLFSENTRY_MAX_CBOR_NESTING < 1U
#error WOLFSENTRY_MAX_CBOR_NESTING must be at least 1.
#endif

#ifndef WOLFSENTRY_MAX_CBOR_TOTAL_LEN
#define WOLFSENTRY_MAX_CBOR_TOTAL_LEN (10U * 1024U * 1024U)
#endif

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_cbor_oneshot(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const unsigned char *cbor_in,
    size_t cbor_in_len,
    wolfsentry_config_load_flags_t load_flags,
    char *err_buf,
    size_t err_buf_size);
    /*!< \brief Load a complete CBOR configuration from an in-memory buffer. */

#endif /* WOLFSENTRY_CBOR_H */
