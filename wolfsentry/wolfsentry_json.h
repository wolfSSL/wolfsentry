/*
 * wolfsentry_json.h
 *
 * Copyright (C) 2021-2025 wolfSSL Inc.
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

/*! @file wolfsentry_json.h
    \brief Types and prototypes for loading/reloading configuration using JSON.

    Include this file in your application for JSON configuration capabilities.
 */

#ifndef WOLFSENTRY_JSON_H
#define WOLFSENTRY_JSON_H

#include "wolfsentry.h"
#include "wolfsentry_config.h"

#ifndef WOLFSENTRY
#define WOLFSENTRY
#endif
#include "centijson_sax.h"

/*! \addtogroup wolfsentry_init
 *  @{
 */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_centijson_errcode_translate(wolfsentry_errcode_t centijson_errcode);
    /*!< \brief Convert CentiJSON numeric error code to closest-corresponding wolfSentry error code. */

#ifndef WOLFSENTRY_MAX_JSON_NESTING
#define WOLFSENTRY_MAX_JSON_NESTING 16
    /*!< \brief Can be overridden. */
#endif

#ifndef WOLFSENTRY_MAX_JSON_TOTAL_LEN
#define WOLFSENTRY_MAX_JSON_TOTAL_LEN (10 * 1024 * 1024)
    /*!< \brief Default cap on total JSON input length, matching centijson's
     *          upstream default.  Set to 0 for unlimited, or override at
     *          build time.  Can also be overridden per-call via the
     *          `JSON_CONFIG` parameter of wolfsentry_config_json_init_ex().
     */
#endif

struct wolfsentry_json_process_state;

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_init(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_config_load_flags_t load_flags,
    struct wolfsentry_json_process_state **jps);
    /*!< \brief Allocate and initialize a `struct wolfsentry_json_process_state` with the designated `load_flags`, to subsequently pass to `wolfsentry_config_json_feed()`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_init_ex(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_config_load_flags_t load_flags,
    const JSON_CONFIG *json_config,
    struct wolfsentry_json_process_state **jps);
    /*!< \brief Variant of `wolfsentry_config_json_init()` with an additional `JSON_CONFIG` argument, `json_config`, for tailoring of JSON parsing dynamics. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_feed(
    struct wolfsentry_json_process_state *jps,
    const unsigned char *json_in,
    size_t json_in_len,
    char *err_buf,
    size_t err_buf_size);
    /*!< \brief Pass a segment of JSON configuration into the parsing engine.  Segments can be as short or as long as desired, to facilitate incremental read-in. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_centijson_errcode(struct wolfsentry_json_process_state *jps, int *json_errcode, const char **json_errmsg);
    /*!< \brief Copy the current error code and/or human-readable error message from a `struct wolfsentry_json_process_state` allocated by `wolfsentry_config_json_init()`. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_fini(
    struct wolfsentry_json_process_state **jps,
    char *err_buf,
    size_t err_buf_size);
    /*!< \brief To be called when done iterating `wolfsentry_config_json_feed()`, completing the configuration load. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_oneshot(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const unsigned char *json_in,
    size_t json_in_len,
    wolfsentry_config_load_flags_t load_flags,
    char *err_buf,
    size_t err_buf_size);
    /*!< \brief Load a complete JSON configuration from an in-memory buffer. */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_oneshot_ex(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const unsigned char *json_in,
    size_t json_in_len,
    wolfsentry_config_load_flags_t load_flags,
    const JSON_CONFIG *json_config,
    char *err_buf,
    size_t err_buf_size);
    /*!< \brief Variant of `wolfsentry_config_json_oneshot()` with an additional `JSON_CONFIG` argument, `json_config`, for tailoring of JSON parsing dynamics. */

/*! @} */

#endif /* WOLFSENTRY_JSON_H */
