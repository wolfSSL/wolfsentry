/*
 * wolfsentry_json.h
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

/*! @file wolfsentry_json.h
    \brief Types and prototypes for loading/reloading configuration using JSON.

    Include this file in your application for JSON configuration capabilities.
 */

#ifndef WOLFSENTRY_JSON_H
#define WOLFSENTRY_JSON_H

#include "wolfsentry.h"

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

typedef uint32_t wolfsentry_config_load_flags_t;
    /*!< \brief Type for holding flag bits from #wolfsentry_config_load_flags */

/*! \brief Flags to be `OR`d together to communicate options to wolfsentry_config_json_init() */
enum wolfsentry_config_load_flags {
    WOLFSENTRY_CONFIG_LOAD_FLAG_NONE             = 0U,
        /*!< \brief Default behavior @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH         = 1U << 0U,
        /*!< \brief Add to current configuration, rather than replacing it. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN          = 1U << 1U,
        /*!< \brief Test the load operation, as modified by other flags, without updating current configuration. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT = 1U << 2U,
        /*!< \brief Test the load operation before replacing the current configuration. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_NO_ROUTES_OR_EVENTS = 1U << 3U,
        /*!< \brief Skip routes and events in the supplied configuration. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_ABORT = 1U << 4U,
        /*!< \brief When loading JSON user values, treat as an error when duplicate keys are found. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_USEFIRST = 1U << 5U,
        /*!< \brief When loading JSON user values, when duplicate keys are found, keep the first one. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_USELAST = 1U << 6U,
        /*!< \brief When loading JSON user values, when duplicate keys are found, keep the last one. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_MAINTAINDICTORDER = 1U << 7U,
        /*!< \brief When loading JSON user values, store extra sequence information so that dictionaries are rendered in same sequence by `json_dom_dump()` and `wolfsentry_kv_render_value()`. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_FLUSH_ONLY_ROUTES = 1U << 8U,
        /*!< \brief Don't flush the events or user values, just flush the routes, before loading incremental configuration JSON. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_FINI             = 1U << 30U
        /*!< \brief Internal use. @hideinitializer */
};

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
