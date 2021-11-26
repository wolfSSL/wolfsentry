/*
 * wolfsentry_json.h
 *
 * Copyright (C) 2021 wolfSSL Inc.
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

#ifndef WOLFSENTRY_JSON_H
#define WOLFSENTRY_JSON_H

#include "wolfsentry.h"

#ifdef WOLFSENTRY_NO_STDIO
#error wolfsentry_json requires stdio
#endif

#ifndef WOLFSENTRY
#define WOLFSENTRY
#endif
#include "centijson_sax.h"

typedef enumint_t wolfsentry_config_load_flags_t;
enum {
    WOLFSENTRY_CONFIG_LOAD_FLAG_NONE             = 0U,
    WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH         = 1U << 0U,
    WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN          = 1U << 1U,
    WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT = 1U << 2U,
    WOLFSENTRY_CONFIG_LOAD_FLAG_FINI             = 1U << 30U
};

struct wolfsentry_json_process_state;

/*!
   \brief Initialize the JSON configuration object

   \param wolfsentry the wolfsentry object
   \param load_flags the configuration loading flags
   \param jps the initialized JSON process state

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_init(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_config_load_flags_t load_flags,
    struct wolfsentry_json_process_state **jps);

/*!
   \brief Set the default JSON parser default config

   \param jps the JSON process state
   \param config the configuration to set

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_set_default_config(
    struct wolfsentry_json_process_state *jps,
    struct wolfsentry_eventconfig *config);

/*!
   \brief Send data into the JSON parser

   \param jps the JSON process state
   \param json_in the data to insert into the parser
   \param json_in_len the length of the json_in
   \param err_buf a pointer to a buffer for error messages
   \param err_buf_size the size of err_buf

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa wolfsentry_config_json_fini
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_feed(
    struct wolfsentry_json_process_state *jps,
    const char *json_in,
    size_t json_in_len,
    char *err_buf,
    size_t err_buf_size);

/*!
   \brief Get the error code and message from the JSON parser

   \param jps the JSON process state
   \param json_errcode the returned error code
   \param json_errmsg the returned error message

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_centijson_errcode(struct wolfsentry_json_process_state *jps, int *json_errcode, const char **json_errmsg);

/*!
   \brief Finialize processing the JSON data started with wolfsentry_config_json_feed

   \param jps the JSON process state
   \param err_buf a pointer to a buffer for error messages
   \param err_buf_size the size of err_buf

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa wolfsentry_config_json_feed
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_fini(
    struct wolfsentry_json_process_state **jps,
    char *err_buf,
    size_t err_buf_size);

/*!
   \brief Process the an entired JSON buffer in a single shot instead of parts

   \param json_in the JSON text to parse
   \param json_in_len the length of json_in
   \param load_flags the flags for the JSON loading
   \param err_buf a pointer to a buffer for error messages
   \param err_buf_size the size of err_buf

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_oneshot(
    struct wolfsentry_context *wolfsentry,
    const char *json_in,
    size_t json_in_len,
    wolfsentry_config_load_flags_t load_flags,
    char *err_buf,
    size_t err_buf_size);

#endif /* WOLFSENTRY_JSON_H */
