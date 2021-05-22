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
    WOLFSENTRY_CONFIG_LOAD_FLAG_NONE = 0,
    WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH = 1 << 0,
    WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN = 1 << 1
};

struct json_process_state;

wolfsentry_errcode_t wolfsentry_config_json_init(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_config_load_flags_t load_flags,
    struct json_process_state **jps);

wolfsentry_errcode_t wolfsentry_config_json_set_default_config(
    struct json_process_state *jps,
    struct wolfsentry_eventconfig *config);

wolfsentry_errcode_t wolfsentry_config_json_feed(
    struct json_process_state *jps,
    const char *json_in,
    size_t json_in_len,
    char *err_buf,
    size_t err_buf_size);

wolfsentry_errcode_t wolfsentry_config_centijson_errcode(struct json_process_state *jps, int *json_errcode, const char **json_errmsg);

wolfsentry_errcode_t wolfsentry_config_json_fini(
    struct json_process_state *jps,
    char *err_buf,
    size_t err_buf_size);

wolfsentry_errcode_t wolfsentry_config_json_oneshot(
    struct wolfsentry_context *wolfsentry,
    const char *json_in,
    size_t json_in_len,
    wolfsentry_config_load_flags_t load_flags,
    char *err_buf,
    size_t err_buf_size);

#endif /* WOLFSENTRY_JSON_H */
