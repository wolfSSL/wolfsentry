/*
 * kv.c
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

#include "wolfsentry_internal.h"
#ifdef WOLFSENTRY_HAVE_JSON_DOM
#include <wolfsentry/wolfsentry_json.h>
#include <wolfsentry/centijson_dom.h>
#endif

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_KV_C

static inline int wolfsentry_kv_key_cmp_1(const char *left_label, const unsigned int left_label_len, const char *right_label, const unsigned int right_label_len) {
    int ret;

    if (left_label_len >= right_label_len) {
        ret = memcmp(left_label, right_label, right_label_len);
        if ((ret == 0) && (left_label_len != right_label_len))
            ret = 1;
    } else {
        ret = memcmp(left_label, right_label, left_label_len);
        if (ret == 0)
            ret = -1;
    }

    WOLFSENTRY_RETURN_VALUE(ret);
}

static int wolfsentry_kv_key_cmp(struct wolfsentry_kv_pair_internal *left, struct wolfsentry_kv_pair_internal *right) {
    return wolfsentry_kv_key_cmp_1(
        WOLFSENTRY_KV_KEY(&left->kv),
        (unsigned int)WOLFSENTRY_KV_KEY_LEN(&left->kv),
        WOLFSENTRY_KV_KEY(&right->kv),
        (unsigned int)WOLFSENTRY_KV_KEY_LEN(&right->kv));
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_new(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    int data_len, /* length with terminating null if WOLFSENTRY_KV_STRING, raw length if WOLFSENTRY_KV_BYTES, 0 otherwise */
    struct wolfsentry_kv_pair_internal **kv)
{
    size_t kv_size;
    if (key_len == 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (data_len < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    else if (data_len > WOLFSENTRY_KV_MAX_VALUE_BYTES)
        WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    if (key_len < 0)
        key_len = (int)strlen(key);
    if (key_len > WOLFSENTRY_MAX_LABEL_BYTES)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
    kv_size = sizeof **kv + (size_t)key_len + 1 + (size_t)data_len;
    if ((*kv = (struct wolfsentry_kv_pair_internal *)WOLFSENTRY_MALLOC(kv_size)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    memset(*kv, 0, kv_size);
    (*kv)->header.refcount = 1;
    (*kv)->header.id = WOLFSENTRY_ENT_ID_NONE;
    (*kv)->kv.key_len = key_len;
    memcpy((*kv)->kv.b,key,(size_t)key_len);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_drop_reference(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_pair_internal *kv,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    wolfsentry_refcount_t refs_left;
    (void)action_results;
    if (kv->header.refcount <= 0)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if ((kv->header.parent_table != NULL) &&
        (kv->header.parent_table->ent_type != WOLFSENTRY_OBJECT_TYPE_KV))
        WOLFSENTRY_ERROR_RETURN(WRONG_OBJECT);
    WOLFSENTRY_REFCOUNT_DECREMENT(kv->header.refcount, refs_left, ret);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    if (refs_left > 0)
        WOLFSENTRY_RETURN_OK;
#ifdef WOLFSENTRY_HAVE_JSON_DOM
    if (WOLFSENTRY_KV_TYPE(&kv->kv) == WOLFSENTRY_KV_JSON) {
        ret = json_value_fini(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)), WOLFSENTRY_KV_V_JSON(&kv->kv));
        if (ret < 0) {
            wolfsentry_errcode_t ret2;
            WOLFSENTRY_REFCOUNT_INCREMENT(kv->header.refcount, ret2);
            if (ret2 < 0)
                WOLFSENTRY_ERROR_RERETURN(ret2);
            else
                WOLFSENTRY_ERROR_RERETURN(wolfsentry_centijson_errcode_translate(ret));
        }
    }
#endif
    WOLFSENTRY_FREE(kv);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_set_mutability(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    struct wolfsentry_kv_pair_internal *kv,
    int mutable)
{
    (void)kv_table;

    WOLFSENTRY_MUTEX_OR_RETURN();

    switch (mutable) {
    case 0:
        if ((kv->kv.v_type & WOLFSENTRY_KV_FLAG_READONLY) == 0)
            kv->kv.v_type |= WOLFSENTRY_KV_FLAG_READONLY;
        WOLFSENTRY_UNLOCK_AND_RETURN_OK;
    case 1:
        if ((kv->kv.v_type & WOLFSENTRY_KV_FLAG_READONLY) != 0)
            WOLFSENTRY_CLEAR_BITS(kv->kv.v_type, WOLFSENTRY_KV_FLAG_READONLY);
        WOLFSENTRY_UNLOCK_AND_RETURN_OK;
    default:
        WOLFSENTRY_ERROR_UNLOCK_AND_RETURN(INVALID_ARG);
    }
}

int wolfsentry_kv_get_mutability(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    const struct wolfsentry_kv_pair_internal *kv)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    (void)kv_table;
    if ((kv->kv.v_type & WOLFSENTRY_KV_FLAG_READONLY) == 0)
        return 1;
    else
        return 0;
}

static wolfsentry_errcode_t wolfsentry_kv_insert_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    struct wolfsentry_kv_pair_internal *kv)
{
    wolfsentry_errcode_t ret;

    if ((ret = wolfsentry_id_allocate(WOLFSENTRY_CONTEXT_ARGS_OUT, &kv->header)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    if ((ret = wolfsentry_table_ent_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, &kv->header, &kv_table->header, 1 /* unique_p */)) < 0)
        (void)wolfsentry_table_ent_delete_by_id_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &kv->header);

    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_insert(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    struct wolfsentry_kv_pair_internal *kv)
{
    wolfsentry_errcode_t ret;

    if (kv_table->validator) {
        ret = kv_table->validator(WOLFSENTRY_CONTEXT_ARGS_OUT, &kv->kv);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
    }

    WOLFSENTRY_MUTEX_OR_RETURN();
    WOLFSENTRY_ERROR_RERETURN_AND_UNLOCK(wolfsentry_kv_insert_1(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_table, kv));
}

static inline int wolfsentry_kv_value_eq_1(struct wolfsentry_kv_pair *a, struct wolfsentry_kv_pair *b) {
    if (WOLFSENTRY_KV_TYPE(a) != WOLFSENTRY_KV_TYPE(b))
        return 0;
    switch (WOLFSENTRY_KV_TYPE(a)) {
    case WOLFSENTRY_KV_NONE:
        return 0;
    case WOLFSENTRY_KV_NULL:
    case WOLFSENTRY_KV_TRUE:
    case WOLFSENTRY_KV_FALSE:
        return 1;
    case WOLFSENTRY_KV_UINT:
        return (WOLFSENTRY_KV_V_UINT(a) == WOLFSENTRY_KV_V_UINT(b));
    case WOLFSENTRY_KV_SINT:
        return (WOLFSENTRY_KV_V_SINT(a) == WOLFSENTRY_KV_V_SINT(b));
    case WOLFSENTRY_KV_FLOAT:
        return (WOLFSENTRY_KV_V_FLOAT(a) == WOLFSENTRY_KV_V_FLOAT(b));
    case WOLFSENTRY_KV_STRING:
        if (WOLFSENTRY_KV_V_STRING_LEN(a) != WOLFSENTRY_KV_V_STRING_LEN(b))
            return 0;
        return memcmp(WOLFSENTRY_KV_V_STRING(a), WOLFSENTRY_KV_V_STRING(b), WOLFSENTRY_KV_V_STRING_LEN(a));
    case WOLFSENTRY_KV_BYTES:
        if (WOLFSENTRY_KV_V_BYTES_LEN(a) != WOLFSENTRY_KV_V_BYTES_LEN(b))
            return 0;
        return memcmp(WOLFSENTRY_KV_V_BYTES(a), WOLFSENTRY_KV_V_BYTES(b), WOLFSENTRY_KV_V_BYTES_LEN(a));
#ifdef WOLFSENTRY_HAVE_JSON_DOM
    case WOLFSENTRY_KV_JSON:
        return 0; /* don't try to recursively compare the json trees. */
#endif
    }
    return 0;
}

/* same as wolfsentry_kv_insert unless key already exists.  if it does and
 * matches, the table is unchanged.  if it does and doesn't match, the old ent is
 * deleted and the new one is inserted.
 */
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_set(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    struct wolfsentry_kv_pair_internal *kv)
{
    struct wolfsentry_kv_pair_internal *old;
    wolfsentry_errcode_t ret;

    if (kv_table->validator) {
        ret = kv_table->validator(WOLFSENTRY_CONTEXT_ARGS_OUT, &kv->kv);
        WOLFSENTRY_RERETURN_IF_ERROR(ret);
    }

    WOLFSENTRY_MUTEX_OR_RETURN();

    old = kv;

    if (wolfsentry_table_ent_get(WOLFSENTRY_CONTEXT_ARGS_OUT, &kv_table->header, (struct wolfsentry_table_ent_header **)&old) >= 0) {
        if (old->kv.v_type & WOLFSENTRY_KV_FLAG_READONLY)
            WOLFSENTRY_ERROR_UNLOCK_AND_RETURN(NOT_PERMITTED);
        if (wolfsentry_kv_value_eq_1(&kv->kv, &old->kv)) {
            ret = wolfsentry_kv_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, kv, NULL);
            WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);
            WOLFSENTRY_UNLOCK_AND_RETURN_OK;
        }
        if (((ret = wolfsentry_table_ent_delete_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &old->header)) < 0) ||
            ((ret = wolfsentry_kv_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, old, NULL)) < 0))
        {
            WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
        }
    }

    ret = wolfsentry_kv_insert_1(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_table, kv);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

static wolfsentry_errcode_t wolfsentry_kv_get_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    const struct wolfsentry_kv_pair_internal *kv_template,
    struct wolfsentry_kv_pair_internal **kv)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *ret_kv = (struct wolfsentry_kv_pair_internal *)kv_template;
    WOLFSENTRY_SHARED_OR_RETURN();
    if ((ret = wolfsentry_table_ent_get(WOLFSENTRY_CONTEXT_ARGS_OUT, &kv_table->header, (struct wolfsentry_table_ent_header **)&ret_kv)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    /* special-case request for uint with object sint that is >= 0. */
    if ((WOLFSENTRY_KV_TYPE(&kv_template->kv) == WOLFSENTRY_KV_UINT) &&
        (WOLFSENTRY_KV_TYPE(&ret_kv->kv) == WOLFSENTRY_KV_SINT) &&
        (WOLFSENTRY_KV_V_SINT(&ret_kv->kv) >= 0))
        ;
    else if ((WOLFSENTRY_KV_TYPE(&kv_template->kv) != WOLFSENTRY_KV_NONE) &&
        (WOLFSENTRY_KV_TYPE(&kv_template->kv) != WOLFSENTRY_KV_TYPE(&ret_kv->kv)))
        WOLFSENTRY_ERROR_UNLOCK_AND_RETURN(WRONG_TYPE);
    *kv = ret_kv;
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_kv_get_2(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    const char *key,
    int key_len,
    wolfsentry_kv_type_t type,
    struct wolfsentry_kv_pair_internal **kv)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv_template;
    if ((ret = wolfsentry_kv_new(WOLFSENTRY_CONTEXT_ARGS_OUT, key, key_len, 0 /* data_len */, &kv_template)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    kv_template->kv.v_type = type;
    ret = wolfsentry_kv_get_1(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_table, kv_template, kv);
    (void)wolfsentry_kv_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_template, NULL);
    WOLFSENTRY_ERROR_RERETURN(ret);
}

static wolfsentry_errcode_t wolfsentry_kv_get_reference_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    const struct wolfsentry_kv_pair_internal *kv_template,
    struct wolfsentry_kv_pair_internal **kv)
{
    wolfsentry_errcode_t ret = wolfsentry_kv_get_1(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_table, kv_template, kv);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    WOLFSENTRY_REFCOUNT_INCREMENT((*kv)->header.refcount, ret);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_get_reference(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    const char *key,
    int key_len,
    wolfsentry_kv_type_t type,
    struct wolfsentry_kv_pair_internal **kv)
{
    struct wolfsentry_kv_pair_internal *kv_template;
    wolfsentry_errcode_t ret;
    if ((ret = wolfsentry_kv_new(WOLFSENTRY_CONTEXT_ARGS_OUT, key, key_len, 0 /* data_len */, &kv_template)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    kv_template->kv.v_type = type;
    ret = wolfsentry_kv_get_reference_1(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_table, kv_template, kv);
    (void)wolfsentry_kv_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_template, NULL);

    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_get_type(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    const char *key,
    int key_len,
    wolfsentry_kv_type_t *type)
{
    struct wolfsentry_kv_pair_internal *kv_template;
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv = NULL;
    if ((ret = wolfsentry_kv_new(WOLFSENTRY_CONTEXT_ARGS_OUT, key, key_len, 0 /* data_len */, &kv_template)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    ret = wolfsentry_kv_get_1(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_table, kv_template, &kv);
    (void)wolfsentry_kv_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_template, NULL);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    *type = WOLFSENTRY_KV_TYPE(&kv->kv);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_kv_type_to_string(
    wolfsentry_kv_type_t type,
    const char **out)
{
    switch (type) {
    case WOLFSENTRY_KV_NONE:
        *out = "none";
        break;
    case WOLFSENTRY_KV_NULL:
        *out = "null";
        break;
    case WOLFSENTRY_KV_TRUE:
        *out = "true";
        break;
    case WOLFSENTRY_KV_FALSE:
        *out = "false";
        break;
    case WOLFSENTRY_KV_UINT:
        *out = "uint";
        break;
    case WOLFSENTRY_KV_SINT:
        *out = "sint";
        break;
    case WOLFSENTRY_KV_FLOAT:
        *out = "float";
        break;
    case WOLFSENTRY_KV_STRING:
        *out = "string";
        break;
    case WOLFSENTRY_KV_BYTES:
        *out = "bytes";
        break;
    case WOLFSENTRY_KV_JSON:
        *out = "json";
        break;
    default:
        WOLFSENTRY_ERROR_RETURN(WRONG_TYPE);
    }
    WOLFSENTRY_RETURN_OK;
}

#ifndef WOLFSENTRY_NO_STDIO

struct dump_buf_state {
    char *out;
    int out_space;
};

#ifdef WOLFSENTRY_HAVE_JSON_DOM
static wolfsentry_errcode_t _json_value_dump_writer(const char* str, size_t size, struct dump_buf_state *dbs) {
    if (size > (size_t)dbs->out_space)
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    memcpy(dbs->out, str, size);
    dbs->out += size;
    dbs->out_space -= (int)size;
    return 0;
}
#endif

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_kv_render_value(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_pair *kv,
    char *out,
    int *out_len)
{
    size_t out_space;
    if (*out_len < 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    out_space = (size_t)*out_len;
    switch (WOLFSENTRY_KV_TYPE(kv)) {
    case WOLFSENTRY_KV_NONE:
        WOLFSENTRY_ERROR_RETURN(WRONG_TYPE);
    case WOLFSENTRY_KV_NULL:
        *out_len = snprintf(out, out_space, "null");
        break;
    case WOLFSENTRY_KV_TRUE:
        *out_len = snprintf(out, out_space, "true");
        break;
    case WOLFSENTRY_KV_FALSE:
        *out_len = snprintf(out, out_space, "false");
        break;
    case WOLFSENTRY_KV_UINT:
        *out_len = snprintf(out, out_space, "%lu", (long unsigned int)WOLFSENTRY_KV_V_UINT(kv));
        break;
    case WOLFSENTRY_KV_SINT:
        *out_len = snprintf(out, out_space, "%ld", (long int)WOLFSENTRY_KV_V_SINT(kv));
        break;
    case WOLFSENTRY_KV_FLOAT:
        *out_len = snprintf(out, out_space, "%.10f", WOLFSENTRY_KV_V_FLOAT(kv));
        break;
    case WOLFSENTRY_KV_STRING:
        *out_len = snprintf(out, out_space, "\"%.*s\"", (int)WOLFSENTRY_KV_V_STRING_LEN(kv), WOLFSENTRY_KV_V_STRING(kv));
        break;
    case WOLFSENTRY_KV_BYTES:
        WOLFSENTRY_ERROR_RETURN(WRONG_TYPE);
    case WOLFSENTRY_KV_JSON: {
#ifdef WOLFSENTRY_HAVE_JSON_DOM
        struct dump_buf_state dbs = { out, *out_len };
        int ret = json_dom_dump(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(wolfsentry)),
                            WOLFSENTRY_KV_V_JSON(kv),
                            (JSON_DUMP_CALLBACK)_json_value_dump_writer,
                            &dbs /* user_data */,
                            4 /* tab_width */,
                            0 /* flags */);
        if (ret < 0)
            WOLFSENTRY_ERROR_RERETURN(wolfsentry_centijson_errcode_translate(ret));
        if (dbs.out_space <= 0)
            WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
        *out_len = *out_len - dbs.out_space;
        out[*out_len] = 0;
        WOLFSENTRY_RETURN_OK;
#else
        WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
        WOLFSENTRY_ERROR_RETURN(IMPLEMENTATION_MISSING);
#endif
    }
    default:
        WOLFSENTRY_ERROR_RETURN(WRONG_TYPE);
    }
    if (*out_len >= (int)out_space)
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);
    else
        WOLFSENTRY_RETURN_OK;
}

#endif /* !WOLFSENTRY_NO_STDIO */

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_clone(
    struct wolfsentry_context *src_context,
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread,
#endif
    struct wolfsentry_table_ent_header * const src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header ** const new_ent,
    wolfsentry_clone_flags_t flags)
{
    struct wolfsentry_kv_pair_internal * const src_kv_pair = (struct wolfsentry_kv_pair_internal * const)src_ent;
    struct wolfsentry_kv_pair_internal ** const new_kv_pair = (struct wolfsentry_kv_pair_internal ** const)new_ent;
    size_t new_size = sizeof *src_kv_pair + (size_t)src_kv_pair->kv.key_len + 1;

    if (WOLFSENTRY_KV_TYPE(&src_kv_pair->kv) == WOLFSENTRY_KV_STRING)
        new_size += src_kv_pair->kv.a.string_len + 1;
    else if (WOLFSENTRY_KV_TYPE(&src_kv_pair->kv) == WOLFSENTRY_KV_BYTES)
        new_size += src_kv_pair->kv.a.bytes_len;

    (void)src_context;
    (void)flags;

    if ((*new_kv_pair = WOLFSENTRY_MALLOC_1(dest_context->hpi.allocator, new_size)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    memcpy(*new_kv_pair, src_kv_pair, new_size);

#ifdef WOLFSENTRY_HAVE_JSON_DOM
    if (WOLFSENTRY_KV_TYPE(&src_kv_pair->kv) == WOLFSENTRY_KV_JSON) {
        int ret = json_value_clone(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(wolfsentry_get_allocator(dest_context)),
                                   &src_kv_pair->kv.a.v_json, &(*new_kv_pair)->kv.a.v_json);
        if (ret < 0)
            WOLFSENTRY_ERROR_RERETURN(wolfsentry_centijson_errcode_translate(ret));
    }
#endif

    WOLFSENTRY_TABLE_ENT_HEADER_RESET(**new_ent);

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_delete(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    const char *key,
    int key_len)
{
    struct wolfsentry_kv_pair_internal *kv_template;
    struct wolfsentry_kv_pair_internal *old = NULL;
    wolfsentry_errcode_t ret;
    if ((ret = wolfsentry_kv_new(WOLFSENTRY_CONTEXT_ARGS_OUT, key, key_len, 0 /* data_len */, &kv_template)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    WOLFSENTRY_MUTEX_OR_RETURN();

    ret = wolfsentry_kv_get_1(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_table, kv_template, &old);
    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_kv_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, kv_template, NULL));
    WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);
    if (old->kv.v_type & WOLFSENTRY_KV_FLAG_READONLY)
        WOLFSENTRY_ERROR_UNLOCK_AND_RETURN(NOT_PERMITTED);
    if ((ret = wolfsentry_table_ent_delete_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &old->header)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    ret = wolfsentry_kv_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, old, NULL);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

struct apply_validator_context {
    struct wolfsentry_context *wolfsentry;
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread;
#endif
    wolfsentry_kv_validator_t validator;
};

static wolfsentry_errcode_t apply_validator(struct apply_validator_context *context, struct wolfsentry_kv_pair_internal *object, wolfsentry_action_res_t *action_results) {
    (void)action_results;
#ifdef WOLFSENTRY_THREADSAFE
    WOLFSENTRY_ERROR_RERETURN(context->validator(context->wolfsentry, context->thread, &object->kv));
#else
    WOLFSENTRY_ERROR_RERETURN(context->validator(context->wolfsentry, &object->kv));
#endif
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_set_validator(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_table *kv_table,
    wolfsentry_kv_validator_t validator,
    wolfsentry_action_res_t *action_results)
{
    WOLFSENTRY_MUTEX_OR_RETURN();
    if (validator) {
        struct apply_validator_context context = { wolfsentry,
#ifdef WOLFSENTRY_THREADSAFE
                                                   thread,
#endif
                                                   validator };
        wolfsentry_errcode_t ret = wolfsentry_table_map(WOLFSENTRY_CONTEXT_ARGS_OUT, &kv_table->header, (wolfsentry_map_function_t)apply_validator, (void *)&context, action_results);
        WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);
    }
    wolfsentry->user_values->validator = validator;
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_kv_pair_export(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_pair_internal *kv,
    const struct wolfsentry_kv_pair **kv_exports)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    *kv_exports = &kv->kv;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_iterate_start(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_table *table,
    struct wolfsentry_cursor **cursor)
{
    int ret;
    if ((*cursor = (struct wolfsentry_cursor *)WOLFSENTRY_MALLOC(sizeof **cursor)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if ((ret = wolfsentry_table_cursor_init(WOLFSENTRY_CONTEXT_ARGS_OUT, *cursor)) < 0)
        goto out;
    if ((ret = wolfsentry_table_cursor_seek_to_head(&table->header, *cursor)) < 0)
        goto out;
  out:
    if (ret < 0)
        WOLFSENTRY_FREE(*cursor);
    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_iterate_seek_to_head(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_table *table,
    struct wolfsentry_cursor *cursor)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_table_cursor_seek_to_head(&table->header, cursor));
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_iterate_seek_to_tail(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_table *table,
    struct wolfsentry_cursor *cursor)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_table_cursor_seek_to_tail(&table->header, cursor));
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_iterate_current(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_kv_pair_internal **kv)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    (void)table;
    *kv = (struct wolfsentry_kv_pair_internal *)wolfsentry_table_cursor_current(cursor);
    if (*kv == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_iterate_prev(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_kv_pair_internal **kv)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    (void)table;
    *kv = (struct wolfsentry_kv_pair_internal *)wolfsentry_table_cursor_prev(cursor);
    if (*kv == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_iterate_next(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_table *table,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_kv_pair_internal **kv)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    (void)table;
    *kv = (struct wolfsentry_kv_pair_internal *)wolfsentry_table_cursor_next(cursor);
    if (*kv == NULL)
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_iterate_end(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_kv_table *table,
    struct wolfsentry_cursor **cursor)
{
    (void)table;
    WOLFSENTRY_FREE(*cursor);
    *cursor = NULL;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_set_validator(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_kv_validator_t validator,
    wolfsentry_action_res_t *action_results)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_kv_set_validator(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, validator, action_results));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_set_mutability(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    int mutable)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv = NULL;
    if ((ret = wolfsentry_kv_get_2(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, key, key_len, WOLFSENTRY_KV_NONE, &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_kv_set_mutability(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv, mutable));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_mutability(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    int *mutable)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv = NULL;
    if ((ret = wolfsentry_kv_get_2(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, key, key_len, WOLFSENTRY_KV_NONE, &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    *mutable = wolfsentry_kv_get_mutability(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_type(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    wolfsentry_kv_type_t *type)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_kv_get_type(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, key, key_len, type));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_delete(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_kv_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, key, key_len));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_null(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    int overwrite_p)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv;
    if ((ret = wolfsentry_kv_new(WOLFSENTRY_CONTEXT_ARGS_OUT, key, key_len, 0 /* data_len */, &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    kv->kv.v_type = WOLFSENTRY_KV_NULL;
    if (overwrite_p)
        ret = wolfsentry_kv_set(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);
    else
        ret = wolfsentry_kv_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);

    if (ret < 0)
        WOLFSENTRY_FREE(kv);

    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_bool(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    wolfsentry_kv_type_t value,
    int overwrite_p)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv;
    if ((value != WOLFSENTRY_KV_TRUE) && (value != WOLFSENTRY_KV_FALSE))
        WOLFSENTRY_ERROR_RETURN(WRONG_TYPE);
    if ((ret = wolfsentry_kv_new(WOLFSENTRY_CONTEXT_ARGS_OUT, key, key_len, 0 /* data_len */, &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    kv->kv.v_type = value;
    if (overwrite_p)
        ret = wolfsentry_kv_set(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);
    else
        ret = wolfsentry_kv_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);

    if (ret < 0)
        WOLFSENTRY_FREE(kv);

    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_bool(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    wolfsentry_kv_type_t *value)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv = NULL;
    if ((ret = wolfsentry_kv_get_2(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, key, key_len, WOLFSENTRY_KV_NONE, &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    if ((WOLFSENTRY_KV_TYPE(&kv->kv) != WOLFSENTRY_KV_TRUE) &&
        (WOLFSENTRY_KV_TYPE(&kv->kv) != WOLFSENTRY_KV_FALSE))
        WOLFSENTRY_ERROR_RETURN(WRONG_TYPE);
    *value = WOLFSENTRY_KV_TYPE(&kv->kv);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_uint(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    uint64_t value,
    int overwrite_p)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv;
    if ((ret = wolfsentry_kv_new(WOLFSENTRY_CONTEXT_ARGS_OUT, key, key_len, 0 /* data_len */, &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    kv->kv.v_type = WOLFSENTRY_KV_UINT;
    WOLFSENTRY_KV_V_UINT(&kv->kv) = value;
    if (overwrite_p)
        ret = wolfsentry_kv_set(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);
    else
        ret = wolfsentry_kv_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);
    if (ret < 0)
        WOLFSENTRY_FREE(kv);

    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_uint(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    uint64_t *value)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv = NULL;
    if ((ret = wolfsentry_kv_get_2(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, key, key_len, WOLFSENTRY_KV_UINT, &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    *value = WOLFSENTRY_KV_V_UINT(&kv->kv);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_sint(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    int64_t value,
    int overwrite_p)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv;
    if ((ret = wolfsentry_kv_new(WOLFSENTRY_CONTEXT_ARGS_OUT, key, key_len, 0 /* data_len */, &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    kv->kv.v_type = WOLFSENTRY_KV_SINT;
    WOLFSENTRY_KV_V_SINT(&kv->kv) = value;
    if (overwrite_p)
        ret = wolfsentry_kv_set(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);
    else
        ret = wolfsentry_kv_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);

    if (ret < 0)
        WOLFSENTRY_FREE(kv);

    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_sint(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    int64_t *value)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv = NULL;
    if ((ret = wolfsentry_kv_get_2(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, key, key_len, WOLFSENTRY_KV_SINT, &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    *value = WOLFSENTRY_KV_V_SINT(&kv->kv);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_double(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    double value,
    int overwrite_p)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv;
    if ((ret = wolfsentry_kv_new(WOLFSENTRY_CONTEXT_ARGS_OUT, key, key_len, 0 /* data_len */, &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    kv->kv.v_type = WOLFSENTRY_KV_FLOAT;
    WOLFSENTRY_KV_V_FLOAT(&kv->kv) = value;
    if (overwrite_p)
        ret = wolfsentry_kv_set(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);
    else
        ret = wolfsentry_kv_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);

    if (ret < 0)
        WOLFSENTRY_FREE(kv);

    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_float(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    double *value)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv = NULL;
    if ((ret = wolfsentry_kv_get_2(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, key, key_len, WOLFSENTRY_KV_FLOAT, &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    *value = WOLFSENTRY_KV_V_FLOAT(&kv->kv);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_string(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    const char *value,
    int value_len /* without terminating null */,
    int overwrite_p)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv;
    if (value_len < 0)
        value_len = (int)strlen(value);
    if (value_len > WOLFSENTRY_KV_MAX_VALUE_BYTES)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
    if ((ret = wolfsentry_kv_new(WOLFSENTRY_CONTEXT_ARGS_OUT, key, key_len, value_len + 1, &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    kv->kv.v_type = WOLFSENTRY_KV_STRING;
    WOLFSENTRY_KV_V_STRING_LEN(&kv->kv) = (size_t)value_len;
    memcpy(WOLFSENTRY_KV_V_STRING(&kv->kv), value, (size_t)value_len);
    WOLFSENTRY_KV_V_STRING(&kv->kv)[value_len] = 0;
    if (overwrite_p)
        ret = wolfsentry_kv_set(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);
    else
        ret = wolfsentry_kv_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);

    if (ret < 0)
        WOLFSENTRY_FREE(kv);

    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_string(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    const char **value,
    int *value_len,
    struct wolfsentry_kv_pair_internal **user_value_record)
{
    wolfsentry_errcode_t ret;
    if ((ret = wolfsentry_kv_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, key, key_len, WOLFSENTRY_KV_STRING, user_value_record)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    *value = WOLFSENTRY_KV_V_STRING(&(*user_value_record)->kv);
    *value_len = (int)WOLFSENTRY_KV_V_STRING_LEN(&(*user_value_record)->kv);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_bytes(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    const byte *value,
    int value_len,
    int overwrite_p)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv;
    if ((ret = wolfsentry_kv_new(WOLFSENTRY_CONTEXT_ARGS_OUT, key, key_len, value_len, &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    kv->kv.v_type = WOLFSENTRY_KV_BYTES;
    WOLFSENTRY_KV_V_BYTES_LEN(&kv->kv) = (size_t)value_len;
    memcpy(WOLFSENTRY_KV_V_BYTES(&kv->kv), value, (size_t)value_len);
    if (overwrite_p)
        ret = wolfsentry_kv_set(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);
    else
        ret = wolfsentry_kv_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);

    if (ret < 0)
        WOLFSENTRY_FREE(kv);

    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_bytes_base64(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    const char *value,
    int value_len,
    int overwrite_p)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv;
    if (value_len < 0)
        value_len = (int)strlen(value);
    if ((ret = wolfsentry_kv_new(WOLFSENTRY_CONTEXT_ARGS_OUT, key, key_len, WOLFSENTRY_BASE64_DECODED_BUFSPC(value_len), &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    kv->kv.v_type = WOLFSENTRY_KV_BYTES;
    WOLFSENTRY_KV_V_BYTES_LEN(&kv->kv) = (size_t)WOLFSENTRY_BASE64_DECODED_BUFSPC(value_len);
    if ((ret = wolfsentry_base64_decode(value, (size_t)value_len, WOLFSENTRY_KV_V_BYTES(&kv->kv), &WOLFSENTRY_KV_V_BYTES_LEN(&kv->kv), 1 /* ignore_junk_p */)) < 0)
        goto out;

    if (overwrite_p)
        ret = wolfsentry_kv_set(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);
    else
        ret = wolfsentry_kv_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);

  out:

    if (ret < 0)
        WOLFSENTRY_FREE(kv);

    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_bytes(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    const byte **value,
    int *value_len,
    struct wolfsentry_kv_pair_internal **user_value_record)
{
    wolfsentry_errcode_t ret;
    if ((ret = wolfsentry_kv_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, key, key_len, WOLFSENTRY_KV_BYTES, user_value_record)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    *value = WOLFSENTRY_KV_V_BYTES(&(*user_value_record)->kv);
    *value_len = (int)WOLFSENTRY_KV_V_BYTES_LEN(&(*user_value_record)->kv);
    WOLFSENTRY_RETURN_OK;
}

#ifdef WOLFSENTRY_HAVE_JSON_DOM
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_get_json(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    JSON_VALUE **value,
    struct wolfsentry_kv_pair_internal **user_value_record)
{
    wolfsentry_errcode_t ret;
    if ((ret = wolfsentry_kv_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, key, key_len, WOLFSENTRY_KV_STRING, user_value_record)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    *value = WOLFSENTRY_KV_V_JSON(&(*user_value_record)->kv);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_store_json(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *key,
    int key_len,
    JSON_VALUE *value,
    int overwrite_p)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_kv_pair_internal *kv;
    if ((ret = wolfsentry_kv_new(WOLFSENTRY_CONTEXT_ARGS_OUT, key, key_len, 0 /* value_len */, &kv)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    kv->kv.v_type = WOLFSENTRY_KV_JSON;
    memcpy(&kv->kv.a.v_json, value, sizeof kv->kv.a.v_json);
    if (overwrite_p)
        ret = wolfsentry_kv_set(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);
    else
        ret = wolfsentry_kv_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, kv);

    if (ret < 0)
        WOLFSENTRY_FREE(kv);

    WOLFSENTRY_ERROR_RERETURN(ret);
}
#endif /* WOLFSENTRY_HAVE_JSON_DOM */

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_value_release_record(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_kv_pair_internal **user_value_record)
{
    wolfsentry_errcode_t ret = wolfsentry_kv_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, *user_value_record, NULL);
    if (ret >= 0)
        *user_value_record = NULL;
    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_values_iterate_start(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_cursor **cursor)
{
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_kv_table_iterate_start(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, cursor));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_values_iterate_seek_to_head(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_cursor *cursor)
{
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_kv_table_iterate_seek_to_head(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, cursor));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_values_iterate_seek_to_tail(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_cursor *cursor)
{
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_kv_table_iterate_seek_to_tail(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, cursor));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_values_iterate_current(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_kv_pair_internal **kv)
{
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_kv_table_iterate_current(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, cursor, kv));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_values_iterate_prev(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_kv_pair_internal **kv)
{
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_kv_table_iterate_prev(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, cursor, kv));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_values_iterate_next(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_cursor *cursor,
    struct wolfsentry_kv_pair_internal **kv)
{
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_kv_table_iterate_next(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, cursor, kv));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_user_values_iterate_end(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_cursor **cursor)
{
    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_kv_table_iterate_end(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->user_values, cursor));
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_init(
    struct wolfsentry_kv_table *kv_table)
{
    WOLFSENTRY_TABLE_HEADER_RESET(kv_table->header);
    kv_table->header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_kv_key_cmp;
    kv_table->header.free_fn = (wolfsentry_ent_free_fn_t)wolfsentry_kv_drop_reference;
    kv_table->header.ent_type = WOLFSENTRY_OBJECT_TYPE_KV;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_kv_table_clone_header(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    (void)src_table;
    (void)dest_context;
    (void)dest_table;
    (void)flags;

    if (src_table->ent_type != WOLFSENTRY_OBJECT_TYPE_KV)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    ((struct wolfsentry_kv_table *)dest_table)->validator = ((struct wolfsentry_kv_table *)src_table)->validator;

    WOLFSENTRY_RETURN_OK;
}
