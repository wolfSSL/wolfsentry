/*
 * centijson_dom.c
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

/*
 * CentiJSON
 * <http://github.com/mity/centijson>
 *
 * Copyright (c) 2018 Martin Mitas
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifdef WOLFSENTRY
    #ifndef WOLFSENTRY_HAVE_JSON_DOM
        #error building centijson_dom.c with WOLFSENTRY_HAVE_JSON_DOM unset
    #endif
    #include "wolfsentry/wolfsentry_json.h"
#else
    #include <string.h>
    #include "wolfsentry/centijson_dom.h"
#endif

#include <stdlib.h>

#ifdef WOLFSENTRY

static void *json_malloc(WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator), size_t size) {
    if (allocator)
        return allocator->malloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator), size);
    else
        return malloc(size);
}
#define malloc(size) json_malloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(&dom_parser->parser, allocator), size)
static void json_free(WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator), void *ptr) {
    if (allocator)
        allocator->free(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator->context), ptr);
    else
        free(ptr);
    WOLFSENTRY_RETURN_VOID;
}
#define free(ptr) json_free(WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(&dom_parser->parser, allocator), ptr)
static void *json_realloc(WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator), void *ptr, size_t size) {
    if (ptr == NULL)
        return json_malloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator), size);
    if (allocator)
        return allocator->realloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator->context), ptr, size);
    else
        return realloc(ptr, size);
}
#define realloc(ptr, size) json_realloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(&dom_parser->parser, allocator), ptr, size)

#endif

static int
init_number(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, const unsigned char* data, size_t data_size)
{
    int is_int32_compatible;
    int is_uint32_compatible;
    int is_int64_compatible;
    int is_uint64_compatible;
    int ret;

    ret = json_analyze_number(data, data_size,
            &is_int32_compatible, &is_uint32_compatible,
            &is_int64_compatible, &is_uint64_compatible);
    if (ret < 0)
        return ret;

    if(is_int32_compatible) {
        return json_value_init_int32(
#ifdef WOLFSENTRY
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
            v, json_number_to_int32(data, data_size));
    } else if(is_uint32_compatible) {
        return json_value_init_uint32(
#ifdef WOLFSENTRY
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
            v, json_number_to_uint32(data, data_size));
    } else if(is_int64_compatible) {
        return json_value_init_int64(
#ifdef WOLFSENTRY
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
            v, json_number_to_int64(data, data_size));
    } else if(is_uint64_compatible) {
        return json_value_init_uint64(
#ifdef WOLFSENTRY
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
            v, json_number_to_uint64(data, data_size));
    } else {
        double d;
        int err;
        err = json_number_to_double(data, data_size, &d);
        if(err != 0)
            return err;
        return json_value_init_double(
#ifdef WOLFSENTRY
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
            v, d);
    }
}

int
json_dom_process(JSON_TYPE type, const unsigned char* data, size_t data_size, void* user_data)
{
    JSON_DOM_PARSER* dom_parser = (JSON_DOM_PARSER*) user_data;
    JSON_VALUE* new_json_value;
    int ret = 0;

    if(type == JSON_ARRAY_END || type == JSON_OBJECT_END) {
        /* Reached end of current array or object? Just pop-up in the path. */
        dom_parser->path_size--;
        return 0;
    }

    if(type == JSON_KEY) {
        /* Object key: We just store it until we get the json_value to use it with. */
        if(json_value_init_string_(
#ifdef WOLFSENTRY
               WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(&dom_parser->parser, allocator),
#endif
               &dom_parser->key, data, data_size) != 0)
            return JSON_ERR_OUTOFMEMORY;
        return 0;
    }

    /* We have to create a new json_value. We need to add it into the enclosing
     * array or object; or we are not in one, then store it directly into the
     * root. */
    if(dom_parser->path_size > 0) {
        JSON_VALUE* parent = dom_parser->path[dom_parser->path_size - 1];

        if(json_value_type(parent) == JSON_VALUE_ARRAY) {
            new_json_value = json_value_array_append(
#ifdef WOLFSENTRY
                WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(&dom_parser->parser, allocator),
#endif
                parent);
            if(new_json_value == NULL)
                return JSON_ERR_OUTOFMEMORY;
        } else {
            new_json_value = json_value_dict_get_or_add_(
#ifdef WOLFSENTRY
                WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(&dom_parser->parser, allocator),
#endif
                                parent,
                                json_value_string(&dom_parser->key),
                                json_value_string_length(&dom_parser->key));
            ret = json_value_fini(
#ifdef WOLFSENTRY
                WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(&dom_parser->parser, allocator),
#endif
                &dom_parser->key);
            if (ret < 0)
                return ret;

            if(new_json_value == NULL)
                return JSON_ERR_OUTOFMEMORY;

            if(!json_value_is_new(new_json_value)) {
                /* We have already set json_value for this key. */
                switch(dom_parser->flags & JSON_DOM_DUPKEY_MASK) {
                    case JSON_DOM_DUPKEY_USEFIRST:  return 0;
                    case JSON_DOM_DUPKEY_USELAST:
                        ret = json_value_fini(
#ifdef WOLFSENTRY
                            WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(&dom_parser->parser, allocator),
#endif
                            new_json_value);
                        if (ret < 0)
                            return ret;
                        break;
                    case JSON_DOM_DUPKEY_ABORT:     /* Pass through. */
                    default:
                        memcpy(&dom_parser->parser.err_pos, &dom_parser->parser.value_pos, sizeof(JSON_INPUT_POS));
                        return JSON_DOM_ERR_DUPKEY;
                }
            }
        }
    } else {
        new_json_value = &dom_parser->root;
    }

    /* Initialize the new json_value. */
    switch(type) {
        case JSON_NULL:         json_value_init_null(new_json_value); break;
        case JSON_FALSE:        ret = json_value_init_bool(new_json_value, 0); break;
        case JSON_TRUE:         ret = json_value_init_bool(new_json_value, 1); break;
        case JSON_NUMBER:
            ret = init_number(
#ifdef WOLFSENTRY
                WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(&dom_parser->parser, allocator),
#endif
                new_json_value, data, data_size);
            break;
        case JSON_STRING:
            ret = json_value_init_string_(
#ifdef WOLFSENTRY
                WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(&dom_parser->parser, allocator),
#endif
                new_json_value, data, data_size);
            break;
        case JSON_ARRAY_BEG:
            ret = json_value_init_array(
#ifdef WOLFSENTRY
                WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(&dom_parser->parser, allocator),
#endif
                new_json_value);
            break;
        case JSON_OBJECT_BEG:
            ret = json_value_init_dict_ex(
#ifdef WOLFSENTRY
                WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(&dom_parser->parser, allocator),
#endif
                new_json_value, NULL, dom_parser->dict_flags);
            break;
        default:                return JSON_ERR_INTERNAL;
    }

    if(ret < 0)
        return JSON_ERR_OUTOFMEMORY;

    if(type == JSON_ARRAY_BEG || type == JSON_OBJECT_BEG) {
        /* Push the array or object to the path, so we know where to
         * append their json_values. */
        if(dom_parser->path_size >= dom_parser->path_alloc) {
            JSON_VALUE** new_path;
            size_t new_path_alloc = dom_parser->path_alloc * 2;

            if(new_path_alloc == 0)
                new_path_alloc = 32;
            new_path = (JSON_VALUE**) realloc(dom_parser->path, new_path_alloc * sizeof(JSON_VALUE*));
            if(new_path == NULL)
                return JSON_ERR_OUTOFMEMORY;

            dom_parser->path = new_path;
            dom_parser->path_alloc = new_path_alloc;
        }

        dom_parser->path[dom_parser->path_size++] = new_json_value;
    }

    return 0;
}

WOLFSENTRY_API int
json_dom_init_1(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_DOM_PARSER* dom_parser, unsigned dom_flags)
{
    dom_parser->path = NULL;
    dom_parser->path_size = 0;
    dom_parser->path_alloc = 0;
    json_value_init_null(&dom_parser->root);
    json_value_init_null(&dom_parser->key);
    dom_parser->flags = dom_flags | JSON_DOM_FLAG_INITED;
    dom_parser->dict_flags = (dom_flags & JSON_DOM_MAINTAINDICTORDER) ? JSON_VALUE_DICT_MAINTAINORDER : 0;
#ifdef WOLFSENTRY
    dom_parser->parser.allocator = allocator;
#ifdef WOLFSENTRY_THREADSAFE
    dom_parser->parser.thread = thread;
#endif    
#endif
    return 0;
}

int
json_dom_init(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_DOM_PARSER* dom_parser, const JSON_CONFIG* config, unsigned dom_flags)
{
    static const JSON_CALLBACKS callbacks = {
        json_dom_process
    };
    int ret = json_dom_init_1(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        dom_parser, dom_flags);
    if (ret == 0)
        return json_init(
#ifdef WOLFSENTRY
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
            &dom_parser->parser, &callbacks, config, (void*) dom_parser);
    else
        return ret;
}

WOLFSENTRY_API int
json_dom_feed(JSON_DOM_PARSER* dom_parser, const unsigned char* input, size_t size)
{
    return json_feed(&dom_parser->parser, input, size);
}

int json_dom_clean(JSON_DOM_PARSER* dom_parser) {
    int ret;

    if (! (dom_parser->flags & JSON_DOM_FLAG_INITED))
        return JSON_ERR_NOT_INITED;

    ret = json_value_fini(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(&dom_parser->parser, allocator),
#endif
        &dom_parser->root);
    if (ret < 0)
        return ret;

    ret = json_value_fini(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX3(&dom_parser->parser, allocator),
#endif
        &dom_parser->key);
    if (ret < 0)
        return ret;

    free(dom_parser->path);
    dom_parser->path = NULL;

    dom_parser->flags &= ~JSON_DOM_FLAG_INITED;

    return 0;
}

WOLFSENTRY_API int
json_dom_fini(JSON_DOM_PARSER* dom_parser, JSON_VALUE* p_root, JSON_INPUT_POS* p_pos)
{
    int ret;

    if (! (dom_parser->flags & JSON_DOM_FLAG_INITED))
        return JSON_ERR_NOT_INITED;

    ret = json_fini(&dom_parser->parser, p_pos);

    if(ret >= 0) {
        memcpy(p_root, &dom_parser->root, sizeof(JSON_VALUE));
        json_value_init_null(&dom_parser->root);
    } else {
        json_value_init_null(p_root);
    }

    (void)json_dom_clean(dom_parser);

    return ret;
}

/* Used internally by load_config.c:handle_user_value_clause() */
int
json_dom_fini_aux(JSON_DOM_PARSER* dom_parser, JSON_VALUE* p_root)
{
    if (! (dom_parser->flags & JSON_DOM_FLAG_INITED))
        return JSON_ERR_NOT_INITED;

    memcpy(p_root, &dom_parser->root, sizeof(JSON_VALUE));
    json_value_init_null(&dom_parser->root);

    return json_dom_clean(dom_parser);
}

WOLFSENTRY_API int
json_dom_parse(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
               const unsigned char* input, size_t size, const JSON_CONFIG* config,
               unsigned dom_flags, JSON_VALUE* p_root, JSON_INPUT_POS* p_pos)
{
    JSON_DOM_PARSER dom_parser;
    int ret;

    ret = json_dom_init(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        &dom_parser, config, dom_flags);
    if(ret < 0)
        return ret;

    /* We rely on propagation of any error code into json_fini(). */
    if (json_dom_feed(&dom_parser, input, size) < 0) {
    }

    return json_dom_fini(&dom_parser, p_root, p_pos);
}

typedef struct JSON_DOM_DUMP_PARAMS {
    JSON_DUMP_CALLBACK write_func;
    void* user_data;
    unsigned tab_width;
    unsigned flags;
} JSON_DOM_DUMP_PARAMS;

static int
json_dom_dump_indent(unsigned nest_level, JSON_DOM_DUMP_PARAMS* params)
{
    static const char tabs[] = "\t\t\t\t\t\t\t\t";
    static const unsigned n_tabs = sizeof(tabs) - 1;
    static const char spaces[] = "                                ";
    static const unsigned n_spaces = sizeof(spaces) - 1;

    unsigned i;
    unsigned n;
    unsigned run;
    const char* str;

    if((params->flags & JSON_DOM_DUMP_MINIMIZE)  ||  nest_level == 0)
        return 0;

    if(params->flags & JSON_DOM_DUMP_INDENTWITHSPACES) {
        n = nest_level * params->tab_width;
        run = n_spaces;
        str = spaces;
    } else {
        n = nest_level;
        run = n_tabs;
        str = tabs;
    }

    for(i = 0; i < n; i += run) {
        int ret = params->write_func((const unsigned char *)str, (run > n - i) ? n - i : run, params->user_data);
        if(ret < 0)
            return ret;
    }

    return 0;
}

static int
json_dom_dump_newline(JSON_DOM_DUMP_PARAMS* params)
{
    if(params->flags & JSON_DOM_DUMP_MINIMIZE)
        return 0;

    if(params->flags & JSON_DOM_DUMP_FORCECLRF)
        return params->write_func((const unsigned char *)"\r\n", 2, params->user_data);
    else
        return params->write_func((const unsigned char *)"\n", 1, params->user_data);
}

/* NOLINTBEGIN(misc-no-recursion) */
static int
json_dom_dump_helper(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
                     const JSON_VALUE* node, int nest_level,
                     JSON_DOM_DUMP_PARAMS* params)
{
    int ret = 0;

    if(nest_level >= 0) {
        ret = json_dom_dump_indent((unsigned int)nest_level, params);
        if(ret < 0)
            return ret;
    } else {
        nest_level = -nest_level;
    }

    switch(json_value_type(node)) {
        case JSON_VALUE_NULL:
            ret = params->write_func((const unsigned char *)"null", 4, params->user_data);
            break;

        case JSON_VALUE_BOOL:
            if(json_value_bool(node))
                ret = params->write_func((const unsigned char *)"true", 4, params->user_data);
            else
                ret = params->write_func((const unsigned char *)"false", 5, params->user_data);
            break;

        case JSON_VALUE_INT32:
            ret = json_dump_int32(json_value_int32(node),
                            params->write_func, params->user_data);
            break;

        case JSON_VALUE_UINT32:
            ret = json_dump_uint32(json_value_uint32(node),
                            params->write_func, params->user_data);
            break;

        case JSON_VALUE_INT64:
            ret = json_dump_int64(json_value_int64(node),
                            params->write_func, params->user_data);
            break;

        case JSON_VALUE_UINT64:
            ret = json_dump_uint64(json_value_uint64(node),
                            params->write_func, params->user_data);
            break;

        case JSON_VALUE_FLOAT:
        case JSON_VALUE_DOUBLE:
            ret = json_dump_double(json_value_double(node),
                            params->write_func, params->user_data);
            break;

        case JSON_VALUE_STRING:
            ret = json_dump_string(json_value_string(node), json_value_string_length(node),
                            params->write_func, params->user_data);
            break;

        case JSON_VALUE_ARRAY:
        {
            const JSON_VALUE* json_values;
            size_t i, n;

            ret = params->write_func((const unsigned char *)"[", 1, params->user_data);
            if(ret < 0)
                return ret;

            ret = json_dom_dump_newline(params);
            if(ret < 0)
                return ret;

            n = json_value_array_size(node);
            json_values = json_value_array_get_all(node);
            for(i = 0; i < n; i++) {
                ret = json_dom_dump_helper(
#ifdef WOLFSENTRY
                    WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
                    &json_values[i], nest_level+1, params);
                if(ret < 0)
                    return ret;

                if(i < n - 1) {
                    ret = params->write_func((const unsigned char *)",", 1, params->user_data);
                    if(ret < 0)
                        return ret;
                }

                ret = json_dom_dump_newline(params);
                if(ret < 0)
                    return ret;
            }

            ret = json_dom_dump_indent((unsigned int)nest_level, params);
            if(ret < 0)
                return ret;

            ret = params->write_func((const unsigned char *)"]", 1, params->user_data);
            break;
        }

        case JSON_VALUE_DICT:
        {
            const JSON_VALUE** keys;
            size_t i, n;

            ret = params->write_func((const unsigned char *)"{", 1, params->user_data);
            if(ret < 0)
                return ret;

            ret = json_dom_dump_newline(params);
            if(ret < 0)
                return ret;

            n = json_value_dict_size(node);
            if(n > 0) {
                size_t keys_size;
#ifdef WOLFSENTRY
                keys = json_malloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator), sizeof(JSON_VALUE*) * n);
#else
                keys = malloc(sizeof(JSON_VALUE*) * n);
#endif
                if(keys == NULL)
                    return JSON_ERR_OUTOFMEMORY;

                if((params->flags & JSON_DOM_DUMP_PREFERDICTORDER)  &&
                   (json_value_dict_flags(node) & JSON_VALUE_DICT_MAINTAINORDER))
                    keys_size = json_value_dict_keys_ordered(node, keys, n);
                else
                    keys_size = json_value_dict_keys_sorted(node, keys, n);
                if (keys_size != n)
                    return JSON_ERR_INTERNAL;

                for(i = 0; i < n; i++) {
                    JSON_VALUE* json_value;

                    ret = json_dom_dump_helper(
#ifdef WOLFSENTRY
                        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
                        keys[i], nest_level+1, params);
                    if(ret < 0)
                        break;

                    ret = params->write_func((const unsigned char *)": ",
                            (params->flags & JSON_DOM_DUMP_MINIMIZE) ? 1 : 2,
                            params->user_data);
                    if(ret < 0)
                        break;

                    json_value = json_value_dict_get_(node, json_value_string(keys[i]), json_value_string_length(keys[i]));
                    ret = json_dom_dump_helper(
#ifdef WOLFSENTRY
                        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
                        json_value, -(nest_level+1), params);
                    if(ret < 0)
                        break;

                    if(i < n - 1) {
                        ret = params->write_func((const unsigned char *)",", 1, params->user_data);
                        if(ret < 0)
                            break;
                    }

                    ret = json_dom_dump_newline(params);
                    if(ret < 0)
                        break;
                }

#ifdef WOLFSENTRY
                json_free(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator), keys);
#else
                free(keys);
#endif
                if(ret < 0)
                    return ret;
            }

            ret = json_dom_dump_indent((unsigned int)nest_level, params);
            if(ret < 0)
                return ret;

            ret = params->write_func((const unsigned char *)"}", 1, params->user_data);
            break;
        }
    }

    return ret;
}
/* NOLINTEND(misc-no-recursion) */

WOLFSENTRY_API int
json_dom_dump(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
              const JSON_VALUE* root, JSON_DUMP_CALLBACK write_func,
              void* user_data, unsigned tab_width, unsigned flags)
{
    JSON_DOM_DUMP_PARAMS params = { write_func, user_data, tab_width, flags };
    int ret;

    ret = json_dom_dump_helper(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        root, 0, &params);
    if(ret < 0)
        return ret;

    ret = json_dom_dump_newline(&params);
    return ret;
}

WOLFSENTRY_API const char* json_dom_error_str(int err_code)
{
    static const char unexpected_code[] = "Unexpected DOM error code";
    static const char *const errs[] =
    {
        "Duplicate key" /* JSON_DOM_ERR_DUPKEY (-1000) */
    };
    const int array_size = sizeof errs / sizeof errs[0];
    if (err_code > -1000)
        return json_error_str(err_code);
    err_code += 1000;
    if(-array_size < err_code && err_code <= 0)
        return errs[-err_code];
    return unexpected_code;
}
