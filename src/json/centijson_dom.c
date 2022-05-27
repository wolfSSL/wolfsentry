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

#include "wolfsentry/centijson_dom.h"

#include <string.h>


static int
init_number(VALUE* v, const char* data, size_t data_size)
{
    int is_int32_compatible;
    int is_uint32_compatible;
    int is_int64_compatible;
    int is_uint64_compatible;

    json_analyze_number(data, data_size,
            &is_int32_compatible, &is_uint32_compatible,
            &is_int64_compatible, &is_uint64_compatible);

    if(is_int32_compatible) {
        return value_init_int32(v, json_number_to_int32(data, data_size));
    } else if(is_uint32_compatible) {
        return value_init_uint32(v, json_number_to_uint32(data, data_size));
    } else if(is_int64_compatible) {
        return value_init_int64(v, json_number_to_int64(data, data_size));
    } else if(is_uint64_compatible) {
        return value_init_uint64(v, json_number_to_uint64(data, data_size));
    } else {
        double d;
        int err;
        err = json_number_to_double(data, data_size, &d);
        if(err != 0)
            return err;
        return value_init_double(v, d);
    }
}

static int
json_dom_process(JSON_TYPE type, const char* data, size_t data_size, void* user_data)
{
    JSON_DOM_PARSER* dom_parser = (JSON_DOM_PARSER*) user_data;
    VALUE* new_value;
    int init_val_ret = 0;

    if(type == JSON_ARRAY_END || type == JSON_OBJECT_END) {
        /* Reached end of current array or object? Just pop-up in the path. */
        dom_parser->path_size--;
        return 0;
    }

    if(type == JSON_KEY) {
        /* Object key: We just store it until we get the value to use it with. */
        if(value_init_string_(&dom_parser->key, data, data_size) != 0)
            return JSON_ERR_OUTOFMEMORY;
        return 0;
    }

    /* We have to create a new value. We need to add it into the enclosing
     * array or object; or we are not in one, then store it directly into the
     * root. */
    if(dom_parser->path_size > 0) {
        VALUE* parent = dom_parser->path[dom_parser->path_size - 1];

        if(value_type(parent) == VALUE_ARRAY) {
            new_value = value_array_append(parent);
            if(new_value == NULL)
                return JSON_ERR_OUTOFMEMORY;
        } else {
            new_value = value_dict_get_or_add_(parent,
                                value_string(&dom_parser->key),
                                value_string_length(&dom_parser->key));
            value_fini(&dom_parser->key);

            if(new_value == NULL)
                return JSON_ERR_OUTOFMEMORY;

            if(!value_is_new(new_value)) {
                /* We have already set value for this key. */
                switch(dom_parser->flags & JSON_DOM_DUPKEY_MASK) {
                    case JSON_DOM_DUPKEY_USEFIRST:  return 0;
                    case JSON_DOM_DUPKEY_USELAST:   value_fini(new_value); break;
                    case JSON_DOM_DUPKEY_ABORT:     /* Pass through. */
                    default:
                        memcpy(&dom_parser->parser.err_pos, &dom_parser->parser.value_pos, sizeof(JSON_INPUT_POS));
                        return JSON_DOM_ERR_DUPKEY;
                }
            }
        }
    } else {
        new_value = &dom_parser->root;
    }

    /* Initialize the new value. */
    switch(type) {
        case JSON_NULL:         value_init_null(new_value); break;
        case JSON_FALSE:        value_init_bool(new_value, 0); break;
        case JSON_TRUE:         value_init_bool(new_value, 1); break;
        case JSON_NUMBER:       init_val_ret = init_number(new_value, data, data_size); break;
        case JSON_STRING:       init_val_ret = value_init_string_(new_value, data, data_size); break;
        case JSON_ARRAY_BEG:    init_val_ret = value_init_array(new_value); break;
        case JSON_OBJECT_BEG:   init_val_ret = value_init_dict_ex(new_value, NULL, dom_parser->dict_flags); break;
        default:                return JSON_ERR_INTERNAL;
    }

    if(init_val_ret < 0)
        return JSON_ERR_OUTOFMEMORY;

    if(type == JSON_ARRAY_BEG || type == JSON_OBJECT_BEG) {
        /* Push the array or object to the path, so we know where to
         * append their values. */
        if(dom_parser->path_size >= dom_parser->path_alloc) {
            VALUE** new_path;
            size_t new_path_alloc = dom_parser->path_alloc * 2;

            if(new_path_alloc == 0)
                new_path_alloc = 32;
            new_path = (VALUE**) realloc(dom_parser->path, new_path_alloc * sizeof(VALUE*));
            if(new_path == NULL)
                return JSON_ERR_OUTOFMEMORY;

            dom_parser->path = new_path;
            dom_parser->path_alloc = new_path_alloc;
        }

        dom_parser->path[dom_parser->path_size++] = new_value;
    }

    return 0;
}

int
json_dom_init(JSON_DOM_PARSER* dom_parser, const JSON_CONFIG* config, unsigned dom_flags)
{
    static const JSON_CALLBACKS callbacks = {
        json_dom_process
    };

    dom_parser->path = NULL;
    dom_parser->path_size = 0;
    dom_parser->path_alloc = 0;
    value_init_null(&dom_parser->root);
    value_init_null(&dom_parser->key);
    dom_parser->flags = dom_flags;
    dom_parser->dict_flags = (dom_flags & JSON_DOM_MAINTAINDICTORDER) ? VALUE_DICT_MAINTAINORDER : 0;

    return json_init(&dom_parser->parser, &callbacks, config, (void*) dom_parser);
}

int
json_dom_feed(JSON_DOM_PARSER* dom_parser, const char* input, size_t size)
{
    return json_feed(&dom_parser->parser, input, size);
}

int
json_dom_fini(JSON_DOM_PARSER* dom_parser, VALUE* p_root, JSON_INPUT_POS* p_pos)
{
    int ret;

    ret = json_fini(&dom_parser->parser, p_pos);

    if(ret >= 0) {
        memcpy(p_root, &dom_parser->root, sizeof(VALUE));
    } else {
        value_init_null(p_root);
        value_fini(&dom_parser->root);
    }

    value_fini(&dom_parser->key);
    free(dom_parser->path);

    return ret;
}

int
json_dom_parse(const char* input, size_t size, const JSON_CONFIG* config,
               unsigned dom_flags, VALUE* p_root, JSON_INPUT_POS* p_pos)
{
    JSON_DOM_PARSER dom_parser;
    int ret;

    ret = json_dom_init(&dom_parser, config, dom_flags);
    if(ret < 0)
        return ret;

    /* We rely on propagation of any error code into json_fini(). */
    json_dom_feed(&dom_parser, input, size);

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
        int ret = params->write_func(str, (run > n - i) ? n - i : run, params->user_data);
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
        return params->write_func("\r\n", 2, params->user_data);
    else
        return params->write_func("\n", 1, params->user_data);
}

static int
json_dom_dump_helper(const VALUE* node, int nest_level,
                     JSON_DOM_DUMP_PARAMS* params)
{
    int ret;

    if(nest_level >= 0) {
        ret = json_dom_dump_indent(nest_level, params);
        if(ret < 0)
            return ret;
    } else {
        nest_level = -nest_level;
    }

    switch(value_type(node)) {
        case VALUE_NULL:
            ret = params->write_func("null", 4, params->user_data);
            break;

        case VALUE_BOOL:
            if(value_bool(node))
                ret = params->write_func("true", 4, params->user_data);
            else
                ret = params->write_func("false", 5, params->user_data);
            break;

        case VALUE_INT32:
            ret = json_dump_int32(value_int32(node),
                            params->write_func, params->user_data);
            break;

        case VALUE_UINT32:
            ret = json_dump_uint32(value_uint32(node),
                            params->write_func, params->user_data);
            break;

        case VALUE_INT64:
            ret = json_dump_int64(value_int64(node),
                            params->write_func, params->user_data);
            break;

        case VALUE_UINT64:
            ret = json_dump_uint64(value_uint64(node),
                            params->write_func, params->user_data);
            break;

        case VALUE_FLOAT:
        case VALUE_DOUBLE:
            ret = json_dump_double(value_double(node),
                            params->write_func, params->user_data);
            break;

        case VALUE_STRING:
            ret = json_dump_string(value_string(node), value_string_length(node),
                            params->write_func, params->user_data);
            break;

        case VALUE_ARRAY:
        {
            const VALUE* values;
            size_t i, n;

            ret = params->write_func("[", 1, params->user_data);
            if(ret < 0)
                return ret;

            ret = json_dom_dump_newline(params);
            if(ret < 0)
                return ret;

            n = value_array_size(node);
            values = value_array_get_all(node);
            for(i = 0; i < n; i++) {
                ret = json_dom_dump_helper(&values[i], nest_level+1, params);
                if(ret < 0)
                    return ret;

                if(i < n - 1) {
                    ret = params->write_func(",", 1, params->user_data);
                    if(ret < 0)
                        return ret;
                }

                ret = json_dom_dump_newline(params);
                if(ret < 0)
                    return ret;
            }

            ret = json_dom_dump_indent(nest_level, params);
            if(ret < 0)
                return ret;

            ret = params->write_func("]", 1, params->user_data);
            break;
        }

        case VALUE_DICT:
        {
            const VALUE** keys;
            size_t i, n;

            ret = params->write_func("{", 1, params->user_data);
            if(ret < 0)
                return ret;

            ret = json_dom_dump_newline(params);
            if(ret < 0)
                return ret;

            n = value_dict_size(node);
            if(n > 0) {
                keys = malloc(sizeof(VALUE*) * n);
                if(keys == NULL)
                    return JSON_ERR_OUTOFMEMORY;

                if((params->flags & JSON_DOM_DUMP_PREFERDICTORDER)  &&
                   (value_dict_flags(node) & VALUE_DICT_MAINTAINORDER))
                    value_dict_keys_ordered(node, keys, n);
                else
                    value_dict_keys_sorted(node, keys, n);

                for(i = 0; i < n; i++) {
                    VALUE* value;

                    ret = json_dom_dump_helper(keys[i], nest_level+1, params);
                    if(ret < 0)
                        break;

                    ret = params->write_func(": ",
                            (params->flags & JSON_DOM_DUMP_MINIMIZE) ? 1 : 2,
                            params->user_data);
                    if(ret < 0)
                        break;

                    value = value_dict_get_(node, value_string(keys[i]), value_string_length(keys[i]));
                    ret = json_dom_dump_helper(value, -(nest_level+1), params);
                    if(ret < 0)
                        break;

                    if(i < n - 1) {
                        ret = params->write_func(",", 1, params->user_data);
                        if(ret < 0)
                            break;
                    }

                    ret = json_dom_dump_newline(params);
                    if(ret < 0)
                        break;
                }

                free(keys);
                if(ret < 0)
                    return ret;
            }

            ret = json_dom_dump_indent(nest_level, params);
            if(ret < 0)
                return ret;

            ret = params->write_func("}", 1, params->user_data);
            break;
        }
    }

    return ret;
}

int
json_dom_dump(const VALUE* root, JSON_DUMP_CALLBACK write_func,
              void* user_data, unsigned tab_width, unsigned flags)
{
    JSON_DOM_DUMP_PARAMS params = { write_func, user_data, tab_width, flags };
    int ret;

    ret = json_dom_dump_helper(root, 0, &params);
    if(ret < 0)
        return ret;

    ret = json_dom_dump_newline(&params);
    return ret;
}

const char* json_dom_error_str(int err_code)
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
