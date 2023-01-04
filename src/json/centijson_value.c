/*
 * C Reusables
 * <http://github.com/mity/c-reusables>
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
        #error building centijson_value.c with WOLFSENTRY_HAVE_JSON_DOM unset
    #endif
    #include "wolfsentry/wolfsentry_json.h"
#else
    #include <string.h>
    #include "wolfsentry/centijson_value.h"
#endif

#include <stdlib.h>

#ifdef WOLFSENTRY

static void *json_malloc(WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator), size_t size) {
    if (allocator)
        return allocator->malloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator->context), size);
    else
        return malloc(size);
}
#define malloc(size) json_malloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator), size)
static void json_free(WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator), void *ptr) {
    if (allocator)
        allocator->free(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator->context), ptr);
    else
        free(ptr);
    WOLFSENTRY_RETURN_VOID;
}
#define free(ptr) json_free(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator), ptr)
static void *json_realloc(WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator), void *ptr, size_t size) {
    if (ptr == NULL)
        return json_malloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator), size);
    if (allocator)
        return allocator->realloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator->context), ptr, size);
    else
        return realloc(ptr, size);
}
#define realloc(ptr, size) json_realloc(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator), ptr, size)

#endif

#define TYPE_MASK       0x0f
#define IS_NEW          0x10    /* only for JSON_VALUE_NULL */
#define HAS_REDCOLOR    0x10    /* only for JSON_VALUE_STRING (when used as RBTREE::key) */
#define HAS_ORDERLIST   0x10    /* only for JSON_VALUE_DICT */
#define HAS_CUSTOMCMP   0x20    /* only for JSON_VALUE_DICT */
#define IS_MALLOCED     0x80


typedef struct ARRAY_tag ARRAY;
struct ARRAY_tag {
    JSON_VALUE* json_value_buf;
    size_t size;
    size_t alloc;
};

typedef struct RBTREE_tag RBTREE;
struct RBTREE_tag {
    /* We store color by using the flag HAS_REDCOLOR of the key. */
    JSON_VALUE key;
    JSON_VALUE json_value;
    RBTREE* left;
    RBTREE* right;

    /* These are present only if HAS_ORDERLIST. */
    RBTREE* order_prev;
    RBTREE* order_next;
};

/* Maximal height of the RB-tree. Given we can never allocate more nodes
 * then 2^(sizeof(void*) * 8) and given the longest root<-->leaf path cannot
 * be longer then twice the shortest one in the RB-tree, the following
 * is guaranteed to be large enough. */
#define RBTREE_MAX_HEIGHT       (2 * 8 * sizeof(void*))

typedef struct DICT_tag DICT;
struct DICT_tag {
    RBTREE* root;
    size_t size;

    /* These are present only when flags JSON_VALUE_DICT_MAINTAINORDER or
     * custom_cmp_func is used. */
    RBTREE* order_head;
    RBTREE* order_tail;
    int (*cmp_func)(const unsigned char*, size_t, const unsigned char*, size_t);
};


#if defined offsetof
    #define OFFSETOF(type, member)      offsetof(type, member)
#elif defined __GNUC__ && __GNUC__ >= 4
    #define OFFSETOF(type, member)      __builtin_offsetof(type, member)
#else
    #define OFFSETOF(type, member)      ((size_t) &((type*)0)->member)
#endif


/***************
 *** Helpers ***
 ***************/

/* We don't want to include <math.h> just because of roundf() and round().
 * Especially as on some systems it requires explicit linking with math
 * library (-lm). */
#define ROUNDF(inttype, x)   ((inttype)((x) >= 0.0f ? (x) + 0.5f : (x) - 0.5f))
#define ROUNDD(inttype, x)   ((inttype)((x) >= 0.0 ? (x) + 0.5 : (x) - 0.5))


static void*
json_value_init_ex(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, JSON_VALUE_TYPE type, size_t size, size_t align)
{
    v->data.data_bytes[0] = (uint8_t) type;

    if(size + align <= sizeof(JSON_VALUE)) {
        return &v->data.data_bytes[align];
    } else {
        void* buf;

        v->data.data_bytes[0] |= IS_MALLOCED;
        buf = malloc(size);
        if(buf == NULL) {
            v->data.data_bytes[0] = (uint8_t) JSON_VALUE_NULL;
            return NULL;
        }

        v->data.data_ptrs[1] = buf;
        return buf;
    }
}

static void*
json_value_init(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, JSON_VALUE_TYPE type, size_t size)
{
    return json_value_init_ex(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, type, size, 1);
}

static int
json_value_init_simple(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, JSON_VALUE_TYPE type, const void* data, size_t size)
{
    void* payload;

    payload = json_value_init(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, type, size);
    if(payload == NULL)
        return -1;

    memcpy(payload, data, size);
    return 0;
}

static void*
json_value_payload_ex(JSON_VALUE* v, size_t align)
{
    if(v == NULL)
        return NULL;

    if(!(v->data.data_bytes[0] & IS_MALLOCED))
        return (void*)(v->data.data_bytes + align);
    else
        return v->data.data_ptrs[1];
}

static void*
json_value_payload(JSON_VALUE* v)
{
    return json_value_payload_ex(v, 1);
}


/********************
 *** Generic info ***
 ********************/

WOLFSENTRY_API JSON_VALUE_TYPE
json_value_type(const JSON_VALUE* v)
{
    if(v == NULL)
        return JSON_VALUE_NULL;
    return (JSON_VALUE_TYPE)(v->data.data_bytes[0] & TYPE_MASK);
}

WOLFSENTRY_API int
json_value_is_compatible(const JSON_VALUE* v, JSON_VALUE_TYPE type)
{
    if(json_value_type(v) == type)
        return 1;

    /* We say any numeric json_value is compatible with another numeric json_value as
     * long as the conversion does not loose much information. */
    switch(json_value_type(v)) {
        case JSON_VALUE_INT32:
            return (type == JSON_VALUE_INT64 || type == JSON_VALUE_FLOAT || type == JSON_VALUE_DOUBLE)  ||
                   (type == JSON_VALUE_UINT32 && json_value_int32(v) >= 0)  ||
                   (type == JSON_VALUE_UINT64 && json_value_int32(v) >= 0);
            break;

        case JSON_VALUE_UINT32:
            return (type == JSON_VALUE_INT64 || type == JSON_VALUE_UINT64 || type == JSON_VALUE_FLOAT || type == JSON_VALUE_DOUBLE)  ||
                   (type == JSON_VALUE_INT32 && json_value_uint32(v) <= INT32_MAX);
            break;

        case JSON_VALUE_INT64:
            return (type == JSON_VALUE_FLOAT || type == JSON_VALUE_DOUBLE)  ||
                   (type == JSON_VALUE_INT32 && json_value_int64(v) >= INT32_MIN && json_value_int64(v) <= INT32_MAX)  ||
                   (type == JSON_VALUE_UINT32 && json_value_int64(v) >= 0 && json_value_int64(v) <= UINT32_MAX)  ||
                   (type == JSON_VALUE_UINT64 && json_value_int64(v) >= 0);
            break;

        case JSON_VALUE_UINT64:
            return (type == JSON_VALUE_FLOAT || type == JSON_VALUE_DOUBLE)  ||
                   (type == JSON_VALUE_INT32 && json_value_uint64(v) <= INT32_MAX)  ||
                   (type == JSON_VALUE_UINT32 && json_value_uint64(v) <= UINT32_MAX)  ||
                   (type == JSON_VALUE_INT64 && json_value_uint64(v) <= INT64_MAX);
            break;

        case JSON_VALUE_FLOAT:
            return (type == JSON_VALUE_DOUBLE)  ||
                   (type == JSON_VALUE_INT32 && json_value_float(v) == (float)json_value_int32(v))  ||
                   (type == JSON_VALUE_UINT32 && json_value_float(v) == (float)json_value_uint32(v))  ||
                   (type == JSON_VALUE_INT64 && json_value_float(v) == (float)json_value_int64(v))  ||
                   (type == JSON_VALUE_UINT64 && json_value_float(v) == (float)json_value_uint64(v));
            break;

        case JSON_VALUE_DOUBLE:
            return (type == JSON_VALUE_FLOAT)  ||
                   (type == JSON_VALUE_INT32 && json_value_double(v) == (double)json_value_int32(v))  ||
                   (type == JSON_VALUE_UINT32 && json_value_double(v) == (double)json_value_uint32(v))  ||
                   (type == JSON_VALUE_INT64 && json_value_double(v) == (double)json_value_int64(v))  ||
                   (type == JSON_VALUE_UINT64 && json_value_double(v) == (double)json_value_uint64(v));
            break;

        default:
            break;
    }

    return 0;
}

WOLFSENTRY_API int
json_value_is_new(const JSON_VALUE* v)
{
    return (v != NULL  &&  json_value_type(v) == JSON_VALUE_NULL  &&  (v->data.data_bytes[0] & IS_NEW));
}

/* note path is technically UTF-8, but arg is signed char to streamline the
 * common case of caller code passing string literals as the path.
 */
WOLFSENTRY_API JSON_VALUE*
json_value_path(JSON_VALUE* root, const char* path)
{
    const unsigned char* token_beg = (const unsigned char *)path;
    const unsigned char* token_end;
    JSON_VALUE* v = root;

    while(1) {
        token_end = token_beg;
        while(*token_end != '\0'  &&  *token_end != '/')
            token_end++;

        if(token_end - token_beg > 2  &&  token_beg[0] == '['  &&  token_end[-1] == ']') {
            size_t index = 0;

            token_beg++;
            while('0' <= *token_beg  &&  *token_beg <= '9') {
                index = index * 10U + (*token_beg - (unsigned)'0');
                token_beg++;
            }
            if(*token_beg != ']')
                return NULL;

            v = json_value_array_get(v, index);
        } else if(token_end - token_beg > 0) {
            v = json_value_dict_get_(v, token_beg, (size_t)(token_end - token_beg));
        }

        if(v == NULL)
            return NULL;

        if(*token_end == '\0')
            return v;

        token_beg = token_end+1;
    }
}


/********************
 *** Initializers ***
 ********************/

WOLFSENTRY_API void
json_value_init_null(JSON_VALUE* v)
{
    if(v != NULL)
        v->data.data_bytes[0] = (uint8_t) JSON_VALUE_NULL;
}

static void
json_value_init_new(JSON_VALUE* v)
{
    v->data.data_bytes[0] = ((uint8_t) JSON_VALUE_NULL) | IS_NEW;
}

WOLFSENTRY_API int
json_value_init_bool(JSON_VALUE* v, int b)
{
    if(v == NULL)
        return -1;

    v->data.data_bytes[0] = (uint8_t) JSON_VALUE_BOOL;
    v->data.data_bytes[1] = (b != 0) ? 1 : 0;

    return 0;
}

WOLFSENTRY_API int
json_value_init_int32(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, int32_t i32)
{
    if(v == NULL)
        return -1;

    return json_value_init_simple(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, JSON_VALUE_INT32, &i32, sizeof(int32_t));
}

WOLFSENTRY_API int
json_value_init_uint32(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, uint32_t u32)
{
    if(v == NULL)
        return -1;

    return json_value_init_simple(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, JSON_VALUE_UINT32, &u32, sizeof(uint32_t));
}

WOLFSENTRY_API int
json_value_init_int64(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, int64_t i64)
{
    if(v == NULL)
        return -1;

    return json_value_init_simple(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, JSON_VALUE_INT64, &i64, sizeof(int64_t));
}

WOLFSENTRY_API int
json_value_init_uint64(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, uint64_t u64)
{
    if(v == NULL)
        return -1;

    return json_value_init_simple(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, JSON_VALUE_UINT64, &u64, sizeof(uint64_t));
}

WOLFSENTRY_API int
json_value_init_float(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, float f)
{
    if(v == NULL)
        return -1;

    return json_value_init_simple(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, JSON_VALUE_FLOAT, &f, sizeof(float));
}

WOLFSENTRY_API int
json_value_init_double(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, double d)
{
    if(v == NULL)
        return -1;

    return json_value_init_simple(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, JSON_VALUE_DOUBLE, &d, sizeof(double));
}

WOLFSENTRY_API int
json_value_init_string_(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, const unsigned char* str, size_t len)
{
    uint8_t* payload;
    size_t tmplen;
    size_t off;

    if(v == NULL)
        return -1;

    tmplen = len;
    off = 0;
    while(tmplen >= 128) {
        off++;
        tmplen = tmplen >> 7;
    }
    off++;

    payload = json_value_init(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, JSON_VALUE_STRING, off + len + 1);
    if(payload == NULL)
        return -1;

    tmplen = len;
    off = 0;
    while(tmplen >= 128) {
        payload[off++] = (uint8_t)(0x80 | (tmplen & 0x7f));
        tmplen = tmplen >> 7;
    }
    payload[off++] = tmplen & 0x7f;

    memcpy(payload + off, str, len);
    payload[off + len] = '\0';
    return 0;
}

WOLFSENTRY_API int
json_value_init_string(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, const unsigned char* str)
{
    return json_value_init_string_(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, str, (str != NULL) ? strlen((const char *)str) : 0);
}

WOLFSENTRY_API int
json_value_init_array(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v)
{
    uint8_t* payload;

    if(v == NULL)
        return -1;

    payload = json_value_init_ex(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, JSON_VALUE_ARRAY, sizeof(ARRAY), sizeof(void*));
    if(payload == NULL)
        return -1;
    memset(payload, 0, sizeof(ARRAY));

    return 0;
}

WOLFSENTRY_API int
json_value_init_dict(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v)
{
    return json_value_init_dict_ex(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, NULL, 0);
}

WOLFSENTRY_API int
json_value_init_dict_ex(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
                   JSON_VALUE* v,
                   int (*custom_cmp_func)(const unsigned char*, size_t, const unsigned char*, size_t),
                   unsigned flags)
{
    void* payload;
    size_t payload_size;

    if(v == NULL)
        return -1;

    if(custom_cmp_func != NULL  ||  (flags & JSON_VALUE_DICT_MAINTAINORDER))
        payload_size = sizeof(DICT);
    else
        payload_size = OFFSETOF(DICT, order_head);

    payload = json_value_init_ex(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, JSON_VALUE_DICT, payload_size, sizeof(void*));
    if(payload == NULL)
        return -1;
    memset(payload, 0, payload_size);

    if(custom_cmp_func != NULL) {
        v->data.data_bytes[0] |= HAS_CUSTOMCMP;
        ((DICT*)payload)->cmp_func = custom_cmp_func;
    }

    if(flags & JSON_VALUE_DICT_MAINTAINORDER)
        v->data.data_bytes[0] |= HAS_ORDERLIST;

    return 0;
}

WOLFSENTRY_API void
json_value_fini(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v)
{
    if(v == NULL)
        return;

    if(json_value_type(v) == JSON_VALUE_ARRAY)
        json_value_array_clean(
#ifdef WOLFSENTRY
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
            v);

    if(json_value_type(v) == JSON_VALUE_DICT)
        json_value_dict_clean(
#ifdef WOLFSENTRY
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
            v);

    if(v->data.data_bytes[0] & 0x80)
        free(json_value_payload(v));

    v->data.data_bytes[0] = JSON_VALUE_NULL;
}


/**************************
 *** Basic type getters ***
 **************************/

WOLFSENTRY_API int
json_value_bool(const JSON_VALUE* v)
{
    if(json_value_type(v) != JSON_VALUE_BOOL)
        return -1;

    return v->data.data_bytes[1];
}

WOLFSENTRY_API int32_t
json_value_int32(const JSON_VALUE* v)
{
    uint8_t* payload = json_value_payload((JSON_VALUE*) v);
    union {
        int32_t i32;
        uint32_t u32;
        int64_t i64;
        uint64_t u64;
        float f;
        double d;
    } ret;

    switch(json_value_type(v)) {
        case JSON_VALUE_INT32:     memcpy(&ret.i32, payload, sizeof(int32_t)); return (int32_t) ret.i32;
        case JSON_VALUE_UINT32:    memcpy(&ret.u32, payload, sizeof(uint32_t)); return (int32_t) ret.u32;
        case JSON_VALUE_INT64:     memcpy(&ret.i64, payload, sizeof(int64_t)); return (int32_t) ret.i64;
        case JSON_VALUE_UINT64:    memcpy(&ret.u64, payload, sizeof(uint64_t)); return (int32_t) ret.u64;
        case JSON_VALUE_FLOAT:     memcpy(&ret.f, payload, sizeof(float)); return ROUNDF(int32_t, ret.f);
        case JSON_VALUE_DOUBLE:    memcpy(&ret.d, payload, sizeof(double)); return ROUNDD(int32_t, ret.d);
        default:            return -1;
    }
}

WOLFSENTRY_API uint32_t
json_value_uint32(const JSON_VALUE* v)
{
    uint8_t* payload = json_value_payload((JSON_VALUE*) v);
    union {
        int32_t i32;
        uint32_t u32;
        int64_t i64;
        uint64_t u64;
        float f;
        double d;
    } ret;

    switch(json_value_type(v)) {
        case JSON_VALUE_INT32:     memcpy(&ret.i32, payload, sizeof(int32_t)); return (uint32_t) ret.i32;
        case JSON_VALUE_UINT32:    memcpy(&ret.u32, payload, sizeof(uint32_t)); return (uint32_t) ret.u32;
        case JSON_VALUE_INT64:     memcpy(&ret.i64, payload, sizeof(int64_t)); return (uint32_t) ret.i64;
        case JSON_VALUE_UINT64:    memcpy(&ret.u64, payload, sizeof(uint64_t)); return (uint32_t) ret.u64;
        case JSON_VALUE_FLOAT:     memcpy(&ret.f, payload, sizeof(float)); return ROUNDF(uint32_t, ret.f);
        case JSON_VALUE_DOUBLE:    memcpy(&ret.d, payload, sizeof(double)); return ROUNDD(uint32_t, ret.d);
        default:            return UINT32_MAX;
    }
}

WOLFSENTRY_API int64_t
json_value_int64(const JSON_VALUE* v)
{
    uint8_t* payload = json_value_payload((JSON_VALUE*) v);
    union {
        int32_t i32;
        uint32_t u32;
        int64_t i64;
        uint64_t u64;
        float f;
        double d;
    } ret;

    switch(json_value_type(v)) {
        case JSON_VALUE_INT32:     memcpy(&ret.i32, payload, sizeof(int32_t)); return (int64_t) ret.i32;
        case JSON_VALUE_UINT32:    memcpy(&ret.u32, payload, sizeof(uint32_t)); return (int64_t) ret.u32;
        case JSON_VALUE_INT64:     memcpy(&ret.i64, payload, sizeof(int64_t)); return (int64_t) ret.i64;
        case JSON_VALUE_UINT64:    memcpy(&ret.u64, payload, sizeof(uint64_t)); return (int64_t) ret.u64;
        case JSON_VALUE_FLOAT:     memcpy(&ret.f, payload, sizeof(float)); return ROUNDF(int64_t, ret.f);
        case JSON_VALUE_DOUBLE:    memcpy(&ret.d, payload, sizeof(double)); return ROUNDD(int64_t, ret.d);
        default:            return -1;
    }
}

WOLFSENTRY_API uint64_t
json_value_uint64(const JSON_VALUE* v)
{
    uint8_t* payload = json_value_payload((JSON_VALUE*) v);
    union {
        int32_t i32;
        uint32_t u32;
        int64_t i64;
        uint64_t u64;
        float f;
        double d;
    } ret;

    switch(json_value_type(v)) {
        case JSON_VALUE_INT32:     memcpy(&ret.i32, payload, sizeof(int32_t)); return (uint64_t) ret.i32;
        case JSON_VALUE_UINT32:    memcpy(&ret.u32, payload, sizeof(uint32_t)); return (uint64_t) ret.u32;
        case JSON_VALUE_INT64:     memcpy(&ret.i64, payload, sizeof(int64_t)); return (uint64_t) ret.i64;
        case JSON_VALUE_UINT64:    memcpy(&ret.u64, payload, sizeof(uint64_t)); return (uint64_t) ret.u64;
        case JSON_VALUE_FLOAT:     memcpy(&ret.f, payload, sizeof(float)); return ROUNDF(uint64_t, ret.f);
        case JSON_VALUE_DOUBLE:    memcpy(&ret.d, payload, sizeof(double)); return ROUNDD(uint64_t, ret.d);
        default:            return UINT64_MAX;
    }
}

WOLFSENTRY_API float
json_value_float(const JSON_VALUE* v)
{
    uint8_t* payload = json_value_payload((JSON_VALUE*) v);
    union {
        int32_t i32;
        uint32_t u32;
        int64_t i64;
        uint64_t u64;
        float f;
        double d;
    } ret;

    switch(json_value_type(v)) {
        case JSON_VALUE_INT32:     memcpy(&ret.i32, payload, sizeof(int32_t)); return (float) ret.i32;
        case JSON_VALUE_UINT32:    memcpy(&ret.u32, payload, sizeof(uint32_t)); return (float) ret.u32;
        case JSON_VALUE_INT64:     memcpy(&ret.i64, payload, sizeof(int64_t)); return (float) ret.i64;
        case JSON_VALUE_UINT64:    memcpy(&ret.u64, payload, sizeof(uint64_t)); return (float) ret.u64;
        case JSON_VALUE_FLOAT:     memcpy(&ret.f, payload, sizeof(float)); return ret.f;
        case JSON_VALUE_DOUBLE:    memcpy(&ret.d, payload, sizeof(double)); return (float) ret.d;
        default:            return -1.0f;   /* FIXME: NaN would be likely better but we do not include <math.h> */
    }
}

WOLFSENTRY_API double
json_value_double(const JSON_VALUE* v)
{
    uint8_t* payload = json_value_payload((JSON_VALUE*) v);
    union {
        int32_t i32;
        uint32_t u32;
        int64_t i64;
        uint64_t u64;
        float f;
        double d;
    } ret;

    switch(json_value_type(v)) {
        case JSON_VALUE_INT32:     memcpy(&ret.i32, payload, sizeof(int32_t)); return (double) ret.i32;
        case JSON_VALUE_UINT32:    memcpy(&ret.u32, payload, sizeof(uint32_t)); return (double) ret.u32;
        case JSON_VALUE_INT64:     memcpy(&ret.i64, payload, sizeof(int64_t)); return (double) ret.i64;
        case JSON_VALUE_UINT64:    memcpy(&ret.u64, payload, sizeof(uint64_t)); return (double) ret.u64;
        case JSON_VALUE_FLOAT:     memcpy(&ret.f, payload, sizeof(float)); return (double) ret.f;
        case JSON_VALUE_DOUBLE:    memcpy(&ret.d, payload, sizeof(double)); return ret.d;
        default:            return -1.0;    /* FIXME: NaN would be likely better but we do not include <math.h> */
    }
}

WOLFSENTRY_API const unsigned char*
json_value_string(const JSON_VALUE* v)
{
    uint8_t* payload;
    size_t off = 0;

    if(json_value_type(v) != JSON_VALUE_STRING)
        return NULL;

    payload = json_value_payload((JSON_VALUE*) v);
    while(payload[off] & 0x80)
        off++;
    off++;

    return (unsigned char*) payload + off;
}

WOLFSENTRY_API size_t
json_value_string_length(const JSON_VALUE* v)
{
    uint8_t* payload;
    size_t off = 0;
    size_t len = 0;
    unsigned shift = 0;

    if(json_value_type(v) != JSON_VALUE_STRING)
        return 0;

    payload = json_value_payload((JSON_VALUE*) v);
    while(payload[off] & 0x80) {
        len |= (size_t)(payload[off] & 0x7f) << shift;
        shift += 7;
        off++;
    }
    len |= (size_t)payload[off] << shift;

    return len;
}


/*******************
 *** JSON_VALUE_ARRAY ***
 *******************/

static ARRAY*
json_value_array_payload(JSON_VALUE* v)
{
    if(json_value_type(v) != JSON_VALUE_ARRAY)
        return NULL;

    return (ARRAY*) json_value_payload_ex(v, sizeof(void*));
}

static int
json_value_array_realloc(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    ARRAY* a, size_t alloc)
{
    JSON_VALUE* json_value_buf;

    json_value_buf = (JSON_VALUE*) realloc(a->json_value_buf, alloc * sizeof(JSON_VALUE));
    if(json_value_buf == NULL)
        return -1;

    a->json_value_buf = json_value_buf;
    a->alloc = alloc;
    return 0;
}

WOLFSENTRY_API JSON_VALUE*
json_value_array_get(const JSON_VALUE* v, size_t index)
{
    ARRAY* a = json_value_array_payload((JSON_VALUE*) v);

    if(a != NULL  &&  index < a->size)
        return &a->json_value_buf[index];
    else
        return NULL;
}

WOLFSENTRY_API JSON_VALUE*
json_value_array_get_all(const JSON_VALUE* v)
{
    ARRAY* a = json_value_array_payload((JSON_VALUE*) v);

    if(a != NULL)
        return a->json_value_buf;
    else
        return NULL;
}

WOLFSENTRY_API size_t
json_value_array_size(const JSON_VALUE* v)
{
    ARRAY* a = json_value_array_payload((JSON_VALUE*) v);

    if(a != NULL)
        return a->size;
    else
        return 0;
}

WOLFSENTRY_API JSON_VALUE*
json_value_array_append(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v)
{
    return json_value_array_insert(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, json_value_array_size(v));
}

WOLFSENTRY_API JSON_VALUE*
json_value_array_insert(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, size_t index)
{
    ARRAY* a = json_value_array_payload(v);

    if(a == NULL  ||  index > a->size)
        return NULL;

    if(a->size >= a->alloc) {
        if(json_value_array_realloc(
#ifdef WOLFSENTRY
               WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
               a, (a->alloc > 0) ? a->alloc * 2 : 1) != 0)
            return NULL;
    }

    if(index < a->size) {
        memmove(a->json_value_buf + index + 1, a->json_value_buf + index,
                (a->size - index) * sizeof(JSON_VALUE));
    }
    json_value_init_new(&a->json_value_buf[index]);
    a->size++;
    return &a->json_value_buf[index];
}

WOLFSENTRY_API int
json_value_array_remove(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, size_t index)
{
    return json_value_array_remove_range(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, index, 1);
}

WOLFSENTRY_API int
json_value_array_remove_range(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, size_t index, size_t count)
{
    ARRAY* a = json_value_array_payload(v);
    size_t i;

    if(a == NULL  ||  index + count > a->size)
        return -1;

    for(i = index; i < index + count; i++)
        json_value_fini(
#ifdef WOLFSENTRY
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
            &a->json_value_buf[i]);

    if(index + count < a->size) {
        memmove(a->json_value_buf + index, a->json_value_buf + index + count,
                (a->size - (index + count)) * sizeof(JSON_VALUE));
    }
    a->size -= count;

    if(4 * a->size < a->alloc)
        json_value_array_realloc(
#ifdef WOLFSENTRY
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
            a, a->alloc / 2);

    return 0;
}

WOLFSENTRY_API void
json_value_array_clean(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v)
{
    ARRAY* a = json_value_array_payload(v);
    size_t i;

    if(a == NULL)
        return;

    for(i = 0; i < a->size; i++)
        json_value_fini(
#ifdef WOLFSENTRY
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
            &a->json_value_buf[i]);

    free(a->json_value_buf);
    memset(a, 0, sizeof(ARRAY));
}


/******************
 *** JSON_VALUE_DICT ***
 ******************/

#define MAKE_RED(node)      do { (node)->key.data.data_bytes[0] |= HAS_REDCOLOR; } while(0)
//#define MAKE_BLACK(node)    do { (node)->key.data.data_bytes[0] &= ~HAS_REDCOLOR; } while(0)
#define MAKE_BLACK(node)    do { (node)->key.data.data_bytes[0] = (uint8_t)((node)->key.data.data_bytes[0] & ~HAS_REDCOLOR); } while(0)
#define TOGGLE_COLOR(node)  do { (node)->key.data.data_bytes[0] ^= HAS_REDCOLOR; } while(0)
#define IS_RED(node)        ((node)->key.data.data_bytes[0] & HAS_REDCOLOR)
#define IS_BLACK(node)      (!IS_RED(node))

static DICT*
json_value_dict_payload(JSON_VALUE* v)
{
    if(json_value_type(v) != JSON_VALUE_DICT)
        return NULL;

    return (DICT*) json_value_payload_ex(v, sizeof(void*));
}

static int
json_value_dict_default_cmp(const unsigned char* key1, size_t len1, const unsigned char* key2, size_t len2)
{
    /* Comparing lengths 1st might be in general especially if the keys are
     * long, but it would break json_value_dict_walk_sorted().
     *
     * In most apps keys are short and ASCII. It is nice to follow
     * lexicographic order at least in such cases as that's what most
     * people expect. And real world, the keys are usually quite short so
     * the cost should be acceptable.
     */

    size_t min_len = (len1 < len2) ? len1 : len2;
    int cmp;

    cmp = memcmp(key1, key2, min_len);
    if(cmp == 0 && len1 != len2)
        cmp = (len1 < len2) ? -1 : +1;

    return cmp;
}

static int
json_value_dict_cmp(const JSON_VALUE* v, const DICT* d,
               const unsigned char* key1, size_t len1, const unsigned char* key2, size_t len2)
{
    if(!(v->data.data_bytes[0] & HAS_CUSTOMCMP))
        return json_value_dict_default_cmp(key1, len1, key2, len2);
    else
        return d->cmp_func(key1, len1, key2, len2);
}

static int
json_value_dict_leftmost_path(RBTREE** path, RBTREE* node)
{
    int n = 0;

    while(node != NULL) {
        path[n++] = node;
        node = node->left;
    }

    return n;
}

WOLFSENTRY_API unsigned
json_value_dict_flags(const JSON_VALUE* v)
{
    DICT* d = json_value_dict_payload((JSON_VALUE*) v);
    unsigned flags = 0;

    if(d != NULL  &&  (v->data.data_bytes[0] & HAS_ORDERLIST))
        flags |= JSON_VALUE_DICT_MAINTAINORDER;

    return flags;
}

WOLFSENTRY_API size_t
json_value_dict_size(const JSON_VALUE* v)
{
    DICT* d = json_value_dict_payload((JSON_VALUE*) v);

    if(d != NULL)
        return d->size;
    else
        return 0;
}

WOLFSENTRY_API size_t
json_value_dict_keys_sorted(const JSON_VALUE* v, const JSON_VALUE** buffer, size_t buffer_size)
{
    DICT* d = json_value_dict_payload((JSON_VALUE*) v);
    RBTREE* stack[RBTREE_MAX_HEIGHT];
    int stack_size = 0;
    RBTREE* node;
    size_t n = 0;

    if(d == NULL)
        return 0;

    stack_size = json_value_dict_leftmost_path(stack, d->root);

    while(stack_size > 0  &&  n < buffer_size) {
        node = stack[--stack_size];
        buffer[n++] = &node->key;
        stack_size += json_value_dict_leftmost_path(stack + stack_size, node->right);
    }

    return n;
}

WOLFSENTRY_API size_t
json_value_dict_keys_ordered(const JSON_VALUE* v, const JSON_VALUE** buffer, size_t buffer_size)
{
    DICT* d = json_value_dict_payload((JSON_VALUE*) v);
    RBTREE* node;
    size_t n = 0;

    if(d == NULL  ||  !(v->data.data_bytes[0] & HAS_ORDERLIST))
        return 0;

    node = d->order_head;
    while(node != NULL  &&  n < buffer_size) {
        buffer[n++] = &node->key;
        node = node->order_next;
    }

    return n;
}

WOLFSENTRY_API JSON_VALUE*
json_value_dict_get_(const JSON_VALUE* v, const unsigned char* key, size_t key_len)
{
    DICT* d = json_value_dict_payload((JSON_VALUE*) v);
    RBTREE* node = (d != NULL) ? d->root : NULL;
    int cmp;

    while(node != NULL) {
        cmp = json_value_dict_cmp(v, d, key, key_len, json_value_string(&node->key), json_value_string_length(&node->key));

        if(cmp < 0)
            node = node->left;
        else if(cmp > 0)
            node = node->right;
        else
            return &node->json_value;
    }

    return NULL;
}

WOLFSENTRY_API JSON_VALUE*
json_value_dict_get(const JSON_VALUE* v, const unsigned char* key)
{
    return json_value_dict_get_(v, key, (key != NULL) ? strlen((const char *)key) : 0);
}

static void
json_value_dict_rotate_left(DICT* d, RBTREE* parent, RBTREE* node)
{
    RBTREE* tmp = node->right;
    node->right = tmp->left;
    tmp->left = node;

    if(parent != NULL) {
        if(parent->left == node)
            parent->left = tmp;
        else if(parent->right == node)
            parent->right = tmp;
    } else {
        d->root = tmp;
    }
}

static void
json_value_dict_rotate_right(DICT* d, RBTREE* parent, RBTREE* node)
{
    RBTREE* tmp = node->left;
    node->left = tmp->right;
    tmp->right = node;

    if(parent != NULL) {
        if(parent->right == node)
            parent->right = tmp;
        else if(parent->left == node)
            parent->left = tmp;
    } else {
        d->root = tmp;
    }
}

/* Fixes the tree after inserting (red) node path[path_len-1]. */
static void
json_value_dict_fix_after_insert(DICT* d, RBTREE** path, int path_len)
{
    RBTREE* node;
    RBTREE* parent;
    RBTREE* grandparent;
    RBTREE* grandgrandparent;
    RBTREE* uncle;

    while(1) {
        node = path[path_len-1];
        parent = (path_len > 1) ? path[path_len-2] : NULL;
        if(parent == NULL) {
            MAKE_BLACK(node);
            d->root = node;
            break;
        }

        if(IS_BLACK(parent))
            break;

        /* If we reach here, there is a double-red issue: The node as well as
         * the parent are red.
         *
         * Note grandparent has to exist (implied from red parent).
         */
        grandparent = path[path_len-3];
        uncle = (grandparent->left == parent) ? grandparent->right : grandparent->left;
        if(uncle == NULL || IS_BLACK(uncle)) {
            /* Black uncle. */
            grandgrandparent = (path_len > 3) ? path[path_len-4] : NULL;
            if(grandparent->left != NULL  &&  grandparent->left->right == node) {
                json_value_dict_rotate_left(d, grandparent, parent);
                parent = node;
                node = node->left;
            } else if(grandparent->right != NULL  &&  grandparent->right->left == node) {
                json_value_dict_rotate_right(d, grandparent, parent);
                parent = node;
                node = node->right;
            }
            if(parent->left == node)
                json_value_dict_rotate_right(d, grandgrandparent, grandparent);
            else
                json_value_dict_rotate_left(d, grandgrandparent, grandparent);

            /* Note that `parent` now,  after the rotations, points to where
             * the grand-parent was originally in the tree hierarchy, and
             * `grandparent` is now its child and also parent of the `uncle`.
             *
             * We switch their colors and hence make sure the upper `parent`
             * is now black. */
            MAKE_BLACK(parent);
            MAKE_RED(grandparent);
            break;
        }

        /* Red uncle. This allows us to make both the parent and the uncle
         * black and propagate the red up to grandparent. */
        MAKE_BLACK(parent);
        MAKE_BLACK(uncle);
        MAKE_RED(grandparent);

        /* But it means we could just move the double-red issue two levels
         * up, so we have to continue re-balancing there. */
        path_len -= 2;
    }
}

WOLFSENTRY_API JSON_VALUE*
json_value_dict_add_(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, const unsigned char* key, size_t key_len)
{
    JSON_VALUE* res;

    res = json_value_dict_get_or_add_(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, key, key_len);
    return (json_value_is_new(res) ? res : NULL);
}

WOLFSENTRY_API JSON_VALUE* json_value_dict_add(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, const unsigned char* key)
{
    return json_value_dict_add_(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, key, strlen((const char *)key));
}

WOLFSENTRY_API JSON_VALUE*
json_value_dict_get_or_add_(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, const unsigned char* key, size_t key_len)
{
    DICT* d = json_value_dict_payload((JSON_VALUE*) v);
    RBTREE* node = (d != NULL) ? d->root : NULL;
    RBTREE* path[RBTREE_MAX_HEIGHT];
    int path_len = 0;
    int cmp;

    if(d == NULL)
        return NULL;

    while(node != NULL) {
        cmp = json_value_dict_cmp(v, d, key, key_len,
                json_value_string(&node->key), json_value_string_length(&node->key));

        path[path_len++] = node;

        if(cmp < 0)
            node = node->left;
        else if(cmp > 0)
            node = node->right;
        else
            return &node->json_value;
    }

    /* Add new node into the tree. */
    node = (RBTREE*) malloc((v->data.data_bytes[0] & HAS_ORDERLIST) ?
                sizeof(RBTREE) : OFFSETOF(RBTREE, order_prev));
    if(node == NULL)
        return NULL;
    if(json_value_init_string_(
#ifdef WOLFSENTRY
           WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
           &node->key, key, key_len) != 0) {
        free(node);
        return NULL;
    }
    json_value_init_new(&node->json_value);
    node->left = NULL;
    node->right = NULL;
    MAKE_RED(node);

    /* Update order_list. */
    if(v->data.data_bytes[0] & HAS_ORDERLIST) {
        node->order_prev = d->order_tail;
        node->order_next = NULL;

        if(d->order_tail != NULL)
            d->order_tail->order_next = node;
        else
            d->order_head = node;
        d->order_tail = node;
    }

    /* Insert the new node. */
    if(path_len > 0) {
        if(cmp < 0)
            path[path_len - 1]->left = node;
        else
            path[path_len - 1]->right = node;
    } else {
        d->root = node;
    }

    /* Re-balance. */
    path[path_len++] = node;
    json_value_dict_fix_after_insert(d, path, path_len);

    d->size++;

    return &node->json_value;
}

WOLFSENTRY_API JSON_VALUE*
json_value_dict_get_or_add(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, const unsigned char* key)
{
    return json_value_dict_get_or_add_(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, key, (key != NULL) ? strlen((const char *)key) : 0);
}

/* Fixes the tree after making the given path one black node shorter.
 * (Note that that the path may end with NULL if the removed node had no child.) */
static void
json_value_dict_fix_after_remove(DICT* d, RBTREE** path, int path_len)
{
    RBTREE* node;
    RBTREE* parent;
    RBTREE* grandparent;
    RBTREE* sibling;

    while(1) {
        node = path[path_len-1];
        if(node != NULL  &&  IS_RED(node)) {
            MAKE_BLACK(node);
            break;
        }

        parent = (path_len > 1) ? path[path_len-2] : NULL;
        if(parent == NULL)
            break;

        /* Sibling has to exist because its subtree must have black
         * count as our subtree + 1. */
        sibling = (parent->left == node) ? parent->right : parent->left;
        grandparent = (path_len > 2) ? path[path_len-3] : NULL;
        if(IS_RED(sibling)) {
            /* Red sibling: Convert to black sibling case. */
            if(parent->left == node)
                json_value_dict_rotate_left(d, grandparent, parent);
            else
                json_value_dict_rotate_right(d, grandparent, parent);

            MAKE_BLACK(sibling);
            MAKE_RED(parent);
            path[path_len-2] = sibling;
            path[path_len-1] = parent;
            path[path_len++] = node;
            continue;
        }

        if((sibling->left != NULL && IS_RED(sibling->left))  ||
           (sibling->right != NULL && IS_RED(sibling->right))) {
            /* Black sibling having at least one red child. */
            if(node == parent->left && (sibling->right == NULL || IS_BLACK(sibling->right))) {
                MAKE_RED(sibling);
                MAKE_BLACK(sibling->left);
                json_value_dict_rotate_right(d, parent, sibling);
                sibling = parent->right;
            } else if(node == parent->right && (sibling->left == NULL || IS_BLACK(sibling->left))) {
                MAKE_RED(sibling);
                MAKE_BLACK(sibling->right);
                json_value_dict_rotate_left(d, parent, sibling);
                sibling = parent->left;
            }

            if(IS_RED(sibling) != IS_RED(parent))
                TOGGLE_COLOR(sibling);
            MAKE_BLACK(parent);
            if(node == parent->left) {
                MAKE_BLACK(sibling->right);
                json_value_dict_rotate_left(d, grandparent, parent);
            } else {
                MAKE_BLACK(sibling->left);
                json_value_dict_rotate_right(d, grandparent, parent);
            }
            break;
        }

        /* Black sibling with both children black. Make sibling subtree one
         * black shorter to match our subtree and try to resolve the black
         * deficit at the parent level. */
        if(IS_RED(parent)) {
            MAKE_RED(sibling);
            MAKE_BLACK(parent);
            break;
        } else {
            /* Fix the black deficit higher in the tree. */
            MAKE_RED(sibling);
            path_len--;
        }
    }
}

WOLFSENTRY_API int
json_value_dict_remove_(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, const unsigned char* key, size_t key_len)
{
    DICT* d = json_value_dict_payload((JSON_VALUE*) v);
    RBTREE* node = (d != NULL) ? d->root : NULL;
    RBTREE* single_child;
    RBTREE* path[RBTREE_MAX_HEIGHT];
    int path_len = 0;
    int cmp;

    /* Find the node to remove. */
    while(node != NULL) {
        cmp = json_value_dict_cmp(v, d, key, key_len,
                json_value_string(&node->key), json_value_string_length(&node->key));

        path[path_len++] = node;

        if(cmp < 0)
            node = node->left;
        else if(cmp > 0)
            node = node->right;
        else
            break;
    }
    if(node == NULL)
        return -1;

    /* It is far more easier to remove a node at the bottom of the tree, if it
     * has at most one child. Therefore, if we are not at the bottom, we switch
     * our place with another node, which is our direct successor; i.e. with
     * the minimal json_value of the right subtree. */
    if(node->right != NULL) {
        RBTREE* successor;
        int node_index = path_len-1;

        if(node->right->left != NULL) {
            RBTREE* tmp;

            path_len += json_value_dict_leftmost_path(path + path_len, node->right);
            successor = path[path_len-1];

            tmp = successor->right;
            successor->right = node->right;
            node->right = tmp;

            if(path[path_len-2]->left == successor)
                path[path_len-2]->left = node;
            else
                path[path_len-2]->right = node;

            path[node_index] = successor;
            path[path_len-1] = node;
        } else if(node->left != NULL) {
            /* node->right is the successor. Must be handled specially as the
             * code above would entangle the pointers. */
            successor = node->right;

            node->right = successor->right;
            successor->right = node;

            path[path_len-1] = successor;
            path[path_len++] = node;
        } else {
            /* node->left == NULL; i.e. node has at most one child.
             * The code below is capable to handle this. */
            successor = NULL;
        }

        if(successor != NULL) {
            /* Common work for the two active code paths above. */
            successor->left = node->left;
            node->left = NULL;

            if(node_index > 0) {
                if(path[node_index-1]->left == node)
                    path[node_index-1]->left = successor;
                else
                    path[node_index-1]->right = successor;
            } else {
                d->root = successor;
            }

            if(IS_RED(successor) != IS_RED(node)) {
                TOGGLE_COLOR(successor);
                TOGGLE_COLOR(node);
            }
        }
    }

    /* The node now cannot have more then one child. Move it upwards
     * to the node's place. */
    single_child = (node->left != NULL) ? node->left : node->right;
    if(path_len > 1) {
        if(path[path_len-2]->left == node)
            path[path_len-2]->left = single_child;
        else
            path[path_len-2]->right = single_child;
    } else {
        d->root = single_child;
    }
    path[path_len-1] = single_child;

    /* Node is now successfully disconnected. But the tree may need
     * re-balancing if we have removed black node. */
    if(IS_BLACK(node))
        json_value_dict_fix_after_remove(d, path, path_len);

    /* Kill the node */
    if(v->data.data_bytes[0] & HAS_ORDERLIST) {
        if(node->order_prev != NULL)
            node->order_prev->order_next = node->order_next;
        else
            d->order_head = node->order_next;

        if(node->order_next != NULL)
            node->order_next->order_prev = node->order_prev;
        else
            d->order_tail = node->order_prev;
    }
    json_value_fini(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        &node->key);
    json_value_fini(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        &node->json_value);
    free(node);
    d->size--;

    return 0;
}

WOLFSENTRY_API int
json_value_dict_remove(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v, const unsigned char* key)
{
    return json_value_dict_remove_(
#ifdef WOLFSENTRY
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
        v, key, (key != NULL) ? strlen((const char *)key) : 0);
}

WOLFSENTRY_API int
json_value_dict_walk_ordered(const JSON_VALUE* v, int (*visit_func)(const JSON_VALUE*, JSON_VALUE*, void*), void* ctx)
{
    DICT* d = json_value_dict_payload((JSON_VALUE*) v);
    RBTREE* node;
    int ret;

    if(d == NULL  ||  !(v->data.data_bytes[0] & HAS_ORDERLIST))
        return -1;

    node = d->order_head;
    while(node != NULL) {
        ret = visit_func(&node->key, &node->json_value, ctx);
        if(ret < 0)
            return ret;
        node = node->order_next;
    }

    return 0;
}

WOLFSENTRY_API int
json_value_dict_walk_sorted(const JSON_VALUE* v, int (*visit_func)(const JSON_VALUE*, JSON_VALUE*, void*), void* ctx)
{
    DICT* d = json_value_dict_payload((JSON_VALUE*) v);
    RBTREE* stack[RBTREE_MAX_HEIGHT];
    int stack_size = 0;
    RBTREE* node;
    int ret;

    if(d == NULL)
        return -1;

    stack_size = json_value_dict_leftmost_path(stack, d->root);

    while(stack_size > 0) {
        node = stack[--stack_size];
        ret = visit_func(&node->key, &node->json_value, ctx);
        if(ret < 0)
            return ret;
        stack_size += json_value_dict_leftmost_path(stack + stack_size, node->right);
    }

    return 0;
}

WOLFSENTRY_API void
json_value_dict_clean(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
    JSON_VALUE* v)
{
    DICT* d = json_value_dict_payload((JSON_VALUE*) v);
    RBTREE* stack[RBTREE_MAX_HEIGHT];
    int stack_size;
    RBTREE* node;
    RBTREE* right;

    if(d == NULL)
        return;

    stack_size = json_value_dict_leftmost_path(stack, d->root);

    while(stack_size > 0) {
        node = stack[--stack_size];
        right = node->right;

        json_value_fini(
#ifdef WOLFSENTRY
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
            &node->key);
        json_value_fini(
#ifdef WOLFSENTRY
            WOLFSENTRY_CONTEXT_ARGS_OUT_EX(allocator),
#endif
            &node->json_value);
        free(node);

        stack_size += json_value_dict_leftmost_path(stack + stack_size, right);
    }

    if(v->data.data_bytes[0] & HAS_ORDERLIST)
        memset(d, 0, OFFSETOF(DICT, cmp_func));
    else
        memset(d, 0, OFFSETOF(DICT, order_head));
}



#ifdef CRE_TEST
/* Verification of RB-tree correctness. */

/* Returns black height of the tree, or -1 on an error. */
static int
json_value_dict_verify_recurse(RBTREE* node)
{
    int left_black_height;
    int right_black_height;
    int black_height;

    if(node->left != NULL) {
        if(IS_RED(node) && IS_RED(node->left))
            return -1;

        left_black_height = json_value_dict_verify_recurse(node->left);
        if(left_black_height < 0)
            return left_black_height;
    } else {
        left_black_height = 1;
    }

    if(node->right != NULL) {
        if(IS_RED(node) && IS_RED(node->right))
            return -1;

        right_black_height = json_value_dict_verify_recurse(node->right);
        if(right_black_height < 0)
            return right_black_height;
    } else {
        right_black_height = 1;
    }

    if(left_black_height != right_black_height)
        return -1;

    black_height = left_black_height;
    if(IS_BLACK(node))
        black_height++;
    return black_height;
}

/* Returns 0 if ok, or -1 on an error. */
int
json_value_dict_verify(JSON_VALUE* v)
{
    DICT* d = json_value_dict_payload(v);
    if(d == NULL)
        return -1;

    if(d->root == NULL)
        return 0;

    if(IS_RED(d->root))
        return -1;

    return (json_value_dict_verify_recurse(d->root) > 0) ? 0 : -1;
}

#endif  /* #ifdef CRE_TEST */
