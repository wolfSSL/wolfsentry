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

#ifndef CENTIJSON_VALUE_H
#define CENTIJSON_VALUE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

#ifdef WOLFSENTRY
#include "wolfsentry.h"
#endif
#ifndef WOLFSENTRY_API
#define WOLFSENTRY_API
#endif

/* The value structure.
 * Use as opaque.
 */
typedef struct JSON_VALUE {
    /* We need at least 2 * sizeof(void*). Sixteen bytes covers that on 64-bit
     * platforms and it seems as a good compromise allowing to "inline" all
     * numeric types as well as short strings; which is good idea: most dict
     * keys as well as many string values are in practice quite short. */
    union {
        uint8_t data_bytes[16];
        void *data_ptrs[16 / sizeof(void *)];
    } data;
} JSON_VALUE;


/* Value types.
 */
typedef enum JSON_VALUE_TYPE {
    JSON_VALUE_NULL = 0,
    JSON_VALUE_BOOL,
    JSON_VALUE_INT32,
    JSON_VALUE_UINT32,
    JSON_VALUE_INT64,
    JSON_VALUE_UINT64,
    JSON_VALUE_FLOAT,
    JSON_VALUE_DOUBLE,
    JSON_VALUE_STRING,
    JSON_VALUE_ARRAY,
    JSON_VALUE_DICT
} JSON_VALUE_TYPE;


/* Free any resources the value holds.
 * For ARRAY and DICT it is recursive.
 */
WOLFSENTRY_API void json_value_fini(JSON_VALUE* v);

/* Get value type.
 */
WOLFSENTRY_API JSON_VALUE_TYPE json_value_type(const JSON_VALUE* v);

/* Check whether the value is "compatible" with the given type.
 *
 * This is especially useful for determining whether a numeric value can be
 * "casted" to other numeric type. The function does some basic checking
 * whether such conversion looses substantial information.
 *
 * For example, value initialized with init_float(&v, 1.0f) is considered
 * compatible with INT32, because 1.0f has zero fraction and 1 fits between
 * INT32_MIN and INT32_MAX. Therefore calling int32_value(&v) gets sensible
 * result.
 */
WOLFSENTRY_API int json_value_is_compatible(const JSON_VALUE* v, JSON_VALUE_TYPE type);

/* Values newly added into array or dictionary are of type VALUE_NULL.
 *
 * Additionally, for such newly created values, an internal flag is used to
 * mark that the value was never explicitly initialized by the application.
 *
 * This function checks value of the flag, and allows thus the caller to
 * distinguish whether the value was just added; or whether the value was
 * explicitly initialized as VALUE_NULL with value_init_null().
 *
 * Caller is supposed to initialize all such newly added value with any of the
 * value_init_XXX() functions, and hence reset the flag.
 */
WOLFSENTRY_API int json_value_is_new(const JSON_VALUE* v);

/* Simple recursive getter, capable to get a value dwelling deep in the
 * hierarchy formed by nested arrays and dictionaries.
 *
 * Limitations: The function is not capable to deal with object keys which
 * contain zero byte '\0', slash '/' or brackets '[' ']' because those are
 * interpreted by the function as special characters:
 *
 *  -- '/' delimits dictionary keys (and optionally also array indexes;
 *     paths "foo/[4]" and "foo[4]" are treated as equivalent.)
 *  -- '[' ']' enclose array indexes (for distinguishing from numbered
 *     dictionary keys). Note that negative indexes are supported here;
 *     '[-1]' refers to the last element in the array, '[-2]' to the element
*       before the last element etc.
 *  -- '\0' terminates the whole path (as is normal with C strings).
 *
 * Examples:
 *
 *  (1) value_path(root, "") gets directly the root.
 *
 *  (2) value_path(root, "foo") gets value keyed with 'foo' if root is a
 *      dictionary having such value, or NULL otherwise.
 *
 *  (3) value_path(root, "[4]") gets value with index 4 if root is an array
 *      having so many members, or NULL otherwise.
 *
 *  (4) value_path(root, "foo[2]/bar/baz[3]") walks deeper and deeper and
 *      returns a value stored there assuming these all conditions are true:
 *       -- root is dictionary having the key "foo";
 *       -- that value is a nested list having the index [2];
 *       -- that value is a nested dictionary having the key "bar";
 *       -- that value is a nested dictionary having the key "baz";
 *       -- and finally, that is a list having the index [3].
 *      If any of those is not fulfilled, then NULL is returned.
 */
WOLFSENTRY_API JSON_VALUE* json_value_path(JSON_VALUE* root, const char* path);

/* value_build_path() is similar to value_path(); but allows easy populating
 * of value hierarchies.
 *
 * If all values along the path already exist, the behavior is exactly the same
 * as value_path().
 *
 * But when a value corresponding to any component of the path does not exist
 * then, instead of returning NULL, new value is added into the parent
 * container (assuming the parent existing container has correct type as
 * assumed by the path.)
 *
 * Caller may use empty "[]" to always enforce appending a new value into an
 * array. E.g. value_build_path(root, "multiple_values/[]/name") makes sure the
 * root contains an array under the key "multiple_values", and a new dictionary
 * is appended at the end of the array. This new dictionary gets a new value
 * under the key "name". Assuming the function succeeds, the caller can now be
 * sure the "name" is initialized as VALUE_NULL because the new dictionary has
 * been just created and added as the last element if the list.
 *
 * If such new value does not correspond to the last path component, the new
 * value gets initialized as the right type so subsequent path component can
 * be treated the same way.
 *
 * If the function creates the value corresponding to the last component of the
 * path, it is initialized as VALUE_NULL and the "new flag" is set for it, so
 * caller can test this condition with value_is_new().
 *
 * Returns NULL if the path cannot be resolved because any existing value
 * has a type incompatible with the path; if creation of any value along the
 * path fails; or if an array index is out of bounds.
 */
WOLFSENTRY_API JSON_VALUE* json_value_build_path(JSON_VALUE* root, const char* path);


/******************
 *** VALUE_NULL ***
 ******************/

/* Note it is guaranteed that VALUE_NULL does not need any explicit clean-up;
 * i.e. application may avoid calling value_fini().
 *
 * But it is allowed to. value_fini() for VALUE_NULL is a noop.
 */


/* Static initializer.
 */
#define JSON_VALUE_NULL_INITIALIZER    { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } }

WOLFSENTRY_API void json_value_init_null(JSON_VALUE* v);


/******************
 *** VALUE_BOOL ***
 ******************/

WOLFSENTRY_API int json_value_init_bool(JSON_VALUE* v, int b);

WOLFSENTRY_API int json_value_bool(const JSON_VALUE* v);


/*********************
 *** Numeric types ***
 *********************/


/* Initializers.
 */
WOLFSENTRY_API int json_value_init_int32(JSON_VALUE* v, int32_t i32);
WOLFSENTRY_API int json_value_init_uint32(JSON_VALUE* v, uint32_t u32);
WOLFSENTRY_API int json_value_init_int64(JSON_VALUE* v, int64_t i64);
WOLFSENTRY_API int json_value_init_uint64(JSON_VALUE* v, uint64_t u64);
WOLFSENTRY_API int json_value_init_float(JSON_VALUE* v, float f);
WOLFSENTRY_API int json_value_init_double(JSON_VALUE* v, double d);

/* Getters.
 *
 * Note you may use any of the getter function for any numeric value. These
 * functions perform required conversions under the hood. The conversion may
 * have have the same side/limitations as C casting.
 *
 * However application may use json_value_is_compatible() to verify whether the
 * conversion should provide a reasonable result.
 */
WOLFSENTRY_API int32_t json_value_int32(const JSON_VALUE* v);
WOLFSENTRY_API uint32_t json_value_uint32(const JSON_VALUE* v);
WOLFSENTRY_API int64_t json_value_int64(const JSON_VALUE* v);
WOLFSENTRY_API uint64_t json_value_uint64(const JSON_VALUE* v);
WOLFSENTRY_API float json_value_float(const JSON_VALUE* v);
WOLFSENTRY_API double json_value_double(const JSON_VALUE* v);


/********************
 *** JSON_VALUE_STRING ***
 ********************/

/* Note JSON_VALUE_STRING allows to store any sequences of any bytes, even a binary
 * data. No particular encoding of the string is assumed. Even zero bytes are
 * allowed (but then the caller has to use json_value_init_string_() and specify
 * the string length explicitly).
 */

/* The function json_value_init_string_() initializes the JSON_VALUE_STRING with any
 * sequence of bytes, of any length. It also adds automatically one zero byte
 * (not counted in the length of the string).
 *
 * The function json_value_init_string() is equivalent to calling directly
 * json_value_init_string_(str, strlen(str)).
 *
 * The parameter str is allowed to be NULL (then the functions behave the same
 * way as if it is points to an empty string).
 */
WOLFSENTRY_API int json_value_init_string_(JSON_VALUE* v, const char* str, size_t len);
WOLFSENTRY_API int json_value_init_string(JSON_VALUE* v, const char* str);

/* Get pointer to the internal buffer holding the string. The caller may assume
 * the returned string is always zero-terminated.
 */
WOLFSENTRY_API const char* json_value_string(const JSON_VALUE* v);

/* Get length of the string. (The implicit zero terminator does not count.)
 */
WOLFSENTRY_API size_t json_value_string_length(const JSON_VALUE* v);


/*******************
 *** JSON_VALUE_ARRAY ***
 *******************/

/* Array of values.
 *
 * Note that any new value added into the array with json_value_array_append() or
 * json_value_array_insert() is initially of the type JSON_VALUE_NULL and that it has
 * an internal flag marking the value as new (so that json_value_is_new() returns
 * non-zero for it). Application is supposed to initialize the newly added
 * value by any of the value initialization functions.
 *
 * WARNING: Modifying contents of an array (i.e. inserting, appending and also
 * removing a value)  can lead to reallocation of internal array buffer.
 * Hence, consider all JSON_VALUE* pointers invalid after modifying the array.
 * That includes the return values of json_value_array_get(), json_value_array_get_all(),
 * but also preceding calls of json_value_array_append() and json_value_array_insert().
 */
WOLFSENTRY_API int json_value_init_array(JSON_VALUE* v);

/* Get count of items in the array.
 */
WOLFSENTRY_API size_t json_value_array_size(const JSON_VALUE* v);

/* Get the specified item.
 */
WOLFSENTRY_API JSON_VALUE* json_value_array_get(const JSON_VALUE* v, size_t index);

/* Get pointer to internal C array of all items.
 */
WOLFSENTRY_API JSON_VALUE* json_value_array_get_all(const JSON_VALUE* v);

/* Append/insert new item.
 */
WOLFSENTRY_API JSON_VALUE* json_value_array_append(JSON_VALUE* v);
WOLFSENTRY_API JSON_VALUE* json_value_array_insert(JSON_VALUE* v, size_t index);

/* Remove an item (or range of items).
 */
WOLFSENTRY_API int json_value_array_remove(JSON_VALUE* v, size_t index);
WOLFSENTRY_API int json_value_array_remove_range(JSON_VALUE* v, size_t index, size_t count);

/* Remove and destroy all members (recursively).
 */
WOLFSENTRY_API void json_value_array_clean(JSON_VALUE* v);


/******************
 *** JSON_VALUE_DICT ***
 ******************/

/* Dictionary of values. (Internally implemented as red-black tree.)
 *
 * Note that any new value added into the dictionary is initially of the type
 * JSON_VALUE_NULL and that it has  an internal flag marking the value as new
 * (so that json_value_is_new() returns non-zero for it). Application is supposed
 * to initialize the newly added value by any of the value initialization
 * functions.
 *
 * Note that all the functions adding/removing any items may invalidate all
 * pointers into the dictionary.
 */


/* Flag for init_dict_ex() asking to maintain the order in which the dictionary
 * is populated and enabling dict_walk_ordered().
 *
 * If used, the dictionary consumes more memory.
 */
#define JSON_VALUE_DICT_MAINTAINORDER      0x0001

/* Initialize the value as a (empty) dictionary.
 *
 * json_value_init_dict_ex() allows to specify custom comparer function (may be NULL)
 * or flags changing the default behavior of the dictionary.
 */
WOLFSENTRY_API int json_value_init_dict(JSON_VALUE* v);
WOLFSENTRY_API int json_value_init_dict_ex(JSON_VALUE* v,
                       int (*custom_cmp_func)(const char* /*key1*/, size_t /*len1*/,
                                              const char* /*key2*/, size_t /*len2*/),
                       unsigned flags);

/* Get flags of the dictionary.
 */
WOLFSENTRY_API unsigned json_value_dict_flags(const JSON_VALUE* v);

/* Get count of items in the dictionary.
 */
WOLFSENTRY_API size_t json_value_dict_size(const JSON_VALUE* v);

/* Get all keys.
 *
 * If the buffer provided by the caller is too small, only subset of keys shall
 * be retrieved.
 *
 * Returns count of retrieved keys.
 */
WOLFSENTRY_API size_t json_value_dict_keys_sorted(const JSON_VALUE* v, const JSON_VALUE** buffer, size_t buffer_size);
WOLFSENTRY_API size_t json_value_dict_keys_ordered(const JSON_VALUE* v, const JSON_VALUE** buffer, size_t buffer_size);

/* Find an item with the given key, or return NULL of no such item exists.
 */
WOLFSENTRY_API JSON_VALUE* json_value_dict_get_(const JSON_VALUE* v, const char* key, size_t key_len);
WOLFSENTRY_API JSON_VALUE* json_value_dict_get(const JSON_VALUE* v, const char* key);

/* Add new item with the given key of type JSON_VALUE_NULL.
 *
 * Returns NULL if the key is already used.
 */
WOLFSENTRY_API JSON_VALUE* json_value_dict_add_(JSON_VALUE* v, const char* key, size_t key_len);
WOLFSENTRY_API JSON_VALUE* json_value_dict_add(JSON_VALUE* v, const char* key);

/* This is combined operation of json_value_dict_get() and json_value_dict_add().
 *
 * Get value of the given key. If no such value exists, new one is added.
 * Application can check for such situation with json_value_is_new().
 *
 * NULL is returned only in an out-of-memory situation.
 */
WOLFSENTRY_API JSON_VALUE* json_value_dict_get_or_add_(JSON_VALUE* v, const char* key, size_t key_len);
WOLFSENTRY_API JSON_VALUE* json_value_dict_get_or_add(JSON_VALUE* v, const char* key);

/* Remove and destroy (recursively) the given item from the dictionary.
 */
WOLFSENTRY_API int json_value_dict_remove_(JSON_VALUE* v, const char* key, size_t key_len);
WOLFSENTRY_API int json_value_dict_remove(JSON_VALUE* v, const char* key);

/* Walking over all items in the dictionary. The callback function is called
 * for every item in the dictionary, providing key and value and propagating
 * the user data into it. If the callback returns non-zero, the function
 * aborts immediately.
 *
 * Note dict_walk_ordered() is supported only if DICT_MAINTAINORDER
 * flag was used in init_dict().
 */
WOLFSENTRY_API int json_value_dict_walk_ordered(const JSON_VALUE* v,
            int (*visit_func)(const JSON_VALUE*, JSON_VALUE*, void*), void* ctx);
WOLFSENTRY_API int json_value_dict_walk_sorted(const JSON_VALUE* v,
            int (*visit_func)(const JSON_VALUE*, JSON_VALUE*, void*), void* ctx);

/* Remove and destroy all members (recursively).
 */
WOLFSENTRY_API void json_value_dict_clean(JSON_VALUE* v);


#ifdef __cplusplus
}
#endif

#endif  /* CENTIJSON_VALUE_H */
