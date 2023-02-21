/*
 * centijson_sax.h
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

#ifndef CENTIJSON_SAX_H
#define CENTIJSON_SAX_H

#if !defined(WOLFSENTRY) && !defined(WOLFSENTRY_API)
    #define WOLFSENTRY_API
#endif

#ifndef WOLFSENTRY
#include <stdint.h>
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


/* JSON data types.
 *
 * Note that we distinguish beginning/end of the arrays and objects for
 * the purposes of the processing.
 */
typedef enum JSON_TYPE {
    JSON_NULL,
    JSON_FALSE,
    JSON_TRUE,
    JSON_NUMBER,
    JSON_STRING,
    JSON_KEY,     /* String in the specific role of an object key. */
    JSON_ARRAY_BEG,
    JSON_ARRAY_END,
    JSON_OBJECT_BEG,
    JSON_OBJECT_END
} JSON_TYPE;


/* Error codes.
 */
#define JSON_ERR_SUCCESS                0
#define JSON_ERR_INTERNAL               (-1)    /* This should never happen. If you see it, report bug ;-) */
#define JSON_ERR_OUTOFMEMORY            (-2)
#define JSON_ERR_SYNTAX                 (-4)    /* Generic syntax error. (More specific error codes are preferred.) */
#define JSON_ERR_BADCLOSER              (-5)    /* Mismatch in brackets (e.g. "{ ]" or "[ }") */
#define JSON_ERR_BADROOTTYPE            (-6)    /* Root type not allowed by CONFIG::flags. */
#define JSON_ERR_EXPECTEDVALUE          (-7)    /* Something unexpected where value has to be. */
#define JSON_ERR_EXPECTEDKEY            (-8)    /* Something unexpected where key has to be. */
#define JSON_ERR_EXPECTEDVALUEORCLOSER  (-9)    /* Something unexpected where value or array/object closer has to be. */
#define JSON_ERR_EXPECTEDKEYORCLOSER    (-10)   /* Something unexpected where key or array/object closer has to be. */
#define JSON_ERR_EXPECTEDCOLON          (-11)   /* Something unexpected where colon has to be. */
#define JSON_ERR_EXPECTEDCOMMAORCLOSER  (-12)   /* Something unexpected where comma or array/object has to be. */
#define JSON_ERR_EXPECTEDEOF            (-13)   /* Something unexpected where end-of-file has to be. */
#define JSON_ERR_MAXTOTALLEN            (-14)   /* Reached JSON_CONFIG::max_total_len */
#define JSON_ERR_MAXTOTALVALUES         (-15)   /* Reached JSON_CONFIG::max_total_values */
#define JSON_ERR_MAXNESTINGLEVEL        (-16)   /* Reached JSON_CONFIG::max_nesting_level */
#define JSON_ERR_MAXNUMBERLEN           (-17)   /* Reached JSON_CONFIG::max_number_len */
#define JSON_ERR_MAXSTRINGLEN           (-18)   /* Reached JSON_CONFIG::max_string_len */
#define JSON_ERR_MAXKEYLEN              (-19)   /* Reached JSON_CONFIG::max_key_len */
#define JSON_ERR_UNCLOSEDSTRING         (-20)   /* Unclosed string */
#define JSON_ERR_UNESCAPEDCONTROL       (-21)   /* Unescaped control character (in a string) */
#define JSON_ERR_INVALIDESCAPE          (-22)   /* Invalid/unknown escape sequence (in a string) */
#define JSON_ERR_INVALIDUTF8            (-23)   /* Invalid UTF-8 (in a string) */
#define JSON_ERR_NOT_INITED             (-24)   /* Attempt to access an uninited JSON_PARSER or JSON_DOM_PARSER. */


/* Bits for JSON_CONFIG::flags.
 */
#define JSON_NONULLASROOT           0x0001U  /* Disallow null to be root value */
#define JSON_NOBOOLASROOT           0x0002U  /* Disallow false or true to be root value */
#define JSON_NONUMBERASROOT         0x0004U  /* Disallow number to be root value */
#define JSON_NOSTRINGASROOT         0x0008U  /* Disallow string to be root value */
#define JSON_NOARRAYASROOT          0x0010U  /* Disallow array to be root value */
#define JSON_NOOBJECTASROOT         0x0020U  /* Disallow object  to be root value */

#define JSON_NOSCALARROOT           (JSON_NONULLASROOT | JSON_NOBOOLASROOT |  \
                                     JSON_NONUMBERASROOT | JSON_NOSTRINGASROOT)
#define JSON_NOVECTORROOT           (JSON_NOARRAYASROOT | JSON_NOOBJECTASROOT)

#define JSON_IGNOREILLUTF8KEY       0x0100U  /* Ignore ill-formed UTF-8 (for keys). */
#define JSON_FIXILLUTF8KEY          0x0200U  /* Replace ill-formed UTF-8 char with replacement char (for keys). */
#define JSON_IGNOREILLUTF8VALUE     0x0400U  /* Ignore ill-formed UTF-8 (for string values). */
#define JSON_FIXILLUTF8VALUE        0x0800U  /* Replace ill-formed UTF-8 char with replacement char (for string values). */



/* Parser options, passed into json_init().
 *
 * If NULL is passed to json_init(), default values are used.
 */
typedef struct JSON_CONFIG {
    size_t max_total_len;       /* zero means no limit; default: 10 MB */
    size_t max_total_values;    /* zero means no limit; default: 0 */
    size_t max_number_len;      /* zero means no limit; default: 512 */
    size_t max_string_len;      /* zero means no limit; default: 65536 */
    size_t max_key_len;         /* zero means no limit; default: 512 */
    unsigned max_nesting_level; /* zero means no limit; default: 512 */
    unsigned flags;             /* default: 0 */
} JSON_CONFIG;


/* Helper structure describing position in the input.
 *
 * It is used to specify where in the input a parsing error occurred for
 * better diagnostics.
 */
typedef struct JSON_INPUT_POS {
    size_t offset;
    unsigned line_number;
    unsigned column_number;
} JSON_INPUT_POS;


/* Callbacks the application has to implement, to process the parsed data.
 */
typedef struct JSON_CALLBACKS {
    /* Data processing callback. For now (and maybe forever) the only callback.
     *
     * Note that `data` and `data_size` are set only for JSON_KEY, JSON_STRING
     * and JSON_NUMBER. (For the other types the callback always gets NULL and
     * 0).
     *
     * Inside an object, the application is guaranteed to get keys and their
     * corresponding values in the alternating fashion (i.e. in the order
     * as they are in the JSON input.).
     *
     * Application can abort the parsing operation by returning a non-zero.
     * Note the non-zero return value of the callback is propagated to
     * json_feed() and json_fini().
     */
    int (*process)(JSON_TYPE /*type*/, const unsigned char* /*data*/,
                   size_t /*data_size*/, void* /*user_data*/);
} JSON_CALLBACKS;


/* Internal parser state. Use pointer to this structure as an opaque handle.
 */
typedef struct JSON_PARSER {
#ifdef WOLFSENTRY
    struct wolfsentry_allocator *allocator;
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread;
#endif
#endif
    JSON_CALLBACKS callbacks;
    JSON_CONFIG config;
    void* user_data;

    JSON_INPUT_POS pos;
    JSON_INPUT_POS value_pos;
    JSON_INPUT_POS err_pos;

    int errcode;

    size_t value_counter;

    char* nesting_stack;
    size_t nesting_level;
    size_t nesting_stack_size;

    unsigned automaton;
    unsigned state;
    unsigned substate;

    uint32_t codepoint[2];

    unsigned char* buf;
    size_t buf_used;
    size_t buf_alloced;

    size_t last_cl_offset;  /* Offset of most recently seen '\r' */
} JSON_PARSER;



/* Fill `config` with options used by default.
 */
WOLFSENTRY_API_VOID json_default_config(JSON_CONFIG* config);


/* Initialize the parser, associate it with the given callbacks and
 * configuration. Returns zero on success, non-zero on an error.
 *
 * If `config` is NULL, default values are used.
 */
WOLFSENTRY_API int json_init(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
              JSON_PARSER* parser,
              const JSON_CALLBACKS* callbacks,
              const JSON_CONFIG* config,
              void* user_data);

/* Feed the parser with more input.
 *
 * Returns zero on success.
 *
 * If an error occurs it returns non-zero and any attempt to call json_feed()
 * again shall just fail with the same error code. Note the application should
 * still  call json_fini() to release all resources allocated by the parser.
 */
WOLFSENTRY_API int json_feed(JSON_PARSER* parser, const unsigned char* input, size_t size);

/* Finish parsing of the document (note it can still call some callbacks); and
 * release any resources held by the parser.
 *
 * Returns zero on success, or non-zero on failure.
 *
 * If `p_pos` is not NULL, it is filled with info about reached position in the
 * input. It can help in diagnostics if the parsing failed.
 *
 * Note that if the preceding call to json_feed() failed, the error status also
 * propagates into json_fini().
 *
 * Also note this function may still fail even when all preceding calls to
 * json_feed() succeeded. This typically happens when the parser was fed with
 * an incomplete JSON document.
 */
WOLFSENTRY_API int json_fini(JSON_PARSER* parser, JSON_INPUT_POS* p_pos);


/* Simple wrapper function for json_init() + json_feed() + json_fini(), usable
 * when the provided input contains complete JSON document.
 */
WOLFSENTRY_API int json_parse(
#ifdef WOLFSENTRY
    WOLFSENTRY_CONTEXT_ARGS_IN_EX(struct wolfsentry_allocator *allocator),
#endif
               const unsigned char* input, size_t size,
               const JSON_CALLBACKS* callbacks, const JSON_CONFIG* config,
               void* user_data, JSON_INPUT_POS* p_pos);


/* Converts error code to human readable error message
 */
WOLFSENTRY_API const char* json_error_str(int err_code);

WOLFSENTRY_API const char* json_type_str(JSON_TYPE type);


/*****************
 *** Utilities ***
 *****************/

/* When implementing the callback processing the parsed data, these utilities
 * below may come handy.
 */

/* Analyze the string holding a JSON number, and analyze whether it can
 * fit into integer types.
 *
 * (Note it says "no" in cases the number string contains any fraction or
 * exponent part.)
 */
WOLFSENTRY_API int json_analyze_number(const unsigned char* num, size_t num_size,
                         int* p_is_int32_compatible,
                         int* p_is_uint32_compatible,
                         int* p_is_int64_compatible,
                         int* p_is_uint64_compatible);

/* Convert the string holding JSON number to the given C type.
 *
 * Note the conversion to any of the integer types is undefined unless
 * json_analyze_number() says it's fine.
 *
 * Also note that json_number_to_double() can fail with JSON_ERR_OUTOFMEMORY.
 * Hence its prototype differs.
 */
WOLFSENTRY_API int32_t json_number_to_int32(const unsigned char* num, size_t num_size);
WOLFSENTRY_API uint32_t json_number_to_uint32(const unsigned char* num, size_t num_size);
WOLFSENTRY_API int64_t json_number_to_int64(const unsigned char* num, size_t num_size);
WOLFSENTRY_API uint64_t json_number_to_uint64(const unsigned char* num, size_t num_size);
WOLFSENTRY_API int json_number_to_double(const unsigned char* num, size_t num_size, double* p_result);


typedef int (*JSON_DUMP_CALLBACK)(const unsigned char* /*str*/, size_t /*size*/, void* /*user_data*/);

/* Helpers for writing numbers and strings in JSON-compatible format.
 *
 * Note that json_dump_string() assumes the string is a well-formed UTF-8
 * string which needs no additional Unicode validation. The function "only"
 * handles proper escaping of control characters.
 *
 * The provided writer callback must write all the data provided to it and
 * return zero to indicate success, or non-zero to indicate an error and abort
 * the operation.
 *
 * All these return zero on success, JSON_ERR_OUTOFMEMORY, or an error code
 * propagated from the writer callback.
 *
 * (Given that all the other JSON stuff is trivial to output, the application
 * is supposed to implement that manually.)
 */
WOLFSENTRY_API int json_dump_int32(int32_t i32, JSON_DUMP_CALLBACK write_func, void* user_data);
WOLFSENTRY_API int json_dump_uint32(uint32_t u32, JSON_DUMP_CALLBACK write_func, void* user_data);
WOLFSENTRY_API int json_dump_int64(int64_t i64, JSON_DUMP_CALLBACK write_func, void* user_data);
WOLFSENTRY_API int json_dump_uint64(uint64_t u64, JSON_DUMP_CALLBACK write_func, void* user_data);
WOLFSENTRY_API int json_dump_double(double dbl, JSON_DUMP_CALLBACK write_func, void* user_data);
WOLFSENTRY_API int json_dump_string(const unsigned char* str, size_t size, JSON_DUMP_CALLBACK write_func, void* user_data);


#ifdef __cplusplus
}  /* extern "C" { */
#endif

#endif  /* CENTIJSON_SAX_H */
