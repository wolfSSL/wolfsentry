/*
 * wolfsentry_util.h
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

/*! @file wolfsentry_util.h
    \brief Utility and convenience macros for both internal and application use.

    Included by `wolfsentry.h`.
 */

#ifndef WOLFSENTRY_UTIL_H
#define WOLFSENTRY_UTIL_H

#ifndef offsetof
/* gcc and clang define this in stddef.h to use sanitizer-safe builtins. */
#define offsetof(structure, element) ((uintptr_t)&(((structure *)0)->element))
    /*!< \brief Evaluates to the byte offset of `element` in `structure`.  @hideinitializer */
#endif
#ifndef sizeof_field
#define sizeof_field(structure, element) sizeof(((structure *)0)->element)
    /*!< \brief Evaluates to the size in bytes of `element` in `structure`.  @hideinitializer */
#endif
#ifndef instance_of_field
#define instance_of_field(structure, element) (((structure *)0)->element)
    /*!< \brief Evaluates to a dummy instance of `element` in `structure`, e.g. to be passed to MAX_UINT_OF().  @hideinitializer */
#endif
#ifndef container_of
#define container_of(ptr, container_type, member_name) ((container_type *)(void *)(((byte *)(ptr)) - offsetof(container_type, member_name))) /* NOLINT(bugprone-casting-through-void) */
    /*!< \brief Evaluates to a pointer to the struct of type `container_type` within which `ptr` points to the member named `member_name`.  @hideinitializer */
#endif
#ifndef length_of_array
#define length_of_array(x) (sizeof (x) / sizeof (x)[0])
    /*!< \brief Evaluates to the number of elements in `x`, which must be an array.  @hideinitializer */
#endif
#ifndef end_ptr_of_array
#define end_ptr_of_array(x) (&(x)[length_of_array(x)])
    /*!< \brief Evaluates to a pointer to the byte immediately following the end of array `x`.  @hideinitializer */
#endif

#ifndef popcount32
#ifdef __GNUC__
#define popcount32(x) __builtin_popcount(x)
    /*!< \brief Evaluates to the number of set bits in `x`.  @hideinitializer */
#else
#error Must supply binding for popcount32() on non-__GNUC__ targets.
#endif
#endif

#if defined(__GNUC__) && !defined(WOLFSENTRY_NO_BUILTIN_CLZ)
#ifndef LOG2_32
#define LOG2_32(x) (31 - __builtin_clz((unsigned int)(x)))
   /*!< \brief Evaluates to the floor of the base 2 logarithm of `x`, which must be a 32 bit integer.  @hideinitializer */
#endif
#ifndef LOG2_64
#define LOG2_64(x) ((sizeof(unsigned long long) * 8ULL) - (unsigned long long)__builtin_clzll((unsigned long long)(x)) - 1ULL)
   /*!< \brief Evaluates to the floor of the base 2 logarithm of `x`, which must be a 64 bit integer.  @hideinitializer */
#endif
#endif

#define streq(vs,fs,vs_len) (((vs_len) == strlen(fs)) && (memcmp(vs,fs,vs_len) == 0))
   /*!< \brief Evaluates to true iff string `vs` of length `vs_len` (not including a terminating null, if any) equals null-terminated string `fs`.  @hideinitializer */
#define strcaseeq(vs,fs,vs_len) (((vs_len) == strlen(fs)) && (strncasecmp(vs,fs,vs_len) == 0))
   /*!< \brief Evaluates to true iff string `vs` of length `vs_len` (not including a terminating null, if any) equals null-terminated string `fs`, neglecting case distinctions.  @hideinitializer */

#define WOLFSENTRY_BYTE_STREAM_DECLARE_STACK(buf, bufsiz) static const size_t buf ## siz = (bufsiz); unsigned char (buf)[bufsiz], *buf ## _p; size_t buf ## spc
   /*!< \brief Byte stream helper macro  @hideinitializer */
#define WOLFSENTRY_BYTE_STREAM_DECLARE_HEAP(buf, bufsiz) static const size_t buf ## siz = (bufsiz); unsigned char *(buf), *buf ## _p; size_t buf ## spc
   /*!< \brief Byte stream helper macro  @hideinitializer */
#define WOLFSENTRY_BYTE_STREAM_INIT_HEAP(buf) ((buf) = (unsigned char *)WOLFSENTRY_MALLOC(buf ## siz))
   /*!< \brief Byte stream helper macro  @hideinitializer */
#define WOLFSENTRY_BYTE_STREAM_FREE_HEAP(buf) WOLFSENTRY_FREE(buf)
   /*!< \brief Byte stream helper macro  @hideinitializer */
#define WOLFSENTRY_BYTE_STREAM_RESET(buf) do { (buf ## _p) = (buf); (buf ## spc) = (buf ## siz); } while (0)
   /*!< \brief Byte stream helper macro  @hideinitializer */
#define WOLFSENTRY_BYTE_STREAM_LEN(buf) ((buf ## siz) - (buf ## spc))
   /*!< \brief Byte stream helper macro  @hideinitializer */
#define WOLFSENTRY_BYTE_STREAM_HEAD(buf) (buf)
   /*!< \brief Byte stream helper macro  @hideinitializer */
#define WOLFSENTRY_BYTE_STREAM_PTR(buf) (&(buf ## _p))
   /*!< \brief Byte stream helper macro  @hideinitializer */
#define WOLFSENTRY_BYTE_STREAM_SPC(buf) (&(buf ## spc))
   /*!< \brief Byte stream helper macro  @hideinitializer */

#define MAX_UINT_OF(x) ((((uint64_t)1 << ((sizeof(x) * (uint64_t)BITS_PER_BYTE) - (uint64_t)1)) - (uint64_t)1) | ((uint64_t)1 << ((sizeof(x) * (uint64_t)BITS_PER_BYTE) - (uint64_t)1)))
   /*!< \brief Evaluates to the largest representable `unsigned int` in a word the size of `x`.  @hideinitializer */
#define MAX_SINT_OF(x) ((int64_t)((((uint64_t)1 << ((sizeof(x) * (uint64_t)BITS_PER_BYTE) - (uint64_t)2)) - (uint64_t)1) | ((uint64_t)1 << ((sizeof(x) * (uint64_t)BITS_PER_BYTE) - (uint64_t)2))))
   /*!< \brief Evaluates to the largest representable `signed int` in a word the size of `x`.  @hideinitializer */
#define MIN_SINT_OF(x) ((int64_t)((uint64_t)1 << ((sizeof(x) * (uint64_t)BITS_PER_BYTE) - (uint64_t)1)))
   /*!< \brief Evaluates to the largest negative representable `signed int` in a word the size of `x`.  @hideinitializer */

#define WOLFSENTRY_SET_BITS(enumint, bits) ((enumint) |= (bits))
   /*!< \brief Sets the designated `bits` in `enumint`.  @hideinitializer */
#define WOLFSENTRY_CHECK_BITS(enumint, bits) (((enumint) & (bits)) == (bits))
   /*!< \brief Evaluates to true if `bits` are all set in `enumint`.  @hideinitializer */
#define WOLFSENTRY_CLEAR_BITS(enumint, bits) ((enumint) &= ~(uint32_t)(bits))
   /*!< \brief Clears the designated `bits` in `enumint`.  @hideinitializer */
#define WOLFSENTRY_MASKIN_BITS(enumint, bits) ((enumint) & (bits))
   /*!< \brief Evaluates to the bits that are set in both `enumint` and `bits`.  @hideinitializer */
#define WOLFSENTRY_MASKOUT_BITS(enumint, bits) ((enumint) & ~(uint32_t)(bits))
   /*!< \brief Evaluates to the bits that are set `enumint` but not set in `bits`.  @hideinitializer */
#define WOLFSENTRY_CLEAR_ALL_BITS(enumint) ((enumint) = 0)
   /*!< \brief Clears all bits in `enumint`.  @hideinitializer */

#if defined(__STRICT_ANSI__) || defined(WOLFSENTRY_PEDANTIC_C) || \
    ((WOLFSENTRY_FLEXIBLE_ARRAY_SIZE + 0) > 0)
    #define WOLFSENTRY_STACKBUF_MINBUF 1
#else
    #define WOLFSENTRY_STACKBUF_MINBUF 0
#endif

#define WOLFSENTRY_STACKBUF(type, flex_slot, buf_size, buf_name) struct {  \
        type buf_name;                                                     \
        byte buf[(buf_size) > (sizeof(type) - offsetof(type, flex_slot)) ? \
                 (buf_size) - (sizeof(type) - offsetof(type, flex_slot)) : \
                 WOLFSENTRY_STACKBUF_MINBUF];                              \
    } buf_name

#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE 8
#endif

#define WOLFSENTRY_BITS_TO_BYTES(x) (((x) + 7U) >> 3U)
   /*!< \brief Evaluates to the number of bytes needed to represent `x` bits.  @hideinitializer */

/* helpers for stringifying the expanded value of a macro argument rather than its literal text: */
/*! @cond doxygen_all */
#define _qq(x) #x
#define _q(x) _qq(x)
/*! @endcond */

#ifdef WOLFSENTRY_THREADSAFE

#ifdef WOLFSENTRY_HAVE_GNU_ATOMICS

#define WOLFSENTRY_ATOMIC_INCREMENT(i, x) __atomic_add_fetch(&(i),x,__ATOMIC_SEQ_CST)
   /*!< \brief Adds `x` to `i` thread-safely, returning the sum.  @hideinitializer */
#define WOLFSENTRY_ATOMIC_DECREMENT(i, x) __atomic_sub_fetch(&(i),x,__ATOMIC_SEQ_CST)
   /*!< \brief Subtracts `x` from `i` thread-safely, returning the difference.  @hideinitializer */
#define WOLFSENTRY_ATOMIC_POSTINCREMENT(i, x) __atomic_fetch_add(&(i),x,__ATOMIC_SEQ_CST)
   /*!< \brief Adds `x` to `i` thread-safely, returning the operand `i`.  @hideinitializer */
#define WOLFSENTRY_ATOMIC_POSTDECREMENT(i, x) __atomic_fetch_sub(&(i),x,__ATOMIC_SEQ_CST)
   /*!< \brief Subtracts `x` from `i` thread-safely, returning the operand `i`.  @hideinitializer */
#define WOLFSENTRY_ATOMIC_STORE(i, x) __atomic_store_n(&(i), x, __ATOMIC_RELEASE)
   /*!< \brief Sets `i` to `x`, subject to benign races from other threads.  @hideinitializer */
#define WOLFSENTRY_ATOMIC_LOAD(i) __atomic_load_n(&(i), __ATOMIC_CONSUME)
   /*!< \brief Returns the value of `i`, subject to benign races from other threads.  @hideinitializer */
#define WOLFSENTRY_ATOMIC_CMPXCHG(ptr, expected, desired, weak_p, success_memorder, failure_memorder) __atomic_compare_exchange_n(ptr, expected, desired, weak_p, success_memorder, failure_memorder)
   /*!< \brief Sets `*ptr` to `desired` and returns true iff `*ptr` has the value `*expected`, otherwise sets `*expected` to the actual value of `*ptr` and returns false.  @hideinitializer */

#elif defined(THREADX)

/* ThreadX atomic operation implementations */
#include "tx_api.h"

/* ThreadX interrupt control for atomic operations */
#define WOLFSENTRY_ATOMIC_INCREMENT(i, x) ({ \
    UINT posture = tx_interrupt_control(TX_INT_DISABLE); \
    __typeof__(i) result = (i) + (x); \
    (i) = result; \
    (void)tx_interrupt_control(posture); \
    result; \
})

#define WOLFSENTRY_ATOMIC_DECREMENT(i, x) ({ \
    UINT posture = tx_interrupt_control(TX_INT_DISABLE); \
    __typeof__(i) result = (i) - (x); \
    (i) = result; \
    (void)tx_interrupt_control(posture); \
    result; \
})

#define WOLFSENTRY_ATOMIC_POSTINCREMENT(i, x) ({ \
    UINT posture = tx_interrupt_control(TX_INT_DISABLE); \
    __typeof__(i) old_val = (i); \
    (i) += (x); \
    (void)tx_interrupt_control(posture); \
    old_val; \
})

#define WOLFSENTRY_ATOMIC_POSTDECREMENT(i, x) ({ \
    UINT posture = tx_interrupt_control(TX_INT_DISABLE); \
    __typeof__(i) old_val = (i); \
    (i) -= (x); \
    (void)tx_interrupt_control(posture); \
    old_val; \
})

#define WOLFSENTRY_ATOMIC_STORE(i, x) ({ \
    UINT posture = tx_interrupt_control(TX_INT_DISABLE); \
    (i) = (x); \
    (void)tx_interrupt_control(posture); \
    (i); \
})

#define WOLFSENTRY_ATOMIC_LOAD(i) ({ \
    UINT posture = tx_interrupt_control(TX_INT_DISABLE); \
    __typeof__(i) val = (i); \
    (void)tx_interrupt_control(posture); \
    val; \
})

#define WOLFSENTRY_ATOMIC_CMPXCHG(ptr, expected, desired, weak_p, success_memorder, failure_memorder) ({ \
    UINT posture = tx_interrupt_control(TX_INT_DISABLE); \
    int result = 0; \
    if (*(ptr) == *(expected)) { \
        *(ptr) = (desired); \
        result = 1; \
    } else { \
        *(expected) = *(ptr); \
        result = 0; \
    } \
    (void)tx_interrupt_control(posture); \
    result; \
})

#else

#if !defined(WOLFSENTRY_ATOMIC_INCREMENT) || !defined(WOLFSENTRY_ATOMIC_DECREMENT) || \
    !defined(WOLFSENTRY_ATOMIC_POSTINCREMENT) || !defined(WOLFSENTRY_ATOMIC_POSTDECREMENT) || \
    !defined(WOLFSENTRY_ATOMIC_STORE) || !defined(WOLFSENTRY_ATOMIC_LOAD) || \
    !defined(WOLFSENTRY_ATOMIC_CMPXCHG)
   #error Missing required atomic implementation(s)
#endif

#endif /* WOLFSENTRY_HAVE_GNU_ATOMICS */

#define WOLFSENTRY_ATOMIC_INCREMENT_BY_ONE(i) WOLFSENTRY_ATOMIC_INCREMENT(i, 1)
   /*!< \brief Adds 1 to `i` thread-safely, returning the sum.  @hideinitializer */
#define WOLFSENTRY_ATOMIC_DECREMENT_BY_ONE(i) WOLFSENTRY_ATOMIC_DECREMENT(i, 1)
   /*!< \brief Subtracts 1 from `i` thread-safely, returning the difference.  @hideinitializer */

/* caution, _TEST_AND_SET() alters arg2 (and returns false) on failure. */
#define WOLFSENTRY_ATOMIC_TEST_AND_SET(i, expected, intended)           \
    WOLFSENTRY_ATOMIC_CMPXCHG(                                          \
        &(i),                                                           \
        &(expected),                                                    \
        intended,                                                       \
        0 /* weak */,                                                   \
        __ATOMIC_SEQ_CST /* success_memmodel */,                        \
        __ATOMIC_SEQ_CST /* failure_memmodel */);
   /*!< \brief Sets `i` to `intended` and returns true iff `i` has the value `expected`, otherwise sets `expected` to the actual value of `i` and returns false.  @hideinitializer */

#define WOLFSENTRY_ATOMIC_UPDATE_FLAGS(i, set_i, clear_i, pre_i, post_i)\
do {                                                                    \
    *(pre_i) = (i);                                                     \
    for (;;) {                                                          \
        *(post_i) = (*(pre_i) | (set_i)) & ~(clear_i);                  \
        if (*(post_i) == *(pre_i))                                      \
            break;                                                      \
        if (WOLFSENTRY_ATOMIC_CMPXCHG(                                  \
                &(i),                                                   \
                (pre_i),                                                \
                *(post_i),                                              \
                0 /* weak */,                                           \
                __ATOMIC_SEQ_CST /* success_memmodel */,                \
                __ATOMIC_SEQ_CST /* failure_memmodel */))               \
            break;                                                      \
    }                                                                   \
} while (0)
   /*!< \brief Sets bits `set_i` in `i`, clears bits `clear_i` in `i`, and sets `pre_i` to the value of `i` before any changes, and `post_i` to the value of `i` after changes.  @hideinitializer */

#define WOLFSENTRY_ATOMIC_RESET(i, pre_i)                               \
do {                                                                    \
    *(pre_i) = (i);                                                     \
    for (;;) {                                                          \
        if (*(pre_i) == 0)                                              \
            break;                                                      \
        if (WOLFSENTRY_ATOMIC_CMPXCHG(                                  \
                &(i),                                                   \
                (pre_i),                                                \
                0,                                                      \
                0 /* weak */,                                           \
                __ATOMIC_SEQ_CST /* success_memmodel */,                \
                __ATOMIC_SEQ_CST /* failure_memmodel */))               \
            break;                                                      \
    }                                                                   \
} while (0)
   /*!< \brief Clears all bits in `i`, saving the previous value of `i` in `pre_i`.  @hideinitializer */

#define WOLFSENTRY_ATOMIC_INCREMENT_UNSIGNED_SAFELY(i, x, out)          \
do {                                                                    \
    __typeof__(i) _pre_i = (i);                                         \
    __typeof__(i) _post_i = _pre_i;                                     \
    for (;;) {                                                          \
        if (MAX_UINT_OF(i) - _pre_i < (x)) {                            \
            _post_i = 0;                                                \
            break;                                                      \
        }                                                               \
        _post_i = (__typeof__(i))(_pre_i + (x));                        \
        if (_post_i == _pre_i)                                          \
            break;                                                      \
        if (WOLFSENTRY_ATOMIC_CMPXCHG(                                  \
                &(i),                                                   \
                &_pre_i,                                                \
                _post_i,                                                \
                0 /* weak */,                                           \
                __ATOMIC_SEQ_CST /* success_memmodel */,                \
                __ATOMIC_SEQ_CST /* failure_memmodel */))               \
            break;                                                      \
    }                                                                   \
    (out) = _post_i;                                                    \
} while(0)
   /*!< \brief Adds `x` to unsigned integer `i`, guarding against overflow, saving the sum to `out`.  If overflow would occur, error is indicated by saving `0` to `out`, and `i` is left unchanged.  @hideinitializer */

#define WOLFSENTRY_ATOMIC_INCREMENT_UNSIGNED_SAFELY_BY_ONE(i, out)      \
    WOLFSENTRY_ATOMIC_INCREMENT_UNSIGNED_SAFELY(i, 1U, out)
   /*!< \brief Increments unsigned integer `i` by one, guarding against overflow, saving the result to `out`.  If overflow would occur, error is indicated by saving `0` to `out`, and `i` is left unchanged.  @hideinitializer */

#define WOLFSENTRY_ATOMIC_DECREMENT_UNSIGNED_SAFELY(i, x, out)          \
do {                                                                    \
    __typeof__(i) _pre_i = (i);                                         \
    __typeof__(i) _post_i = _pre_i;                                     \
    for (;;) {                                                          \
        if (_pre_i < (x)) {                                             \
            _post_i = MAX_UINT_OF(i);                                   \
            break;                                                      \
        }                                                               \
        _post_i = (__typeof__(i))(_pre_i - (x));                        \
        if (_post_i == _pre_i)                                          \
            break;                                                      \
        if (WOLFSENTRY_ATOMIC_CMPXCHG  (                                \
                &(i),                                                   \
                &_pre_i,                                                \
                _post_i,                                                \
                0 /* weak */,                                           \
                __ATOMIC_SEQ_CST /* success_memmodel */,                \
                __ATOMIC_SEQ_CST /* failure_memmodel */))               \
            break;                                                      \
    }                                                                   \
    (out) = _post_i;                                                    \
} while(0)
   /*!< \brief Subtracts `x` from unsigned integer `i`, guarding against underflow, saving the difference to `out`.  If underflow would occur, error is indicated by saving a max-value integer (all-1s) to `out`, and `i` is left unchanged.  @hideinitializer */

#define WOLFSENTRY_ATOMIC_DECREMENT_UNSIGNED_SAFELY_BY_ONE(i, out)      \
    WOLFSENTRY_ATOMIC_DECREMENT_UNSIGNED_SAFELY(i, 1U, out)
   /*!< \brief Decrements unsigned integer `i` by 1, guarding against underflow, saving the difference to `out`.  If underflow would occur, error is indicated by saving a max-value integer (all-1s) to `out`, and `i` is left unchanged.  @hideinitializer */

#else /* !WOLFSENTRY_THREADSAFE */

#define WOLFSENTRY_ATOMIC_INCREMENT(i, x) ((i) += (x))
#define WOLFSENTRY_ATOMIC_INCREMENT_BY_ONE(i) (++(i))
#define WOLFSENTRY_ATOMIC_DECREMENT(i, x) ((i) -= (x))
#define WOLFSENTRY_ATOMIC_DECREMENT_BY_ONE(i) (--(i))
#define WOLFSENTRY_ATOMIC_STORE(i, x) ((i)=(x))
#define WOLFSENTRY_ATOMIC_LOAD(i) (i)

#define WOLFSENTRY_ATOMIC_UPDATE_FLAGS(i, set_i, clear_i, pre_i, post_i)\
do {                                                                    \
    *(pre_i) = (i);                                                     \
    *(post_i) = (*(pre_i) | (set_i)) & ~(clear_i);                      \
    if (*(post_i) != *(pre_i))                                          \
        (i) = *(post_i);                                                \
} while (0)

#define WOLFSENTRY_ATOMIC_RESET(i, pre_i) do { *(pre_i) = (i); (i) = 0; } while (0)

#define WOLFSENTRY_ATOMIC_INCREMENT_UNSIGNED_SAFELY(i, x, out)          \
    do {                                                                \
        if (((x) > MAX_UINT_OF(i)) || ((MAX_UINT_OF(i) - (i) < (x))))   \
            (out) = 0U;                                                 \
        else                                                            \
            (out) = (i) = (__typeof__(i))((i) + (x));                   \
    } while (0)

#define WOLFSENTRY_ATOMIC_INCREMENT_UNSIGNED_SAFELY_BY_ONE(i, out)      \
    WOLFSENTRY_ATOMIC_INCREMENT_UNSIGNED_SAFELY(i, 1U, out)

#define WOLFSENTRY_ATOMIC_DECREMENT_UNSIGNED_SAFELY(i, x, out)          \
    do {                                                                \
        if (((x) > MAX_UINT_OF(i)) || ((i) < (x)))                      \
            (out) = MAX_UINT_OF(i);                                     \
        else                                                            \
            (out) = (i) = (__typeof__(i))((i) - (x));                   \
    } while (0)

#define WOLFSENTRY_ATOMIC_DECREMENT_UNSIGNED_SAFELY_BY_ONE(i, out)      \
    WOLFSENTRY_ATOMIC_DECREMENT_UNSIGNED_SAFELY(i, 1U, out)

#endif /* WOLFSENTRY_THREADSAFE */

#endif /* WOLFSENTRY_UTIL_H */
