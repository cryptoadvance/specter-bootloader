/**
 * @file       bl_util.h
 * @brief      Utility functions for Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef BL_UTIL_H_INCLUDED
/// Avoids multiple inclusion of the same file
#define BL_UTIL_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/// Text of internal error
#define BL_INTERNAL_ERROR "internal error"

#ifdef UNIT_TEST
/// Makes function static only if we are not building unit tests
#define BL_STATIC_NO_TEST
#else
/// Makes function static only if we are not building unit tests
#define BL_STATIC_NO_TEST static
#endif

/// Type of argument passed to callback functions
typedef uintptr_t bl_cbarg_t;

/**
 * Prototype for callback function called to report operation progress
 *
 * @param ctx          user-provided context
 * @param arg          user-provided argument
 * @param total        total number of steps
 * @param complete     number of complete steps
 */
typedef void (*bl_cb_progress_t)(void* ctx, bl_cbarg_t arg, uint32_t total,
                                 uint32_t complete);

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Tests two blocks of memory for equality
 *
 * If any of the pointers is NULL the result is always false.
 *
 * @param mema  pointer to the first block of memory
 * @param memb  pointer to the second block of memory
 * @param len   length of compared memory blocks
 * @return      true if memory blocks are equal
 */
static inline bool bl_memeq(const uint8_t* mema, const uint8_t* memb,
                            size_t len) {
  if (mema && memb && len) {
    return 0 == memcmp(mema, memb, len);
  }
  return false;
}

/**
 * Tests if all bytes of the memory block are equal to the value
 *
 * @param ptr    pointer to a block of memory
 * @param value  value to compare with
 * @param num    number of bytes to compare
 * @return       true if all bytes are equal to value
 */
bool bl_memveq(const void* ptr, int value, size_t num);

/**
 * Tests two strings for equality
 *
 * If any of the strings is NULL the result is always false.
 *
 * @param stra  first string, null-terminated, may be NULL
 * @param strb  second string, null-terminated, may be NULL
 * @return      true if strings are equal
 */
static inline bool bl_streq(const char* stra, const char* strb) {
  if (stra && strb) {
    return 0 == strcmp(stra, strb);
  }
  return false;
}

/**
 * Sets callback function which is called to report progress of operations
 *
 * @param cb_progress  pointer to callback function, NULL to disable
 * @param user_ctx     user-provided context passed to callback function
 */
void bl_set_progress_callback(bl_cb_progress_t cb_progress, void* user_ctx);

/**
 * Reports progress by calling a callback function if it is initialized
 *
 * @param arg       argument passed to callback function
 * @param total     total number of steps
 * @param complete  number of complete steps
 */
void bl_report_progress(bl_cbarg_t arg, uint32_t total, uint32_t complete);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // BL_UTIL_H_INCLUDED