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

#if defined(__GNUC__) || defined(__clang__)
/// Compiler attribute
#define BL_ATTRS(x) __attribute__(x)
#else
/// Compiler attribute (empty macro)
#define BL_ATTRS(x)
#endif

/// Text of internal error
#define BL_INTERNAL_ERROR "internal error"

#ifdef UNIT_TEST
/// Makes function static only if we are not building unit tests
#define BL_STATIC_NO_TEST
#else
/// Makes function static only if we are not building unit tests
#define BL_STATIC_NO_TEST static
#endif

/// Maximum allowed value ov version number
#define BL_VERSION_MAX 4199999999U
/// Version is not available
#define BL_VERSION_NA 0U
/// Maximum size of version string including null character
#define BL_VERSION_STR_MAX 16U

/**
 * Macro returning size of structure's member
 *
 * @param type    type name of the structure
 * @param member  member name
 * @return        size of member in bytes
 */
#define BL_MEMBER_SIZE(type, member) sizeof(((type*)0)->member)

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
static inline bool bl_memeq(const void* mema, const void* memb, size_t len) {
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
 * Appends characters from one string to another with bounds checking
 *
 * This operation is guaranteed to be atomic: if the function fails,
 * the destination string remains unchanged and no extra data is written to the
 * destination buffer.
 *
 * @param dst       destination buffer containing 1-st null-terminated string
 * @param dst_size  size of the destination buffer in bytes
 * @param src       buffer containing 2-nd null-terminated string
 * @return          true if successful
 */
bool bl_strcat_checked(char* dst, size_t dst_size, const char* src);

/**
 * Appends formatted data to a string
 *
 * @param dst_buf   destination buffer containing a null-terminated string
 * @param dst_size  size of the destination buffer in bytes
 * @param format    null-terminated format string
 * @param ...       list of arguments
 * @return          true if successful
 */
bool bl_format_append(char* dst_buf, size_t dst_size, const char* format, ...);

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

/**
 * Calculates percent of completeness in 0.01% inits
 *
 * @param total     total number of steps
 * @param complete  number of complete steps
 */
uint32_t bl_percent_x100(uint32_t total, uint32_t complete);

/**
 * Returns version string from version number
 *
 * Provided buffer should have size at least BL_VERSION_STR_MAX bytes to be able
 * to receive any possible version string.
 *
 * @param version   version number, as stored in header
 * @param buf       buffer where version null-terminated string will be placed
 * @param buf_size  size of provided buffer in bytes
 * @return          true if successful
 */
bool bl_version_to_str(uint32_t version, char* buf, size_t buf_size);

/**
 * Returns version string from version number formated for signature message
 *
 * Provided buffer should have size at least BL_VERSION_STR_MAX bytes to be able
 * to receive any possible version string.
 *
 * @param version   version number, as stored in header
 * @param buf       buffer where version null-terminated string will be placed
 * @param buf_size  size of provided buffer in bytes
 * @return          true if successful
 */
bool bl_version_to_sig_str(uint32_t version, char* buf, size_t buf_size);

/**
 * Decodes XML version tag
 *
 * @param tag  tag string
 * @return     decoded version or BL_VERSION_NA in case of failure
 */
uint32_t bl_decode_version_tag(const char* tag);

#ifdef __cplusplus
}  // extern "C"
#endif

/**
 * Checks if version number corresponds to a "release candidate" version
 *
 * @param version  version number, as stored in header
 * @return         true if this version is a "release candidate"
 * @return false
 */
static inline bool bl_version_is_rc(uint32_t version) {
  if (version != BL_VERSION_NA && version <= BL_VERSION_MAX) {
    uint32_t rc_rev = version % 100U;
    return rc_rev <= 98U;
  }
  return false;
}

/**
 * No-op function used to keep variable from removal by compiler and linker
 *
 * It exists because "volatile" and "__attribute__((used))" do not work in 100%
 * of cases and modification of linker script is inconvenient and may break
 * existing projects.
 *
 * @param ptr  pointer to a variable
 */
static inline void bl_keep_variable(volatile const void* ptr) {
  (void)*(volatile const char*)ptr;
}

/**
 * Returns maximum of two uint32_t numbers
 *
 * @param a  1-st number
 * @param b  2-nd number
 * @return   maximum of (a,b)
 */
static inline uint32_t bl_max_u32(uint32_t a, uint32_t b) {
  return (a > b) ? a : b;
}

/**
 * Returns maximum of three uint32_t numbers
 *
 * @param a  1-st number
 * @param b  2-nd number
 * @param c  3-rd number
 * @return   maximum of (a,b,c)
 */
static inline uint32_t bl_max3_u32(uint32_t a, uint32_t b, uint32_t c) {
  return bl_max_u32(bl_max_u32(a, b), c);
}

#endif  // BL_UTIL_H_INCLUDED
