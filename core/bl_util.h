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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Tests if all bytes of the memory block are equal to the value
 *
 * @param ptr    pointer to a block of memory
 * @param value  value to compare with
 * @param num    number of bytes to compare
 * @return       true if all bytes are equal to value
 */
bool bl_memvcmp(const void* ptr, int value, size_t num);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // BL_UTIL_H_INCLUDED