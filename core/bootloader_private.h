/**
 * @file       bootloader_private.h
 * @brief      Private functions of Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef BOOTLOADER_PRIVATE_H_INCLUDED
/// Avoids multiple inclusion of the same file
#define BOOTLOADER_PRIVATE_H_INCLUDED

#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

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

#endif  // BOOTLOADER_PRIVATE_H_INCLUDED
