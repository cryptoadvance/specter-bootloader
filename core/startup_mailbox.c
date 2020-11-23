/**
 * @file       startup_mailbox.c
 * @brief      Mailbox used to pass parameters to the Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include "startup_mailbox.h"
#include "crc32.h"

/// Expected size of the mailbox structure
#define MAILBOX_EXPECTED_SIZE 32U

/**
 * Checks that code is compiled and liked correctly
 * @return  true if successful
 */
static inline bool sanity_check(void) {
  return (MAILBOX_EXPECTED_SIZE == sizeof(bl_args_t));
}

bool bl_read_args(const void* p_mailbox, bl_args_t* p_args) {
  if (sanity_check() && p_mailbox && p_args) {
    const bl_args_t* p_mb_args = (const bl_args_t*)p_mailbox;
    uint32_t crc = crc32_fast(p_mailbox, offsetof(bl_args_t, struct_crc), 0U);
    if (crc == p_mb_args->struct_crc) {
      *p_args = *p_mb_args;
      return true;
    }
  }
  return false;
}

bool bl_write_args(void* p_mailbox, const bl_args_t* p_args) {
  if (sanity_check()) {
    bl_args_t* p_mb_args = (bl_args_t*)p_mailbox;
    *p_mb_args = *p_args;
    p_mb_args->struct_crc =
        crc32_fast(p_mailbox, offsetof(bl_args_t, struct_crc), 0U);
    return true;
  }
  return false;
}
