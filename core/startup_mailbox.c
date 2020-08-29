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

/// Linker variable: mailbox size in 32-bit words
extern char _startup_mailbox_size;

/// Mailbox used by the Start-up code to pass parameters to the Bootloader
__attribute__((section(".startup_mailbox.bss")))
__attribute__((used)) static bl_args_t startup_mailbox;

/**
 * Checks that code is compiled and liked correctly
 * @return  true if successful
 */
static inline bool sanity_check(void) {
  return (MAILBOX_EXPECTED_SIZE == sizeof(startup_mailbox)) &&
         ((size_t)(&_startup_mailbox_size) == sizeof(startup_mailbox));
}

bool bl_read_args(bl_args_t* p_destination) {
  if (sanity_check()) {
    uint32_t crc =
        crc32_fast(&startup_mailbox, offsetof(bl_args_t, struct_crc), 0U);
    if (crc == startup_mailbox.struct_crc) {
      *p_destination = startup_mailbox;
      return true;
    }
  }
  return false;
}

bool bl_write_args(const bl_args_t* p_source) {
  if (sanity_check()) {
    startup_mailbox = *p_source;
    startup_mailbox.struct_crc =
        crc32_fast(&startup_mailbox, offsetof(bl_args_t, struct_crc), 0U);
    return true;
  }
  return false;
}
