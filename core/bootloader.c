/**
 * @file       bootloader.c
 * @brief      Bootloader implementation (main loop)
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include "bootloader.h"

/**
 * Checks that code is compiled and liked correctly
 * @return  true if successful
 */
static inline bool sanity_check(void) {
  int x = 1;
  char* is_le_machine = (char*)&x;
  return is_le_machine;
}

bl_status_t bootloader_run(const bl_args_t* p_args, bl_flags_t flags) {
  // TODO: implement
  return bl_status_normal_exit;
}
