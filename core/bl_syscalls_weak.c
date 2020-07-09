/**
 * @file       bl_syscalls_weak.c
 * @brief      System abstraction layer for Bootloader core (weak functions)
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include <stdlib.h>
#include "bl_syscalls.h"

/// Adds "weak" attribute
#define WEAK                            BL_ATTRS((weak))

WEAK bool blsys_flash_map_get_items(int items, ...) {
  return false;
}

WEAK bool blsys_flash_erase(bl_addr_t addr, size_t size) {
  return false;
}

WEAK bool blsys_flash_write(bl_addr_t addr, const uint8_t* buf, size_t len) {
  return false;
}

WEAK bool blsys_check_storage(void) {
  return false;
}

WEAK bool blsys_mount_storage(void) {
  return false;
}

WEAK const char* blsys_ffind_first(bl_ffind_ctx_t* ctx, const char* path,
                                   const char* pattern) {
  return NULL;
}

WEAK const char* blsys_ffind_next(bl_ffind_ctx_t* ctx) {
  return NULL;
}

WEAK void blsys_ffind_close(bl_ffind_ctx_t* ctx) {
}

WEAK bool blsys_fopen(bl_file_t* p_file, const char * filename,
                      const char* mode) {
  return false;
}

WEAK size_t blsys_fread(void* ptr, size_t size, size_t count,
                        bl_file_t* p_file) {
  return 0U;
}

WEAK void blsys_fclose(bl_file_t* p_file) {
}

BL_ATTRS((weak, noreturn)) void blsys_fatal_error(const char* text)  {
  (void)text;
  exit(1);
}

WEAK bl_alert_status_t blsys_alert(blsys_alert_type_t type, const char* caption,
                                   const char* text, uint32_t time_ms,
                                   uint32_t flags) {
  return bl_alert_terminated;
}

WEAK void blsys_progress(const char* caption, const char* operation,
                         uint32_t n_total, uint32_t complete) {
}
