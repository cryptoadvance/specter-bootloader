/**
 * @file       bl_syscalls.c
 * @brief      System abstraction layer for STM32F469I-DISCO platform
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 *
 * System abstraction layer for STM32F469I-DISCO platform. These functions are
 * called from core of Bootloader to obtain platform parameters and to perform
 * platform-specific operations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bl_util.h"
#include "bl_syscalls.h"
#include "ff.h"

/// Flash memory map
// clang-format off
const bl_addr_t bl_flash_map[bl_flash_map_nitems] = {
  [bl_flash_firmware_base]          = 0x08008000U,
  [bl_flash_firmware_size]          = (96U + 1760U) * 1024U,
  [bl_flash_bootloader_image_base]  = 0x081C0000U,
  [bl_flash_bootloader_copy1_base]  = 0x081C0000U,
  [bl_flash_bootloader_copy2_base]  = 0x081E0000U,
  [bl_flash_bootloader_size]        = 128U * 1024U };
// clang-format on

bool blsys_init(void) {
  // TODO: implement
  return false;
}

void blsys_deinit(void) {
  // TODO: implement
}

bool blsys_flash_erase(bl_addr_t addr, size_t size) {
  // TODO: implement
  return false;
}

bool blsys_flash_read(bl_addr_t addr, void* buf, size_t len) {
  // TODO: implement
  return false;
}

bool blsys_flash_write(bl_addr_t addr, const void* buf, size_t len) {
  // TODO: implement
  return false;
}

uint32_t blsys_media_devices(void) {
  // TODO: implement
  return 0U;
}

bool blsys_media_check(uint32_t device_idx) {
  // TODO: implement
  return false;
}

bool blsys_media_mount(uint32_t device_idx) {
  // TODO: implement
  return false;
}

void blsys_media_umount(void) {
  // TODO: implement
}

BL_ATTRS((noreturn)) void blsys_fatal_error(const char* text) {
  // TODO: implement
  exit(1);
}

bl_alert_status_t blsys_alert(blsys_alert_type_t type, const char* caption,
                              const char* text, uint32_t time_ms,
                              uint32_t flags) {
  // TODO: implement
  return bl_alert_terminated;
}

void blsys_progress(const char* caption, const char* operation,
                    uint32_t percent_x100) {
  // TODO: implement
}
