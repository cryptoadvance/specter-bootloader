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

bool blsys_init(void) {
  // TODO: implement
  return false;
}

void blsys_deinit(void) {
  // TODO: implement
}

bool blsys_flash_map_get_items(int items, ...) {
  // TODO: implement
  return false;
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

void blsys_progress(const char* caption, const char* operation, uint32_t total,
                    uint32_t complete) {
  // TODO: implement
}
