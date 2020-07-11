/**
 * @file       bl_syscalls_weak.c
 * @brief      System abstraction layer for Bootloader core (weak functions)
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bootloader_private.h"
#include "bl_syscalls.h"

// TODO: remove
#if 0
DIR *dir;
struct dirent *ent;
if ((dir = opendir ("c:\\src\\")) != NULL) {
  /* print all the files and directories within directory */
  while ((ent = readdir (dir)) != NULL) {
    printf ("%s\n", ent->d_name);
  }
  closedir (dir);
} else {
  /* could not open directory */
  perror ("");
  return EXIT_FAILURE;
}
#endif

bool blsys_init(void) {
  // TODO: implement
  return true;
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

bool blsys_flash_read(bl_addr_t addr, const uint8_t* buf, size_t len) {
  // TODO: implement
  return false;
}

bool blsys_flash_write(bl_addr_t addr, const uint8_t* buf, size_t len) {
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

const char* blsys_ffind_first(bl_ffind_ctx_t* ctx, const char* path,
                              const char* pattern) {
  // TODO: implement
  return NULL;
}

const char* blsys_ffind_next(bl_ffind_ctx_t* ctx) {
  // TODO: implement
  return NULL;
}

void blsys_ffind_close(bl_ffind_ctx_t* ctx) {
  // TODO: implement
}

bl_file_t blsys_fopen(bl_file_obj_t* p_file_obj, const char* filename,
                      const char* mode) {
  // TODO: implement
  return NULL;
}

size_t blsys_fread(void* ptr, size_t size, size_t count,
                   bl_file_t file) {
  // TODO: implement
  return 0U;
}

int blsys_fseek(bl_file_t file, bl_foffset_t offset, int origin) {
  // TODO: implement
  return -1; // Failed
}

bl_fsize_t blsys_fsize(bl_file_t file) {
  // TODO: implement
  return 0U;
}

int blsys_feof(bl_file_t file) {
  // TODO: implement
  return -1;
}

void blsys_fclose(bl_file_t file) {
  // TODO: implement
}

bl_alert_status_t blsys_alert(blsys_alert_type_t type, const char* caption,
                                   const char* text, uint32_t time_ms,
                                   uint32_t flags) {
  // TODO: implement
  return bl_alert_terminated;
}

void blsys_progress(const char* caption, const char* operation,
                         uint32_t n_total, uint32_t complete) {
  // TODO: implement
}
