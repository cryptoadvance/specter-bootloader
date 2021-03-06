/**
 * @file       bl_syscalls_test.c
 * @brief      System call emulation for unit tests
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "bl_util.h"
#include "bl_syscalls.h"

/// Flags used with fnmatch() function to match file names
#define FNMATCH_FLAGS (FNM_FILE_NAME | FNM_PERIOD)

/// Flash memory map
// clang-format off
const bl_addr_t bl_flash_map[bl_flash_map_nitems] = {
  [bl_flash_firmware_base]          = 0x08020000U,
  [bl_flash_firmware_size]          = 1664U * 1024U,
  [bl_flash_firmware_part1_size]    = 128U * 1024U,
  [bl_flash_bootloader_image_base]  = 0x081C0000U,
  [bl_flash_bootloader_copy1_base]  = 0x081C0000U,
  [bl_flash_bootloader_copy2_base]  = 0x081E0000U,
  [bl_flash_bootloader_size]        = 128U * 1024U };
// clang-format on

/// Maps alert type to string
// clang-format off
static const char* alert_type_str[bl_nalerts] = {
  [bl_alert_info]    = "INFO",
  [bl_alert_warning] = "WARNING",
  [bl_alert_error]   = "ERROR" };
// clang-format on

/// Base address of emulated flash memory
const bl_addr_t flash_emu_base = 0x08000000U;
/// Buffer in RAM used to emulate flash memory
uint8_t* flash_emu_buf = NULL;
/// Size of currently allocated flash emulation buffer
size_t flash_emu_size = 0U;

bool blsys_init(void) {
  flash_emu_buf = (uint8_t*)malloc(flash_emu_size);
  if (!flash_emu_buf) {
    blsys_fatal_error("Unable to allocate flash emulation buffer");
  }
  memset(flash_emu_buf, 0xFF, flash_emu_size);
  return true;
}

void blsys_deinit(void) {
  if (flash_emu_buf) {
    free(flash_emu_buf);
  }
}

/**
 * Checks if area in flash memory falls in valid address range
 *
 * @param addr  starting address
 * @param size  area size
 * @return      true if successful
 */
static bool check_flash_area(bl_addr_t addr, size_t size) {
  if (addr >= flash_emu_base && addr <= SIZE_MAX - size &&
      addr + size <= flash_emu_base + flash_emu_size) {
    return true;
  }
  return false;
}

bool blsys_flash_erase(bl_addr_t addr, size_t size) {
  if (flash_emu_buf && check_flash_area(addr, size)) {
    size_t offset = addr - flash_emu_base;
    memset(flash_emu_buf + offset, 0xFFU, size);
    return true;
  }
  return false;
}

bool blsys_flash_read(bl_addr_t addr, void* buf, size_t len) {
  if (flash_emu_buf && buf && check_flash_area(addr, len)) {
    size_t offset = addr - flash_emu_base;
    memcpy(buf, flash_emu_buf + offset, len);
    return true;
  }
  return false;
}

bool blsys_flash_write(bl_addr_t addr, const void* buf, size_t len) {
  if (flash_emu_buf && buf && check_flash_area(addr, len)) {
    size_t offset = addr - flash_emu_base;
    // Check if flash area is erased
    for(size_t idx = offset; idx < offset + len; ++idx) {
      if(flash_emu_buf[idx] != 0xFFU) {
        return false;
      }
    }
    memcpy(flash_emu_buf + offset, buf, len);
    return true;
  }
  return false;
}

uint32_t blsys_media_devices(void) { return 1U; }

bool blsys_media_check(uint32_t device_idx) {
  return (0U == device_idx) ? true : false;
}

bool blsys_media_mount(uint32_t device_idx) {
  return (0U == device_idx) ? true : false;
}

void blsys_media_umount(void) {}

const char* blsys_ffind_first(bl_ffind_ctx_t* ctx, const char* path,
                              const char* pattern) {
  if (ctx && path && pattern) {
    ctx->pattern = strdup(pattern);
    ctx->dir = opendir(('\0' == *path || bl_streq(path, "/")) ? "./" : path);
    if (ctx->pattern && ctx->dir) {
      struct dirent* ent;
      do {
        ent = readdir(ctx->dir);
        if (ent) {
          if (0 == fnmatch(pattern, ent->d_name, FNMATCH_FLAGS)) {
            return ent->d_name;
          }
        }
      } while (ent);
    }
  }
  return NULL;
}

const char* blsys_ffind_next(bl_ffind_ctx_t* ctx) {
  if (ctx && ctx->pattern && ctx->dir) {
    struct dirent* ent;
    do {
      ent = readdir(ctx->dir);
      if (ent) {
        if (0 == fnmatch(ctx->pattern, ent->d_name, FNMATCH_FLAGS)) {
          return ent->d_name;
        }
      }
    } while (ent);
  }
  return NULL;
}

void blsys_ffind_close(bl_ffind_ctx_t* ctx) {
  if (ctx) {
    if (ctx->pattern) {
      free(ctx->pattern);
      ctx->pattern = NULL;
    }
    if (ctx->dir) {
      closedir(ctx->dir);
      ctx->dir = NULL;
    }
  }
}

bl_file_t blsys_fopen(bl_file_obj_t* p_file_obj, const char* filename,
                      const char* mode) {
  (void)p_file_obj;
  return fopen(filename, mode);
}

size_t blsys_fread(void* ptr, size_t size, size_t count, bl_file_t file) {
  return fread(ptr, size, count, file);
}

bl_foffset_t blsys_ftell(bl_file_t file) { return (bl_foffset_t)ftell(file); }

int blsys_fseek(bl_file_t file, bl_foffset_t offset, int origin) {
  return fseek(file, offset, origin);
}

bl_fsize_t blsys_fsize(bl_file_t file) {
  bl_fsize_t file_size = 0U;

  long curr_pos = ftell(file);
  if (curr_pos >= 0) {
    if (fseek(file, 0L, SEEK_END)) {
      long end_pos = ftell(file);
      if (end_pos >= 0) {
        file_size = (bl_fsize_t)end_pos;
      }
    }
    fseek(file, curr_pos, SEEK_SET);
  }
  return file_size;
}

int blsys_feof(bl_file_t file) { return feof(file); }

int blsys_fclose(bl_file_t file) { return fclose(file); }

bl_alert_status_t blsys_alert(blsys_alert_type_t type, const char* caption,
                              const char* text, uint32_t time_ms,
                              uint32_t flags) {
  return bl_alert_terminated;
}

void blsys_progress(const char* caption, const char* operation,
                    uint32_t percent_x100) {}
