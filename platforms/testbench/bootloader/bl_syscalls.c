/**
 * @file       bl_syscalls.c
 * @brief      System call emulation for little-endian desktop computer
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "bl_util.h"
#include "bl_syscalls.h"

/// Name of file where contents of emulated flash memory is written
#define FLASH_EMU_FILE "flash_dump.bin"
/// Base address of emulated flash memory
#define FLASH_EMU_BASE 0x08000000U
/// Size of emulated flash memory, 2 megabytes
#define FLASH_EMU_SIZE (2U * 1024U * 1024U)
/// Flags used with fnmatch() function to match file names
#define FNMATCH_FLAGS (FNM_FILE_NAME | FNM_PERIOD)

/// Flash memory map
// clang-format off
static const bl_addr_t flash_map[bl_flash_map_nitems] = {
  [bl_flash_firmware_base]          = 0x08008000U,
  [bl_flash_firmware_size]          = (96U + 1760U) * 1024U,
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

/// Buffer in RAM used to emulate flash memory
static uint8_t* flash_emu_buf = NULL;
/// Printed characters of the progress message
static int progress_n_chr = -1;

bool blsys_init(void) {
  progress_n_chr = -1;
  flash_emu_buf = malloc(FLASH_EMU_SIZE);
  if (!flash_emu_buf) {
    blsys_fatal_error("unable to allocate flash emulation buffer");
  }
  memset(flash_emu_buf, 0xFF, FLASH_EMU_SIZE);
  return true;
}

void blsys_deinit(void) {
  if (flash_emu_buf) {
    size_t written = 0U;
    FILE* out_file = fopen(FLASH_EMU_FILE, "wb");
    if (out_file) {
      written = fwrite(flash_emu_buf, FLASH_EMU_SIZE, 1U, out_file);
      fclose(out_file);
    }
    free(flash_emu_buf);
    if (!written) {
      blsys_fatal_error("unable to dump emulated flash memory to a file");
    }
  }
}

bool blsys_flash_map_get_items(int items, ...) {
  va_list ap;

  va_start(ap, items);
  for (int i = 0; i < items; ++i) {
    bl_flash_map_item_t item_id = (bl_flash_map_item_t)va_arg(ap, int);
    bl_addr_t* p_item = va_arg(ap, bl_addr_t*);
    if ((int)item_id < 0 || (int)item_id >= bl_flash_map_nitems || !p_item) {
      return false;
    }
    *p_item = flash_map[item_id];
  }
  va_end(ap);

  return true;
}

/**
 * Checks if area in flash memory falls in valid address range
 *
 * @param addr  starting address
 * @param size  area size
 * @return      true if successful
 */
static bool check_flash_area(bl_addr_t addr, size_t size) {
  if (addr >= FLASH_EMU_BASE && addr <= SIZE_MAX - size &&
      addr + size <= FLASH_EMU_BASE + FLASH_EMU_SIZE) {
    return true;
  }
  return false;
}

bool blsys_flash_erase(bl_addr_t addr, size_t size) {
  if (flash_emu_buf && check_flash_area(addr, size)) {
    size_t offset = addr - FLASH_EMU_BASE;
    memset(flash_emu_buf + offset, 0, size);
    return true;
  }
  return false;
}

bool blsys_flash_read(bl_addr_t addr, void* buf, size_t len) {
  if (flash_emu_buf && buf && check_flash_area(addr, len)) {
    size_t offset = addr - FLASH_EMU_BASE;
    memcpy(buf, flash_emu_buf + offset, len);
    return true;
  }
  return false;
}

bool blsys_flash_write(bl_addr_t addr, const void* buf, size_t len) {
  if (flash_emu_buf && buf && check_flash_area(addr, len)) {
    size_t offset = addr - FLASH_EMU_BASE;
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
    ctx->dir = opendir(path);
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
  bool arg_error = true;
  if ((int)type >= 0 && (int)type < bl_nalerts && caption && text) {
    const char* alert = alert_type_str[type] ? alert_type_str[type] : "UNKNOWN";
    arg_error = false;
    const size_t buf_size = strlen(caption) + strlen(text) + 100U;
    char* str_buf = malloc(buf_size);
    if (str_buf) {
      int n_chr =
          snprintf(str_buf, buf_size, "(%s) %s: %s", alert, caption, text);
      if (n_chr > 0) {
        printf("\n%s", str_buf);
        progress_n_chr = -1;
      }
      free(str_buf);
    }
  }

  if (arg_error || (BL_FOREVER == time_ms)) {
    blsys_deinit();
    printf("\nBootloader terminated");
    exit(-1);
  }
  return bl_alert_terminated;
}

/**
 * Erases a number of characters from console using backspace
 *
 * @param n_chr  number of character to erase, no-op if < 1
 */
static void console_erase(int n_chr) {
  if (n_chr > 0) {
    char* str_buf = malloc(3U * n_chr + 1U);
    if (str_buf) {
      memset(str_buf, '\b', n_chr);
      memset(str_buf + n_chr, ' ', n_chr);
      memset(str_buf + 2U * n_chr, '\b', n_chr);
      str_buf[3U * n_chr] = '\0';
      printf("%s", str_buf);
      free(str_buf);
    }
  }
}

void blsys_progress(const char* caption, const char* operation, uint32_t total,
                    uint32_t complete) {
  if (caption && operation) {
    const size_t buf_size = strlen(caption) + strlen(operation) + 100U;
    char* str_buf = malloc(buf_size);
    if (str_buf) {
      uint64_t progress = (uint64_t)complete * 100U / total;
      int n_chr = snprintf(str_buf, buf_size, "%s: %s - %3u%%", caption,
                           operation, (unsigned int)progress);
      if (n_chr > 0) {
        console_erase(progress_n_chr);
        printf(progress_n_chr > 0 ? "%s" : "\n%s", str_buf);
        progress_n_chr = n_chr;
      }
      free(str_buf);
    }
  }
}
