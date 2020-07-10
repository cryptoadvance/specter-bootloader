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
#include "ff.h"

/// Adds "weak" attribute
#define WEAK                            BL_ATTRS((weak))

WEAK bool blsys_flash_map_get_items(int items, ...) {
  return false;
}

WEAK bool blsys_flash_erase(bl_addr_t addr, size_t size) {
  return false;
}

WEAK bool blsys_flash_read(bl_addr_t addr, const uint8_t* buf, size_t len) {
  return false;
}

WEAK bool blsys_flash_write(bl_addr_t addr, const uint8_t* buf, size_t len) {
  return false;
}

WEAK uint32_t blsys_media_devices(void) {
  return 0U;
}

WEAK bool blsys_media_check(uint32_t device_idx) {
  return false;
}

WEAK bool blsys_media_mount(uint32_t device_idx) {
  return false;
}

WEAK void blsys_media_umount(void) {
}

WEAK const char* blsys_ffind_first(bl_ffind_ctx_t* ctx, const char* path,
                                   const char* pattern) {
  if(ctx && path && pattern) {
    // Only 8 bit encodings are supported
    if(sizeof(char) == sizeof(TCHAR)) {
      FRESULT fr = f_findfirst( &ctx->dj, &ctx->fno, (const TCHAR*)path,
                                (const TCHAR*)pattern );
      if(fr == FR_OK && ctx->fno.fname[0]) {
        return ctx->fno.fname;
      }
    }
  }
  return NULL;
}

WEAK const char* blsys_ffind_next(bl_ffind_ctx_t* ctx) {
  if(ctx) {
    // Only 8 bit encodings are supported
    if(sizeof(char) == sizeof(TCHAR)) {
      FRESULT fr = f_findnext(&ctx->dj, &ctx->fno);
      if(fr == FR_OK && ctx->fno.fname[0]) {
        return ctx->fno.fname;
      }
    }
  }
  return NULL;
}

WEAK void blsys_ffind_close(bl_ffind_ctx_t* ctx) {
  if(ctx) {
    f_closedir(&ctx->dj);
  }
}

/**
 * Returns FatFs f_open() mode code from POSIX fopen() mode string
 *
 * @param mode  POSIX mode string
 * @return      FatFs integer mode code (set of flags), or -1 if failed
 */
static int get_fatfs_mode(const char* mode) {
  if(bl_streq("rb", mode)) {
    return (FA_READ | FA_OPEN_EXISTING);
  }
  return -1;
}

WEAK bl_file_t* blsys_fopen(bl_file_t* p_file, const char* filename,
                            const char* mode) {
  if(p_file && filename && mode && sizeof(char) == sizeof(TCHAR)) {
    int fatfs_mode = get_fatfs_mode(mode);
    if(fatfs_mode != -1) {
      if(FR_OK == f_open(p_file, (const TCHAR*)filename, fatfs_mode)) {
        return p_file;
      }
    }
  }
  return NULL;
}

WEAK size_t blsys_fread(void* ptr, size_t size, size_t count,
                        bl_file_t* p_file) {
  if(ptr && size && count && p_file) {
    UINT bytes_read = 0U;
    if(FR_OK == f_read(p_file, ptr, (UINT)(size * count), &bytes_read)) {
      return (size_t)bytes_read;
    }
  }
  return 0U;
}

WEAK int blsys_fseek(bl_file_t* p_file, bl_foffset_t offset, int origin) {
  bl_foffset_t new_pos = -1;

  if(SEEK_SET == origin) {
    new_pos = offset;
  } else if(SEEK_CUR == origin) {
    new_pos = (bl_foffset_t)f_tell(p_file) + offset;
  } else if(SEEK_END == origin) {
    new_pos = (bl_foffset_t)f_size(p_file) + offset;
  }

  if(new_pos >= 0) {
    if(FR_OK == f_lseek(p_file, (FSIZE_t)new_pos)) {
      if((bl_foffset_t)f_tell(p_file) == new_pos) {
        return 0; // Successful
      }
    }
  }
  return -1; // Failed
}

WEAK bl_fsize_t blsys_fsize(bl_file_t* p_file) {
  if(p_file) {
    return (bl_fsize_t)f_size(p_file);
  }
  return 0U;
}

WEAK int blsys_feof(bl_file_t* p_file) {
  if(p_file) {
    return f_eof(p_file);
  }
  return -1;
}

WEAK void blsys_fclose(bl_file_t* p_file) {
  if(p_file) {
    f_close(p_file);
  }
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
