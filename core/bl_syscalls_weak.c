/**
 * @file       bl_syscalls_weak.c
 * @brief      System abstraction layer for Bootloader core (weak functions)
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crc32.h"
#include "bl_util.h"
#include "bl_syscalls.h"

#ifndef PLATFORM_ID
/// Fallback platform identifier (normally should be defined in build)
#define PLATFORM_ID "unknown"
#endif

#ifdef WEAK
#undef WEAK
#endif
/// Adds "weak" attribute
#define WEAK BL_ATTRS((weak))

WEAK const char* blsys_platform_id(void) {
  static const char* platform_id_ = PLATFORM_ID;
  return platform_id_;
}

WEAK bool blsys_init(void) { return true; }

WEAK void blsys_deinit(void) {}

WEAK bool blsys_flash_map_get_items(int items, ...) { return false; }

WEAK bool blsys_flash_erase(bl_addr_t addr, size_t size) { return false; }

WEAK bool blsys_flash_read(bl_addr_t addr, void* buf, size_t len) {
  return false;
}

WEAK bool blsys_flash_write(bl_addr_t addr, const void* buf, size_t len) {
  return false;
}

WEAK bool blsys_flash_crc32(uint32_t* p_crc, bl_addr_t addr, size_t len) {
  if (p_crc && len) {
    uint8_t buf[128];
    size_t rm_bytes = len;
    bl_addr_t curr_addr = addr;

    while (rm_bytes) {
      size_t read_len = (rm_bytes < sizeof(buf)) ? rm_bytes : sizeof(buf);
      if (!blsys_flash_read(curr_addr, buf, read_len)) {
        return false;
      }
      *p_crc = crc32_fast(buf, read_len, *p_crc);
      curr_addr += read_len;
      rm_bytes -= read_len;
    }
    return true;
  }
  return false;
}

WEAK uint32_t blsys_media_devices(void) { return 1U; }

WEAK const char* blsys_media_name(uint32_t device_idx) {
  static const char* unknown = "unknown";
  return unknown;
}

WEAK bool blsys_media_check(uint32_t device_idx) {
  return (0U == device_idx) ? true : false;
}

WEAK bool blsys_media_mount(uint32_t device_idx) {
  return (0U == device_idx) ? true : false;
}

WEAK void blsys_media_umount(void) {}

WEAK const char* blsys_ffind_first(bl_ffind_ctx_t* ctx, const char* path,
                                   const char* pattern) {
#ifndef BL_NO_FATFS
  if (ctx && path && pattern) {
    // Only 8 bit encodings are supported
    if (sizeof(char) == sizeof(TCHAR)) {
      FRESULT fr = f_findfirst(&ctx->dj, &ctx->fno, (const TCHAR*)path,
                               (const TCHAR*)pattern);
      if (fr == FR_OK && ctx->fno.fname[0]) {
        return ctx->fno.fname;
      }
    }
  }
#endif  // !BL_NO_FATFS
  return NULL;
}

WEAK const char* blsys_ffind_next(bl_ffind_ctx_t* ctx) {
#ifndef BL_NO_FATFS
  if (ctx) {
    // Only 8 bit encodings are supported
    if (sizeof(char) == sizeof(TCHAR)) {
      FRESULT fr = f_findnext(&ctx->dj, &ctx->fno);
      if (fr == FR_OK && ctx->fno.fname[0]) {
        return ctx->fno.fname;
      }
    }
  }
#endif  // !BL_NO_FATFS
  return NULL;
}

WEAK void blsys_ffind_close(bl_ffind_ctx_t* ctx) {
#ifndef BL_NO_FATFS
  if (ctx) {
    f_closedir(&ctx->dj);
  }
#endif  // !BL_NO_FATFS
}

/**
 * Returns FatFs f_open() mode code from POSIX fopen() mode string
 *
 * @param mode  POSIX mode string
 * @return      FatFs integer mode code (set of flags), or -1 if failed
 */
static int get_fatfs_mode(const char* mode) {
#ifndef BL_NO_FATFS
  if (bl_streq("rb", mode)) {
    return (FA_READ | FA_OPEN_EXISTING);
  }
#endif  // !BL_NO_FATFS
  return -1;
}

WEAK bl_file_t blsys_fopen(bl_file_obj_t* p_file_obj, const char* filename,
                           const char* mode) {
#ifndef BL_NO_FATFS
  if (p_file_obj && filename && mode && sizeof(char) == sizeof(TCHAR)) {
    int fatfs_mode = get_fatfs_mode(mode);
    if (fatfs_mode != -1) {
      if (FR_OK == f_open(p_file_obj, (const TCHAR*)filename, fatfs_mode)) {
        return (bl_file_t)p_file_obj;
      }
    }
  }
#endif  // !BL_NO_FATFS
  return NULL;
}

WEAK size_t blsys_fread(void* ptr, size_t size, size_t count, bl_file_t file) {
#ifndef BL_NO_FATFS
  if (ptr && size && count && file) {
    UINT bytes_read = 0U;
    if (FR_OK == f_read(file, ptr, (UINT)(size * count), &bytes_read)) {
      return (size_t)bytes_read / size;
    }
  }
#endif  // !BL_NO_FATFS
  return 0U;
}

WEAK bl_foffset_t blsys_ftell(bl_file_t file) {
#ifndef BL_NO_FATFS
  if (file) {
    return (bl_foffset_t)f_tell(file);
  }
#endif  // !BL_NO_FATFS
  return -1;
}

WEAK int blsys_fseek(bl_file_t file, bl_foffset_t offset, int origin) {
#ifndef BL_NO_FATFS
  if (file) {
    bl_foffset_t new_pos = -1;

    if (SEEK_SET == origin) {
      new_pos = offset;
    } else if (SEEK_CUR == origin) {
      new_pos = (bl_foffset_t)f_tell(file) + offset;
    } else if (SEEK_END == origin) {
      new_pos = (bl_foffset_t)f_size(file) + offset;
    }

    if (new_pos >= 0) {
      if (FR_OK == f_lseek(file, (FSIZE_t)new_pos)) {
        if ((bl_foffset_t)f_tell(file) == new_pos) {
          return 0;  // Successful
        }
      }
    }
  }
#endif        // !BL_NO_FATFS
  return -1;  // Failed
}

WEAK bl_fsize_t blsys_fsize(bl_file_t file) {
#ifndef BL_NO_FATFS
  if (file) {
    return (bl_fsize_t)f_size(file);
  }
#endif  // !BL_NO_FATFS
  return 0U;
}

WEAK int blsys_feof(bl_file_t file) {
#ifndef BL_NO_FATFS
  if (file) {
    return f_eof(file);
  }
#endif  // !BL_NO_FATFS
  return -1;
}

WEAK int blsys_fclose(bl_file_t file) {
#ifndef BL_NO_FATFS
  if (file) {
    if (FR_OK == f_close(file)) {
      return 0;  // Successful
    }
  }
#endif  // !BL_NO_FATFS
  return EOF;
}

BL_ATTRS((weak, noreturn)) void blsys_fatal_error(const char* text) {
  blsys_alert(bl_alert_error, "Bootloader Error", text, BL_FOREVER, 0U);
  blsys_media_umount();
  blsys_deinit();
  exit(1);
  while (1) {  // Should not get there
  }
}

WEAK bl_alert_status_t blsys_alert(blsys_alert_type_t type, const char* caption,
                                   const char* text, uint32_t time_ms,
                                   uint32_t flags) {
  if (BL_FOREVER == time_ms) {
    blsys_media_umount();
    blsys_deinit();
    exit(1);
    while (1) {  // Should not get there
    }
  }
  return bl_alert_terminated;
}

WEAK void blsys_progress(const char* caption, const char* operation,
                         uint32_t percent_x100) {}
