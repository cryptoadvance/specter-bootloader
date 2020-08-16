/**
 * @file       bl_syscalls.c
 * @brief      System abstraction layer for STM32F469I-DISCO platform
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 *
 * System abstraction layer for STM32F469I-DISCO platform. These functions are
 * called from core of Bootloader to obtain platform parameters and to perform
 * platform-specific operations.
 *
 * Flash sector mapping is taken from the MicroPython project. Original license
 * and copyright notice are provided at the end of file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stm32f4xx_hal.h"
#include "bl_util.h"
#include "bl_syscalls.h"
#include "ff.h"

/// Index of the
#define DEVICE_IDX_MICROSD 0U
/// Base address of flash memory region to which Bootloader has access
#define FLASH_WR_BASE (bl_flash_map[bl_flash_firmware_base])
/// Size of flash memory region to which Bootloader has access
#define FLASH_WR_SIZE                     \
  (bl_flash_map[bl_flash_firmware_size] + \
   2U * bl_flash_map[bl_flash_bootloader_size])
/// All flash memory error flags
#define FLASH_FLAG_ALL_ERRORS_                                                 \
  (FLASH_FLAG_EOP | FLASH_FLAG_OPERR | FLASH_FLAG_WRPERR | FLASH_FLAG_PGAERR | \
   FLASH_FLAG_PGPERR | FLASH_FLAG_PGSERR)

/// Indexes of the media devices
typedef enum media_device_idx_t {
  media_micro_sd = 0,  ///< microSD card slot
  media_n_devices      ///< Number of media devices, not a device index
} media_device_idx_t;

/// Flash memory layout entry
typedef struct {
  bl_addr_t base_address;  ///< Base address of the sector
  bl_addr_t sector_size;   ///< Size of the sector
  uint32_t sector_count;   ///< Number of sectors having the same size
} flash_layout_t;

/// Layout of flash memory
// clang-format off
static const flash_layout_t flash_layout[] = {
  { 0x08000000, 0x04000, 4 },
  { 0x08010000, 0x10000, 1 },
  { 0x08020000, 0x20000, 3 },
  #if defined(FLASH_SECTOR_8)
  { 0x08080000, 0x20000, 4 },
  #endif
  #if defined(FLASH_SECTOR_12)
  { 0x08100000, 0x04000, 4 },
  { 0x08110000, 0x10000, 1 },
  { 0x08120000, 0x20000, 7 },
  #endif
};
// clang-format on

/// Flash memory map
// clang-format off
const bl_addr_t bl_flash_map[bl_flash_map_nitems] = {
  [bl_flash_firmware_base]          = 0x08020000U,
  [bl_flash_firmware_size]          = 1664U * 1024U,
  [bl_flash_bootloader_image_base]  = 0x081C0000U,
  [bl_flash_bootloader_copy1_base]  = 0x081C0000U,
  [bl_flash_bootloader_copy2_base]  = 0x081E0000U,
  [bl_flash_bootloader_size]        = 128U * 1024U };
// clang-format on

/// Names of media devices
static const char* media_name[media_n_devices] = {[media_micro_sd] = "microSD"};

/**
 * Returns information about flash memory sector specified by address
 *
 * @param addr        address within flash memory range
 * @param start_addr  pointer to variable receiving start address of the sector,
 *                    ignored if NULL
 * @param size        pointer to variable receiving size of the sector,
 *                    ignored if NULL
 * @return            sector index, or -1 if address is incorrect
 */
int flash_get_sector_info(bl_addr_t addr, bl_addr_t* start_addr,
                          bl_addr_t* size) {
  if (addr >= flash_layout[0].base_address) {
    int sector_index = 0;
    for (int i = 0; i < sizeof(flash_layout) / sizeof(flash_layout[0]); ++i) {
      for (int j = 0; j < flash_layout[i].sector_count; ++j) {
        bl_addr_t sector_start_next = flash_layout[i].base_address +
                                      (j + 1) * flash_layout[i].sector_size;
        if (addr < sector_start_next) {
          if (start_addr != NULL) {
            *start_addr =
                flash_layout[i].base_address + j * flash_layout[i].sector_size;
          }
          if (size != NULL) {
            *size = flash_layout[i].sector_size;
          }
          return sector_index;
        }
        ++sector_index;
      }
    }
  }
  return -1;
}

bool blsys_init(void) { return true; }

void blsys_deinit(void) {}

/**
 * Checks if area in flash memory falls in valid address range
 *
 * @param addr  starting address
 * @param size  area size
 * @return      true if successful
 */
static bool check_flash_area(bl_addr_t addr, size_t size) {
  if (addr >= FLASH_WR_BASE && addr <= SIZE_MAX - size &&
      addr + size <= FLASH_WR_BASE + FLASH_WR_SIZE) {
    return true;
  }
  return false;
}

bool blsys_flash_erase(bl_addr_t addr, size_t size) {
  if (size && check_flash_area(addr, size)) {
    bl_addr_t first_s_addr = 0U;
    int first_s_idx = flash_get_sector_info(addr, &first_s_addr, NULL);
    bl_addr_t last_s_addr = 0U;
    bl_addr_t last_s_size = 0U;
    int last_s_idx =
        flash_get_sector_info(addr + size - 1U, &last_s_addr, &last_s_size);
    if (first_s_idx >= 0 && last_s_idx >= first_s_idx && first_s_addr == addr &&
        (addr + size) == (last_s_addr + last_s_size)) {
      if (HAL_OK == HAL_FLASH_Unlock()) {
        __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_ALL_ERRORS_);
        FLASH_EraseInitTypeDef erase_cmd = {
            .TypeErase = TYPEERASE_SECTORS,
            .VoltageRange = VOLTAGE_RANGE_3,
            .Sector = first_s_idx,
            .NbSectors = last_s_idx - first_s_idx,
        };
        uint32_t erase_err = 0;
        int erase_status = HAL_FLASHEx_Erase(&erase_cmd, &erase_err);
        return (HAL_OK == HAL_FLASH_Lock()) && (HAL_OK == erase_status);
      }
    }
  }
  return false;
}

bool blsys_flash_read(bl_addr_t addr, void* buf, size_t len) {
  if (buf && len && check_flash_area(addr, len)) {
    memcpy(buf, (const void*)addr, len);
    return true;
  }
  return false;
}

bool blsys_flash_write(bl_addr_t addr, const void* buf, size_t len) {
  if (buf && len && check_flash_area(addr, len) && sizeof(uint64_t) > 1U) {
    if (HAL_OK == HAL_FLASH_Unlock()) {
      uint32_t curr_addr = (uint32_t)addr;
      const uint8_t* p_buf = buf;
      const uint8_t* p_end = buf + len;
      bool ok = true;

      // Write the first part of data that is not 64-bit aligned
      while (ok && (curr_addr & (sizeof(uint64_t) - 1U)) && p_buf != p_end) {
        ok = ok &&
             (HAL_OK == HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, curr_addr++,
                                          (uint64_t)*p_buf++));
      }

      // Write the middle part of data, aligned to 64-bit boundary
      size_t rm_dwords = (p_end - p_buf) >> 3;
      while (ok && rm_dwords) {
        ok = ok &&
             (HAL_OK == HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD,
                                          curr_addr, *(const uint64_t*)p_buf));
        curr_addr += sizeof(uint64_t);
        p_buf += sizeof(uint64_t);
        --rm_dwords;
      }

      // Write the last part of data that is not 64-bit aligned
      while (ok && p_buf != p_end) {
        ok = ok &&
             (HAL_OK == HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, curr_addr++,
                                          (uint64_t)*p_buf++));
      }

      return (HAL_OK == HAL_FLASH_Lock()) && ok &&
             bl_memeq((const void*)addr, buf, len);
    }
  }
  return false;
}

uint32_t blsys_media_devices(void) { return media_n_devices; }

const char* blsys_media_name(uint32_t device_idx) {
  static const char* invalid = "<invalid>";
  if (device_idx < media_n_devices && media_name[device_idx]) {
    return media_name[device_idx];
  }
  return invalid;
}

bool blsys_media_check(uint32_t device_idx) {
  if (media_micro_sd == device_idx) {
    return true;  // TODO implement check
  }
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

/*
 * Flash sector mapping is taken from the MicroPython project,
 * http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2013, 2014 Damien P. George
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */