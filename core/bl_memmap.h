/**
 * @file       bl_memmap.h
 * @brief      Bootloader: embedded memory map
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 *
 * This header contains definitions used to create an embedded memory map record
 * inside the firmware. This record is parsed by tools like
 * 'make-initial-firmware.py' to obtain memory map of the binary module.
 */

#ifndef BL_MEMMAP_H_INCLUDED
#define BL_MEMMAP_H_INCLUDED

#include "bl_util.h"

/// Opening XML-like tag
#define BL_MEMMAP_OPENING_TAG "<memory_map:lebin>"
/// Closing XML-like tag
#define BL_MEMMAP_CLOSING_TAG "</memory_map:lebin>"
/// Size of one element in bytes
#define BL_ELEM_SIZE (sizeof(bl_addr_t))
/// Initializes predefined fields of the bl_memmap_rec_t structure
#define BL_MEMMAP_REC_PREDEFINED                               \
  .opening = BL_MEMMAP_OPENING_TAG, .elem_size = BL_ELEM_SIZE, \
  .closing = BL_MEMMAP_CLOSING_TAG

/// XML-like memory map record containing elements in LE binary format
typedef struct BL_ATTRS((packed)) bl_memmap_rec_t {
  /// Opening tag, should be initialized with BL_MEMMAP_OPENING_TAG
  char opening[sizeof(BL_MEMMAP_OPENING_TAG) - 1];
  /// Size of one element in bytes, should be initialized with BL_ELEM_SIZE
  uint8_t elem_size;
  /// Size in flash memory reserved for the Bootloader
  bl_addr_t bootloader_size;
  /// Start of the Main Firmware in flash memory
  bl_addr_t main_firmware_start;
  /// Size reserved for the Main Firmware
  bl_addr_t main_firmware_size;
  /// Closing tag, should be initialized with BL_MEMMAP_CLOSING_TAG
  char closing[sizeof(BL_MEMMAP_CLOSING_TAG) - 1];
} bl_memmap_rec_t;

#endif  // BL_MEMMAP_H_INCLUDED