/**
 * @file       bootloader.h
 * @brief      Main include file for Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef BOOTLOADER_H_INCLUDED
/// Avoids multiple inclusion of the same file
#define BOOTLOADER_H_INCLUDED

#if defined(__GNUC__) || defined(__clang__)
  /// Compiler attribute
  #define BL_ATTRS(x)                   __attribute__(x)
#else
  /// Compiler attribute (empty macro)
  #define BL_ATTRS(x)
#endif

/// Bootloader arguments stored in the Start-up Mailbox
typedef struct __attribute__((packed)) bl_args_ {
  uint32_t loaded_from;  ///< Address in Flash of active bootloader
  uint32_t rsv[6];       ///< Reserved arguments, set to 0
  uint32_t struct_crc;   ///< CRC of this structure using LE representation
} bl_args_t;

/// Bootloader flags
typedef enum bl_flags_t_ {
  bl_flag_no_args_crc_check = (1 << 0) ///< Disables check of arguments CRC
} bl_flags_t;



#endif // BOOTLOADER_H_INCLUDED
