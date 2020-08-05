/**
 * @file       bl_integrity_check.h
 * @brief      Bootloader integrity check functions
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef BL_INTEGRITY_CHECK_H_INCLUDED
/// Avoids multiple inclusion of the same file
#define BL_INTEGRITY_CHECK_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "bootloader.h"
#include "bl_util.h"
#include "bl_syscalls.h"

/// Size of integrity check record
#define BL_ICR_SIZE 32U

// The following types are private and defined only in implementation of
// signature module and in unit tests.
#ifdef BL_ICR_DEFINE_PRIVATE_TYPES

/// One section of integrity check record
typedef struct __attribute__((packed)) bl_icr_sect_ {
  uint32_t pl_size;  ///< Payload size
  uint32_t pl_crc;   ///< Payload CRC
} bl_icr_sect_t;

/// Integrity check record
///
/// This structure has fixed size of 32 bytes. All 32-bit words are stored in
/// little-endian format. CRC is calculated over first 28 bytes byte of this
/// structure.
typedef struct __attribute__((packed)) bl_integrity_check_rec_ {
  uint32_t magic;           ///< Magic word, BL_ICR_MAGIC
  uint32_t struct_rev;      ///< Revision of structure format
  uint32_t pl_ver;          ///< Payload version, 0 if not available
  bl_icr_sect_t main_sect;  ///< Main section
  bl_icr_sect_t aux_sect;   ///< Auxilary section (if available)
  uint32_t struct_crc;      ///< CRC of this structure using LE representation
} bl_integrity_check_rec_t;

#endif  // BL_ICR_DEFINE_PRIVATE_TYPES

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates integrity check record in the flash memory
 *
 * @param sect_addr  address of section in flash memory
 * @param sect_size  full size of section in flash memory
 * @param pl_size    size of payload (firmware) stored in firmware section
 * @param pl_ver     version of payload (firmware)
 * @return           true if integrity check record successfully created
 */
bool bl_icr_create(bl_addr_t sect_addr, uint32_t sect_size, uint32_t pl_size,
                   uint32_t pl_ver);

/**
 * Verifies integrity of payload stored in a section of flash memory
 *
 * @param sect_addr  address of section in flash memory
 * @param sect_size  full size of section in flash memory
 * @param p_pl_ver   pointer to variable receiving payload version, can be NULL
 * @return           true if section contains valid payload
 */
bool bl_icr_verify(bl_addr_t sect_addr, uint32_t sect_size, uint32_t* p_pl_ver);

/**
 * Returns version from an integrity check record without actual integrity check
 *
 * @param sect_addr  address of section in flash memory
 * @param sect_size  full size of section in flash memory
 * @param p_pl_ver   pointer to variable receiving payload version
 * @return           true if valid version is retrieved
 */
bool bl_icr_get_version(bl_addr_t sect_addr, uint32_t sect_size, uint32_t* p_pl_ver);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // BL_INTEGRITY_CHECK_H_INCLUDED