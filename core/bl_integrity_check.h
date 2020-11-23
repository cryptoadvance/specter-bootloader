/**
 * @file       bl_integrity_check.h
 * @brief      Bootloader integrity and version check functions
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
#include "bl_util.h"
#include "bl_syscalls.h"

// The following types are private and defined only in implementation of
// signature module and in unit tests.
#ifdef BL_ICR_DEFINE_PRIVATE_TYPES

/// Size of integrity check record
#define BL_ICR_SIZE 32U
/// Size of version check record
#define BL_VCR_SIZE 32U
/// Total overhead from all metadata stored together with firmware
#define BL_FW_SECT_OVERHEAD (BL_ICR_SIZE + BL_VCR_SIZE)
// Offset of ICR record from the end of firmware section
#define BL_ICR_OFFSET_FROM_END (BL_ICR_SIZE + BL_VCR_SIZE)
// Offset of VCR record from the end of firmware section
#define BL_VCR_OFFSET_FROM_END (BL_VCR_SIZE)
/// Magic word, "INTG" in LE
#define BL_ICR_MAGIC 0x47544E49UL
/// Magic string for version check record: 16 bytes with terminating '\0'
#define BL_VCR_MAGIC "VERSIONCHECKREC"
/// ICR: structure revision
#define BL_ICR_STRUCT_REV 1U
/// ICR: size of the part of integrity check record that is checked using CRC
#define ICR_CRC_CHECKED_SIZE offsetof(bl_integrity_check_rec_t, struct_crc)
/// VCR: structure revision
#define BL_VCR_STRUCT_REV 1U
/// VCR: size of the part of integrity check record that is checked using CRC
#define VCR_CRC_CHECKED_SIZE offsetof(bl_version_check_rec_t, struct_crc)

/// One section of integrity check record
typedef struct BL_ATTRS((packed)) bl_icr_sect_ {
  uint32_t pl_size;  ///< Payload size
  uint32_t pl_crc;   ///< Payload CRC
} bl_icr_sect_t;

/// Integrity check record
///
/// This structure has fixed size of 32 bytes. All 32-bit words are stored in
/// little-endian format. CRC is calculated over first 28 bytes of this
/// structure.
typedef struct BL_ATTRS((packed)) bl_integrity_check_rec_ {
  uint32_t magic;           ///< Magic word, BL_ICR_MAGIC
  uint32_t struct_rev;      ///< Revision of structure format
  uint32_t pl_ver;          ///< Payload version, 0 if not available
  bl_icr_sect_t main_sect;  ///< Main section
  bl_icr_sect_t aux_sect;   ///< Auxilary section (if available)
  uint32_t struct_crc;      ///< CRC of this structure using LE representation
} bl_integrity_check_rec_t;

/// Version check record
///
/// This structure has fixed size of 32 bytes. All 32-bit words are stored in
/// little-endian format. CRC is calculated over first 28 bytes of this
/// structure.
typedef struct BL_ATTRS((packed)) bl_version_check_rec_t_ {
  char magic[sizeof(BL_VCR_MAGIC)];  ///< Magic string, BL_VCR_MAGIC
  uint32_t struct_rev;               ///< Revision of structure format
  uint32_t pl_ver;                   ///< Payload version, 0 if not available
  uint32_t rsv[1];                   ///< Reserved word
  uint32_t struct_crc;  ///< CRC of this structure using LE representation
} bl_version_check_rec_t;

#endif  // BL_ICR_DEFINE_PRIVATE_TYPES

/// Place of a version check record inside the firmware section
typedef enum bl_vcr_place_t_ {
  /// At the beginning of the section
  bl_vcr_starting = (1 << 0),
  /// At the end of the section
  bl_vcr_ending = (1 << 1),
  /// At any valid place inside the section
  bl_vcr_any = (int)bl_vcr_starting | (int)bl_vcr_ending,
} bl_vcr_place_t;

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
 * @return           true if the integrity check record is successfully created
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
bool bl_icr_get_version(bl_addr_t sect_addr, uint32_t sect_size,
                        uint32_t* p_pl_ver);

/**
 * Checks if flash memory section has enough space to store the payload
 *
 * @param sect_size  full size of section in flash memory
 * @param pl_size    size of payload (firmware) stored in firmware section
 * @return           true if the payload can be stored in the given section
 */
bool bl_icr_check_sect_size(uint32_t sect_size, uint32_t pl_size);

/**
 * Creates a version check record in the flash memory
 *
 * @param sect_addr  address of section in flash memory
 * @param sect_size  full size of section in flash memory
 * @param pl_ver     version of payload (firmware)
 * @param place      place of a VCR record inside the firmware memory section
 * @return           true if the version check record is successfully created
 */
bool bl_vcr_create(bl_addr_t sect_addr, uint32_t sect_size, uint32_t pl_ver,
                   bl_vcr_place_t place);

/**
 * Reads the version check record and returns payload version from it
 *
 * If *bl_vcr_any* is passed as a *place* parameter, then the function looks
 * through all records returning the latest available version.
 *
 * @param sect_addr  address of section in flash memory
 * @param sect_size  full size of section in flash memory
 * @param place      place of a VCR record inside the firmware section
 * @return           payload version or BL_VERSION_NA if unsuccessful
 */
uint32_t bl_vcr_get_version(bl_addr_t sect_addr, uint32_t sect_size,
                            bl_vcr_place_t place);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // BL_INTEGRITY_CHECK_H_INCLUDED