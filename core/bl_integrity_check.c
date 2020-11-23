/**
 * @file       bl_integrity_check.c
 * @brief      Bootloader integrity and version check functions
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

/// Forces inclusion of private types
#define BL_ICR_DEFINE_PRIVATE_TYPES
#include <string.h>
#include "crc32.h"
#include "bl_integrity_check.h"
#include "bl_util.h"
#include "bl_syscalls.h"

/**
 * Creates integrity check record structure for the Main section
 *
 * @param p_icr      pointer to variable receiving integrity check record
 * @param main_addr  starting address of the Main section in flash memory
 * @param main_size  size of the Main section in flash memory
 * @param pl_size    size of payload (firmware) stored in firmware section
 * @param pl_ver     version of payload (firmware)
 * @return           true if successful
 */
BL_STATIC_NO_TEST bool icr_struct_create_main(bl_integrity_check_rec_t* p_icr,
                                              bl_addr_t main_addr,
                                              uint32_t main_size,
                                              uint32_t pl_size,
                                              uint32_t pl_ver) {
  if (p_icr && main_size && pl_size) {
    uint32_t crc = 0U;
    if (blsys_flash_crc32(&crc, main_addr, pl_size)) {
      memset(p_icr, 0, sizeof(bl_integrity_check_rec_t));
      p_icr->magic = BL_ICR_MAGIC;
      p_icr->struct_rev = BL_ICR_STRUCT_REV;
      p_icr->pl_ver = pl_ver;
      p_icr->main_sect.pl_size = pl_size;
      p_icr->main_sect.pl_crc = crc;
      p_icr->struct_crc = crc32_fast(p_icr, ICR_CRC_CHECKED_SIZE, 0U);
      return true;
    }
  }
  return false;
}

bool bl_icr_create(bl_addr_t sect_addr, uint32_t sect_size, uint32_t pl_size,
                   uint32_t pl_ver) {
  if (bl_icr_check_sect_size(sect_size, pl_size)) {
    bl_integrity_check_rec_t icr;
    bl_addr_t icr_addr = sect_addr + sect_size - BL_ICR_OFFSET_FROM_END;
    if (icr_struct_create_main(&icr, sect_addr, sect_size, pl_size, pl_ver)) {
      return blsys_flash_write(icr_addr, &icr, sizeof(icr));
    }
  }
  return false;
}

/**
 * Validates an integrity check record
 *
 * @param p_icr      pointer to integrity check record
 * @return           true if integrity check record is valid
 */
static bool icr_validate(const bl_integrity_check_rec_t* p_icr) {
  if (p_icr) {
    return (BL_ICR_MAGIC == p_icr->magic &&
            BL_ICR_STRUCT_REV == p_icr->struct_rev &&
            crc32_fast(p_icr, ICR_CRC_CHECKED_SIZE, 0U) == p_icr->struct_crc &&
            p_icr->pl_ver <= BL_VERSION_MAX);
  }
  return false;
}

/**
 * Verifies integrity of the Main section in flash memory
 *
 * @param p_icr      pointer to integrity check record, assumed to be valid
 * @param main_addr  starting address of the Main section in flash memory
 * @return           true if section is valid
 */
BL_STATIC_NO_TEST bool icr_verify_main(const bl_integrity_check_rec_t* p_icr,
                                       bl_addr_t main_addr) {
  if (p_icr) {
    if (0U == p_icr->aux_sect.pl_size && 0U == p_icr->aux_sect.pl_crc) {
      uint32_t crc = 0U;
      if (blsys_flash_crc32(&crc, main_addr, p_icr->main_sect.pl_size)) {
        return (crc == p_icr->main_sect.pl_crc);
      }
    }
  }
  return false;
}

/**
 * Reads an integrity check record from the end of a firmware section
 *
 * @param p_icr      pointer to variable receiving an integrity check record
 * @param sect_addr  address of section in flash memory
 * @param sect_size  full size of section in flash memory
 * @return           true if integrity check record read successfully
 */
static bool icr_get(bl_integrity_check_rec_t* p_icr, bl_addr_t sect_addr,
                    uint32_t sect_size) {
  if (p_icr && sect_size && sect_size > BL_FW_SECT_OVERHEAD) {
    bl_addr_t icr_addr = sect_addr + sect_size - BL_ICR_OFFSET_FROM_END;
    if (blsys_flash_read(icr_addr, p_icr, sizeof(bl_integrity_check_rec_t))) {
      return icr_validate(p_icr);
    }
  }
  return false;
}

bool bl_icr_verify(bl_addr_t sect_addr, uint32_t sect_size,
                   uint32_t* p_pl_ver) {
  if (sect_size) {
    if (p_pl_ver) {
      *p_pl_ver = BL_VERSION_NA;
    }
    bl_integrity_check_rec_t icr;
    if (icr_get(&icr, sect_addr, sect_size) &&
        icr_verify_main(&icr, sect_addr)) {
      if (p_pl_ver) {
        *p_pl_ver = icr.pl_ver;
      }
      return true;
    }
  }
  return false;
}

bool bl_icr_get_version(bl_addr_t sect_addr, uint32_t sect_size,
                        uint32_t* p_pl_ver) {
  if (sect_size && p_pl_ver) {
    *p_pl_ver = BL_VERSION_NA;
    bl_integrity_check_rec_t icr;
    if (icr_get(&icr, sect_addr, sect_size)) {
      *p_pl_ver = icr.pl_ver;
      return true;
    }
  }
  return false;
}

bool bl_icr_check_sect_size(uint32_t sect_size, uint32_t pl_size) {
  return (sect_size && pl_size && sect_size <= BL_ADDR_MAX - sect_size &&
          pl_size <= UINT32_MAX - BL_FW_SECT_OVERHEAD &&
          pl_size + BL_FW_SECT_OVERHEAD <= sect_size);
}

/**
 * Validates a version check record
 *
 * @param p_vcr      pointer to version check record
 * @return           true if version check record is valid
 */
BL_STATIC_NO_TEST bool vcr_validate(const bl_version_check_rec_t* p_vcr) {
  static const char vcr_magic[BL_MEMBER_SIZE(bl_version_check_rec_t, magic)] =
      BL_VCR_MAGIC;
  if (p_vcr) {
    return (bl_memeq(p_vcr->magic, vcr_magic, sizeof(vcr_magic)) &&
            BL_VCR_STRUCT_REV == p_vcr->struct_rev &&
            crc32_fast(p_vcr, VCR_CRC_CHECKED_SIZE, 0U) == p_vcr->struct_crc &&
            p_vcr->pl_ver <= BL_VERSION_MAX);
  }
  return false;
}

/**
 * Reads a version check record from the firmware section
 *
 * @param p_vcr     pointer to variable receiving a version check record
 * @param vcr_addr  address of record in the flash memory
 * @return          true if version check record read successfully
 */
static bool vcr_get(bl_version_check_rec_t* p_vcr, bl_addr_t vcr_addr) {
  if (p_vcr) {
    if (blsys_flash_read(vcr_addr, p_vcr, sizeof(bl_version_check_rec_t))) {
      return vcr_validate(p_vcr);
    }
  }
  return false;
}

bool bl_vcr_create(bl_addr_t sect_addr, uint32_t sect_size, uint32_t pl_ver,
                   bl_vcr_place_t place) {
  if (sect_size && sect_size > BL_FW_SECT_OVERHEAD &&
      sect_size > BL_VCR_OFFSET_FROM_END &&
      sect_addr < BL_ADDR_MAX - sect_size && pl_ver <= BL_VERSION_MAX &&
      (bl_vcr_starting == place || bl_vcr_ending == place)) {
    bl_version_check_rec_t vcr = {
        .magic = BL_VCR_MAGIC,
        .struct_rev = BL_VCR_STRUCT_REV,
        .pl_ver = pl_ver,
    };
    vcr.struct_crc = crc32_fast(&vcr, VCR_CRC_CHECKED_SIZE, 0U);
    bl_addr_t vcr_addr = (bl_vcr_starting == place)
                             ? sect_addr
                             : sect_addr + sect_size - BL_VCR_OFFSET_FROM_END;
    // Write record to flash memory
    if (blsys_flash_write(vcr_addr, &vcr, sizeof(vcr))) {
      // Verify
      return (bl_vcr_get_version(sect_addr, sect_size, place) == pl_ver);
    }
  }
  return false;
}

uint32_t bl_vcr_get_version(bl_addr_t sect_addr, uint32_t sect_size,
                            bl_vcr_place_t place) {
  uint32_t version = BL_VERSION_NA;
  if (sect_size && sect_size > BL_FW_SECT_OVERHEAD &&
      sect_size > BL_VCR_OFFSET_FROM_END &&
      sect_addr < BL_ADDR_MAX - sect_size) {
    bl_version_check_rec_t vcr;
    if ((int)place & (int)bl_vcr_starting) {
      if (vcr_get(&vcr, sect_addr) && vcr.pl_ver > version) {
        version = vcr.pl_ver;
      }
    }
    if ((int)place & (int)bl_vcr_ending) {
      if (vcr_get(&vcr, sect_addr + sect_size - BL_VCR_OFFSET_FROM_END) &&
          vcr.pl_ver > version) {
        version = vcr.pl_ver;
      }
    }
  }
  return version;
}