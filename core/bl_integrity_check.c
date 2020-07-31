/**
 * @file       bl_integrity_check.c
 * @brief      Bootloader integrity check functions
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#define BL_ICR_DEFINE_PRIVATE_TYPES
#include <string.h>
#include "crc32.h"
#include "bl_integrity_check.h"
#include "bl_util.h"
#include "bl_syscalls.h"

// Magic word, "INTG" in LE
#define BL_ICR_MAGIC 0x47544E49UL
// Structure revision
#define BL_ICR_STRUCT_REV 1U
// Size of the part of integrity check record that is checked using CRC
#define ICR_CRC_CHECKED_SIZE offsetof(bl_integrity_check_rec_t, struct_crc)

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
  if (sect_size && pl_size && sect_size <= BL_ADDR_MAX - sect_size &&
      sect_size >= pl_size + BL_ICR_SIZE) {
    bl_integrity_check_rec_t icr;
    bl_addr_t icr_addr = sect_addr + sect_size - BL_ICR_SIZE;
    if (icr_struct_create_main(&icr, sect_addr, sect_size, pl_size, pl_ver)) {
      return blsys_flash_write(icr_addr, (const uint8_t*)&icr, sizeof(icr));
    }
  }
  return false;
}

/**
 * Verifies integrity of the Main section in flash memory
 *
 * @param p_icr      pointer to integrity check record
 * @param main_addr  starting address of the Main section in flash memory
 * @param p_pl_ver   pointer to variable receiving payload version, can be NULL
 * @return           true if section is valid
 */
BL_STATIC_NO_TEST bool icr_verify_main(const bl_integrity_check_rec_t* p_icr,
                                       bl_addr_t main_addr,
                                       uint32_t* p_pl_ver) {
  bool is_valid = false;
  if (p_icr) {
    if (BL_ICR_MAGIC == p_icr->magic &&
        BL_ICR_STRUCT_REV == p_icr->struct_rev) {
      uint32_t crc = crc32_fast(p_icr, ICR_CRC_CHECKED_SIZE, 0U);
      if (crc == p_icr->struct_crc) {
        if (0U == p_icr->aux_sect.pl_size && 0U == p_icr->aux_sect.pl_crc) {
          crc = 0U;
          if (blsys_flash_crc32(&crc, main_addr, p_icr->main_sect.pl_size)) {
            is_valid = (crc == p_icr->main_sect.pl_crc);
          }
        }
      }
    }
  }

  if (is_valid && p_pl_ver) {
    *p_pl_ver = p_icr->pl_ver;
  }
  return is_valid;
}

bool bl_icr_verify(bl_addr_t sect_addr, uint32_t sect_size,
                   uint32_t* p_pl_ver) {
  if (sect_size) {
    bl_integrity_check_rec_t icr;
    bl_addr_t icr_addr = sect_addr + sect_size - BL_ICR_SIZE;
    if (blsys_flash_read(icr_addr, (uint8_t*)&icr, sizeof(icr))) {
      return icr_verify_main(&icr, sect_addr, p_pl_ver);
    }
  }
  return false;
}
