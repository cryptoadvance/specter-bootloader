/**
 * @file       test_bl_integrity_check.cpp
 * @brief      Unit tests for integrity check functions
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#define BL_ICR_DEFINE_PRIVATE_TYPES
#include "catch2/catch.hpp"
#include "crc32.h"
#include "flash_buf.hpp"
#include "bl_section.h"
#include "bl_integrity_check.h"

// External functions declared as conditionally static (BL_STATIC_NO_TEST)
extern "C" {
bool icr_struct_create_main(bl_integrity_check_rec_t* p_icr,
                            bl_addr_t main_addr, uint32_t main_size,
                            uint32_t pl_size, uint32_t pl_ver);
bool icr_verify_main(const bl_integrity_check_rec_t* p_icr, bl_addr_t main_addr,
                     uint32_t* p_pl_ver);
}

/// Reference payload
static const uint8_t ref_payload[] = {
    0x18, 0x54, 0x29, 0xd4, 0x05, 0xdb, 0x13, 0xc8, 0x78, 0x27,
    0x3d, 0x5e, 0xe7, 0x5a, 0x68, 0x7c, 0x4a, 0xb8, 0x4e, 0x35,
    0xb4, 0x41, 0xb2, 0x87, 0xc3, 0x35, 0x9c, 0xab, 0x90, 0x28};

/// CRC of reference payload
static const uint32_t ref_payload_crc = 0x77AC5BCCU;
/// Reference payload version
const uint32_t ref_version = 102213405U;  // "1.22.134-rc5"

// TODO add tests
TEST_CASE("Integrity check record: internals") {
  FlashBuf flash(ref_payload, sizeof(ref_payload));
  bl_integrity_check_rec_t icr;

  // Valid
  REQUIRE(icr_struct_create_main(&icr, flash.base(), flash.size(),
                                 sizeof(ref_payload), ref_version));
  REQUIRE(icr.struct_crc ==
          crc32_fast(&icr, offsetof(bl_integrity_check_rec_t, struct_crc), 0U));
  REQUIRE(icr.pl_ver == ref_version);
  uint32_t version = 0U;
  REQUIRE(icr_verify_main(&icr, flash.base(), &version));
  REQUIRE(version == ref_version);

  // Corrupted structure
  icr.main_sect.pl_size ^= 1U;
  REQUIRE_FALSE(icr_verify_main(&icr, flash.base(), NULL));
  icr.main_sect.pl_size ^= 1U;
  REQUIRE(icr_verify_main(&icr, flash.base(), NULL));

  // Corrupted payload
  flash[flash.pl_size() - 1] ^= 1U;
  REQUIRE_FALSE(icr_verify_main(&icr, flash.base(), NULL));
  flash[flash.pl_size() - 1] ^= 1U;
  REQUIRE(icr_verify_main(&icr, flash.base(), NULL));

  // Wrong arguments of icr_verify_main()
  REQUIRE_FALSE(icr_verify_main(NULL, flash.base(), NULL));

  // Wrong arguments of icr_struct_create_main()
  REQUIRE_FALSE(icr_struct_create_main(NULL, flash.base(), flash.size(),
                                       sizeof(ref_payload), ref_version));
  REQUIRE_FALSE(icr_struct_create_main(&icr, flash.base(), 0U,
                                       sizeof(ref_payload), ref_version));
  REQUIRE_FALSE(icr_struct_create_main(&icr, flash.base(), flash.size(), 0U,
                                       ref_version));
}

TEST_CASE("Integrity check record") {
  FlashBuf flash(ref_payload, sizeof(ref_payload), BL_ICR_SIZE);

  // Valid
  REQUIRE(bl_icr_create(flash.base(), flash.size(), sizeof(ref_payload),
                        ref_version));
  uint32_t version = 0U;
  REQUIRE(bl_icr_verify(flash.base(), flash.size(), &version));
  REQUIRE(version == ref_version);

  // Corrupted payload
  flash[flash.pl_size() - 1] ^= 1U;
  REQUIRE_FALSE(bl_icr_verify(flash.base(), flash.size(), NULL));
  flash[flash.pl_size() - 1] ^= 1U;
  REQUIRE(bl_icr_verify(flash.base(), flash.size(), NULL));

  // Wrong argument of bl_icr_verify()
  REQUIRE_FALSE(bl_icr_verify(flash.base(), 0U, NULL));

  // Wrong argument of bl_icr_create()
  REQUIRE_FALSE(
      bl_icr_create(flash.base(), 0U, sizeof(ref_payload), ref_version));
  REQUIRE_FALSE(bl_icr_create(flash.base(), flash.size(), 0U, ref_version));
  REQUIRE_FALSE(bl_icr_create(flash.base(), flash.size(),
                              sizeof(ref_payload) + 1U, ref_version));
  REQUIRE_FALSE(bl_icr_create(flash.base(), sizeof(ref_payload), flash.size(),
                              ref_version));
}