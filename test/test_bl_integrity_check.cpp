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
bool icr_verify_main(const bl_integrity_check_rec_t* p_icr,
                     bl_addr_t main_addr);
bool vcr_validate(const bl_version_check_rec_t* p_vcr);
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

TEST_CASE("Integrity check record: internals") {
  FlashBuf flash(ref_payload, sizeof(ref_payload));
  bl_integrity_check_rec_t icr;

  // Valid
  REQUIRE(icr_struct_create_main(&icr, flash.base(), flash.size(),
                                 sizeof(ref_payload), ref_version));
  REQUIRE(icr.struct_crc ==
          crc32_fast(&icr, offsetof(bl_integrity_check_rec_t, struct_crc), 0U));
  REQUIRE(icr.pl_ver == ref_version);
  REQUIRE(icr_verify_main(&icr, flash.base()));

  // Corrupted structure
  icr.main_sect.pl_size ^= 1U;
  REQUIRE_FALSE(icr_verify_main(&icr, flash.base()));
  icr.main_sect.pl_size ^= 1U;
  REQUIRE(icr_verify_main(&icr, flash.base()));

  // Corrupted payload
  flash[flash.pl_size() - 1] ^= 1U;
  REQUIRE_FALSE(icr_verify_main(&icr, flash.base()));
  flash[flash.pl_size() - 1] ^= 1U;
  REQUIRE(icr_verify_main(&icr, flash.base()));

  // Wrong arguments of icr_verify_main()
  REQUIRE_FALSE(icr_verify_main(NULL, flash.base()));

  // Wrong arguments of icr_struct_create_main()
  REQUIRE_FALSE(icr_struct_create_main(NULL, flash.base(), flash.size(),
                                       sizeof(ref_payload), ref_version));
  REQUIRE_FALSE(icr_struct_create_main(&icr, flash.base(), 0U,
                                       sizeof(ref_payload), ref_version));
  REQUIRE_FALSE(icr_struct_create_main(&icr, flash.base(), flash.size(), 0U,
                                       ref_version));
}

TEST_CASE("Integrity check record") {
  FlashBuf flash(ref_payload, sizeof(ref_payload), BL_FW_SECT_OVERHEAD);

  // Valid
  REQUIRE(bl_icr_create(flash.base(), flash.size(), sizeof(ref_payload),
                        ref_version));
  uint32_t version = 0U;
  REQUIRE(bl_icr_verify(flash.base(), flash.size(), &version));
  REQUIRE(version == ref_version);

  // Valid, read the version without verification
  version = 0U;
  REQUIRE(bl_icr_get_version(flash.base(), flash.size(), &version));
  REQUIRE(version == ref_version);

  // Corrupted payload
  flash[flash.pl_size() - 1] ^= 1U;
  REQUIRE_FALSE(bl_icr_verify(flash.base(), flash.size(), NULL));
  flash[flash.pl_size() - 1] ^= 1U;
  REQUIRE(bl_icr_verify(flash.base(), flash.size(), NULL));

  // Wrong argument of bl_icr_verify()
  REQUIRE_FALSE(bl_icr_verify(flash.base(), 0U, NULL));

  // Wrong argument of bl_icr_get_version()
  REQUIRE_FALSE(bl_icr_get_version(flash.base(), 0U, &version));
  REQUIRE_FALSE(bl_icr_get_version(flash.base(), flash.size(), NULL));

  // Wrong argument of bl_icr_create()
  REQUIRE_FALSE(
      bl_icr_create(flash.base(), 0U, sizeof(ref_payload), ref_version));
  REQUIRE_FALSE(bl_icr_create(flash.base(), flash.size(), 0U, ref_version));
  REQUIRE_FALSE(bl_icr_create(flash.base(), flash.size(),
                              sizeof(ref_payload) + 1U, ref_version));
  REQUIRE_FALSE(bl_icr_create(flash.base(), sizeof(ref_payload), flash.size(),
                              ref_version));
}

TEST_CASE("Firmware sector size validation") {
  // Valid
  REQUIRE(bl_icr_check_sect_size(1U + BL_FW_SECT_OVERHEAD, 1U));
  REQUIRE(bl_icr_check_sect_size(123456U + BL_FW_SECT_OVERHEAD, 123456U));
  REQUIRE(bl_icr_check_sect_size(123456U + BL_FW_SECT_OVERHEAD, 123456U - 1U));

  // Invalid
  REQUIRE_FALSE(bl_icr_check_sect_size(0U, 0U));
  REQUIRE_FALSE(bl_icr_check_sect_size(0, 1U));
  REQUIRE_FALSE(bl_icr_check_sect_size(BL_FW_SECT_OVERHEAD - 1U, 1U));
  REQUIRE_FALSE(bl_icr_check_sect_size(BL_FW_SECT_OVERHEAD, 0U));
  REQUIRE_FALSE(
      bl_icr_check_sect_size(123456U + BL_FW_SECT_OVERHEAD, 123456U + 1U));
}

/**
 * Recalculates CRC in VCR record
 *
 * @param vcr  reference to VCR record
 * @return     pointer to updated VCR record
 */
static bl_version_check_rec_t* vcr_recalc_crc(bl_version_check_rec_t& vcr) {
  vcr.struct_crc = crc32_fast(&vcr, VCR_CRC_CHECKED_SIZE, 0U);
  return &vcr;
}

TEST_CASE("Version check record: validation") {
  bl_version_check_rec_t ref_vcr = {
      .magic = BL_VCR_MAGIC,
      .struct_rev = BL_VCR_STRUCT_REV,
      .pl_ver = 12345,
  };
  ref_vcr.struct_crc = crc32_fast(&ref_vcr, VCR_CRC_CHECKED_SIZE, 0U);

  // Valid
  SECTION("valid") {
    SECTION("trivial") { REQUIRE(vcr_validate(&ref_vcr)); }
    SECTION("non-zero reserved word") {
      auto vcr = ref_vcr;
      vcr.rsv[0] ^= 12345;
      REQUIRE(vcr_validate(vcr_recalc_crc(vcr)));
    }
  }

  // Invalid
  SECTION("invalid") {
    SECTION("wrong magic string") {
      auto vcr = ref_vcr;
      for (int i = 0; i < sizeof(vcr.magic); ++i) {
        for (int bit = 0; bit < 7; ++bit) {
          vcr.magic[i] ^= 1 << bit;
          REQUIRE_FALSE(vcr_validate(vcr_recalc_crc(vcr)));
          vcr.magic[i] ^= 1 << bit;
          REQUIRE(vcr_validate(vcr_recalc_crc(vcr)));
        }
      }
    }
    SECTION("wrong structure revision") {
      auto vcr = ref_vcr;
      vcr.struct_rev = 123456U;
      REQUIRE_FALSE(vcr_validate(vcr_recalc_crc(vcr)));
    }
    SECTION("wrong payload version") {
      auto vcr = ref_vcr;
      vcr.pl_ver = BL_VERSION_MAX + 1;
      REQUIRE_FALSE(vcr_validate(vcr_recalc_crc(vcr)));
    }
    SECTION("wrong CRC") {
      auto vcr = ref_vcr;
      vcr.struct_crc ^= 1;
      REQUIRE_FALSE(vcr_validate(&vcr));
    }
    SECTION("corrupted contents") {
      auto vcr = ref_vcr;
      vcr.rsv[0] ^= 1;
      REQUIRE_FALSE(vcr_validate(&vcr));
    }
  }
}

TEST_CASE("Version check record: high level") {
  // Valid
  SECTION("valid") {
    SECTION("empty storage") {
      FlashBuf flash(NULL, 12345 + BL_FW_SECT_OVERHEAD);
      // Read from empty storage
      REQUIRE(BL_VERSION_NA ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_starting));
      REQUIRE(BL_VERSION_NA ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_ending));
      REQUIRE(BL_VERSION_NA ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_any));
    }
    SECTION("starting record") {
      FlashBuf flash(NULL, 12345 + BL_FW_SECT_OVERHEAD);
      REQUIRE(bl_vcr_create(flash.base(), flash.size(), ref_version,
                            bl_vcr_starting));
      REQUIRE(ref_version ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_starting));
      REQUIRE(BL_VERSION_NA ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_ending));
      REQUIRE(ref_version ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_any));
    }
    SECTION("ending record") {
      FlashBuf flash(NULL, 12345 + BL_FW_SECT_OVERHEAD);
      REQUIRE(bl_vcr_create(flash.base(), flash.size(), ref_version,
                            bl_vcr_ending));
      REQUIRE(BL_VERSION_NA ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_starting));
      REQUIRE(ref_version ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_ending));
      REQUIRE(ref_version ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_any));
    }
    SECTION("both records") {
      FlashBuf flash(NULL, 12345 + BL_FW_SECT_OVERHEAD);
      REQUIRE(bl_vcr_create(flash.base(), flash.size(), 102U, bl_vcr_starting));
      REQUIRE(bl_vcr_create(flash.base(), flash.size(), 101U, bl_vcr_ending));
      REQUIRE(102U ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_starting));
      REQUIRE(101U ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_ending));
      REQUIRE(102U ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_any));
    }
  }

  SECTION("invalid") {
    SECTION("corrupted starting record") {
      FlashBuf flash(NULL, 12345 + BL_FW_SECT_OVERHEAD);
      REQUIRE(bl_vcr_create(flash.base(), flash.size(), 102U, bl_vcr_starting));
      REQUIRE(bl_vcr_create(flash.base(), flash.size(), 101U, bl_vcr_ending));
      flash[0] ^= 1;
      REQUIRE(BL_VERSION_NA ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_starting));
      REQUIRE(101U ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_ending));
      REQUIRE(101U ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_any));
    }
    SECTION("corrupted ending record") {
      FlashBuf flash(NULL, 12345 + BL_FW_SECT_OVERHEAD);
      REQUIRE(bl_vcr_create(flash.base(), flash.size(), 201U, bl_vcr_starting));
      REQUIRE(bl_vcr_create(flash.base(), flash.size(), 202U, bl_vcr_ending));
      flash[flash.size() - 1] ^= 1;
      REQUIRE(201U ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_starting));
      REQUIRE(BL_VERSION_NA ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_ending));
      REQUIRE(201U ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_any));
    }
    SECTION("corrupted both records") {
      FlashBuf flash(NULL, 12345 + BL_FW_SECT_OVERHEAD);
      REQUIRE(bl_vcr_create(flash.base(), flash.size(), 102U, bl_vcr_starting));
      REQUIRE(bl_vcr_create(flash.base(), flash.size(), 101U, bl_vcr_ending));
      flash[0] ^= 1;
      flash[flash.size() - 1] ^= 1;
      REQUIRE(BL_VERSION_NA ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_starting));
      REQUIRE(BL_VERSION_NA ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_ending));
      REQUIRE(BL_VERSION_NA ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_any));
    }
  }

  SECTION("wrong arguments") {
    SECTION("bl_vcr_create()") {
      SECTION("zero size") {
        FlashBuf flash(NULL, 12345 + BL_FW_SECT_OVERHEAD);
        REQUIRE_FALSE(bl_vcr_create(flash.base(), 0, 102U, bl_vcr_starting));
      }

      SECTION("size too small") {
        FlashBuf flash(NULL, 12345 + BL_FW_SECT_OVERHEAD);
        REQUIRE_FALSE(bl_vcr_create(flash.base(), BL_FW_SECT_OVERHEAD - 1U,
                                    102U, bl_vcr_starting));
      }
      SECTION("wrong place (bl_vcr_any)") {
        FlashBuf flash(NULL, 12345 + BL_FW_SECT_OVERHEAD);
        REQUIRE_FALSE(
            bl_vcr_create(flash.base(), flash.size(), 102U, bl_vcr_any));
      }
      SECTION("wrong place") {
        FlashBuf flash(NULL, 12345 + BL_FW_SECT_OVERHEAD);
        REQUIRE_FALSE(bl_vcr_create(flash.base(), flash.size(), 102U,
                                    (bl_vcr_place_t)1234567));
      }
    }
    SECTION("bl_vcr_get_version()") {
      // Prepare a valid starting record
      FlashBuf flash(NULL, 12345 + BL_FW_SECT_OVERHEAD);
      REQUIRE(bl_vcr_create(flash.base(), flash.size(), ref_version,
                            bl_vcr_starting));
      REQUIRE(ref_version ==
              bl_vcr_get_version(flash.base(), flash.size(), bl_vcr_starting));
      SECTION("zero size") {
        REQUIRE(BL_VERSION_NA ==
                bl_vcr_get_version(flash.base(), 0U, bl_vcr_starting));
      }
      SECTION("size too small") {
        REQUIRE(BL_VERSION_NA == bl_vcr_get_version(flash.base(),
                                                    BL_FW_SECT_OVERHEAD - 1,
                                                    bl_vcr_starting));
      }
    }
  }
}
