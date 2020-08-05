/**
 * @file       test_bl_section.cpp
 * @brief      Unit tests for functions working with Bootloader sections
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include "catch2/catch.hpp"
#include "crc32.h"
#include "progress_monitor.hpp"
#include "flash_buf.hpp"
#include "bl_section.h"

/// Digital signature algorithm string: secp256k1-sha256
#define SECP256K1_SHA256 "secp256k1-sha256"

// External functions declared as conditionally static (BL_STATIC_NO_TEST)
extern "C" {
bool validate_section_name(const char* str, size_t buf_size);
bool validate_attributes(const uint8_t* attr_list, size_t buf_size);
}

/// Reference payload
static const uint8_t ref_payload[] = {
    0x18, 0x54, 0x29, 0xd4, 0x05, 0xdb, 0x13, 0xc8, 0x78, 0x27,
    0x3d, 0x5e, 0xe7, 0x5a, 0x68, 0x7c, 0x4a, 0xb8, 0x4e, 0x35,
    0xb4, 0x41, 0xb2, 0x87, 0xc3, 0x35, 0x9c, 0xab, 0x90, 0x28};

/// Reference header with valid CRC
// clang-format off
static const bl_section_t ref_header = {
  .magic = BL_SECT_MAGIC,
  .struct_rev = BL_SECT_STRUCT_REV,
  .name = "boot",
  .pl_ver = 102213405U, // "1.22.134-rc5"
  .pl_size = sizeof(ref_payload),
  .pl_crc = 0x77AC5BCCU, // CRC of ref_payload
  .attr_list = {
    bl_attr_algorithm, 16U, 's', 'e', 'c', 'p', '2', '5', '6', 'k', '1', '-',
      's', 'h', 'a', '2', '5', '6',
    bl_attr_base_addr, 4U, 0x00U, 0x00U, 0x1CU, 0x08U, // 0x081C0000 in LE
    bl_attr_entry_point, 2U, 0x29U, 0x6EU //  0x6E29 in LE
  },
  .struct_crc = 0x8938D2B2U // Correct
};
// clang-format on

/// Reference header, serialized to byte string
static const char ref_header_serialized[] =
    "SECT\x01\x00\x00\x00boot\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x1d\xa7\x17\x06\x1e\x00\x00\x00\xcc[\xacw\x01\x10secp256k1-"
    "sha256\x02\x04\x00\x00\x1c\x08\x03\x02)"
    "n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\xb2\xd2\x38\x89";

/// Reference section, serialized to byte string
static const char ref_section_serialized[] =
    "SECT\x01\x00\x00\x00boot\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x1d\xa7\x17\x06\x1e\x00\x00\x00\xcc[\xacw\x01\x10secp256k1-"
    "sha256\x02\x04\x00\x00\x1c\x08\x03\x02)"
    "n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\xb2\xd2\x38\x89\x18T)"
    "\xd4\x05\xdb\x13\xc8x'="
    "^\xe7Zh|J\xb8N5\xb4\x41\xb2\x87\xc3\x35\x9c\xab\x90(";

/// Hash sentence of the reference section
static const char ref_section_hash_sentence[] =
    "boot\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1d\xa7\x17\x06+"
    "\xdb\xae\xf9\xc3\x8a>\x00\xdc\x9b\x98\x84\x8fn\xbf\x18\xb5{T{"
    "\xd3\x39\xe5\xef\x90\x11\xfd\xb7\x10\x15\xa5\x87";

/// File wrapper around payload buffer
class PayloadFile {
 public:
  inline PayloadFile(const uint8_t* pl_buf = ref_payload,
                     uint32_t pl_size = sizeof(ref_payload))
      : fd(fmemopen((void*)pl_buf, pl_size, "r")) {
    if (!fd) {
      REQUIRE(false);  // Abort test
    }
  }

  inline ~PayloadFile() {
    if (fd) {
      fclose(fd);
    }
  }

  inline operator bl_file_t() const { return (bl_file_t)fd; }

 private:
  FILE* fd;
};

/**
 * Tests two strings for equality
 *
 * If any of the strings is NULL the result is always false.
 *
 * @param stra  first string, null-terminated, may be NULL
 * @param strb  second string, null-terminated, may be NULL
 * @return      true if strings are equal
 */
static inline bool streq(const char* stra, const char* strb) {
  if (stra && strb) {
    return 0 == strcmp(stra, strb);
  }
  REQUIRE(false);  // Abort test
  return false;
}

/**
 * Corrects CRC in the header
 *
 * @param p_hdr  pointer to section header
 * @return       pointer to section header (same as argument)
 */
static bl_section_t* correct_crc(bl_section_t* p_hdr) {
  if (!p_hdr) {
    REQUIRE(false);  // Abort test
    return NULL;
  }
  uint32_t crc = crc32_fast(p_hdr, offsetof(bl_section_t, struct_crc), 0U);
  p_hdr->struct_crc = crc;
  return p_hdr;
}

/**
 * Corrects structure and payload CRC in the header
 *
 * @param p_hdr    pointer to section header
 * @param pl_buf   buffer containing payload
 * @param pl_size  size occupied by payload in the given buffer
 * @return         pointer to section header (same as argument)
 */
static bl_section_t* correct_crc_with_pl(bl_section_t* p_hdr,
                                         const uint8_t* pl_buf,
                                         uint32_t pl_size) {
  if (!p_hdr || !pl_buf || !pl_size) {
    REQUIRE(false);  // Abort test
    return NULL;
  }
  p_hdr->pl_crc = crc32_fast(pl_buf, pl_size, 0U);
  return correct_crc(p_hdr);
}

/**
 * Puts string into buffer, filling the rest with null characters
 *
 * @param dst       destination buffer
 * @param dst_size  size of destination buffer
 * @param str       source null-terminated string
 * @return          true if successful
 */
static bool strput(char* dst, size_t dst_size, const char* str) {
  if (dst && dst_size && str) {
    size_t len = strlen(str);
    if (len + 1U <= dst_size) {
      memcpy(dst, str, len);
      memset(dst + len, 0, dst_size - len);
      return true;
    }
  }
  return false;
}

TEST_CASE("Validate section name") {
  SECTION("valid") {
    char name[] = "boot1";
    REQUIRE(validate_section_name(name, sizeof(name)));
  }

  SECTION("valid, minimum size") {
    char name[] = "b";
    REQUIRE(validate_section_name(name, sizeof(name)));
  }

  SECTION("valid, minimum size with tail") {
    char name[] = {'b', 0, 0, 0};
    REQUIRE(validate_section_name(name, sizeof(name)));
  }

  SECTION("invalid, NULL string") {
    REQUIRE_FALSE(validate_section_name(NULL, 10U));
  }

  SECTION("invalid, empty string") {
    char name[] = {0, 0, 0, 0};
    REQUIRE_FALSE(validate_section_name(name, sizeof(name)));
  }

  SECTION("invalid, begins with digit") {
    char name[] = "1boot";
    REQUIRE_FALSE(validate_section_name(name, sizeof(name)));
  }

  SECTION("invalid, wrong character") {
    char name[] = "boot#1";
    REQUIRE_FALSE(validate_section_name(name, sizeof(name)));
  }

  SECTION("invalid, non-zero byte after string") {
    char name[] = "boot\0X";
    REQUIRE(validate_section_name(name, sizeof(name) - 2U));
    REQUIRE_FALSE(validate_section_name(name, sizeof(name) - 1U));
  }

  SECTION("invalid, not null-terminated") {
    char name[] = {'b', 'o', 'o', 't'};
    REQUIRE_FALSE(validate_section_name(name, sizeof(name)));
  }
}

TEST_CASE("Validate attributes") {
  SECTION("valid") {
    uint8_t attrs[] = {1U, 2U, 0xAAU, 0xBBU, 0U, 0U, 0U, 0U};
    REQUIRE(validate_attributes(attrs, sizeof(attrs)));
  }

  SECTION("valid, attribute with no value") {
    uint8_t attrs[] = {1U, 0U, 0U, 0U, 0U, 0U, 0U, 0U};
    REQUIRE(validate_attributes(attrs, sizeof(attrs)));
  }

  SECTION("valid, maximum attribute size") {
    uint8_t attrs[] = {1U, 6U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU};
    REQUIRE(validate_attributes(attrs, sizeof(attrs)));
  }

  SECTION("valid, minimum list size") {
    uint8_t attrs[] = {1U, 0U};
    REQUIRE(validate_attributes(attrs, sizeof(attrs)));
  }

  SECTION("invalid, oversized attribute") {
    uint8_t attrs[] = {1U, 7U, 0xAAU, 0xBBU, 0U, 0U, 0U, 0U};
    REQUIRE_FALSE(validate_attributes(attrs, sizeof(attrs)));
  }

  SECTION("invalid, list too small") {
    uint8_t attrs[] = {1U};
    REQUIRE_FALSE(validate_attributes(attrs, sizeof(attrs)));
  }

  SECTION("invalid, list is NULL") {
    REQUIRE_FALSE(validate_attributes(NULL, 8U));
  }

  SECTION("invalid, non-zero byte(s) after last attribute") {
    uint8_t attrs1[] = {1U, 2U, 0xAAU, 0xBBU, 0U, 1U, 0U, 0U};
    REQUIRE_FALSE(validate_attributes(attrs1, sizeof(attrs1)));

    uint8_t attrs2[] = {1U, 2U, 0xAAU, 0xBBU, 0U, 0U, 1U, 0U};
    REQUIRE_FALSE(validate_attributes(attrs2, sizeof(attrs2)));

    uint8_t attrs3[] = {1U, 2U, 0xAAU, 0xBBU, 0U, 0U, 0U, 1U};
    REQUIRE_FALSE(validate_attributes(attrs3, sizeof(attrs3)));
  }
}

TEST_CASE("Validate header") {
  SECTION("valid") {
    SECTION("reference header") {
      REQUIRE(blsect_validate_header(&ref_header));
    }

    SECTION("version: N/A") {
      bl_section_t hdr = ref_header;
      hdr.pl_ver = BL_VERSION_NA;
      REQUIRE(blsect_validate_header(correct_crc(&hdr)));
    }

    SECTION("version: last valid") {
      bl_section_t hdr = ref_header;
      hdr.pl_ver = BL_VERSION_MAX;
      REQUIRE(blsect_validate_header(correct_crc(&hdr)));
    }

    SECTION("maximum payload size") {
      bl_section_t hdr = ref_header;
      hdr.pl_size = BL_PAYLOAD_SIZE_MAX;
      REQUIRE(blsect_validate_header(correct_crc(&hdr)));
    }

    SECTION("attribute with maximum size") {
      bl_section_t hdr = ref_header;
      hdr.attr_list[1] = sizeof(hdr.attr_list) - 2U;
      REQUIRE(blsect_validate_header(correct_crc(&hdr)));
    }

    SECTION("unknown attribute") {
      bl_section_t hdr = ref_header;
      hdr.attr_list[0] = 0xFE;
      REQUIRE(blsect_validate_header(correct_crc(&hdr)));
    }
  }

  SECTION("invalid") {
    SECTION("NULL pointer") { REQUIRE_FALSE(blsect_validate_header(NULL)); }

    SECTION("wrong magic word") {
      bl_section_t hdr = ref_header;
      hdr.magic = 0xDEADBEEFU;
      REQUIRE_FALSE(blsect_validate_header(correct_crc(&hdr)));
    }

    SECTION("wrong structure revision") {
      bl_section_t hdr = ref_header;
      hdr.struct_rev = 0xDEADBEEFU;
      REQUIRE_FALSE(blsect_validate_header(correct_crc(&hdr)));
    }

    SECTION("no ending null in name") {
      bl_section_t hdr = ref_header;
      memset(hdr.name, 'a', sizeof(hdr.name));
      REQUIRE_FALSE(blsect_validate_header(correct_crc(&hdr)));
    }

    SECTION("null character inside name") {
      const char bad_name[] = "bad\0name";
      bl_section_t hdr = ref_header;
      REQUIRE(sizeof(hdr.name) >= sizeof(bad_name));
      memset(hdr.name, 0, sizeof(hdr.name));
      memcpy(hdr.name, bad_name, sizeof(bad_name));
      REQUIRE_FALSE(blsect_validate_header(correct_crc(&hdr)));
    }

    SECTION("wrong payload version") {
      bl_section_t hdr = ref_header;
      hdr.pl_ver = BL_VERSION_MAX + 1U;
      REQUIRE_FALSE(blsect_validate_header(correct_crc(&hdr)));
    }

    SECTION("wrong payload size") {
      bl_section_t hdr = ref_header;
      hdr.pl_size = 0U;
      REQUIRE_FALSE(blsect_validate_header(correct_crc(&hdr)));

      hdr = ref_header;
      hdr.pl_size = BL_PAYLOAD_SIZE_MAX + 1;
      REQUIRE_FALSE(blsect_validate_header(correct_crc(&hdr)));
    }

    SECTION("oversized attribute") {
      bl_section_t hdr = ref_header;
      hdr.attr_list[1] = sizeof(hdr.attr_list) - 1U;
      REQUIRE_FALSE(blsect_validate_header(correct_crc(&hdr)));
    }

    SECTION("non-zero byte after last attribute") {
      bl_section_t hdr = ref_header;
      hdr.attr_list[sizeof(hdr.attr_list) - 1] = 1U;
      REQUIRE_FALSE(blsect_validate_header(correct_crc(&hdr)));
    }

    SECTION("wrong crc") {
      bl_section_t hdr = ref_header;
      hdr.struct_crc ^= 1U;
      REQUIRE_FALSE(blsect_validate_header(&hdr));
    }
  }
}

TEST_CASE("Validate payload") {
  SECTION("valid, reference payload") {
    REQUIRE(blsect_validate_payload(&ref_header, ref_payload));
  }

  SECTION("invalid, empty payload") {
    bl_section_t header = ref_header;
    header.pl_size = 0U;
    REQUIRE_FALSE(blsect_validate_payload(&header, ref_payload));
  }

  SECTION("invalid, NULL payload") {
    REQUIRE_FALSE(blsect_validate_payload(&ref_header, NULL));
  }

  SECTION("invalid, broken payload") {
    uint8_t pl[sizeof(ref_payload)];
    memcpy(pl, ref_payload, sizeof(pl));
    REQUIRE(blsect_validate_payload(&ref_header, pl));
    pl[sizeof(pl) - 1U] ^= 1U;
    REQUIRE_FALSE(blsect_validate_payload(&ref_header, pl));
  }

  SECTION("invalid, broken CRC") {
    bl_section_t hdr = ref_header;
    REQUIRE(blsect_validate_payload(&hdr, ref_payload));

    hdr.pl_crc ^= 1U;
    REQUIRE_FALSE(blsect_validate_payload(correct_crc(&hdr), ref_payload));
  }
}

TEST_CASE("Validate payload from file") {
  SECTION("valid, reference payload") {
    ProgressMonitor monitor(12345U);
    REQUIRE(
        blsect_validate_payload_from_file(&ref_header, PayloadFile(), 12345U));
    REQUIRE(monitor.is_complete());
  }

  SECTION("valid, long payload") {
    // Generate payload buffer
    REQUIRE(BL_PAYLOAD_SIZE_MAX > 1000U);
    const size_t pl_size = BL_PAYLOAD_SIZE_MAX - 3U;
    auto pl_buf = std::make_unique<uint8_t[]>(pl_size);
    for (size_t i = 0; i < pl_size; ++i) {
      pl_buf[i] = (uint8_t)(i & 0xFFU);
    }

    // Create header and virtual file
    bl_section_t hdr = ref_header;
    hdr.pl_size = pl_size;
    hdr.pl_crc = crc32_fast(pl_buf.get(), pl_size, 0U);
    auto file = PayloadFile(pl_buf.get(), pl_size);

    ProgressMonitor monitor(12345U);
    REQUIRE(blsect_validate_payload_from_file(correct_crc(&hdr), file, 12345U));
    REQUIRE(monitor.is_complete());
  }

  SECTION("invalid, NULL header") {
    REQUIRE_FALSE(blsect_validate_payload_from_file(NULL, PayloadFile(), 0U));
  }

  SECTION("invalid, NULL file") {
    REQUIRE_FALSE(blsect_validate_payload_from_file(&ref_header, NULL, 0U));
  }

  SECTION("invalid, corrupted payload") {
    // Generate payload buffer
    REQUIRE(BL_PAYLOAD_SIZE_MAX > 1000U);
    const size_t pl_size = BL_PAYLOAD_SIZE_MAX - 3U;
    auto pl_buf = std::make_unique<uint8_t[]>(pl_size);
    for (size_t i = 0; i < pl_size; ++i) {
      pl_buf[i] = (uint8_t)(i & 0xFFU);
    }

    // Create header and virtual file
    bl_section_t hdr = ref_header;
    hdr.pl_size = pl_size;
    hdr.pl_crc = crc32_fast(pl_buf.get(), pl_size, 0U);

    // Corrupt payload
    pl_buf[9U * pl_size / 10U] ^= 1U;

    auto file = PayloadFile(pl_buf.get(), pl_size);
    REQUIRE_FALSE(
        blsect_validate_payload_from_file(correct_crc(&hdr), file, 0U));
  }

  SECTION("invalid, oversized payload") {
    // Generate payload buffer
    const size_t pl_size = BL_PAYLOAD_SIZE_MAX + 1U;
    auto pl_buf = std::make_unique<uint8_t[]>(pl_size);
    memset(pl_buf.get(), 0xEE, pl_size);

    bl_section_t hdr = ref_header;
    hdr.pl_size = pl_size;
    hdr.pl_crc = crc32_fast(pl_buf.get(), pl_size, 0U);
    auto file = PayloadFile(pl_buf.get(), pl_size);

    REQUIRE_FALSE(
        blsect_validate_payload_from_file(correct_crc(&hdr), file, 0U));
  }
}

TEST_CASE("Validate payload from flash") {
  SECTION("valid, reference payload") {
    auto flash = FlashBuf(ref_payload, sizeof(ref_payload));
    ProgressMonitor monitor(3456U);
    REQUIRE(
        blsect_validate_payload_from_flash(&ref_header, flash_emu_base, 3456U));
    REQUIRE(monitor.is_complete());
  }

  SECTION("valid, reference payload with offset") {
    size_t offset = 123U;
    auto flash = FlashBuf(NULL, offset + sizeof(ref_payload));
    memcpy((uint8_t*)flash + offset, ref_payload, sizeof(ref_payload));
    ProgressMonitor monitor(123456U);
    REQUIRE(blsect_validate_payload_from_flash(
        &ref_header, flash_emu_base + offset, 123456U));
    REQUIRE(monitor.is_complete());
  }

  SECTION("valid, long payload") {
    // Generate payload buffer
    const size_t pl_size = BL_PAYLOAD_SIZE_MAX;
    auto flash = FlashBuf(NULL, pl_size);
    for (size_t i = 0; i < pl_size; ++i) {
      flash[i] = (uint8_t)(i & 0xFFU);
    }

    // Create header
    bl_section_t hdr = ref_header;
    hdr.pl_size = pl_size;
    hdr.pl_crc = crc32_fast(flash, pl_size, 0U);
    (void)correct_crc(&hdr);

    ProgressMonitor monitor(123456U);
    REQUIRE(blsect_validate_payload_from_flash(&hdr, flash_emu_base, 123456U));
    REQUIRE(monitor.is_complete());
  }

  SECTION("invalid, NULL header") {
    REQUIRE_FALSE(blsect_validate_payload_from_flash(NULL, flash_emu_base, 0U));
  }

  SECTION("invalid, corrupted payload") {
    // Generate payload buffer
    const size_t pl_size = BL_PAYLOAD_SIZE_MAX;
    auto flash = FlashBuf(NULL, pl_size);
    for (size_t i = 0; i < pl_size; ++i) {
      flash[i] = (uint8_t)(i & 0xFFU);
    }

    // Create header
    bl_section_t hdr = ref_header;
    hdr.pl_size = pl_size;
    hdr.pl_crc = crc32_fast(flash, pl_size, 0U);
    (void)correct_crc(&hdr);

    // Corrupt payload
    flash[9U * pl_size / 10U] ^= 1U;

    REQUIRE_FALSE(blsect_validate_payload_from_flash(&hdr, flash_emu_base, 0U));
  }
}

TEST_CASE("Check if payload section") {
  SECTION("reference header") { REQUIRE(blsect_is_payload(&ref_header)); }

  SECTION("section named \"firmware\"") {
    bl_section_t hdr = ref_header;
    REQUIRE(strput(hdr.name, sizeof(hdr.name), "firmware"));
    REQUIRE(blsect_is_payload(&hdr));
  }

  SECTION("section named \"sign\"") {
    bl_section_t hdr = ref_header;
    REQUIRE(strput(hdr.name, sizeof(hdr.name), "sign"));
    REQUIRE_FALSE(blsect_is_payload(&hdr));
  }
}

TEST_CASE("Check if signature section") {
  SECTION("reference header") {
    REQUIRE_FALSE(blsect_is_signature(&ref_header));
  }

  SECTION("section named \"firmware\"") {
    bl_section_t hdr = ref_header;
    REQUIRE(strput(hdr.name, sizeof(hdr.name), "firmware"));
    REQUIRE_FALSE(blsect_is_signature(&hdr));
  }

  SECTION("section named \"sign\"") {
    bl_section_t hdr = ref_header;
    REQUIRE(strput(hdr.name, sizeof(hdr.name), "sign"));
    REQUIRE(blsect_is_signature(&hdr));
  }
}

TEST_CASE("Get integer attribute") {
  SECTION("from reference header") {
    bl_section_t hdr = ref_header;
    bl_uint_t base_addr = 0;
    bl_uint_t entry = 0;
    bl_uint_t non_existent = 0xEEEEEEEEU;
    bl_uint_t tmp = 0;

    // Valid
    REQUIRE(blsect_get_attr_uint(&hdr, bl_attr_base_addr, &base_addr));
    REQUIRE(0x081C0000U == base_addr);
    REQUIRE(blsect_get_attr_uint(&hdr, bl_attr_entry_point, &entry));
    REQUIRE(0x6E29 == entry);

    // Invalid
    REQUIRE_FALSE(blsect_get_attr_uint(&hdr, (bl_attr_t)0xFE, &non_existent));
    REQUIRE(0xEEEEEEEEU == non_existent);
    REQUIRE_FALSE(blsect_get_attr_uint(NULL, bl_attr_base_addr, &tmp));
    REQUIRE_FALSE(blsect_get_attr_uint(&hdr, bl_attr_base_addr, NULL));
  }

  SECTION("zero-length integer") {
    bl_section_t hdr = ref_header;
    const bl_attr_t attr_id = (bl_attr_t)0xA0;

    REQUIRE(sizeof(hdr.attr_list) >= 2U);
    memset(hdr.attr_list, 0, sizeof(hdr.attr_list));
    hdr.attr_list[0] = attr_id;
    hdr.attr_list[1] = 0U;

    bl_uint_t tmp = 123456;
    REQUIRE(blsect_get_attr_uint(&hdr, attr_id, &tmp));
    REQUIRE(0U == tmp);
  }

  SECTION("oversized integer") {
    bl_section_t hdr = ref_header;
    const bl_attr_t attr_id = (bl_attr_t)0xA0;

    REQUIRE(sizeof(hdr.attr_list) >= 3U + sizeof(bl_uint_t));
    memset(hdr.attr_list, 0, sizeof(hdr.attr_list));
    hdr.attr_list[0] = attr_id;
    hdr.attr_list[1] = sizeof(bl_uint_t);

    bl_uint_t tmp = 123456;
    REQUIRE(blsect_get_attr_uint(&hdr, attr_id, &tmp));
    REQUIRE(0U == tmp);
    ++hdr.attr_list[1];
    REQUIRE_FALSE(blsect_get_attr_uint(&hdr, attr_id, &tmp));
  }
}

TEST_CASE("Get string attribute") {
  SECTION("from reference header") {
    const char buf_size = strlen(SECP256K1_SHA256) + 1U;
    char buf[buf_size];

    REQUIRE(blsect_get_attr_str(&ref_header, bl_attr_algorithm, buf, buf_size));
    REQUIRE(streq(buf, SECP256K1_SHA256));
    REQUIRE_FALSE(
        blsect_get_attr_str(&ref_header, (bl_attr_t)0xFE, buf, buf_size));
  }

  SECTION("multiple strings") {
    const char attrs_str[] = "\xA1\x8String 1\xA3\x8String 3\xA2\x8String 2";
    char buf[8U + 1U] = "";

    bl_section_t hdr = ref_header;
    memset(hdr.attr_list, 0, sizeof(hdr.attr_list));
    REQUIRE(sizeof(hdr.attr_list) >= sizeof(attrs_str));
    strcpy((char*)hdr.attr_list, attrs_str);

    REQUIRE(validate_attributes(hdr.attr_list, sizeof(hdr.attr_list)));
    REQUIRE(blsect_get_attr_str(&hdr, (bl_attr_t)0xA1, buf, sizeof(buf)));
    REQUIRE(streq(buf, "String 1"));
    REQUIRE(blsect_get_attr_str(&hdr, (bl_attr_t)0xA2, buf, sizeof(buf)));
    REQUIRE(streq(buf, "String 2"));
    REQUIRE(blsect_get_attr_str(&hdr, (bl_attr_t)0xA3, buf, sizeof(buf)));
    REQUIRE(streq(buf, "String 3"));
  }

  SECTION("invalid, null-character in string") {
    char attrs_str[] = "\xA1\x8String 1\xA3\x8String 3\xA2\x8String 2";
    char buf[8U + 1U] = "";

    bl_section_t hdr = ref_header;
    memset(hdr.attr_list, 0, sizeof(hdr.attr_list));
    REQUIRE(sizeof(hdr.attr_list) >= sizeof(attrs_str));
    strcpy((char*)hdr.attr_list, attrs_str);

    REQUIRE(blsect_get_attr_str(&hdr, (bl_attr_t)0xA3, buf, sizeof(buf)));
    // Insert null character inside the string with identifier 0xA3
    hdr.attr_list[14] = '\0';
    REQUIRE_FALSE(blsect_get_attr_str(&hdr, (bl_attr_t)0xA3, buf, sizeof(buf)));
  }
}

TEST_CASE("Get version string") {
  char buf[BL_VERSION_STR_MAX];

  // Valid
  REQUIRE(blsect_version_to_str(102213405U, buf, sizeof(buf)));
  REQUIRE(streq(buf, "1.22.134-rc5"));
  REQUIRE(blsect_version_to_str(1200001599, buf, sizeof(buf)));
  REQUIRE(streq(buf, "12.0.15"));
  REQUIRE(blsect_version_to_str(1, buf, sizeof(buf)));
  REQUIRE(streq(buf, "0.0.0-rc1"));
  REQUIRE(blsect_version_to_str(4199999999, buf, sizeof(buf)));
  REQUIRE(streq(buf, "41.999.999"));
  REQUIRE(blsect_version_to_str(BL_VERSION_NA, buf, sizeof(buf)));
  REQUIRE(streq(buf, ""));

  // Invalid
  REQUIRE_FALSE(blsect_version_to_str(102213405U, NULL, sizeof(buf)));
  REQUIRE_FALSE(blsect_version_to_str(102213405U, buf, 0U));
  REQUIRE_FALSE(blsect_version_to_str(BL_VERSION_MAX + 1U, buf, sizeof(buf)));
}

TEST_CASE("Get hash sentence from flash") {
  SECTION("valid, reference section") {
    bl_hash_sentence_t hash;
    FlashBuf flash(ref_payload, sizeof(ref_payload));
    ProgressMonitor monitor(12345U);

    REQUIRE(blsect_hash_sentence_from_flash(&ref_header, flash_emu_base, &hash,
                                            12345U));
    REQUIRE(0 == memcmp(&hash, &ref_section_hash_sentence, sizeof(hash)));
    REQUIRE(monitor.is_complete());
  }

  SECTION("invalid") {
    bl_hash_sentence_t hash;
    FlashBuf flash(ref_payload, sizeof(ref_payload));
    REQUIRE(blsect_hash_sentence_from_flash(&ref_header, flash_emu_base, &hash,
                                            0U));
    REQUIRE(0 == memcmp(&hash, &ref_section_hash_sentence, sizeof(hash)));
    flash[0] ^= 1;
    REQUIRE(blsect_hash_sentence_from_flash(&ref_header, flash_emu_base, &hash,
                                            0U));
    REQUIRE(0 != memcmp(&hash, &ref_section_hash_sentence, sizeof(hash)));
  }
}
