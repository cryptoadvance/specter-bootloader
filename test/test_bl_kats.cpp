/**
 * @file       test_bl_kats.cpp
 * @brief      Proxy-tests, running known answer tests of Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#define BL_ICR_DEFINE_PRIVATE_TYPES
#include "catch2/catch.hpp"
#include "crc32.h"
#include "flash_buf.hpp"
#include "bl_section.h"
#include "bl_kats.h"

// External functions declared as conditionally static (BL_STATIC_NO_TEST)
extern "C" {
bool buf_equal(const uint8_t* bufa, const uint8_t* bufb, size_t len);
bool do_sha256_kat(void);
bool do_ecdsa_secp256k1_kat(void);
}

TEST_CASE("Bootloader KATs") {
  SECTION("buffer comparison") {
    const int max_len = 81;
    uint8_t bufa[max_len];
    uint8_t bufb[max_len];

    for(int i = 0; i < max_len; ++i) {
      bufa[i] = bufb[i] = (i + 1) & 0xFFU;
    }

    // Brute force over all possible variants up to max_len
    // WARNING: complexity is O(n!)
    for(int len = 1; len < max_len; ++len) {
      for(int byte = 0; byte < len; ++byte) {
        for(int bit = 0; bit < 8; ++bit) {
          REQUIRE(buf_equal(bufa, bufb, len));
          bufb[byte] ^= 1 << bit;
          REQUIRE_FALSE(buf_equal(bufa, bufb, len));
          bufb[byte] ^= 1 << bit;
          REQUIRE(buf_equal(bufa, bufb, len));
        }
      }
    }
  }

  SECTION("known answer tests") {
    REQUIRE(do_sha256_kat());
    REQUIRE(do_ecdsa_secp256k1_kat());
    REQUIRE(bl_run_kats());
  }
}
