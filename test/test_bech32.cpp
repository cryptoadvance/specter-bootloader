/**
 * @file       test_bech32.cpp
 * @brief      Unit tests for Bech32 functions
 * @author     Pieter Wuille
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2017 Pieter Wuille
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "catch2/catch.hpp"
extern "C" {
#include "segwit_addr.h"
}

/// Bech32 strings with valid checksums
static const char* valid_checksum[] = {
    "A12UEL5L",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedchar"
    "actersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
    "qqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
};

/// Bech32 strings with invalid checksums
static const char* invalid_checksum[] = {
    " 1nwldj5",
    "\x7f"
    "1axkwrx",
    "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcha"
    "ractersbio1569pvx",
    "pzry9x0s0muk",
    "1pzry9x0s0muk",
    "x1b4n0q5v",
    "li1dgmt3",
    "de1lg7wt\xff",
};

/**
 * Compares two strings, case insensitive
 *
 * @param s1  1-st string
 * @param s2  2-nd string
 * @param n   length of each string
 * @return    comparision result:
 *              * 0 if strings are equal
 *              * >0 if c1 > c2
 *              * <0 if c1 < c2
 */
int my_strncasecmp(const char* s1, const char* s2, size_t n) {
  size_t i = 0;
  while (i < n) {
    char c1 = s1[i];
    char c2 = s2[i];
    if (c1 >= 'A' && c1 <= 'Z') c1 = (c1 - 'A') + 'a';
    if (c2 >= 'A' && c2 <= 'Z') c2 = (c2 - 'A') + 'a';
    if (c1 < c2) return -1;
    if (c1 > c2) return 1;
    if (c1 == 0) return 0;
    ++i;
  }
  return 0;
}

TEST_CASE("Bech32") {
  SECTION("valid") {
    size_t i;
    for (i = 0; i < sizeof(valid_checksum) / sizeof(valid_checksum[0]); ++i) {
      uint8_t data[82];
      char rebuild[92];
      char hrp[84];
      size_t data_len;
      REQUIRE(bech32_decode(hrp, data, &data_len, valid_checksum[i]));
      REQUIRE(bech32_encode(rebuild, hrp, data, data_len));
      REQUIRE(0 == my_strncasecmp(rebuild, valid_checksum[i], 92));
    }
  }
  SECTION("invalid") {
    size_t i;
    for (i = 0; i < sizeof(invalid_checksum) / sizeof(invalid_checksum[0]);
         ++i) {
      uint8_t data[82];
      char hrp[84];
      size_t data_len;
      int ok = 1;
      REQUIRE_FALSE(bech32_decode(hrp, data, &data_len, invalid_checksum[i]));
    }
  }
}
