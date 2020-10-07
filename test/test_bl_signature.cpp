/**
 * @file       test_bl_signature.cpp
 * @brief      Unit tests for signature functions
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#define BLSIG_DEFINE_PRIVATE_TYPES
#include <algorithm>
#include <vector>
#include <string.h>
#include "catch2/catch.hpp"
#include "progress_monitor.hpp"
#include "secp256k1.h"
#include "secp256k1_preallocated.h"
#include "bl_signature.h"

// Digital signature algorithm string: secp256k1-sha256
#define SECP256K1_SHA256 "secp256k1-sha256"
// Size of public key fingerprint data in bytes
#define FP_SIZE BL_MEMBER_SIZE(fingerprint_t, bytes)
// Number of signature records in the reference Signature section payload
#define REF_N_SIGS 3U
// Number of public keys in the reference list of public keys
#define REF_N_PUBKEYS 3U
// Length of the reference message in bytes
#define REF_MESSAGE_LEN (sizeof(ref_message_str) - 1U)

// External functions declared as conditionally static (BL_STATIC_NO_TEST)
extern "C" {
bool check_duplicating_signatures(const signature_rec_t* sig_recs,
                                  uint32_t n_sig);
void pubkey_fingerprint(fingerprint_t* p_result, const bl_pubkey_t* p_pubkey);
const bl_pubkey_t* find_pubkey(const bl_pubkey_t** p_pubkeys,
                               const fingerprint_t* p_fingerprint);
bool verify_signature(secp256k1_context* verify_ctx, const signature_t* p_sig,
                      const uint8_t* message, size_t message_len,
                      const bl_pubkey_t* p_pubkey);
secp256k1_context* create_verify_ctx(void);
void destroy_verify_ctx(secp256k1_context* verify_ctx);
}

// Reference public key, 65 bytes
static const bl_pubkey_t ref_pubkey = {
    .bytes = {0x04, 0x0b, 0x61, 0x6d, 0x40, 0x3d, 0x49, 0x56, 0xe6, 0xab, 0x00,
              0x7a, 0x36, 0xe2, 0xa7, 0xa5, 0x73, 0x19, 0xfa, 0x82, 0x36, 0x19,
              0x77, 0xbb, 0x30, 0x73, 0x80, 0xfa, 0x43, 0xff, 0x8f, 0x83, 0x26,
              0x24, 0xb5, 0x70, 0x42, 0x26, 0xbb, 0x0c, 0x87, 0xdf, 0x8f, 0x49,
              0xb4, 0xbf, 0x46, 0x3d, 0x18, 0xbc, 0x29, 0x2b, 0xce, 0xfd, 0x83,
              0xf2, 0x9f, 0x5b, 0x81, 0xe0, 0xc9, 0x02, 0xc6, 0x5e, 0x21}};

// Fingerprint of the reference public key, 16 bytes + '\0'
static const uint8_t ref_pubkey_fp_bytes[] =
    "\x05v\xc1\xa9\x0e\x1c\x90\x15V:(<{\xb7\xe0\xf8";

// Reference message. Terminating null character should be ignored.
static const uint8_t ref_message_str[] =
    "b77.777.777rc77-77.777.777rc77-1tudm93ag6fu6y7x4q6s87ar6zskyc"
    "pmceltrmt7s577aa94yzan9zeyvfd";

// Compact 64-byte signature of the reference message (no terminating
// null-character) using a private key paired with the reference public key.
// Terminating null character of the signature should be ignored.
static const uint8_t ref_signature[BL_MEMBER_SIZE(signature_t, bytes)] = {
    0x38U, 0xCBU, 0x80U, 0xF9U, 0x06U, 0x32U, 0xD0U, 0x94U, 0x77U, 0x4EU, 0xB6U,
    0x86U, 0xACU, 0xFCU, 0x9EU, 0xAEU, 0xECU, 0xD2U, 0x61U, 0xCBU, 0xAEU, 0x16U,
    0x23U, 0x5BU, 0x84U, 0x24U, 0xB2U, 0xDBU, 0x83U, 0xB8U, 0xB3U, 0x8AU, 0x23U,
    0xD5U, 0xDEU, 0xF2U, 0x39U, 0xA8U, 0x9BU, 0x43U, 0x4CU, 0x1CU, 0xEFU, 0x80U,
    0xFFU, 0xA4U, 0xDCU, 0xC0U, 0x4FU, 0x87U, 0xC6U, 0x8DU, 0x40U, 0x5AU, 0x74U,
    0xA8U, 0x18U, 0x1AU, 0x25U, 0x21U, 0xBAU, 0xE0U, 0x2DU, 0x9FU};

// Reference list of public keys
static const bl_pubkey_t ref_multisig_pubkey_list[REF_N_PUBKEYS + 1] = {
    // Corresponding private key: "vend1.pem"
    {.bytes = {0x04U, 0xC4U, 0x11U, 0x3FU, 0x2CU, 0x96U, 0x1FU, 0xC9U, 0xC5U,
               0x25U, 0x23U, 0x44U, 0xF6U, 0x26U, 0x6CU, 0x8AU, 0xB3U, 0x34U,
               0xD4U, 0x1DU, 0x6DU, 0x7FU, 0xE9U, 0x23U, 0x79U, 0x51U, 0x51U,
               0x52U, 0x2FU, 0x7CU, 0x66U, 0x96U, 0xC6U, 0xDFU, 0x00U, 0x89U,
               0x9AU, 0x6FU, 0x96U, 0x99U, 0xF1U, 0xFFU, 0xD3U, 0x98U, 0x6EU,
               0x0BU, 0xC0U, 0xDEU, 0x79U, 0xF1U, 0xDFU, 0xF0U, 0x05U, 0xC5U,
               0x55U, 0x95U, 0x6DU, 0x25U, 0x15U, 0x21U, 0xBCU, 0x58U, 0xACU,
               0x1AU, 0x9BU}},
    // Corresponding private key: "vend2.pem"
    {.bytes = {0x04U, 0x59U, 0x86U, 0x95U, 0xD1U, 0x57U, 0x8AU, 0xB1U, 0xFBU,
               0xADU, 0xEBU, 0x53U, 0x68U, 0xE3U, 0x13U, 0xB6U, 0xC6U, 0x3BU,
               0x83U, 0xD3U, 0x0EU, 0x35U, 0x30U, 0x07U, 0x32U, 0x91U, 0x4CU,
               0xECU, 0x3CU, 0xD9U, 0x8DU, 0xE2U, 0xBDU, 0xE6U, 0x4EU, 0x2CU,
               0xA4U, 0x3DU, 0xBFU, 0xF4U, 0x3EU, 0xD5U, 0x3BU, 0xF2U, 0xACU,
               0x40U, 0x08U, 0x96U, 0xE7U, 0x4CU, 0x36U, 0x99U, 0x9DU, 0xBCU,
               0x36U, 0xE1U, 0x46U, 0x29U, 0xD8U, 0xFDU, 0x58U, 0xAEU, 0x7BU,
               0xEDU, 0x80U}},
    // Corresponding private key: "vend3.pem"
    {.bytes = {0x04U, 0x4FU, 0xC6U, 0x8BU, 0x8CU, 0xA5U, 0xCEU, 0x74U, 0xC6U,
               0x50U, 0xC4U, 0x69U, 0x0AU, 0x62U, 0x55U, 0xDDU, 0x86U, 0xF3U,
               0x25U, 0x66U, 0xA1U, 0x33U, 0x62U, 0x0BU, 0x83U, 0x4CU, 0x60U,
               0x09U, 0x6FU, 0xD2U, 0x3FU, 0xC0U, 0x1FU, 0xA0U, 0xE7U, 0x19U,
               0x8BU, 0x16U, 0x39U, 0xE4U, 0x65U, 0x20U, 0x7AU, 0xB1U, 0x77U,
               0x77U, 0x72U, 0x0AU, 0x35U, 0x87U, 0xE3U, 0x15U, 0x8AU, 0xCEU,
               0x56U, 0xADU, 0x69U, 0x14U, 0xA9U, 0xB8U, 0x58U, 0x13U, 0x72U,
               0xDEU, 0x5EU}},
    BL_PUBKEY_END_OF_LIST};

// Reference public key set consisting of one public key list
static const bl_pubkey_t* ref_multisig_pubkeys[] = {ref_multisig_pubkey_list,
                                                    NULL};

// The reference contents of Signature section (signature records)
static const signature_rec_t ref_multisig_sigrecs[REF_N_SIGS] = {
    {.fingerprint = {0xE5U, 0xCDU, 0x36U, 0x99U, 0x5BU, 0x54U, 0xF8U, 0x91U,
                     0x98U, 0x24U, 0xE5U, 0x2FU, 0xE9U, 0x8CU, 0xF6U, 0x0EU},
     .signature = {0x7FU, 0xECU, 0x7CU, 0x17U, 0x3DU, 0xC6U, 0x7DU, 0xD7U,
                   0x29U, 0x78U, 0x66U, 0x09U, 0xB8U, 0x8FU, 0xF7U, 0xF6U,
                   0x40U, 0xCBU, 0xD3U, 0xC1U, 0xBDU, 0x17U, 0x4BU, 0x75U,
                   0x70U, 0x61U, 0x27U, 0xACU, 0xD0U, 0x43U, 0xF6U, 0x9AU,
                   0x13U, 0x61U, 0x17U, 0xA9U, 0xFDU, 0xD8U, 0x46U, 0x6CU,
                   0x46U, 0xA5U, 0x37U, 0xF1U, 0xB7U, 0x75U, 0x72U, 0x3DU,
                   0x48U, 0x09U, 0xA0U, 0x2BU, 0xDEU, 0xC6U, 0x52U, 0x91U,
                   0x04U, 0x1CU, 0x03U, 0x9EU, 0x24U, 0xB4U, 0x1FU, 0xBAU}},
    {.fingerprint = {0x64U, 0x62U, 0x5CU, 0x21U, 0x10U, 0x98U, 0xB0U, 0x96U,
                     0xB4U, 0x71U, 0x89U, 0x41U, 0x5EU, 0x57U, 0x20U, 0x93U},
     .signature = {0x54U, 0xE7U, 0xA0U, 0xC5U, 0x96U, 0x35U, 0xD1U, 0xA3U,
                   0x94U, 0xCEU, 0xA4U, 0x48U, 0x4BU, 0x9AU, 0x2CU, 0x04U,
                   0x44U, 0x68U, 0x24U, 0xE1U, 0x33U, 0xA6U, 0xE5U, 0x9CU,
                   0xD6U, 0x2BU, 0x74U, 0x85U, 0x82U, 0x31U, 0xABU, 0xBAU,
                   0x02U, 0x8DU, 0x93U, 0x6CU, 0xD9U, 0xFBU, 0xFFU, 0xB8U,
                   0x46U, 0x9CU, 0xD8U, 0x27U, 0xE8U, 0x9CU, 0x6DU, 0x4BU,
                   0x03U, 0x78U, 0x0FU, 0xF9U, 0x18U, 0x00U, 0x83U, 0xDAU,
                   0x0DU, 0xA3U, 0x31U, 0xAAU, 0xC1U, 0x8FU, 0x6BU, 0xFBU}},
    {.fingerprint = {0x25U, 0x20U, 0xF6U, 0x4AU, 0x5DU, 0x60U, 0xD3U, 0x69U,
                     0x51U, 0x31U, 0xA6U, 0x24U, 0x16U, 0x9FU, 0x95U, 0x9AU},
     .signature = {0xBAU, 0xD9U, 0x03U, 0x89U, 0x36U, 0x97U, 0xF3U, 0x06U,
                   0x3AU, 0x95U, 0xD3U, 0x3EU, 0xECU, 0x45U, 0x9CU, 0x39U,
                   0xF6U, 0xF4U, 0xD2U, 0x83U, 0x7BU, 0xEFU, 0xBBU, 0x2EU,
                   0x50U, 0x18U, 0x16U, 0x15U, 0x83U, 0xADU, 0xBAU, 0x27U,
                   0x24U, 0xD5U, 0x20U, 0x83U, 0x23U, 0x41U, 0x93U, 0x46U,
                   0xAEU, 0x18U, 0xD4U, 0x61U, 0x13U, 0x3EU, 0xBEU, 0xE7U,
                   0xA0U, 0xBBU, 0x9EU, 0xD8U, 0x73U, 0x7AU, 0xBBU, 0x44U,
                   0x84U, 0x78U, 0x50U, 0xB3U, 0x9BU, 0x4CU, 0xF1U, 0xE5U}},
};

/// A wrapper around a secp256k1 context object initialized for verification
class VerifyContext {
 public:
  inline VerifyContext() : ctx(create_verify_ctx()) {}
  inline ~VerifyContext() { destroy_verify_ctx(ctx); }
  inline operator secp256k1_context*() const { return ctx; }

 private:
  secp256k1_context* ctx;
};

/**
 * Tests two blocks of memory for equality
 *
 * If any of the pointers is NULL the result is always false.
 *
 * @param mema  pointer to the first block of memory
 * @param memb  pointer to the second block of memory
 * @param len   length of compared memory blocks
 * @return      true if memory blocks are equal
 */
static inline bool memeq(const uint8_t* mema, const uint8_t* memb, size_t len) {
  if (mema && memb && len) {
    return 0 == memcmp(mema, memb, len);
  }
  REQUIRE(false);  // Abort the test
  return false;
}

TEST_CASE("Check duplicating signatures") {
  const int n_recs = 17U;
  const int last_fp_byte = FP_SIZE - 1;
  auto recs = std::make_unique<signature_rec_t[]>(n_recs);
  for (int i = 0; i < n_recs; ++i) {
    memset(recs[i].fingerprint.bytes, 0, FP_SIZE);
    recs[i].fingerprint.bytes[0] = i + 1U;
  }

  // Valid
  REQUIRE(check_duplicating_signatures(recs.get(), n_recs));

  // Invalid parameters
  REQUIRE_FALSE(check_duplicating_signatures(NULL, n_recs));
  REQUIRE_FALSE(check_duplicating_signatures(recs.get(), 0U));

  // Duplicating fingerprint, trivial example
  recs[n_recs - 1].fingerprint.bytes[0] = recs[0].fingerprint.bytes[0];
  REQUIRE_FALSE(check_duplicating_signatures(recs.get(), n_recs));
  recs[n_recs - 1].fingerprint.bytes[last_fp_byte] = 1U;
  REQUIRE(check_duplicating_signatures(recs.get(), n_recs));

  // Exhaustive check of all possible combinations having a single duplication
  for (int byte_idx = 0; byte_idx < FP_SIZE; ++byte_idx) {
    for (int i = 0; i < n_recs; ++i) {
      memset(recs[i].fingerprint.bytes, 0, FP_SIZE);
      recs[i].fingerprint.bytes[byte_idx] = i + 1U;
    }
    for (int i = 0; i < n_recs; ++i) {
      for (int j = 0; j < n_recs; ++j) {
        if (j != i) {
          fingerprint_t tmp;
          memcpy(tmp.bytes, recs[i].fingerprint.bytes, FP_SIZE);
          REQUIRE(check_duplicating_signatures(recs.get(), n_recs));
          memcpy(recs[i].fingerprint.bytes, recs[j].fingerprint.bytes, FP_SIZE);
          REQUIRE_FALSE(check_duplicating_signatures(recs.get(), n_recs));
          memcpy(recs[i].fingerprint.bytes, tmp.bytes, FP_SIZE);
          REQUIRE(check_duplicating_signatures(recs.get(), n_recs));
        }
      }
    }
  }
}

TEST_CASE("Public key fingerprint") {
  bl_pubkey_t pubkey = ref_pubkey;
  fingerprint_t fp;
  pubkey_fingerprint(&fp, &pubkey);
  REQUIRE(memeq(fp.bytes, ref_pubkey_fp_bytes, FP_SIZE));
  pubkey.bytes[0] ^= 1U;
  pubkey_fingerprint(&fp, &pubkey);
  REQUIRE_FALSE(memeq(fp.bytes, ref_pubkey_fp_bytes, FP_SIZE));
}

TEST_CASE("Find public key by fingerprint") {
  const int n_keys = 23U;
  auto keys = std::make_unique<bl_pubkey_t[]>(n_keys + 1U);
  for (int i = 0; i < n_keys; ++i) {
    memset(keys[i].bytes, i + 1U, sizeof(keys[i].bytes));
  }
  keys[n_keys] = BL_PUBKEY_END_OF_LIST;
  const bl_pubkey_t* key_set[] = {keys.get(), NULL};

  for (int i = 0; i < n_keys; ++i) {
    fingerprint_t fp;
    pubkey_fingerprint(&fp, &keys[i]);
    const bl_pubkey_t* p_found_key = find_pubkey(key_set, &fp);
    REQUIRE(p_found_key == &keys[i]);
  }

  fingerprint_t fp;
  memset(fp.bytes, 0xEE, sizeof(fp.bytes));
  REQUIRE(NULL == find_pubkey(key_set, &fp));
}

TEST_CASE("Verify signature") {
  auto ctx = VerifyContext();
  auto msg =
      std::vector<uint8_t>(ref_message_str, ref_message_str + REF_MESSAGE_LEN);
  signature_t sig;
  memcpy(sig.bytes, ref_signature, sizeof(sig.bytes));

  // Valid
  REQUIRE(verify_signature(ctx, &sig, msg.data(), msg.size(), &ref_pubkey));

  // Wrong message
  auto wrong_msg = msg;
  REQUIRE(verify_signature(ctx, &sig, wrong_msg.data(), wrong_msg.size(),
                           &ref_pubkey));
  wrong_msg[0] ^= 1U;
  REQUIRE_FALSE(verify_signature(ctx, &sig, wrong_msg.data(), wrong_msg.size(),
                                 &ref_pubkey));

  // Wrong key
  bl_pubkey_t wrong_key = ref_pubkey;
  REQUIRE(verify_signature(ctx, &sig, msg.data(), msg.size(), &wrong_key));
  wrong_key.bytes[1] ^= 1U;
  REQUIRE_FALSE(
      verify_signature(ctx, &sig, msg.data(), msg.size(), &wrong_key));

  // Wrong signature
  signature_t wrong_sig = sig;
  REQUIRE(
      verify_signature(ctx, &wrong_sig, msg.data(), msg.size(), &ref_pubkey));
  wrong_sig.bytes[0] ^= 1U;
  REQUIRE_FALSE(
      verify_signature(ctx, &wrong_sig, msg.data(), msg.size(), &ref_pubkey));
}

TEST_CASE("Verify multiple signatures") {
  SECTION("valid") {
    ProgressMonitor monitor(12345U);
    int32_t valid_sigs = blsig_verify_multisig(
        "secp256k1-sha256", (const uint8_t*)ref_multisig_sigrecs,
        sizeof(ref_multisig_sigrecs), ref_multisig_pubkeys, ref_message_str,
        REF_MESSAGE_LEN, 12345U);
    REQUIRE(REF_N_SIGS == valid_sigs);
    REQUIRE(monitor.is_complete());
  }

  SECTION("valid, 2 public key lists") {
    REQUIRE(REF_N_PUBKEYS >= 3);
    auto list1 = std::vector<bl_pubkey_t>(
        {ref_multisig_pubkey_list[0], BL_PUBKEY_END_OF_LIST});
    auto list2 = std::vector<bl_pubkey_t>({ref_multisig_pubkey_list[1],
                                           ref_multisig_pubkey_list[2],
                                           BL_PUBKEY_END_OF_LIST});
    const bl_pubkey_t* pubkeys[] = {list1.data(), list2.data(), NULL};

    ProgressMonitor monitor(12345U);
    int32_t valid_sigs = blsig_verify_multisig(
        "secp256k1-sha256", (const uint8_t*)ref_multisig_sigrecs,
        sizeof(ref_multisig_sigrecs), pubkeys, ref_message_str, REF_MESSAGE_LEN,
        12345U);
    REQUIRE(3 == valid_sigs);
    REQUIRE(monitor.is_complete());
  }

  SECTION("valid, 3 public key lists") {
    REQUIRE(REF_N_PUBKEYS >= 3);
    auto list1 = std::vector<bl_pubkey_t>(
        {ref_multisig_pubkey_list[0], BL_PUBKEY_END_OF_LIST});
    auto list2 = std::vector<bl_pubkey_t>(
        {ref_multisig_pubkey_list[1], BL_PUBKEY_END_OF_LIST});
    auto list3 = std::vector<bl_pubkey_t>(
        {ref_multisig_pubkey_list[2], BL_PUBKEY_END_OF_LIST});
    const bl_pubkey_t* pubkeys[] = {list1.data(), list2.data(), list3.data(),
                                    NULL};

    ProgressMonitor monitor(12345U);
    int32_t valid_sigs = blsig_verify_multisig(
        "secp256k1-sha256", (const uint8_t*)ref_multisig_sigrecs,
        sizeof(ref_multisig_sigrecs), pubkeys, ref_message_str, REF_MESSAGE_LEN,
        12345U);
    REQUIRE(3 == valid_sigs);
    REQUIRE(monitor.is_complete());
  }

  SECTION("empty public key list") {
    REQUIRE(REF_N_PUBKEYS >= 3);
    auto list1 = std::vector<bl_pubkey_t>({BL_PUBKEY_END_OF_LIST});
    auto list2 = std::vector<bl_pubkey_t>(
        {ref_multisig_pubkey_list[0], ref_multisig_pubkey_list[1],
         ref_multisig_pubkey_list[2], BL_PUBKEY_END_OF_LIST});
    const bl_pubkey_t* pubkeys[] = {list1.data(), list2.data(), NULL};

    ProgressMonitor monitor(12345U);
    int32_t valid_sigs = blsig_verify_multisig(
        "secp256k1-sha256", (const uint8_t*)ref_multisig_sigrecs,
        sizeof(ref_multisig_sigrecs), pubkeys, ref_message_str, REF_MESSAGE_LEN,
        12345U);
    REQUIRE(3 == valid_sigs);
    REQUIRE(monitor.is_complete());
  }

  SECTION("duplicating keys in public key lists") {
    REQUIRE(REF_N_PUBKEYS >= 3);
    auto list1 = std::vector<bl_pubkey_t>({ref_multisig_pubkey_list[0],
                                           ref_multisig_pubkey_list[1],
                                           BL_PUBKEY_END_OF_LIST});
    auto list2 = std::vector<bl_pubkey_t>({ref_multisig_pubkey_list[1],
                                           ref_multisig_pubkey_list[2],
                                           BL_PUBKEY_END_OF_LIST});
    const bl_pubkey_t* pubkeys[] = {list1.data(), list2.data(), NULL};

    ProgressMonitor monitor(12345U);
    int32_t valid_sigs = blsig_verify_multisig(
        "secp256k1-sha256", (const uint8_t*)ref_multisig_sigrecs,
        sizeof(ref_multisig_sigrecs), pubkeys, ref_message_str, REF_MESSAGE_LEN,
        12345U);
    REQUIRE(3 == valid_sigs);
    REQUIRE(monitor.is_complete());
  }

  SECTION("all public key lists are empty") {
    auto list1 = std::vector<bl_pubkey_t>({BL_PUBKEY_END_OF_LIST});
    auto list2 = std::vector<bl_pubkey_t>({BL_PUBKEY_END_OF_LIST});
    const bl_pubkey_t* pubkeys[] = {list1.data(), list2.data(), NULL};

    ProgressMonitor monitor(12345U);
    int32_t valid_sigs = blsig_verify_multisig(
        "secp256k1-sha256", (const uint8_t*)ref_multisig_sigrecs,
        sizeof(ref_multisig_sigrecs), pubkeys, ref_message_str, REF_MESSAGE_LEN,
        12345U);
    REQUIRE(0 == valid_sigs);
    REQUIRE(monitor.is_complete());
  }

  SECTION("empty public key set") {
    const bl_pubkey_t* pubkeys[] = {NULL};
    int32_t result = blsig_verify_multisig(
        "secp256k1-sha256", (const uint8_t*)ref_multisig_sigrecs,
        sizeof(ref_multisig_sigrecs), pubkeys, ref_message_str, REF_MESSAGE_LEN,
        0U);
    REQUIRE(0 == result);
  }

  SECTION("bad arguments") {
    REQUIRE(blsig_err_bad_arg ==
            blsig_verify_multisig(
                "secp256k1-sha256", NULL, sizeof(ref_multisig_sigrecs),
                ref_multisig_pubkeys, ref_message_str, REF_MESSAGE_LEN, 0U));
    REQUIRE(blsig_err_bad_arg ==
            blsig_verify_multisig(
                "secp256k1-sha256", (const uint8_t*)ref_multisig_sigrecs, 0U,
                ref_multisig_pubkeys, ref_message_str, REF_MESSAGE_LEN, 0U));
    REQUIRE(blsig_err_bad_arg ==
            blsig_verify_multisig("secp256k1-sha256",
                                  (const uint8_t*)ref_multisig_sigrecs,
                                  sizeof(ref_multisig_sigrecs), NULL,
                                  ref_message_str, REF_MESSAGE_LEN, 0U));
    REQUIRE(blsig_err_bad_arg ==
            blsig_verify_multisig(
                "secp256k1-sha256", (const uint8_t*)ref_multisig_sigrecs,
                sizeof(ref_multisig_sigrecs), ref_multisig_pubkeys, NULL,
                REF_MESSAGE_LEN, 0U));
    REQUIRE(blsig_err_bad_arg ==
            blsig_verify_multisig(
                "secp256k1-sha256", (const uint8_t*)ref_multisig_sigrecs,
                sizeof(ref_multisig_sigrecs), ref_multisig_pubkeys,
                ref_message_str, 0U, 0U));
  }

  SECTION("unsupported algorithm") {
    int32_t result = blsig_verify_multisig(
        "secp256k1-sha2566", (const uint8_t*)ref_multisig_sigrecs,
        sizeof(ref_multisig_sigrecs), ref_multisig_pubkeys, ref_message_str,
        REF_MESSAGE_LEN, 0U);
    REQUIRE(blsig_err_algo_not_supported == result);
  }

  SECTION("duplicating signature") {
    // Create a list of Signature records
    auto recs = std::vector<signature_rec_t>(ref_multisig_sigrecs,
                                             ref_multisig_sigrecs + REF_N_SIGS);
    int32_t result = 0xBADF00D;

    // Add a copy of the first record to the end of the list ant try to verify
    recs.push_back(recs[0]);
    result = blsig_verify_multisig(
        "secp256k1-sha256", (const uint8_t*)recs.data(),
        recs.size() * sizeof(recs[0]), ref_multisig_pubkeys, ref_message_str,
        REF_MESSAGE_LEN, 0U);
    REQUIRE(blsig_err_duplicating_sig == result);

    // Try again without the last record, it should pass
    recs.pop_back();
    result = blsig_verify_multisig(
        "secp256k1-sha256", (const uint8_t*)recs.data(),
        recs.size() * sizeof(recs[0]), ref_multisig_pubkeys, ref_message_str,
        REF_MESSAGE_LEN, 0U);
    REQUIRE(REF_N_SIGS == result);
  }

  SECTION("verification failure") {
    // Create a list of Signature records
    auto recs = std::vector<signature_rec_t>(ref_multisig_sigrecs,
                                             ref_multisig_sigrecs + REF_N_SIGS);
    // Corrupt the last signature and try to verify
    recs[recs.size() - 1].signature.bytes[0] ^= 1U;
    REQUIRE(blsig_err_verification_fail ==
            blsig_verify_multisig(
                "secp256k1-sha256", (const uint8_t*)recs.data(),
                recs.size() * sizeof(recs[0]), ref_multisig_pubkeys,
                ref_message_str, REF_MESSAGE_LEN, 0U));
  }

  SECTION("additional inert signatures") {
    // Create a list of Signature records with additional inert records
    auto recs = std::vector<signature_rec_t>();
    signature_rec_t inert;
    memset(&inert, 0, sizeof(inert));
    for (int i = 0; i < REF_N_SIGS; ++i) {
      memset(inert.fingerprint.bytes, i + 1, sizeof(inert.fingerprint.bytes));
      recs.push_back(inert);
      recs.push_back(ref_multisig_sigrecs[i]);
    }

    REQUIRE(REF_N_SIGS == blsig_verify_multisig(
                              "secp256k1-sha256", (const uint8_t*)recs.data(),
                              recs.size() * sizeof(recs[0]),
                              ref_multisig_pubkeys, ref_message_str,
                              REF_MESSAGE_LEN, 0U));
  }
}

TEST_CASE("Signatures: error text") {
  auto errors = std::vector<const char*>();

  // Simulate "no error" condition
  const char* no_error = blsig_error_text(0);
  REQUIRE(blsig_error_text(1) == no_error);
  REQUIRE(blsig_error_text(2) == no_error);
  errors.push_back(no_error);

  // Simulate "unknown error" condition
  const char* unknown_err = blsig_error_text(-100);
  REQUIRE(blsig_error_text(-101) == unknown_err);
  REQUIRE(blsig_error_text(-102) == unknown_err);
  errors.push_back(unknown_err);

  // Get strings for all known error codes
  std::vector<int32_t> error_codes{
      blsig_err_algo_not_supported, blsig_err_out_of_memory,
      blsig_err_duplicating_sig, blsig_err_verification_fail};
  std::for_each(error_codes.begin(), error_codes.end(), [&](int32_t& code) {
    errors.push_back(blsig_error_text(code));
  });

  // Check that all strings are valid
  std::for_each(errors.begin(), errors.end(), [](const char*& str) {
    REQUIRE(str != NULL);
    REQUIRE(strlen(str) != 0U);
  });

  // Check for duplicating pointers
  std::sort(errors.begin(), errors.end());
  auto i_dup = std::adjacent_find(errors.begin(), errors.end());
  REQUIRE(i_dup == errors.end());
}
