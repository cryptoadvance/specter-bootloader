/**
 * @file       test_bl_signature.cpp
 * @brief      Unit tests for signature functions
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */
// TODO add tests with multiple sets of keys

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
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed "
    "ornare tincidunt pharetra. Mauris at molestie quam, et "
    "placerat justo. Aenean maximus quam tortor, vel pellentesque "
    "sapien tincidunt lacinia. Vivamus id dui at magna lacinia "
    "lacinia porttitor eu justo. Phasellus scelerisque porta "
    "augue. Vestibulum id diam vulputate, sagittis nibh eu, "
    "egestas mi. Proin congue imperdiet dictum.";

// Compact 64-byte signature of the reference message (no terminating
// null-character) using a private key paired with the reference public key.
// Terminating null character of the signature should be ignored.
static const uint8_t ref_signature[BL_MEMBER_SIZE(signature_t, bytes) + 1] =
    "g\x82-Nf$\x83\xdf\x02\xd7\xf7\x98m[|\xdb\x80\xbf\xca\xb4-\xce\xb0\xe8\xf7"
    "\xc8q9\xb3'\xd4\xa2-\xcb\x1e[\xbe\xc4#F\xff\x1e\xa9Q\xb1\xc3\x07\xac@\xa8"
    "\x44\xb3\x84\xd7\xa1\x0e\xc6\xf4\x44\x97\xe7\xac\xe7}";

// Reference list of public keys
static const bl_pubkey_t ref_multisig_pubkey_list[REF_N_PUBKEYS + 1] = {
    {.bytes = {0x04, 0x8C, 0x28, 0xA9, 0x7B, 0xF8, 0x29, 0x8B, 0xC0, 0xD2, 0x3D,
               0x8C, 0x74, 0x94, 0x52, 0xA3, 0x2E, 0x69, 0x4B, 0x65, 0xE3, 0x0A,
               0x94, 0x72, 0xA3, 0x95, 0x4A, 0xB3, 0x0F, 0xE5, 0x32, 0x4C, 0xAA,
               0x40, 0xA3, 0x04, 0x63, 0xA3, 0x30, 0x51, 0x93, 0x37, 0x8F, 0xED,
               0xF3, 0x1F, 0x7C, 0xC0, 0xEB, 0x7A, 0xE7, 0x84, 0xF0, 0x45, 0x1C,
               0xB9, 0x45, 0x9E, 0x71, 0xDC, 0x73, 0xCB, 0xEF, 0x94, 0x82}},
    {.bytes = {0x04, 0xAB, 0x1A, 0xC1, 0x87, 0x2A, 0x38, 0xA2, 0xF1, 0x96, 0xBE,
               0xD5, 0xA6, 0x04, 0x7F, 0x0D, 0xA2, 0xC8, 0x13, 0x0F, 0xE8, 0xDE,
               0x49, 0xFC, 0x4D, 0x5D, 0xFB, 0x20, 0x1F, 0x76, 0x11, 0xD8, 0xE2,
               0x13, 0xF4, 0xA3, 0x7A, 0x32, 0x4D, 0x17, 0xA1, 0xE9, 0xAA, 0x5F,
               0x39, 0xDB, 0x6A, 0x42, 0xB6, 0xF7, 0xEF, 0x93, 0xD3, 0x3E, 0x1E,
               0x54, 0x5F, 0x01, 0xA5, 0x81, 0xF3, 0xC4, 0x29, 0xD1, 0x5B}},
    {.bytes = {0x04, 0x97, 0x29, 0x24, 0x70, 0x32, 0xC0, 0xDF, 0xCF, 0x45, 0xB4,
               0x84, 0x1F, 0xCD, 0x72, 0xF6, 0xE9, 0xA2, 0x42, 0x26, 0x31, 0xFC,
               0x34, 0x66, 0xCF, 0x86, 0x3E, 0x87, 0x15, 0x47, 0x54, 0xDD, 0x40,
               0x91, 0xD1, 0xA2, 0x44, 0x26, 0x5F, 0xEA, 0x1D, 0xCD, 0x15, 0xC7,
               0x5D, 0xCB, 0xD4, 0xDF, 0x36, 0x90, 0xDA, 0xE8, 0x52, 0x55, 0xAC,
               0xAF, 0x49, 0x38, 0x4B, 0x49, 0x2F, 0x2A, 0xA3, 0x61, 0x43}},
    BL_PUBKEY_END_OF_LIST};

// Reference public key set consisting of one public key list
static const bl_pubkey_t* ref_multisig_pubkeys[] = {ref_multisig_pubkey_list,
                                                    NULL};

// The reference contents of Signature section (signature records)
static const signature_rec_t ref_multisig_sigrecs[REF_N_SIGS] = {
    {.fingerprint = {0x73, 0x1A, 0x17, 0xCF, 0x38, 0xA0, 0xC0, 0xD3, 0xBB, 0x92,
                     0x32, 0xCD, 0x47, 0x32, 0x03, 0x77},
     .signature = {0x33, 0xD4, 0xF5, 0xE9, 0xDE, 0x43, 0x28, 0x00, 0xB4, 0xB0,
                   0x39, 0x33, 0xEA, 0x60, 0xA1, 0x7E, 0x5D, 0xA9, 0xE1, 0x10,
                   0x3A, 0xC3, 0x7A, 0xF4, 0xD4, 0x99, 0x9D, 0x6D, 0x36, 0x27,
                   0xDF, 0xAA, 0x6B, 0x78, 0x25, 0xE5, 0x28, 0xE7, 0x0E, 0x82,
                   0xCC, 0x38, 0x51, 0xC8, 0xD8, 0xDA, 0x6F, 0x67, 0x0C, 0x54,
                   0x10, 0xCE, 0x41, 0x11, 0x9A, 0x08, 0x7B, 0x0A, 0x02, 0x7D,
                   0xB3, 0x46, 0xDD, 0x69}},
    {.fingerprint = {0xAD, 0x36, 0xD9, 0x39, 0x81, 0x54, 0x59, 0xE4, 0xB1, 0xBD,
                     0xAC, 0x78, 0xB9, 0xF1, 0xC4, 0x72},
     .signature = {0xAB, 0x49, 0x1A, 0x0C, 0x6F, 0xCF, 0x7A, 0x04, 0xCA, 0x76,
                   0x6B, 0x9C, 0x54, 0x78, 0xCB, 0xFA, 0x98, 0x4E, 0x42, 0xEF,
                   0x6F, 0x01, 0xA4, 0x10, 0x5B, 0x62, 0x87, 0x73, 0xC3, 0x95,
                   0x46, 0x05, 0x00, 0x0F, 0x2C, 0x81, 0x0D, 0x6E, 0x2B, 0x52,
                   0xB5, 0x48, 0xC4, 0xFB, 0xEE, 0x33, 0xBD, 0xF4, 0x6A, 0xAF,
                   0xEB, 0xB5, 0x7C, 0x97, 0xA8, 0xC2, 0x90, 0xB1, 0xA6, 0x12,
                   0x87, 0x6D, 0xA9, 0xBF}},
    {.fingerprint = {0x58, 0x38, 0xD1, 0x29, 0xA9, 0xFC, 0xCE, 0xEF, 0x42, 0x17,
                     0x26, 0x04, 0x05, 0xD8, 0x60, 0x5A},
     .signature = {0xA8, 0x91, 0x91, 0x03, 0x82, 0x52, 0x13, 0x75, 0x24, 0x29,
                   0xBD, 0xCE, 0x2E, 0xFB, 0x9C, 0xA1, 0x2E, 0xBC, 0xB8, 0x79,
                   0xFE, 0xF8, 0x96, 0x02, 0x07, 0x91, 0xD3, 0x74, 0x21, 0x0F,
                   0x54, 0x05, 0x2F, 0xA3, 0x16, 0xFF, 0xC0, 0x94, 0xBB, 0xC4,
                   0xD0, 0x76, 0x8F, 0x03, 0xDD, 0x8D, 0x7F, 0x9A, 0x08, 0x62,
                   0xEC, 0xE7, 0x17, 0x1E, 0x44, 0x2B, 0xBC, 0x2B, 0xEB, 0x72,
                   0xE1, 0x85, 0x8B, 0x43}}};

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
