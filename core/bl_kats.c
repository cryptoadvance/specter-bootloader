/**
 * @file       bl_kats.c
 * @brief      Bootloader known answer tests (KATs) for cryptographic functions
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include <string.h>
#include "sha2.h"
#include "secp256k1.h"
#include "secp256k1_preallocated.h"
#include "bl_kats.h"
#include "bl_util.h"
#include "bl_signature.h"

/// Size of input message of ECDSA algorithm with secp256k1 curve
#define ECDSA_MESSAGE_SIZE 32U
/// Size in bytes of a compact signature of ECDSA algorithm with secp256k1 curve
#define ECDSA_SIG_COMPACT_SIZE 64U
/// Size in bytes of a private key of ECDSA algorithm with secp256k1 curve
#define ECDSA_SECKEY_SIZE 32U
/// Size in bytes of an unpacked public key of ECDSA algorithm (secp256k1 curve)
#define ECDSA_PUBKEY_SIZE 65U

// Reference message. Terminating null character should be ignored.
static const char ref_message[] =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed "
    "ornare tincidunt pharetra. Mauris at molestie quam, et "
    "placerat justo. Aenean maximus quam tortor, vel pellentesque "
    "sapien tincidunt lacinia. Vivamus id dui at magna lacinia "
    "lacinia porttitor eu justo. Phasellus scelerisque porta "
    "augue. Vestibulum id diam vulputate, sagittis nibh eu, "
    "egestas mi. Proin congue imperdiet dictum.";

// Digest of the reference message calculated using SHA-256 hash function
static const uint8_t ref_digest[SHA256_DIGEST_LENGTH] = {
    0xDEU, 0x07U, 0x57U, 0x18U, 0x95U, 0xD0U, 0x02U, 0x3EU, 0x85U, 0xD6U, 0xB3U,
    0xE2U, 0x80U, 0x73U, 0x6AU, 0xF4U, 0x81U, 0xC2U, 0xE8U, 0x06U, 0x41U, 0x12U,
    0x84U, 0xA8U, 0x04U, 0xE0U, 0xD7U, 0x66U, 0xCFU, 0x8CU, 0xBFU, 0x26U};

// Reference ECDSA private (secret) key, 256 bit
static const uint8_t ref_seckey[ECDSA_SECKEY_SIZE] = {
    0x97U, 0xBBU, 0x5CU, 0x85U, 0x61U, 0x42U, 0x3BU, 0x38U, 0xA9U, 0x44U, 0x4EU,
    0x9AU, 0x0DU, 0x9BU, 0xF8U, 0xC9U, 0x21U, 0xD5U, 0xB6U, 0x41U, 0xCBU, 0x25U,
    0xFEU, 0x3CU, 0x72U, 0xABU, 0x05U, 0xDFU, 0x7AU, 0xEFU, 0x4EU, 0x35U};

// Reference ECDSA public key belonging to secp256k1 curve, uncompressed
static const uint8_t ref_pubkey[ECDSA_PUBKEY_SIZE] = {
    0x04U, 0x0BU, 0x61U, 0x6DU, 0x40U, 0x3DU, 0x49U, 0x56U, 0xE6U, 0xABU, 0x00U,
    0x7AU, 0x36U, 0xE2U, 0xA7U, 0xA5U, 0x73U, 0x19U, 0xFAU, 0x82U, 0x36U, 0x19U,
    0x77U, 0xBBU, 0x30U, 0x73U, 0x80U, 0xFAU, 0x43U, 0xFFU, 0x8FU, 0x83U, 0x26U,
    0x24U, 0xB5U, 0x70U, 0x42U, 0x26U, 0xBBU, 0x0CU, 0x87U, 0xDFU, 0x8FU, 0x49U,
    0xB4U, 0xBFU, 0x46U, 0x3DU, 0x18U, 0xBCU, 0x29U, 0x2BU, 0xCEU, 0xFDU, 0x83U,
    0xF2U, 0x9FU, 0x5BU, 0x81U, 0xE0U, 0xC9U, 0x02U, 0xC6U, 0x5EU, 0x21U};

// Reference compact ECDSA signature of the reference digest, calculated using
// the reference private key by a non-deterministic algorithm using secp256k1
// curve.
static const uint8_t ref_signature[ECDSA_SIG_COMPACT_SIZE] = {
    0x67U, 0x82U, 0x2DU, 0x4EU, 0x66U, 0x24U, 0x83U, 0xDFU, 0x02U, 0xD7U, 0xF7U,
    0x98U, 0x6DU, 0x5BU, 0x7CU, 0xDBU, 0x80U, 0xBFU, 0xCAU, 0xB4U, 0x2DU, 0xCEU,
    0xB0U, 0xE8U, 0xF7U, 0xC8U, 0x71U, 0x39U, 0xB3U, 0x27U, 0xD4U, 0xA2U, 0x2DU,
    0xCBU, 0x1EU, 0x5BU, 0xBEU, 0xC4U, 0x23U, 0x46U, 0xFFU, 0x1EU, 0xA9U, 0x51U,
    0xB1U, 0xC3U, 0x07U, 0xACU, 0x40U, 0xA8U, 0x44U, 0xB3U, 0x84U, 0xD7U, 0xA1U,
    0x0EU, 0xC6U, 0xF4U, 0x44U, 0x97U, 0xE7U, 0xACU, 0xE7U, 0x7DU};

// Buffer used by secp256k1 library to allocate context
extern uint8_t blsig_ecdsa_buf[BLSIG_ECDSA_BUF_SIZE];

/**
 * Tests two byte buffers for equality
 *
 * @param bufa  first buffer
 * @param bufb  second buffer
 * @param len   size of compared buffers
 * @return      true if buffers contain identical data
 */
BL_STATIC_NO_TEST bool buf_equal(const uint8_t* bufa, const uint8_t* bufb,
                                 size_t len) {
  if (bufa && bufb && len) {
    uint8_t acc = 0U;
    for (size_t i = 0; i < len; ++i) {
      acc |= bufa[i] ^ bufb[i];
    }
    return (0U == acc);
  }
  return false;
}

/**
 * Runs known answer tests for SHA-256 hash function
 *
 * @return  true if the test passed successfully
 */
BL_STATIC_NO_TEST bool do_sha256_kat(void) {
  if (sizeof(ref_digest) == SHA256_DIGEST_LENGTH) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    memset(digest, 0xEE, sizeof(digest));
    sha256_Raw((const uint8_t*)ref_message, strlen(ref_message), digest);
    return buf_equal(digest, ref_digest, SHA256_DIGEST_LENGTH);
  }
  return false;
}

/**
 * Performs signature KAT for ECDSA deterministic signature (secp256k1 curve)
 *
 * @param ecdsa_ctx  secp256k1 context object, initialized for signing
 * @return           true if the test passed successfully
 */
static bool ecdsa_secp256k1_sign_kat(secp256k1_context* ecdsa_ctx) {
  if (ecdsa_ctx && sizeof(ref_digest) == ECDSA_MESSAGE_SIZE &&
      sizeof(ref_seckey) == ECDSA_SECKEY_SIZE &&
      sizeof(ref_signature) == ECDSA_SIG_COMPACT_SIZE) {
    // Allocate signature object and comact signature buffer, fill with 0xEE
    secp256k1_ecdsa_signature sig_obj;
    uint8_t sig_compact[ECDSA_SIG_COMPACT_SIZE];
    memset(&sig_compact, 0xEE, sizeof(sig_compact));
    memset(&sig_obj, 0xEE, sizeof(sig_obj));

    // Sign the digest with the private key
    bool ok = (1 == secp256k1_ecdsa_sign(ecdsa_ctx, &sig_obj, ref_digest,
                                         ref_seckey, NULL, NULL));
    // Export signature to compact format
    ok = ok && (1 == secp256k1_ecdsa_signature_serialize_compact(
                         ecdsa_ctx, sig_compact, &sig_obj));
    // Comare with the reference deterministic signature
    ok = ok && buf_equal(sig_compact, ref_signature, sizeof(sig_compact));
    return ok;
  }
  return false;
}

/**
 * Performs signature KAT for ECDSA verification (secp256k1 curve)
 *
 * @param ecdsa_ctx  secp256k1 context object, initialized for verification
 * @return           true if the test passed successfully
 */
static bool ecdsa_secp256k1_verify_kat(secp256k1_context* ecdsa_ctx) {
  if (ecdsa_ctx && sizeof(ref_digest) == ECDSA_MESSAGE_SIZE &&
      sizeof(ref_pubkey) == ECDSA_PUBKEY_SIZE &&
      sizeof(ref_signature) == ECDSA_SIG_COMPACT_SIZE) {
    // Allocate public key and signature objects, fill with 0xEE
    secp256k1_pubkey pubkey_obj;
    secp256k1_ecdsa_signature sig_obj;
    memset(&pubkey_obj, 0xEE, sizeof(pubkey_obj));
    memset(&sig_obj, 0xEE, sizeof(sig_obj));

    // Make a copy of the reference digest
    uint8_t digest[SHA256_DIGEST_LENGTH];
    memcpy(digest, ref_digest, sizeof(digest));

    // Parse the public key
    bool ok = (1 == secp256k1_ec_pubkey_parse(ecdsa_ctx, &pubkey_obj,
                                              ref_pubkey, sizeof(ref_pubkey)));
    // Parse compact signature
    ok = ok && (1 == secp256k1_ecdsa_signature_parse_compact(
                         ecdsa_ctx, &sig_obj, ref_signature));
    // Verify the signature
    ok = ok && (1 == secp256k1_ecdsa_verify(ecdsa_ctx, &sig_obj, digest,
                                            &pubkey_obj));
    // Verify the signature with corrupted digest
    digest[SHA256_DIGEST_LENGTH - 1] ^= 1;
    ok = ok && (0 == secp256k1_ecdsa_verify(ecdsa_ctx, &sig_obj, digest,
                                            &pubkey_obj));
    return ok;
  }
  return false;
}

/**
 * Runs known answer tests for ECDSA functions with secp256k1 curve
 *
 * @return true  if all tests passed successfully
 */
BL_STATIC_NO_TEST bool do_ecdsa_secp256k1_kat(void) {
  const unsigned int flags = SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY;
  size_t ctx_size = secp256k1_context_preallocated_size(flags);
  if (ctx_size <= BLSIG_ECDSA_BUF_SIZE) {
    secp256k1_context* ecdsa_ctx =
        secp256k1_context_preallocated_create(blsig_ecdsa_buf, flags);
    if (ecdsa_ctx) {
      bool success = ecdsa_secp256k1_sign_kat(ecdsa_ctx);
      success = success && ecdsa_secp256k1_verify_kat(ecdsa_ctx);
      secp256k1_context_preallocated_destroy(ecdsa_ctx);
      return success;
    }
  }
  return false;
}

bool bl_run_kats(void) {
  bool success = do_sha256_kat();
  success = success && do_ecdsa_secp256k1_kat();
  return success;
}
