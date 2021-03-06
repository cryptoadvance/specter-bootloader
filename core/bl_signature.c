/**
 * @file       bl_signature.c
 * @brief      Bootloader signature functions
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

/// Forces inclusion of private types
#define BLSIG_DEFINE_PRIVATE_TYPES
#include <string.h>
#include "sha2.h"
#include "secp256k1.h"
#include "secp256k1_preallocated.h"
#include "bl_syscalls.h"
#include "bl_signature.h"
#include "bl_util.h"

/// Size of input message of ECDSA algorithm with secp256k1 curve
#define ECDSA_MESSAGE_SIZE 32U
/// Digital signature algorithm string: secp256k1-sha256
#define ALG_SECP256K1_SHA256 "secp256k1-sha256"
/// "Magic" prefix of Bitcoin message
#define BITCOIN_SIG_PREFIX \
  ("\x18"                  \
   "Bitcoin Signed Message:\n")
/// Maximum value of a single-byte integer using variable length encoding
#define VARINT_MAX_ONE_BYTE 0xFCU

/// Table of error strings
const char* error_text[] = {
    [-(int)blsig_err_bad_arg] = "Bad argument",
    [-(int) blsig_err_algo_not_supported] = "Signature algorithm not supported",
    [-(int) blsig_err_out_of_memory] = "Out of memory",
    [-(int) blsig_err_duplicating_sig] = "Duplicating signature",
    [-(int) blsig_err_verification_fail] = "Signature verification failed"};

// Buffer used by secp256k1 library to allocate context
uint8_t blsig_ecdsa_buf[BLSIG_ECDSA_BUF_SIZE];

/**
 * Tests if two signature records have the same public key fingerprint
 *
 * @param p_fp1  pointer to first fingerprint to test
 * @param p_fp2  pointer to second fingerprint to test
 * @return       true if fingerprints are equal
 */
static bool fingerprint_eq(const fingerprint_t* p_fp1,
                           const fingerprint_t* p_fp2) {
  if (p_fp1 && p_fp2) {
    return bl_memeq(p_fp1->bytes, p_fp2->bytes, sizeof(p_fp1->bytes));
  }
  blsys_fatal_error(BL_INTERNAL_ERROR);
  return false;
}

/**
 * Checks if there are duplicating signatures inside a Signature section
 *
 * @param sig_recs  buffer containing signature records
 * @param n_sig     number of signature records
 * @return          true if there is no duplicating signatures
 */
BL_STATIC_NO_TEST bool check_duplicating_signatures(
    const signature_rec_t* sig_recs, uint32_t n_sig) {
  if (sig_recs && n_sig) {
    if (n_sig >= 2) {
      for (uint32_t ref = 0U; ref < n_sig - 1U; ++ref) {
        for (uint32_t check = ref + 1U; check < n_sig; ++check) {
          if (fingerprint_eq(&sig_recs[check].fingerprint,
                             &sig_recs[ref].fingerprint)) {
            // Duplication: two signatures with the same public key fingerprint
            return false;
          }
        }
      }
    }
    return true;  // Section is valid, no duplicating signatures found
  }
  return false;  // To indicate argument error
}

/**
 * Calculates fingerprint of a public key
 *
 * @param p_result  pointer to variable receiving calculated fingerprint
 * @param p_pubkey  pointer to public key
 */
BL_STATIC_NO_TEST void pubkey_fingerprint(fingerprint_t* p_result,
                                          const bl_pubkey_t* p_pubkey) {
  if (sizeof(p_result->bytes) <= SHA256_DIGEST_LENGTH) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    sha256_Raw(p_pubkey->bytes, sizeof(p_pubkey->bytes), digest);
    memcpy(p_result->bytes, digest, sizeof(p_result->bytes));
  } else {
    blsys_fatal_error(BL_INTERNAL_ERROR);
  }
}

/**
 * Searches for a public key in the key set (list of lists) by its fingerprint
 *
 * @param pubkey_set     NULL-terminated list of pointers to public key lists
 * @param p_fingerprint  pointer to public key fingerprint
 * @return               pointer to found public key or NULL if not found
 */
BL_STATIC_NO_TEST const bl_pubkey_t* find_pubkey(
    const bl_pubkey_t** pubkey_set, const fingerprint_t* p_fingerprint) {
  if (pubkey_set && p_fingerprint) {
    const bl_pubkey_t** p_list = pubkey_set;
    while (*p_list != NULL) {
      const bl_pubkey_t* p_key = *p_list;
      while (!bl_pubkey_is_end_record(p_key)) {
        fingerprint_t fp;
        pubkey_fingerprint(&fp, p_key);
        if (fingerprint_eq(&fp, p_fingerprint)) {
          return p_key;
        }
        ++p_key;
      }
      ++p_list;
    }
  }
  return NULL;
}

/**
 * Verifies signature using "secp256k1-sha256" algorithm
 *
 * @param verify_ctx   secp256k1 context object, initialized for verification
 * @param p_sig        pointer to signature
 * @param message      message to be verified
 * @param message_len  length of the message in bytes
 * @param p_pubkey     pointer to public key, can be NULL (returning false)
 * @return             true if signature is valid
 */
BL_STATIC_NO_TEST bool verify_signature(secp256k1_context* verify_ctx,
                                        const signature_t* p_sig,
                                        const uint8_t* message,
                                        size_t message_len,
                                        const bl_pubkey_t* p_pubkey) {
  if (verify_ctx && p_sig && message && message_len &&
      message_len <= VARINT_MAX_ONE_BYTE && p_pubkey &&
      ECDSA_MESSAGE_SIZE == SHA256_DIGEST_LENGTH) {
    // Calculate "inside" SHA-256 of the message with a "magic" prefix
    uint8_t len_byte[1] = {(uint8_t)message_len};
    SHA256_CTX context;
    sha256_Init(&context);
    sha256_Update(&context, (const uint8_t*)BITCOIN_SIG_PREFIX,
                  sizeof(BITCOIN_SIG_PREFIX) - 1U);
    sha256_Update(&context, len_byte, sizeof(len_byte));
    sha256_Update(&context, message, message_len);
    uint8_t digest_in[SHA256_DIGEST_LENGTH];
    sha256_Final(&context, digest_in);

    // Calculate "outside" SHA-256
    sha256_Init(&context);
    sha256_Update(&context, digest_in, sizeof(digest_in));
    uint8_t digest[SHA256_DIGEST_LENGTH];
    sha256_Final(&context, digest);

    // Parse the public key
    secp256k1_pubkey pubkey_obj;
    bool valid = (1 == secp256k1_ec_pubkey_parse(verify_ctx, &pubkey_obj,
                                                 p_pubkey->bytes,
                                                 sizeof(p_pubkey->bytes)));
    // Parse compact signature
    secp256k1_ecdsa_signature sig_obj;
    valid = valid && (1 == secp256k1_ecdsa_signature_parse_compact(
                               verify_ctx, &sig_obj, p_sig->bytes));

    // Verify the signature
    valid = valid && (1 == secp256k1_ecdsa_verify(verify_ctx, &sig_obj, digest,
                                                  &pubkey_obj));
    return valid;
  }
  return false;
}

/**
 * Create a secp256k1 context object initialized for verification
 *
 * @return a newly created context object
 */
BL_STATIC_NO_TEST secp256k1_context* create_verify_ctx(void) {
  const unsigned int flags = SECP256K1_CONTEXT_VERIFY;
  size_t req_size = secp256k1_context_preallocated_size(flags);

  if (req_size <= BLSIG_ECDSA_BUF_SIZE) {
    return secp256k1_context_preallocated_create(blsig_ecdsa_buf, flags);
  }
  return NULL;
}

/**
 * Destroys a secp256k1 context object
 *
 * @param verify_ctx  secp256k1 context object
 */
BL_STATIC_NO_TEST void destroy_verify_ctx(secp256k1_context* verify_ctx) {
  if (verify_ctx) {
    secp256k1_context_preallocated_destroy(verify_ctx);
  }
}

/**
 * Performs verification of multiple signatures using secp256k1-sha256 algorithm
 *
 * @param verify_ctx   secp256k1 context object, initialized for verification
 * @param sig_pl       pointer to contents of Signature section (its payload)
 * @param sig_pl_size  size of the contents of Signature section in bytes
 * @param pubkey_set   NULL-terminated list of pointers to public key lists
 * @param message      message used to generate signature
 * @param message_len  length of the message in bytes
 * @param progr_arg    argument passed to progress callback function
 * @return             number of verified signatures, or a negative number in
 *                     case of error (one of blsig_error_t constants)
 */
static int32_t blsig_verify_multisig_internal(
    secp256k1_context* verify_ctx, const uint8_t* sig_pl, size_t sig_pl_size,
    const bl_pubkey_t** pubkey_set, const uint8_t* message, size_t message_len,
    bl_cbarg_t progr_arg) {
  // Validate all arguments
  if (verify_ctx && sig_pl && sig_pl_size >= sizeof(signature_rec_t) &&
      0U == (sig_pl_size % sizeof(signature_rec_t)) && pubkey_set && message &&
      message_len) {
    // Convert payload to signature records
    const signature_rec_t* sig_recs = (const signature_rec_t*)sig_pl;
    uint32_t n_sig = sig_pl_size / sizeof(signature_rec_t);

    // Look for duplicating signatures and check record number (paranoid)
    if (check_duplicating_signatures(sig_recs, n_sig) && n_sig <= INT32_MAX) {
      int32_t n_valid = 0;                 // Number of valid signatures
      const bl_pubkey_t* p_pubkey = NULL;  // Pointer to current public key

      // Process all signature records
      bl_report_progress(progr_arg, n_sig, 0U);
      for (uint32_t idx = 0U; idx < n_sig; ++idx) {
        // Search for a public key with a matching fingerprint
        p_pubkey = find_pubkey(pubkey_set, &sig_recs[idx].fingerprint);
        if (p_pubkey) {  // If public key is found, verify the signature
          if (verify_signature(verify_ctx, &sig_recs[idx].signature, message,
                               message_len, p_pubkey)) {
            ++n_valid;
          } else {  // Invalid signature found
            return blsig_err_verification_fail;
          }
        }
        bl_report_progress(progr_arg, n_sig, idx + 1U);
      }
      return n_valid;
    }
    return blsig_err_duplicating_sig;
  }
  return blsig_err_bad_arg;
}

int32_t blsig_verify_multisig(const char* algorithm, const uint8_t* sig_pl,
                              size_t sig_pl_size,
                              const bl_pubkey_t** pubkey_set,
                              const uint8_t* message, size_t message_len,
                              bl_cbarg_t progr_arg) {
  if (pubkey_set) {
    if (bl_streq(algorithm, ALG_SECP256K1_SHA256)) {
      secp256k1_context* verify_ctx = create_verify_ctx();
      if (verify_ctx) {
        int32_t result = blsig_verify_multisig_internal(
            verify_ctx, sig_pl, sig_pl_size, pubkey_set, message, message_len,
            progr_arg);
        destroy_verify_ctx(verify_ctx);
        return result;
      }
      return blsig_err_out_of_memory;
    }
    return blsig_err_algo_not_supported;
  }
  return blsig_err_bad_arg;
}

const char* blsig_error_text(int32_t err_code) {
  static const char* no_error = "none";
  static const char* unknown_err = "unknown error";
  const int32_t error_num = sizeof(error_text) / sizeof(error_text[0]);

  if (err_code < 0) {
    int32_t idx = -err_code;
    if (idx < error_num && error_text[idx]) {
      return error_text[idx];
    }
    return unknown_err;
  }
  return no_error;
}
