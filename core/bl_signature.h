/**
 * @file       bl_signature.h
 * @brief      Bootloader signature functions
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef BL_SIGNATURE_H_INCLUDED
/// Avoids multiple inclusion of the same file
#define BL_SIGNATURE_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "bootloader.h"
#include "bl_util.h"

/// Size of secp256k1 uncompressed public key
#define BL_PUBKEY_SIZE 65U

/// Error codes returned by blsig_verify_multisig()
typedef enum blsig_error_t {
  /// One or many argument(s) are invalid
  blsig_err_bad_arg = -1,
  /// Digital signature algorithm is not supported
  blsig_err_algo_not_supported = -2,
  /// Out of memory (cannot allocate ECDSA context)
  blsig_err_out_of_memory = -3,
  /// Duplicating signature found
  blsig_err_duplicating_sig = -4,
  /// Signature verification failure
  blsig_err_verification_fail = -5
} blsig_error_t;

/// Public key
typedef struct BL_ATTRS((packed)) bl_pubkey_t {
  uint8_t bytes[BL_PUBKEY_SIZE];
} bl_pubkey_t;

// The following types are private and defined only in implementation of
// signature module and in unit tests.
#ifdef BLSIG_DEFINE_PRIVATE_TYPES

/// Public key fingerprint
typedef struct BL_ATTRS((packed)) fingerprint_t {
  uint8_t bytes[16];  ///< Fingerprint bytes
} fingerprint_t;

/// Signature: 64-byte compact signature
typedef struct BL_ATTRS((packed)) signature_t {
  uint8_t bytes[64];  ///< Signature bytes
} signature_t;

/// Signature record contained in Signature section
typedef struct BL_ATTRS((packed)) signature_rec_t {
  fingerprint_t fingerprint;  ///< Public key fingerprint
  signature_t signature;      ///< Signature
} signature_rec_t;

#endif  // BLSIG_DEFINE_PRIVATE_TYPES

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Performs verification of multiple signatures
 *
 * This function checks a number of signatures taking on input a list of
 * public keys and a message sonsisted of concatenated hash sentences for each
 * payload section of the firmware.
 *
 * Before the signature verification the function checks that there is no
 * duplicating records in the Signature section. If a duplication is detected,
 * the function fails returning blsig_err_duplicating_sig.
 *
 * In case this function fails for some reason it returns a negative number
 * equal to one of blsig_error_t constants. To convert error code into a text
 * string use blsig_error_text().
 *
 * @param algorithm    string, identifying signature algorithm
 * @param sig_pl       pointer to contents of Signature section (its payload)
 * @param sig_pl_size  size of the contents of Signature section in bytes
 * @param pubkeys      buffer containing list of public keys
 * @param n_keys       number of public keys in the list
 * @param message      message, concatenated hash sentences of Payload sections
 * @param message_len  length of the message in bytes
 * @param progr_arg    argument passed to progress callback function
 * @return             number of verified signatures, or a negative number in
 *                     case of error (one of blsig_error_t constants)
 */
int32_t blsig_verify_multisig(const char* algorithm, const uint8_t* sig_pl,
                              size_t sig_pl_size, const bl_pubkey_t* pubkeys,
                              size_t n_keys, const uint8_t* message,
                              size_t message_len, bl_cbarg_t progr_arg);

/**
 * Returns a text string corresponding to an error code
 *
 * @param err_code  error code returned by blsig_verify_multisig(), a negative
 *                  number
 * @return          constant null-terminated string, always valid and non-NULL
 */
const char* blsig_error_text(int32_t err_code);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // BL_SIGNATURE_H_INCLUDED
