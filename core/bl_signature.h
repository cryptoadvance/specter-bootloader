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
#include "bl_util.h"

/// Size of a secp256k1 uncompressed public key
#define BL_PUBKEY_SIZE 65U
/// Prefix of a secp256k1 uncompressed public key
#define BL_PUBKEY_PREFIX 0x04U
/// Prefix for an "end of list" record
#define BL_PUBKEY_EOL_PREFIX 0x00U
/// Terminating record of a public key list
#define BL_PUBKEY_END_OF_LIST ((bl_pubkey_t){.bytes = {BL_PUBKEY_EOL_PREFIX}})
/// Size of the buffer to be used to store ECC context
#define BLSIG_ECDSA_BUF_SIZE 480U

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
  /// Key data
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
 * public keys and a message generated from Payload sections.
 *
 * Public keys are provided in form of a lis of lists (key set). External list
 * is a list of pointers to bl_pubkey_t[] arrays, terminated with NULL pointer.
 * Internal list is a list of of public keys terminated with
 * BL_PUBKEY_END_OF_LIST record. External list is intended to combine several
 * lists of public keys together, for example a list of Vendor and a list of
 * Maintainer keys. Here is an example of the nested public key lists:
 *
 * \code{.c}
 * // Two basic lists of public keys, terminated with "end of list" record
 * const bl_pubkey_t vendor_keys[] = { {...}, {...}, BL_PUBKEY_END_OF_LIST };
 * const bl_pubkey_t maintainer_keys[] = { {...}, BL_PUBKEY_END_OF_LIST };
 *
 * // The following "lists of lists" are provided to blsig_verify_multisig()
 * const bl_pubkey_t* pubkeys_boot[] = { vendor_keys, NULL };
 * const bl_pubkey_t* pubkeys_main[] = { vendor_keys, maintainer_keys, NULL };
 * \endcode
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
 * @param pubkey_set   NULL-terminated list of pointers to public key lists
 * @param message      message used to generate signature
 * @param message_len  length of the message in bytes
 * @param progr_arg    argument passed to progress callback function
 * @return             number of verified signatures, or a negative number in
 *                     case of error (one of blsig_error_t constants)
 */
int32_t blsig_verify_multisig(const char* algorithm, const uint8_t* sig_pl,
                              size_t sig_pl_size,
                              const bl_pubkey_t** pubkey_set,
                              const uint8_t* message, size_t message_len,
                              bl_cbarg_t progr_arg);

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

/**
 * Checks if the result of signature verification is an error
 *
 * @param verification_result  a value returned by blsig_verify_multisig()
 * @return                     true if the result corresponds to an error
 */
static inline bool blsig_is_error(int32_t verification_result) {
  return (verification_result < 0);
}

/**
 * Checks if a pointer to a public key points to "end of list" record
 *
 * @param p_key  pointer to public key
 * @return       true if the pointer points to the "end of list" record
 */
static inline bool bl_pubkey_is_end_record(const bl_pubkey_t* p_key) {
  return p_key && (BL_PUBKEY_EOL_PREFIX == p_key->bytes[0]);
}

/**
 * Validates public key by checking its prefix
 *
 * @param p_key  pointer to public key
 * @return       true if the public key is valid
 */
static inline bool bl_pubkey_is_valid(const bl_pubkey_t* p_key) {
  return p_key && (BL_PUBKEY_PREFIX == p_key->bytes[0]);
}

#endif  // BL_SIGNATURE_H_INCLUDED
