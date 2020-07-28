/**
 * @file       bl_section.h
 * @brief      Bootloader sections and operations on them
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef BL_SECTION_H_INCLUDED
/// Avoids multiple inclusion of the same file
#define BL_SECTION_H_INCLUDED

#include "bl_syscalls.h"
#include "sha2.h"

/// Magic word, "SECT" in LE
#define BL_SECT_MAGIC 0x54434553UL
/// Structure revision
#define BL_SECT_STRUCT_REV 1U
/// Maximum allowed size of payload (16 megabytes)
#define BL_PAYLOAD_SIZE_MAX (16U * 1024U * 1024U)
/// Digital signature algorithm string: secp256k1-sha256
#define BL_DSA_SECP256K1_SHA256 "secp256k1-sha256"
/// Maximum allowed value ov version number
#define BL_VERSION_MAX 4199999999U
// Version is not available
#define BL_VERSION_NA 0U
/// Maximum size of version string including null character
#define BL_VERSION_STR_MAX 16U
/// Size of secp256k1 uncompressed public key
#define BL_PUBKEY_SIZE 65U
/// Size of SHA-256 output
#define BL_HASH_SIZE 32U
/// Size of hash sentence of a payload section
#define BL_HASH_SENTENCE_SIZE                                                  \
  (BL_MEMBER_SIZE(bl_section_t, name) + BL_MEMBER_SIZE(bl_section_t, pl_ver) + \
   BL_HASH_SIZE)
/// Return code, indicates failure of signature verification
#define BL_VERIFICATION_FAIL -1

/// Type of unsigned integer attribute
typedef uint64_t bl_uint_t;

/// Attribute identifiers
typedef enum bl_attr_t {
  bl_attr_algorithm = 1,    ///< Digital signature algorithm
  bl_attr_base_addr = 2,    ///< Base address of firmware
  bl_attr_entry_point = 3,  ///< Entry point of firmware
} bl_attr_t;

/// Section header
///
/// This structure has a fixed size of 256 bytes. All 32-bit words are stored in
/// little-endian format. CRC is calculated over first 252 bytes of this
/// structure.
typedef struct BL_ATTRS((packed)) bl_section_t {
  uint32_t magic;          ///< Magic word, BL_SECT_MAGIC (“SECT” in LE)
  uint32_t struct_rev;     ///< Revision of structure format
  char name[16];           ///< Name, zero terminated, unused bytes are 0x00
  uint32_t pl_ver;         ///< Payload version, 0 if not available
  uint32_t pl_size;        ///< Payload size
  uint32_t pl_crc;         ///< Payload CRC
  uint8_t attr_list[216];  ///< Attributes, list of: { key, size [, value] }
  uint32_t struct_crc;     ///< CRC of this structure using LE representation
} bl_section_t;

/// Public key
typedef struct BL_ATTRS((packed)) bl_pubkey_t {
  uint8_t bytes[BL_PUBKEY_SIZE];
} bl_pubkey_t;

/// Hash sentence of a payload section
typedef struct BL_ATTRS((packed)) bl_hash_sentence_t {
  uint8_t bytes[BL_HASH_SENTENCE_SIZE];
} bl_hash_sentence_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Sets callback function which is called to report progress of operations
 *
 * @param cb_progress  pointer to callback function
 * @param user_ctx     user-provided context passed to callback function
 */
void blsect_set_progress_callback(bl_cb_progress_t cb_progress, void* user_ctx);

/**
 * Validates header of the section
 *
 * @param p_hdr  pointer to header
 * @return       true if successful
 */
bool blsect_validate_header(const bl_section_t* p_hdr);

/**
 * Validates payload from memory
 *
 * @param p_hdr      pointer to header, assumed to be valid
 * @param pl_buf     buffer containing payload
 * @param pl_size    size occupied by payload in the given buffer
 * @return           true if paylad is valid
 */
bool blsect_validate_payload(const bl_section_t* p_hdr, const uint8_t* pl_buf,
                             uint32_t pl_size);

/**
 * Validates payload reading it from file
 *
 * This function expects that given file is open and its position indicator
 * points to the beginning of payload. After successful execution, position
 * indicator will be moved to the end of payload. If the function fails,
 * resulting file position is undefined.
 *
 * @param p_hdr      pointer to header, assumed to be valid
 * @param file       file with position set to beginning of the payload
 * @param progr_arg  argument passed to progress callback function
 * @return           true if paylad is valid
 */
bool blsect_validate_payload_from_file(const bl_section_t* p_hdr,
                                       bl_file_t file, bl_cbarg_t progr_arg);

/**
 * Validates payload reading it from flash memory
 *
 * @param p_hdr      pointer to header, assumed to be valid
 * @param addr       starting address of payload in flash memory
 * @param progr_arg  argument passed to progress callback function
 * @return           true if paylad is valid
 */
bool blsect_validate_payload_from_flash(const bl_section_t* p_hdr,
                                        bl_addr_t addr, bl_cbarg_t progr_arg);

/**
 * Checks if the given section is a Payload section (contains firmware)
 *
 * @param p_hdr  pointer to header, assumed to be valid
 * @return       true if the section contains firmware
 */
bool blsect_is_payload(const bl_section_t* p_hdr);

/**
 * Checks if the given section is a Signature section
 *
 * @param p_hdr  pointer to header, assumed to be valid
 * @return       true if the section contains signatures
 */
bool blsect_is_signature(const bl_section_t* p_hdr);

/**
 * Gets attribute from header of "unsigned integer" type
 *
 * @param p_hdr    pointer to header, assumed to be valid
 * @param attr_id  attribute identifier
 * @param p_value  pointer to variable, receiving attribute value
 * @return         true if successful
 */
bool blsect_get_attr_uint(const bl_section_t* p_hdr, bl_attr_t attr_id,
                          bl_uint_t* p_value);

/**
 * Gets attribute from header of "string" type
 *
 * @param p_hdr     pointer to header, assumed to be valid
 * @param attr_id   attribute identifier
 * @param buf       buffer where decoded null-terminated string will be placed
 * @param buf_size  size of provided buffer in bytes
 * @return          true if successful
 */
bool blsect_get_attr_str(const bl_section_t* p_hdr, bl_attr_t attr_id,
                         char* buf, size_t buf_size);

/**
 * Returns version string from version number
 *
 * Provided buffer should have size at least BL_VERSION_STR_MAX bytes to be able
 * to receive any possible version string.
 *
 * @param version   version number, as stored in header
 * @param buf       buffer where version null-terminated string will be placed
 * @param buf_size  size of provided buffer in bytes
 * @return          true if successful
 */
bool blsect_version_to_str(uint32_t version, char* buf, size_t buf_size);

/**
 * Calculates hash sentence reading payload from flash memory
 *
 * This function calculates the hash sentence containing section's name, version
 * and hash digest calculated over payload stored in flash memory.
 *
 * @param p_hdr      pointer to header, assumed to be valid
 * @param pl_addr    address of payload in flash memory
 * @param p_result   pointer to variable receiving produced hash sentence
 * @param progr_arg  argument passed to progress callback function
 * @return           true if successful
 */
bool blsect_hash_sentence_from_flash(const bl_section_t* p_hdr,
                                     bl_addr_t pl_addr,
                                     bl_hash_sentence_t* p_result,
                                     bl_cbarg_t progr_arg);

/**
 * Performs verification of multiple signatures
 *
 * This function checks a number of signatures taking on input an array of
 * public keys and an array of hash sentences for each payload section of
 * the firmware. All hash sentences are concatenated and considered as "mesage",
 * used as input for the digital signature algorithm.
 *
 * Before the signature verification the function checks that there is no
 * duplicating records in the Signature section. If a duplication is detected,
 * the function fails returning BL_VERIFICATION_FAIL (negative number).
 *
 * @param p_sig_hdr   pointer to header of signature section, hast to be valid
 * @param sig_pl      pointer to contents of signature section (its payload)
 * @param pub_keys    buffer containing public keys
 * @param n_keys      number of public keys
 * @param message     message, an array of hash sentences from payload sections
 * @param n_sections  number of payload sections to verify
 * @param progr_arg   argument passed to progress callback function
 * @return            number of verified signatures, or BL_VERIFICATION_FAIL
 */
int32_t blsect_verify_signatures(const bl_section_t* p_sig_hdr,
                                 const uint8_t* sig_pl,
                                 const bl_pubkey_t* pub_keys, size_t n_keys,
                                 const bl_hash_sentence_t* message,
                                 size_t n_sections, bl_cbarg_t progr_arg);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // BL_SECTION_H_INCLUDED
