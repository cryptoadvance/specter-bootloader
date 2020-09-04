/**
 * @file       bl_section.h
 * @brief      Bootloader sections and operations on them
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef BL_SECTION_H_INCLUDED
/// Avoids multiple inclusion of the same file
#define BL_SECTION_H_INCLUDED

#include "bl_util.h"
#include "bl_syscalls.h"
/// Magic word, "SECT" in LE
#define BL_SECT_MAGIC 0x54434553UL
/// Structure revision
#define BL_SECT_STRUCT_REV 1U
/// Maximum allowed size of payload (16 megabytes)
#define BL_PAYLOAD_SIZE_MAX (16U * 1024U * 1024U)
/// Size of SHA-256 output
#define BL_HASH_SIZE 32U
/// Size of hash sentence of a payload section
#define BL_HASH_SENTENCE_SIZE                                                  \
  (BL_MEMBER_SIZE(bl_section_t, name) + BL_MEMBER_SIZE(bl_section_t, pl_ver) + \
   BL_HASH_SIZE)
/// Maximum size of string attribute including null character
#define BL_ATTR_STR_MAX (32U + 1U)

/// Type of unsigned integer attribute
typedef uint64_t bl_uint_t;

/// Attribute identifiers
typedef enum bl_attr_t {
  bl_attr_algorithm = 1,    ///< Digital signature algorithm, string
  bl_attr_base_addr = 2,    ///< Base address of firmware
  bl_attr_entry_point = 3,  ///< Entry point of firmware
  bl_attr_platform = 4      ///< Platform identifier, string
} bl_attr_t;

/**
 * Section header
 *
 * This structure has a fixed size of 256 bytes. All 32-bit words are stored in
 * little-endian format. CRC is calculated over first 252 bytes of this
 * structure.
 * @return typedef struct
 */
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

/// Hash sentence of a payload section
typedef struct BL_ATTRS((packed)) bl_hash_sentence_t {
  /// Raw data
  uint8_t bytes[BL_HASH_SENTENCE_SIZE];
} bl_hash_sentence_t;

#ifdef __cplusplus
extern "C" {
#endif

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
 * @return           true if paylad is valid
 */
bool blsect_validate_payload(const bl_section_t* p_hdr, const uint8_t* pl_buf);

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

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // BL_SECTION_H_INCLUDED
