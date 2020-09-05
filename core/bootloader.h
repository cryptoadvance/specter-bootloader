/**
 * @file       bootloader.h
 * @brief      Main include file for Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef BOOTLOADER_H_INCLUDED
/// Avoids multiple inclusion of the same file
#define BOOTLOADER_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "bl_util.h"
#include "bl_signature.h"
#include "bl_syscalls.h"

/// Bootloader arguments stored in the Start-up Mailbox
typedef struct BL_ATTRS((packed)) bl_args_t {
  uint32_t loaded_from;      ///< Address in Flash of active bootloader
  uint32_t startup_version;  ///< Version of the Start-up code
  uint32_t rsv[5];           ///< Reserved arguments, set to 0
  uint32_t struct_crc;       ///< CRC of this structure using LE representation
} bl_args_t;

/// Bootloader flags
typedef enum bl_flags_t_ {
  /// Disables check of arguments CRC (argument structure is considered valid)
  bl_flag_no_args_crc_check = (1 << 0),
  /// Allows upgrading to release candidates (probably unstable) versions
  bl_flag_allow_rc_versions = (1 << 1)
} bl_flags_t;

/// Bootloader exit status
typedef enum bl_status_t_ {
  /// Normal exit, nothing to do for Bootloader
  bl_status_normal_exit = 0,
  /// Firmware upgraded successfully
  bl_status_upgrade_complete,
  /// Base value for errors, for internal use (not a status)
  bl_status_err_base_,
  /// One or several arguments are incorrect
  bl_status_err_arg = bl_status_err_base_,
  // Platform error
  bl_status_err_platform,
  /// Invalid public key set
  bl_status_err_pubkeys,
  /// Internal error of bootloader
  bl_status_err_internal,
  /// Number of exit status items, for internal use (not a status)
  bl_n_statuses_
} bl_status_t;

/// Set of public keys and signature thresholds
typedef struct bl_pubkey_set_t {
  /// Pointer to a list of Vendor public keys
  const bl_pubkey_t* vendor_pubkeys;
  /// Size check value for a list of Vendor public keys
  size_t vendor_pubkeys_size;
  /// Pointer to a list of Maintainer public keys
  const bl_pubkey_t* maintainer_pubkeys;
  /// Size check value for a list of Maintainer public keys
  size_t maintainer_pubkeys_size;
  /// Signature threshold for an upgrade file containing the Bootloader
  int bootloader_sig_threshold;
  /// Signature threshold for an upgrade file containing the Main Firmware only
  int main_fw_sig_threshold;
} bl_pubkey_set_t;

#ifdef __cplusplus
/// Set of public keys and signature thresholds
extern "C" const bl_pubkey_set_t bl_pubkey_set;
#else
/// Set of public keys and signature thresholds
extern const bl_pubkey_set_t bl_pubkey_set;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Runs the Bootloader
 *
 * @param p_args  pointer to argument structure
 * @param flags   flags, a combination of bits defined in bl_flags_t
 * @return        exit status
 */
bl_status_t bootloader_run(const bl_args_t* p_args, uint32_t flags);

/**
 * Returns a text string corresponding to Bootloader's status
 *
 * @param status  status of Bootloader
 * @return        constant null-terminated string, always valid and non-NULL
 */
const char* bootloader_status_text(bl_status_t status);

#ifdef __cplusplus
}  // extern "C"
#endif

/**
 * Checks if Bootloader's status reflects an error
 *
 * @param status  exit status of the Bootloader
 * @return        true if there is an error
 */
static inline bool bootloader_has_error(bl_status_t status) {
  return (int)status >= (int)bl_status_err_base_;
}

// The following types are private and defined only in implementation of
// signature module and in unit tests.
#ifdef BOOTLOADER_H_DEFINE_PRIVATE_TYPES

#include "bl_section.h"
#include "bl_syscalls.h"

/// Maximum size of signature section containing payload records
#define MAX_SIGSECTION_SIZE (32U * 80U)

/// Metadata of a single section
typedef struct sect_metadata_t {
  /// Header
  bl_section_t header;
  /// Offset of payload within upgrade file
  bl_foffset_t pl_file_offset;
  /// Flag indicating that the section is loaded
  bool loaded;
} sect_metadata_t;

/// Metadata stored in an upgrade file
typedef struct file_metadata_t {
  /// Payload section with the Main firmware
  sect_metadata_t main_section;
  /// Payload section with the Bootloader
  sect_metadata_t boot_section;
  /// Signature section
  sect_metadata_t sig_section;
  /// Payload of the Signature section
  uint8_t sig_payload[MAX_SIGSECTION_SIZE];
} file_metadata_t;

/// Version information
typedef struct version_info_t {
  /// Current Bootloader version
  uint32_t bootloader_ver;
  /// Current version of the Main firmware
  uint32_t main_fw_ver;
} version_info_t;

/// Result of version check ordered by rank, ORDER IS IMPORTANT!
typedef enum version_check_res_t {
  /// Upgrade file contains the same version(s) as programmed in flash memory
  version_same = 0,
  /// Upgrade file contains newer version(s), suitable for upgrade
  version_newer,
  /// Upgrade file contains at least one RC version and they are not allowed
  version_rc_blocked,
  /// Upgrade file contains at least one older version
  version_older,
  /// Upgrade file contains invalid versions or bad argument(s) are provided
  version_invalid,
  /// Number of enumerated values in version_check_res_t (not a check result)
  n_version_check_res_
} version_check_res_t;

/// Version identifiers
typedef enum version_id_t {
  version_id_startup = 0, ///< Version of the Start-up code
  version_id_bootloader1, ///< Version of Bootloader's 1-st copy
  version_id_bootloader2, ///< Version of Bootloader's 2-st copy
  version_id_main,        ///< Version of the Main Firmware
  n_version_id_           ///< Number of version identifiers (not an identifier)
} version_id_t;

#endif  // BOOTLOADER_H_DEFINE_PRIVATE_TYPES

#endif  // BOOTLOADER_H_INCLUDED
