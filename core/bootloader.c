/**
 * @file       bootloader.c
 * @brief      Bootloader implementation (main loop)
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

/// Forces inclusion of private types
#define BOOTLOADER_H_DEFINE_PRIVATE_TYPES
#include <string.h>
#include <stdarg.h>
#include "crc32.h"
#include "bootloader.h"
#include "bl_kats.h"
#include "bl_signature.h"
#include "bl_integrity_check.h"

/// Pattern used to search for upgrade files
#define UPGRADE_FILES "specter_upgrade*.bin"
/// Flag file triggering version information display
#define SHOW_VERSION_FILE ".show_version"
/// Maximum length of file name, including terminating null-character
#define UPGRADE_FNAME_MAX (256U + 1U)
/// The directory name where to look for an upgrade file
#define UPGRADE_PATH "/"  // Root directory
/// Name of the section containing the Bootloader firmware
#define NAME_BOOT "boot"
/// Name of the section containing the Main firmware
#define NAME_MAIN "main"
/// Caption text provided to progress reporting function
#define PROGRESS_CAPTION "Firmware Upgrade"
/// Caption text provided used for information messages
#define INFO_CAPTION "Firmware Upgrade"
/// Time in ms, while information message is displayed (2 seconds)
#define INFO_TIME_MS 2000U
/// Time in ms, while version information is displayed (5 seconds)
#define VERSION_DISPLAY_TIME_MS 5000U
#ifdef BL_IO_BUF_SIZE
/// Size of statically allocated shared IO buffer
#define IO_BUF_SIZE BL_IO_BUF_SIZE
#else
/// Size of statically allocated shared IO buffer
#define IO_BUF_SIZE 4096U
#endif
/// Maximum number Payload sections
#define MAX_PL_SECTIONS 2U

/// Flash memory map items
typedef struct flash_map_t {
  bl_addr_t firmware_base;          ///< Base address of [main] Firmware
  bl_addr_t firmware_size;          ///< Size reserved for [main] Firmware
  bl_addr_t bootloader_image_base;  ///< Base address of Bootloader in HEX file
  bl_addr_t bootloader_copy1_base;  ///< Base address of Bootloader copy 1
  bl_addr_t bootloader_copy2_base;  ///< Base address of Bootloader copy 2
  bl_addr_t bootloader_size;        ///< Size reserved for of Bootloader copy
} flash_map_t;

/// Stages of firmware upgrade process
typedef enum upgrading_stage_t {
  stage_read_file = 0,    ///< Reading upgrade file
  stage_verify_file,      ///< Verifying file integrity
  stage_unprotect_flash,  ///< Removing flash memory protection
  stage_erase_flash,      ///< Erasing flash memory
  stage_write_flash,      ///< Writing flash memory
  stage_calc_hash,        ///< Calculating hashes
  stage_verify_sig,       ///< Verifying signatures
  stage_create_icr,       ///< Creating integrity check records
  stage_protect_flash,    ///< Applying flash memory protection
  n_upgrading_stages_     ///< Number of upgrading stages (not a stage)
} upgrading_stage_t;

/// Substages of firmware upgrade process, a set of flags
typedef enum upgrading_substage_t {
  /// None, this stage has no substages
  substage_none = 0,
  /// Base bit of substages (not a substage itself)
  substage_base_bit_ = (1 << 14),
  /// Operation(s) on the Bootloader part
  substage_boot = substage_base_bit_,
  /// Operation(s) on the Main Firmware part
  substage_main = (1 << 15)
} upgrading_substage_t;

/// Information about upgrading stage
typedef struct upgrading_stage_info_t {
  /// Name of the stage
  const char* name;
  /// Input of this stage in total 100% completeness
  uint8_t percent;
} upgrading_stage_info_t;

/// Progress context
typedef struct progress_ctx_t {
  /// Flag indicating that the Bootloader is upgraded
  bool upgrade_boot;
  /// Flag indicating that the Main firmware is upgraded
  bool upgrade_main;
  /// Contribution of Bootloader operations in the stage workload in 0.01%
  uint32_t boot_percent_x100;
} progress_ctx_t;

/// Table with information about each upgrading stage
// clang-format off
static const upgrading_stage_info_t stage_info[n_upgrading_stages_] = {
    [stage_read_file] =
        {.name = "Reading upgrade file", .percent = 2U},
    [stage_verify_file] =
        {.name = "Verifying file integrity", .percent = 21U},
    [stage_unprotect_flash] =
        {.name = "Removing write protection", .percent = 1U},
    [stage_erase_flash] =
        {.name = "Erasing flash memory", .percent = 30U},
    [stage_write_flash] =
        {.name = "Writing flash memory", .percent = 36},
    [stage_calc_hash] =
        {.name = "Verifying signatures", .percent = 5U},
    [stage_verify_sig] =
        {.name = "Verifying signatures", .percent = 2U},
    [stage_create_icr] =
        {.name = "Finishing", .percent = 2U},
    [stage_protect_flash] =
        {.name = "Applying write protection", .percent = 1U}};
// clang-format on

/// Text strings corresponding to Bootloader statuses
static const char* status_text[bl_n_statuses_] = {
    [bl_status_normal_exit] = "Normal exit",
    [bl_status_upgrade_complete] = "Upgrade complete",
    [bl_status_err_arg] = "Argument error",
    [bl_status_err_platform] = "Platform error",
    [bl_status_err_pubkeys] = "Invalid public key set",
    [bl_status_err_internal] = "Internal error"};

/// Text strings corresponding to version check results
static const char* version_check_res_str[n_version_check_res_] = {
    [version_same] = "Same version detected, upgrade skipped",
    [version_newer] = "Version is newer, suitable for upgrade",
    [version_rc_blocked] = "\"Release candidate\" version is not allowed",
    [version_older] = "Older version detected, downgrade is prohibited",
    [version_invalid] = "Upgrade file contains an invalid version",
};

/// Empty public key list
static const bl_pubkey_t empty_pubkey_list[] = {BL_PUBKEY_END_OF_LIST};
// Inert set of public keys and signature thresholds
const bl_pubkey_set_t bl_pubkey_set BL_ATTRS((weak)) = {
    .vendor_pubkeys = empty_pubkey_list,
    .vendor_pubkeys_size = sizeof(empty_pubkey_list),
    .maintainer_pubkeys = empty_pubkey_list,
    .maintainer_pubkeys_size = sizeof(empty_pubkey_list),
    .bootloader_sig_threshold = 0,
    .main_fw_sig_threshold = 0};

/// Statically allocated contex of the Bootloader's main task
static struct {
  /// Memory map of flash memory
  flash_map_t flash_map;
  /// Context of file searching functions
  bl_ffind_ctx_t ffind_ctx;
  /// Name of an upgrade file
  char file_name[UPGRADE_FNAME_MAX];
  /// File object corresponding to an opened upgrade file
  bl_file_obj_t file_obj;
  /// Metadata stored in an upgrade file
  file_metadata_t file_metadata;
  /// Progress context
  progress_ctx_t progress_ctx;
  /// Buffer used by formatted print functions
  char format_buf[256];
  // IO buffer
  uint8_t io_buf[IO_BUF_SIZE];
  /// Hashes of of Payload sections
  bl_hash_t hash_buf[MAX_PL_SECTIONS];
} bl_ctx;

/**
 * Handles fatal error
 *
 * @param format  format string
 * @param ...     variable list of arguments
 */
static void BL_ATTRS((noreturn)) fatal_error(const char* format, ...) {
  va_list args;
  va_start(args, format);
  int out_len =
      vsnprintf(bl_ctx.format_buf, sizeof(bl_ctx.format_buf), format, args);
  va_end(args);
  if (out_len > 0 && out_len < sizeof(bl_ctx.format_buf)) {
    blsys_fatal_error(bl_ctx.format_buf);
  } else {
    blsys_fatal_error("Internal error");
  }

  while (1) {  // Never reached
  }
}

/**
 * Validates a list of public keys
 *
 * @param pubkey_list       list of public keys
 * @param pubkey_list_size  size of the list in bytes
 * @param p_n_keys          pointer to variable receiving number of keys in the
 *                          list (if not NULL)
 * @return                  true if the list is valid
 */
static bool validate_pubkey_list(const bl_pubkey_t* pubkey_list,
                                 size_t pubkey_list_size, size_t* p_n_keys) {
  if (pubkey_list && pubkey_list_size >= sizeof(bl_pubkey_t) &&
      0U == (pubkey_list_size % sizeof(bl_pubkey_t))) {
    // Check for an "end of list" record
    size_t n_elem = pubkey_list_size / sizeof(bl_pubkey_t);
    if (n_elem && bl_pubkey_is_end_record(&pubkey_list[n_elem - 1U])) {
      // Check if all keys have valid prefixes
      for (size_t idx = 0U; idx < n_elem - 1U; ++idx) {
        if (!bl_pubkey_is_valid(&pubkey_list[idx])) {
          return false;
        }
      }
      if (p_n_keys) {
        *p_n_keys = n_elem - 1U;
      }
      return true;
    }
  }
  return false;
}

/**
 * Validates a set of public keys
 *
 * @param p_set  pointer to public key set structure
 * @return       true if key set is valid
 */
static bool validate_pubkey_set(const bl_pubkey_set_t* p_set) {
  if (p_set) {
    size_t vendor_n_keys = 0U;
    size_t maintainer_n_keys = 0U;
    bool ok = validate_pubkey_list(p_set->vendor_pubkeys,
                                   p_set->vendor_pubkeys_size, &vendor_n_keys);
    ok = ok && validate_pubkey_list(p_set->maintainer_pubkeys,
                                    p_set->maintainer_pubkeys_size,
                                    &maintainer_n_keys);
    ok = ok && p_set->bootloader_sig_threshold >= 1 &&
         p_set->bootloader_sig_threshold <= vendor_n_keys;
    ok = ok && p_set->main_fw_sig_threshold >= 1 &&
         p_set->main_fw_sig_threshold <= vendor_n_keys + maintainer_n_keys;
    return ok;
  }
  return false;
}

/**
 * Returns number of payload sections in an upgrade file
 *
 * @param p_md  pointer to upgrade file metadata
 * @return      number of payload sections, 0 if failed
 */
static inline size_t count_payload_sections(const file_metadata_t* p_md) {
  if (p_md) {
    return (p_md->boot_section.loaded ? 1U : 0U) +
           (p_md->main_section.loaded ? 1U : 0U);
  }
  return 0U;
}

/**
 * Checks that code is compiled and liked correctly
 *
 * @return  true if successful
 */
static bool sanity_check(void) {
  int x = 1;
  char is_le_machine = *(char*)&x;

  struct {
    bool flag;
    void* ptr;
  } st = {.flag = true, .ptr = (void*)12345};
  if (!st.flag || !st.ptr) {
    return false;
  }
  memset(&st, 0, sizeof(st));

  return is_le_machine && 0 == NULL && 0 == (int)false && !st.flag && !st.ptr &&
         (n_upgrading_stages_ + 1) < substage_base_bit_;
}

/**
 * Requests full flash memory map from the platform
 *
 * @param p_map  pointer to structure, receiving flash memory map items
 * @return       true if successfull
 */
static inline bool get_flash_memory_map(flash_map_t* p_map) {
  if (p_map) {
    memset(p_map, 0, sizeof(flash_map_t));
    return blsys_flash_map_get_items(
        6, bl_flash_firmware_base, &p_map->firmware_base,
        bl_flash_firmware_size, &p_map->firmware_size,
        bl_flash_bootloader_image_base, &p_map->bootloader_image_base,
        bl_flash_bootloader_copy1_base, &p_map->bootloader_copy1_base,
        bl_flash_bootloader_copy2_base, &p_map->bootloader_copy2_base,
        bl_flash_bootloader_size, &p_map->bootloader_size);
  }
  return false;
}

/**
 * Reads version information from flash memory
 *
 * @param bl_addr  address of currently executed Bootloader
 * @return         version information
 */
static version_info_t get_version_info(bl_addr_t bl_addr) {
  version_info_t info = {.bootloader_ver = BL_VERSION_NA,
                         .main_fw_ver = BL_VERSION_NA};

  (void)bl_icr_get_version(bl_addr, bl_ctx.flash_map.bootloader_size,
                           &info.bootloader_ver);
  (void)bl_icr_get_version(bl_ctx.flash_map.firmware_base,
                           bl_ctx.flash_map.firmware_size, &info.main_fw_ver);
  return info;
}

/**
 * Initializes local context to default values
 *
 * @param p_args  arguments of bootloader_run()
 * @param flags   flags passed to bootloader_run()
 * @return        true if successful
 */
static bool init_context(const bl_args_t* p_args, uint32_t flags) {
  if (p_args) {
    memset(&bl_ctx, 0, sizeof(bl_ctx));
    bool success = get_flash_memory_map(&bl_ctx.flash_map);
    return success;
  }
  return false;
}

/**
 * Initializes progress context
 *
 * @param ctx   pointer to progress context
 * @param p_md  pointer to metadata of an upgrade file
 */
static void init_progress_context(progress_ctx_t* ctx,
                                  const file_metadata_t* p_md) {
  memset(ctx, 0, sizeof(progress_ctx_t));
  ctx->upgrade_boot = p_md->boot_section.loaded;
  ctx->upgrade_main = p_md->main_section.loaded;

  ctx->boot_percent_x100 = 5000U;  // 50% by default
  if (ctx->upgrade_boot && ctx->upgrade_main) {
    uint32_t main_size = p_md->main_section.header.pl_size;
    uint32_t boot_size = p_md->boot_section.header.pl_size;
    if (main_size < UINT32_MAX - boot_size) {
      ctx->boot_percent_x100 =
          bl_percent_x100(main_size + boot_size, boot_size);
    }
  }
}

/**
 * Internal function called from progress reporting callback
 *
 * @param ctx                progress context
 * @param stage              upgrading stage
 * @param substage           upgrading substage
 * @param op_total           total workload of the current operation
 * @param op_complete        completed workload of the current operation
 */
static void on_progress_update_internal(progress_ctx_t* ctx,
                                        upgrading_stage_t stage,
                                        upgrading_substage_t substage,
                                        uint32_t op_total,
                                        uint32_t op_complete) {
  // Accumulate percents of the previous stages
  uint32_t percent_x100 = 0U;
  for (int idx = 0; idx < (int)stage; ++idx) {
    percent_x100 += stage_info[idx].percent;
  }
  percent_x100 *= 100U;  // Convert from 1% to 0.01% units

  // Add percents of the current stage
  uint32_t op_percent_x100 = bl_percent_x100(op_total, op_complete);
  uint32_t stage_percent_x100 = op_percent_x100;
  if (substage_boot == substage) {
    stage_percent_x100 = op_percent_x100 * ctx->boot_percent_x100 / 10000U;
  } else if (substage_main == substage) {
    stage_percent_x100 =
        ctx->boot_percent_x100 +
        op_percent_x100 * (10000U - ctx->boot_percent_x100) / 10000U;
  }
  percent_x100 += stage_percent_x100 * stage_info[stage].percent / 100U;

  // Report current progress
  blsys_progress(PROGRESS_CAPTION, stage_info[stage].name, percent_x100);
}

/**
 * Callback function called to report progress of operations
 *
 * This function is called by other bootloader modules to report progress
 *
 * @param ctx_in          user-provided context
 * @param stage_substage  stage and substage of upgrading process (OR-combibned)
 * @param op_total        total workload of the current operation
 * @param op_complete     completed workload of the current operation
 */
static void on_progress_update(void* ctx_in, bl_cbarg_t stage_substage,
                               uint32_t op_total, uint32_t op_complete) {
  progress_ctx_t* ctx = (progress_ctx_t*)ctx_in;
  upgrading_stage_t stage =
      (upgrading_stage_t)(stage_substage & (substage_base_bit_ - 1));
  upgrading_substage_t substage =
      (upgrading_substage_t)((int)stage_substage & ~(substage_base_bit_ - 1));

  if (stage >= n_upgrading_stages_ || op_complete > op_total) {
    fatal_error("Internal error");
  }

  if (!ctx->upgrade_boot || !ctx->upgrade_main) {
    substage = substage_none;
  }

  on_progress_update_internal(ctx, stage, substage, op_total, op_complete);
}

/**
 * Validates arguments of the Bootloader
 *
 * @param p_args  pointer to argument structure
 * @param flags   flags
 * @return        true if arguments are valid
 */
static bool validate_arguments(const bl_args_t* p_args, uint32_t flags) {
  if (p_args) {
    if ((flags & bl_flag_no_args_crc_check) ||
        p_args->struct_crc ==
            crc32_fast(p_args, offsetof(bl_args_t, struct_crc), 0U)) {
      bl_addr_t bl_copy1 = 0U;
      bl_addr_t bl_copy2 = 0U;
      if (blsys_flash_map_get_items(2, bl_flash_bootloader_copy1_base,
                                    &bl_copy1, bl_flash_bootloader_copy2_base,
                                    &bl_copy2)) {
        if (p_args->loaded_from == bl_copy1 ||
            p_args->loaded_from == bl_copy2) {
          return true;
        }
      }
    }
  }
  return false;
}

/**
 * Returns address of an inactive Bootloader section
 *
 * @param bl_addr  address of currently executed Bootloader
 * @return         address of inactive Bootloader copy
 */
static inline bl_addr_t get_inactive_bl_addr(bl_addr_t bl_addr) {
  return (bl_addr == bl_ctx.flash_map.bootloader_copy1_base)
             ? bl_ctx.flash_map.bootloader_copy2_base
             : bl_ctx.flash_map.bootloader_copy1_base;
}

/**
 * Scans all media devices looking for a specific file
 *
 * @param path     the directory name where to look for an upgrade file
 * @param pattern  the name matching pattern
 * @return         file name, or NULL if not found
 */
static const char* find_file(const char* path, const char* pattern) {
  blsys_media_umount();
  uint32_t n_dev = blsys_media_devices();
  for (uint32_t dev_idx = 0U; dev_idx < n_dev; ++dev_idx) {
    if (blsys_media_check(dev_idx)) {
      if (blsys_media_mount(dev_idx)) {
        const char* fname = blsys_ffind_first(&bl_ctx.ffind_ctx, path, pattern);
        if (fname) {
          if (strlen(fname) + 1U > sizeof(bl_ctx.file_name)) {
            fatal_error("File name is too long");
          }
          strcpy(bl_ctx.file_name, fname);
          if (blsys_ffind_next(&bl_ctx.ffind_ctx)) {
            fatal_error("More than one upgrade file found");
          }
        }
        blsys_ffind_close(&bl_ctx.ffind_ctx);
        if (fname) {
          return bl_ctx.file_name;
        }
        blsys_media_umount();
      } else {
        fatal_error("Unable to mount '%s'", blsys_media_name(dev_idx));
      }
    }
  }
  return NULL;
}

/**
 * Reads the metadata from an upgrade file
 *
 * This function reads section headers of Payload sections and the Signature
 * section entirely with its payload. This operation is expected to be fast
 * enough to not bother with updating the progress indicator.
 *
 * @param p_md  pointer to structure receiving metadata from file
 * @param file  file handle of an upgrade file
 * @return      true if section data is read successfully
 */
BL_STATIC_NO_TEST bool read_metadata(file_metadata_t* p_md, bl_file_t file) {
  if (!p_md) {
    return false;
  }
  bl_fsize_t rm_bytes = blsys_fsize(file);
  sect_metadata_t sect;
  memset(p_md, 0, sizeof(file_metadata_t));

  while (rm_bytes >= sizeof(sect.header)) {
    // Read the header and obtain payload offset in the file
    memset(&sect, 0, sizeof(sect));
    size_t hdr_len = blsys_fread(&sect.header, 1U, sizeof(sect.header), file);
    sect.pl_file_offset = blsys_ftell(file);
    sect.loaded = true;
    // Validate the header and the payload offset
    if (hdr_len != sizeof(sect.header) ||
        !blsect_validate_header(&sect.header) ||
        hdr_len + sect.header.pl_size > rm_bytes ||
        sect.pl_file_offset < hdr_len) {
      return false;
    }
    if (blsect_is_signature(&sect.header)) {  // Handle Signature section
      if (p_md->sig_section.loaded ||
          sect.header.pl_size > MAX_SIGSECTION_SIZE) {
        return false;
      }
      // Read and validate the payload of the Signature section
      size_t pl_len =
          blsys_fread(p_md->sig_payload, 1U, sect.header.pl_size, file);
      if (pl_len != sect.header.pl_size ||
          !blsect_validate_payload(&sect.header, p_md->sig_payload)) {
        return false;
      }
      p_md->sig_section = sect;
    } else {  // Handle Payload sections skipping payload
      if (0 != blsys_fseek(file, sect.header.pl_size, SEEK_CUR)) {
        return false;
      }
      if (bl_streq(NAME_BOOT, sect.header.name) && !p_md->boot_section.loaded) {
        p_md->boot_section = sect;
      } else if (bl_streq(NAME_MAIN, sect.header.name) &&
                 !p_md->main_section.loaded) {
        p_md->main_section = sect;
      } else {
        return false;
      }
    }
    rm_bytes -= hdr_len + sect.header.pl_size;  // Go to the next section
  }
  return (p_md->main_section.loaded || p_md->boot_section.loaded) &&
         p_md->sig_section.loaded && !rm_bytes;
}

/**
 * Checks if given firmware section is compatible with the divice
 *
 * @param p_hdr      pointer to header of the section
 * @param sect_base  base address of the section if the flash memory
 * @param sect_size  size of the section if the flash memory
 * @return           true if section is compatible
 */
static bool check_sect_compatibility(const bl_section_t* p_hdr,
                                     bl_addr_t sect_base, uint32_t sect_size) {
  if (p_hdr) {
    // Get necessary attributes from the header
    char platform[BL_ATTR_STR_MAX] = "";
    bl_uint_t base_addr = 0U;
    if (blsect_get_attr_str(p_hdr, bl_attr_platform, platform,
                            sizeof(platform)) &&
        blsect_get_attr_uint(p_hdr, bl_attr_base_addr, &base_addr)) {
      // Check parameters and attributes
      return bl_streq(platform, blsys_platform_id()) &&
             base_addr == sect_base &&
             bl_icr_check_sect_size(sect_size, p_hdr->pl_size);
    }
  }
  return false;
}

/**
 * Checks if an upgrade file is compatible with the device
 *
 * @param p_md   pointer to upgrade file metadata
 * @param p_map  map of flash memory of the device
 * @return       true if the upgrade file is compatible
 */
static bool check_compatibility(const file_metadata_t* p_md,
                                const flash_map_t* p_map) {
  if (p_md && p_map) {
    if (p_md->boot_section.loaded &&
        !check_sect_compatibility(&p_md->boot_section.header,
                                  p_map->bootloader_image_base,
                                  p_map->bootloader_size)) {
      return false;
    }
    if (p_md->main_section.loaded &&
        !check_sect_compatibility(&p_md->main_section.header,
                                  p_map->firmware_base, p_map->firmware_size)) {
      return false;
    }
    return true;
  }
  return false;
}

/**
 * Checks the new version agains current version
 *
 * @param new_ver    new version of firmware deliverable
 * @param curr_ver   current version of firmware deliverable
 * @param flags      flags passed to bootloader_run()
 * @return           result of version check
 */
static version_check_res_t check_version(uint32_t new_ver, uint32_t curr_ver,
                                         uint32_t flags) {
  if (BL_VERSION_NA == new_ver || new_ver > BL_VERSION_MAX) {
    return version_invalid;
  } else if (0 == (flags & bl_flag_allow_rc_versions) &&
             bl_version_is_rc(new_ver)) {  // No RC allowed
    return version_rc_blocked;
  } else if (new_ver > curr_ver) {
    return version_newer;
  } else if (new_ver == curr_ver) {
    return version_same;
  }
  return version_older;
}

/**
 * Verifies that upgrade file has a higher versions of payloads than programmed
 *
 * This function also filters out the RC versions if they are not explicitly
 * allowed in Bootloader flags (bl_flag_allow_rc_versions).
 *
 * @param p_md   pointer to upgrade file metadata
 * @param curr   structure with current versions
 * @param flags  flags passed to bootloader_run()
 * @return       true if upgrade file has higher versions than programmed
 */
static version_check_res_t check_versions(const file_metadata_t* p_md,
                                          version_info_t curr, uint32_t flags) {
  if (p_md) {
    version_check_res_t check_bl =
        p_md->boot_section.loaded
            ? check_version(p_md->boot_section.header.pl_ver,
                            curr.bootloader_ver, flags)
            : version_same;

    version_check_res_t check_main =
        p_md->main_section.loaded
            ? check_version(p_md->main_section.header.pl_ver, curr.main_fw_ver,
                            flags)
            : version_same;

    // Return check result with the higher rank (severity in case of error)
    return (int)check_main >= (int)check_bl ? check_main : check_bl;
  }
  return version_invalid;
}

/**
 * Returns a text string corresponding to version check result
 *
 * @param res  version check result
 * @return     text, corresponding to a given version check result
 */
static const char* get_version_check_text(version_check_res_t res) {
  static const char* unknown = "unknown";
  if ((int)res >= 0 && (int)res < n_version_check_res_ &&
      version_check_res_str[res]) {
    return version_check_res_str[res];
  }
  return unknown;
}

/**
 * Verifies one payload section of an upgrade file using CRC
 *
 * @param file       file handle of an open upgrade file (already open)
 * @param p_md       pointer to upgrade section metadata
 * @param progr_arg  argument passed to progress callback function
 * @return           true if payload section is valid
 */
static bool verify_payload_section(bl_file_t file, const sect_metadata_t* p_md,
                                   bl_cbarg_t progr_arg) {
  if (p_md && p_md->loaded) {
    if (0 == blsys_fseek(file, p_md->pl_file_offset, SEEK_SET) &&
        blsect_validate_payload_from_file(&p_md->header, file, progr_arg)) {
      return true;
    }
  }
  return false;
}

/**
 * Verifies payload sections of an upgrade file using CRC
 *
 * @param file  file handle of an open upgrade file
 * @param p_md  pointer to upgrade file metadata
 * @return      true if all payload sections are valid
 */
static bool verify_payload_sections(bl_file_t file,
                                    const file_metadata_t* p_md) {
  if (p_md) {
    int n_valid = 0;
    int n_sect = (p_md->boot_section.loaded ? 1 : 0) +
                 (p_md->main_section.loaded ? 1 : 0);

    if (p_md->boot_section.loaded &&
        verify_payload_section(file, &p_md->boot_section,
                               stage_verify_file | substage_boot)) {
      ++n_valid;
    }
    if (p_md->main_section.loaded &&
        verify_payload_section(file, &p_md->main_section,
                               stage_verify_file | substage_main)) {
      ++n_valid;
    }
    return n_valid && (n_valid == n_sect);
  }
  return false;
}

/**
 * Erases sections of the flash memory preparing for an upgrade
 *
 * @param p_md     pointer to upgrade file metadata
 * @param bl_addr  address of currently executed Bootloader
 * @return         true if successful
 */
static bool erase_flash(const file_metadata_t* p_md, bl_addr_t bl_addr) {
  if (p_md) {
    if (p_md->boot_section.loaded) {
      bl_report_progress(stage_erase_flash | substage_boot, 1U, 0U);
      if (!blsys_flash_erase(get_inactive_bl_addr(bl_addr),
                             bl_ctx.flash_map.bootloader_size)) {
        return false;
      }
      bl_report_progress(stage_erase_flash | substage_boot, 1U, 1U);
    }
    if (p_md->main_section.loaded) {
      bl_report_progress(stage_erase_flash | substage_main, 1U, 0U);
      if (!blsys_flash_erase(bl_ctx.flash_map.firmware_base,
                             bl_ctx.flash_map.firmware_size)) {
        return false;
      }
      bl_report_progress(stage_erase_flash | substage_main, 1U, 1U);
    }
    return true;
  }
  return false;
}

/**
 * Enables or disables write protection of flash memory sections
 *
 * @param p_md     pointer to upgrade file metadata
 * @param bl_addr  address of currently executed Bootloader
 * @param enable   required protection state:
 *                   * true - write protection is enabled
 *                   * false - write protection is disabled
 * @return         true if successful
 */
static bool set_write_protection_state(const file_metadata_t* p_md,
                                       bl_addr_t bl_addr, bool enable) {
  if (p_md) {
    upgrading_stage_t stage =
        enable ? stage_protect_flash : stage_unprotect_flash;

    if (p_md->boot_section.loaded) {
      bl_report_progress(stage | substage_boot, 1U, 0U);
      if (!blsys_flash_write_protect(get_inactive_bl_addr(bl_addr),
                                     bl_ctx.flash_map.bootloader_size,
                                     enable)) {
        return false;
      }
      bl_report_progress(stage | substage_boot, 1U, 1U);
    }
    if (p_md->main_section.loaded) {
      bl_report_progress(stage | substage_main, 1U, 0U);
      if (!blsys_flash_write_protect(bl_ctx.flash_map.firmware_base,
                                     bl_ctx.flash_map.firmware_size, enable)) {
        return false;
      }
      bl_report_progress(stage | substage_main, 1U, 1U);
    }
    return true;
  }
  return false;
}

/**
 * Copies one firmware section from an upgrade file to the flash memory
 *
 * @param flash_addr  destination address in flash memory
 * @param file        file handle of an upgrade file
 * @param p_md        pointer to upgrade file metadata
 * @param progr_arg   argument passed to progress callback function
 * @return            true if successful
 */
static bool copy_section(bl_addr_t flash_addr, bl_file_t file,
                         const sect_metadata_t* p_md, bl_cbarg_t progr_arg) {
  if (p_md && p_md->loaded) {
    if (blsys_fseek(file, p_md->pl_file_offset, SEEK_SET) != 0) {
      return false;
    }
    size_t rm_bytes = p_md->header.pl_size;
    bl_addr_t curr_addr = flash_addr;

    bl_report_progress(progr_arg, p_md->header.pl_size, 0U);
    while (rm_bytes) {
      if (blsys_feof(file)) {
        return false;
      }
      size_t copy_len = (rm_bytes < IO_BUF_SIZE) ? rm_bytes : IO_BUF_SIZE;
      size_t got_len = blsys_fread(bl_ctx.io_buf, 1U, copy_len, file);
      if (got_len != copy_len) {
        return false;
      }
      if (!blsys_flash_write(curr_addr, bl_ctx.io_buf, copy_len)) {
        return false;
      }
      curr_addr += copy_len;
      rm_bytes -= copy_len;
      bl_report_progress(progr_arg, p_md->header.pl_size,
                         p_md->header.pl_size - rm_bytes);
    }
    return true;
  }
  return false;
}

/**
 * Copies firmware sections from an upgrade file to the flash memory
 *
 * @param file     file handle of an upgrade file
 * @param p_md     pointer to upgrade file metadata
 * @param bl_addr  address of currently executed Bootloader
 * @return         true if successful
 */
static bool copy_sections(bl_file_t file, const file_metadata_t* p_md,
                          bl_addr_t bl_addr) {
  if (p_md) {
    if (p_md->boot_section.loaded) {
      if (!copy_section(get_inactive_bl_addr(bl_addr), file,
                        &p_md->boot_section,
                        stage_write_flash | substage_boot)) {
        return false;
      }
    }
    if (p_md->main_section.loaded) {
      if (!copy_section(bl_ctx.flash_map.firmware_base, file,
                        &p_md->main_section,
                        stage_write_flash | substage_main)) {
        return false;
      }
    }
    return true;
  }
  return false;
}

/**
 * Calculates hash message reading firmware sections from flash memory
 *
 * @param hash_buf    buffer, where produced hashes will be placed
 * @param p_hash_items  pointer to variable holding capacity of the hash
 *                      buffer, filled with actual number of hashes on return
 * @param p_md          pointer to upgrade file metadata
 * @param bl_addr       address of currently executed Bootloader
 * @return              true is successful
 */
static bool hash_flash_sections(bl_hash_t* hash_buf, size_t* p_hash_items,
                                const file_metadata_t* p_md,
                                bl_addr_t bl_addr) {
  if (hash_buf && p_hash_items && p_md) {
    bl_hash_t* p_item = hash_buf;      // Pointer to current hash item
    size_t avl_items = *p_hash_items;  // Available items in buffer

    if (p_md->boot_section.loaded) {
      if (!avl_items ||
          !blsect_hash_over_flash(&p_md->boot_section.header,
                                  get_inactive_bl_addr(bl_addr), p_item++,
                                  stage_calc_hash | substage_boot)) {
        return false;
      }
      --avl_items;
    }
    if (p_md->main_section.loaded) {
      if (!avl_items ||
          !blsect_hash_over_flash(&p_md->main_section.header,
                                  bl_ctx.flash_map.firmware_base, p_item++,
                                  stage_calc_hash | substage_main)) {
        return false;
      }
    }
    // Update number of items in hash buffer
    *p_hash_items = p_item - hash_buf;
    return true;
  }
  return false;
}

/**
 * Performs verification of multiple signatures
 *
 * On return, a variable pointed by p_result (if not NULL) will receive
 * verification result, having the same format as for blsig_verify_multisig().
 * In case of verification error the result is a negative number negative and
 * the function returns false. Otherwise result means the number of verified
 * signatures, that could be lower than needed threshold (in such case the
 * function still returns false).
 *
 * This function returns true ONLY when all the following conditions are met:
 * (a) there are no duplicating signatures,
 * (b) all signatures for which we have keys are valid,
 * (c) number of valid signatures is equal or greater than the multisig
 * threshold.
 *
 * Multisig thresholds are configured independently for upgrade files containing
 * the Bootloader and for upgrade files having just the Main Firmware.
 *
 * @param p_md        pointer to upgrade file metadata
 * @param p_keyset    set of public keys and multisig thresholds
 * @param hash_buf    buffer with hash structures of payload sections
 * @param hash_items  number of hash structures in buffer
 * @param p_result    pointer to variable receiving verification result
 * @return            true if the message passes multisig verification
 */
static bool verify_multisig(const file_metadata_t* p_md,
                            const bl_pubkey_set_t* p_keyset,
                            const bl_hash_t* hash_buf, size_t hash_items,
                            int32_t* p_result) {
  if (p_result) {
    *p_result = blsig_err_verification_fail;
  }
  if (p_md && p_md->sig_section.loaded && p_keyset && hash_buf &&
      count_payload_sections(p_md) == hash_items && p_result) {
    // Get algorithm identifier from the attributes of the Signature section
    char algorithm[BL_ATTR_STR_MAX] = "";
    if (blsect_get_attr_str(&p_md->sig_section.header, bl_attr_algorithm,
                            algorithm, sizeof(algorithm))) {
      // Prepare public keys
      const bl_pubkey_t* pubkeys_boot[] = {p_keyset->vendor_pubkeys, NULL};
      const bl_pubkey_t* pubkeys_main[] = {p_keyset->vendor_pubkeys,
                                           p_keyset->maintainer_pubkeys, NULL};
      // Make a Bech32 message for signature verification
      uint8_t msg[BL_SIG_MSG_MAX];
      size_t msg_size = sizeof(msg);
      if (blsect_make_signature_message(msg, &msg_size, hash_buf, hash_items)) {
        // Perform signature verification
        *p_result = blsig_verify_multisig(
            algorithm, p_md->sig_payload, p_md->sig_section.header.pl_size,
            p_md->boot_section.loaded ? pubkeys_boot : pubkeys_main, msg,
            msg_size, stage_verify_sig);

        if (*p_result >= 0) {  // Verification is successful
          // Compare number of valid signatures with the thresholds
          return p_md->boot_section.loaded
                     ? *p_result >= p_keyset->bootloader_sig_threshold
                     : *p_result >= p_keyset->main_fw_sig_threshold;
        }
      }
    }
  }
  return false;
}

/**
 * Creates integrity check records in flash memory
 *
 * @param p_md     pointer to upgrade file metadata
 * @param bl_addr  address of currently executed Bootloader
 * @param p_map    map of flash memory of the device
 * @return         true if successful
 */
static bool create_icrs(const file_metadata_t* p_md, bl_addr_t bl_addr,
                        const flash_map_t* p_map) {
  if (p_md) {
    if (p_md->boot_section.loaded) {
      bl_report_progress(stage_create_icr | substage_boot, 1U, 0U);
      if (!bl_icr_create(get_inactive_bl_addr(bl_addr), p_map->bootloader_size,
                         p_md->boot_section.header.pl_size,
                         p_md->boot_section.header.pl_ver)) {
        return false;
      }
      bl_report_progress(stage_create_icr | substage_boot, 1U, 1U);
    }
    if (p_md->main_section.loaded) {
      bl_report_progress(stage_create_icr | substage_main, 1U, 0U);
      if (!bl_icr_create(p_map->firmware_base, p_map->firmware_size,
                         p_md->main_section.header.pl_size,
                         p_md->main_section.header.pl_ver)) {
        return false;
      }
      bl_report_progress(stage_create_icr | substage_main, 1U, 1U);
    }
    return true;
  }
  return false;
}

/**
 * Makes a report regarding a single section of an upgrade file
 *
 * @param dst_buf    destination buffer where report string is placed
 * @param dst_size   size of the destination buffer in bytes
 * @param sect_name  name of upgrade section
 * @param p_sect     pointer to section metadata
 * @param prev_ver   previous version
 * @return           number of characters written to output buffer not including
 *                   terminating null-character, or a negative number in case of
 *                   error
 */
static int make_section_report(char* dst_buf, size_t dst_size,
                               const char* sect_name,
                               const sect_metadata_t* p_sect,
                               uint32_t prev_ver) {
  if (dst_buf && dst_size > 5U && sect_name && p_sect) {
    if (!p_sect->loaded) {
      return 0;
    }
    char vcurr_str[BL_VERSION_STR_MAX];
    char vprev_str[BL_VERSION_STR_MAX];
    if (bl_version_to_str(prev_ver, vprev_str, sizeof(vprev_str)) &&
        bl_version_to_str(p_sect->header.pl_ver, vcurr_str,
                          sizeof(vcurr_str))) {
      return snprintf(dst_buf, dst_size, "%s: %s->%s\n", sect_name,
                      (BL_VERSION_NA == prev_ver) ? "none" : vprev_str,
                      vcurr_str);
    }
  }
  return -1;
}

/**
 * Makes a report regarding successful upgrade
 *
 * @param dst_buf    destination buffer where report string is placed
 * @param dst_size   size of the destination buffer in bytes
 * @param file_name  name of an upgrade file used
 * @param p_md       pointer to upgrade file metadata
 * @param prev_ver   structure with previous versions
 * @return           true if successful
 */
static bool make_upgrade_report(char* dst_buf, size_t dst_size,
                                const char* file_name,
                                const file_metadata_t* p_md,
                                version_info_t prev_ver) {
  if (dst_buf && dst_size > 5U && file_name && p_md) {
    char* p_dst = dst_buf;
    size_t rm_size = dst_size;

    // Report file used
    int res = snprintf(p_dst, rm_size, "File: %s\n", file_name);
    if (res < 0) {
      return false;
    }
    p_dst += res;
    rm_size -= res;

    // Report Bootloader status
    res = make_section_report(p_dst, rm_size, "Bootloader", &p_md->boot_section,
                              prev_ver.bootloader_ver);
    if (res < 0) {
      return false;
    }
    p_dst += res;
    rm_size -= res;

    // Report Main Firmware status
    res = make_section_report(p_dst, rm_size, "Firmware", &p_md->main_section,
                              prev_ver.main_fw_ver);
    if (res < 0) {
      return false;
    }

    // Report state of write protection
    static const char* wrp_string =
#ifdef WRITE_PROTECTION
        "\n\nWrite protection: enabled";
#else
        "\n\nWrite protection: disabled";
#endif
    bool ok = bl_format_append(p_dst, rm_size, wrp_string);

    // Report of read protection
    ok = ok && bl_format_append(p_dst, rm_size, "\nRead protection:  ");
    int rdp_level = blsys_flash_get_read_protection_level();
    if (0 == rdp_level) {
      ok = ok && bl_format_append(p_dst, rm_size, "disabled");
    } else if (rdp_level > 0) {
      ok = ok && bl_format_append(p_dst, rm_size, "Level %i", rdp_level);
    } else {
      ok = ok && bl_format_append(p_dst, rm_size, "unavailable");
    }
    return ok;
  }
  return false;
}

/**
 * Internal function performing firmware upgrade process using an open file
 *
 * @param file    file handle of an open upgrade file
 * @param p_args  arguments of bootloader_run()
 * @param flags   flags passed to bootloader_run()
 * @return        true if upgrade is complete, false if upgrade ignored
 */
static bool do_upgrade_with_file(bl_file_t file, const bl_args_t* p_args,
                                 uint32_t flags) {
  // Report beginning of firmware upgrade process directly (via a system call)
  blsys_progress(PROGRESS_CAPTION, stage_info[stage_read_file].name, 0U);

  // Read metadata: section headers and signatures
  if (!read_metadata(&bl_ctx.file_metadata, file)) {
    fatal_error("Incorrect format of an upgrade file");
  }

  // Check if the upgrade file is compatible with the device
  if (!check_compatibility(&bl_ctx.file_metadata, &bl_ctx.flash_map)) {
    fatal_error("Upgrade file is incompatible with the device");
  }

  // Initialize progress reporting from external modules
  init_progress_context(&bl_ctx.progress_ctx, &bl_ctx.file_metadata);
  bl_set_progress_callback(on_progress_update, &bl_ctx.progress_ctx);

  // Check versions of payload
  version_info_t orig_ver = get_version_info(p_args->loaded_from);
  version_check_res_t version_check =
      check_versions(&bl_ctx.file_metadata, orig_ver, flags);
  if (version_same == version_check) {
    // Same version: normally display notice and exit. But if the Main Firmware
    // is corrupted continue with upgrade (if it has needed payload).
    if (!bl_ctx.file_metadata.main_section.loaded ||
        bl_icr_verify(bl_ctx.flash_map.firmware_base,
                      bl_ctx.flash_map.firmware_size, NULL)) {
      (void)blsys_alert(bl_alert_info, "Version Check",
                        get_version_check_text(version_check), INFO_TIME_MS,
                        0U);
      return false;
    }
  } else if (version_check != version_newer) {
    (void)blsys_alert(bl_alert_error, "Version Check Failed",
                      get_version_check_text(version_check), BL_FOREVER, 0U);
    return false;
  }

  // Check integrity of payload sections in the upgrade file
  if (!verify_payload_sections(file, &bl_ctx.file_metadata)) {
    fatal_error("Upgrade file is corrupted");
  }

  // Remove write protection from needed sections of the flash memory
  if (!set_write_protection_state(&bl_ctx.file_metadata, p_args->loaded_from,
                                  false)) {
    fatal_error("Error while removing write protection");
  }

  // Erase needed sections in the flash memory before copying
  if (!erase_flash(&bl_ctx.file_metadata, p_args->loaded_from)) {
    fatal_error("Error while erasing the flash memory");
  }

  // Copy firmware to the flash memory
  if (!copy_sections(file, &bl_ctx.file_metadata, p_args->loaded_from)) {
    fatal_error("Error copying firmware to the flash memory");
  }

  // Calculate signature message by hashing all Payload sections in flash memory
  size_t hash_items = sizeof(bl_ctx.hash_buf) / sizeof(bl_ctx.hash_buf[0]);
  if (!hash_flash_sections(bl_ctx.hash_buf, &hash_items, &bl_ctx.file_metadata,
                           p_args->loaded_from)) {
    fatal_error("Error calculating hash of the firmware");
  }

  // Verify multiple signatures
  int32_t verify_res = 0;
  if (!verify_multisig(&bl_ctx.file_metadata, &bl_pubkey_set, bl_ctx.hash_buf,
                       hash_items, &verify_res)) {
    const char* err_text = blsig_is_error(verify_res)
                               ? blsig_error_text(verify_res)
                               : "Not enough signatures";
    (void)blsys_alert(bl_alert_error, "Signature Error", err_text, BL_FOREVER,
                      0U);
    return false;
  }

  // Create integrity check records in flash memory
  if (!create_icrs(&bl_ctx.file_metadata, p_args->loaded_from,
                   &bl_ctx.flash_map)) {
    fatal_error("Error creating integrity check records");
  }

#ifdef WRITE_PROTECTION
  // Restore write protection for updated sections of the flash memory
  if (!set_write_protection_state(&bl_ctx.file_metadata, p_args->loaded_from,
                                  true)) {
    fatal_error("Error while applying write protection");
  }
#endif  // WRITE_PROTECTION

  // Notify the user that upgrade is complete
  if (!make_upgrade_report(bl_ctx.format_buf, sizeof(bl_ctx.format_buf),
                           bl_ctx.file_name, &bl_ctx.file_metadata, orig_ver)) {
    fatal_error("Error preparing upgrade report");
  }
  (void)blsys_alert(bl_alert_info, "Upgrade Complete", bl_ctx.format_buf,
                    BL_FOREVER, 0U);

  return true;
}

/**
 * Performs firmware upgrade process
 *
 * @param file_name  file name (optionally with path) of an upgrade file
 * @param p_args     arguments of bootloader_run()
 * @param flags      flags passed to bootloader_run()
 * @return           true if upgrade is complete, false if upgrade ignored
 */
static bool do_upgrade(const char* file_name, const bl_args_t* p_args,
                       uint32_t flags) {
  // Open upgrade file
  bl_file_t file = blsys_fopen(&bl_ctx.file_obj, file_name, "rb");
  if (!file) {
    fatal_error("Cannot open '%s' for reading", file_name);
  }

  // Call internal function processin an open upgrade file
  bool result = do_upgrade_with_file(file, p_args, flags);

  blsys_fclose(file);
  return result;
}

/**
 * Makes a report regarding versions of firmware components
 *
 * Version numbers are provided in versions[] array stored at indexes defined
 * in version_id_t.
 *
 * @param dst_buf      destination buffer where report string is placed
 * @param dst_size     size of the destination buffer in bytes
 * @param versions     array with versions of firmware components
 * @param n_versions   number of elements in versions[] array
 * @param active_bl    version identifier corresponding to an active bootloader
 * @return             true if successful
 */
static bool make_version_report(char* dst_buf, size_t dst_size,
                                const uint32_t* versions, size_t n_versions,
                                int active_bl) {
  static const char ver_none[] = "none";
  if (dst_buf && dst_size && n_versions <= n_version_id_ &&
      (version_id_bootloader1 == active_bl ||
       version_id_bootloader2 == active_bl) &&
      BL_VERSION_STR_MAX >= sizeof(ver_none)) {
    // Convert version numbers to strings
    static const char marker[] = "*";
    char ver_str[n_version_id_][BL_VERSION_STR_MAX + sizeof(marker) + 1U];
    for (int idx = 0; idx < n_version_id_; ++idx) {
      if (idx < n_versions) {
        if (BL_VERSION_NA == versions[idx]) {  // If version is invalid
          strcpy(ver_str[idx], ver_none);
        } else {
          if (!bl_version_to_str(versions[idx], ver_str[idx],
                                 BL_VERSION_STR_MAX)) {
            return false;
          }
        }
        if (idx == active_bl) {  // Mark active bootloader with asterisk
          size_t max_chars = sizeof(ver_str[0]) - BL_VERSION_STR_MAX - 1U;
          strncat(ver_str[idx], marker, max_chars);
        }
      } else {  // If version number is not provided, make an empty string
        ver_str[idx][0] = '\0';
      }
    }

    // Generate text
    // clang-format off
    int text_len = snprintf(
      dst_buf, dst_size,
      "Start-up    : %s\n"   \
      "Bootloader 1: %s\n"   \
      "Bootloader 2: %s\n"   \
      "Firmware    : %s\n\n" \
      "* - active bootloader",
      ver_str[version_id_startup],
      ver_str[version_id_bootloader1],
      ver_str[version_id_bootloader2],
      ver_str[version_id_main]
    );
    // clang-format on

    return text_len > 0;
  }
  return false;
}

/**
 * Shows version information alert
 *
 * @param p_args  arguments of bootloader_run()
 * @param flags   flags passed to bootloader_run()
 */
static void show_version(const bl_args_t* p_args, uint32_t flags) {
  if (!p_args) {
    fatal_error("Internal error");
  }

  // Get versions of firmware components
  uint32_t versions[] = {[version_id_startup] = p_args->startup_version,
                         [version_id_bootloader1] = BL_VERSION_NA,
                         [version_id_bootloader2] = BL_VERSION_NA,
                         [version_id_main] = BL_VERSION_NA};
  const flash_map_t* p_map = &bl_ctx.flash_map;
  (void)bl_icr_get_version(p_map->bootloader_copy1_base, p_map->bootloader_size,
                           &versions[version_id_bootloader1]);
  (void)bl_icr_get_version(p_map->bootloader_copy2_base, p_map->bootloader_size,
                           &versions[version_id_bootloader2]);
  (void)bl_icr_get_version(p_map->firmware_base, p_map->firmware_size,
                           &versions[version_id_main]);

  // Make version report
  if (!make_version_report(bl_ctx.format_buf, sizeof(bl_ctx.format_buf),
                           versions, sizeof(versions) / sizeof(versions[0]),
                           (p_args->loaded_from == p_map->bootloader_copy1_base)
                               ? version_id_bootloader1
                               : version_id_bootloader2)) {
    fatal_error("Error preparing version report");
  }

  // Display message with version information
  (void)blsys_alert(bl_alert_info, "Version Information", bl_ctx.format_buf,
                    VERSION_DISPLAY_TIME_MS, 0U);
}

/**
 * Runs the Bootloader assuming that the platform is already initialized
 *
 * @param p_args  pointer to argument structure
 * @param flags   flags, a combination of bits defined in bl_flags_t
 * @return        exit status
 */
static bl_status_t bootloader_run_initialized(const bl_args_t* p_args,
                                              uint32_t flags) {
  if (!validate_arguments(p_args, flags)) {
    return bl_status_err_arg;
  }
  if (!sanity_check() || !init_context(p_args, flags)) {
    return bl_status_err_internal;
  }
  if (!validate_pubkey_set(&bl_pubkey_set)) {
    return bl_status_err_pubkeys;
  }

#ifdef READ_PROTECTION
  int rdp_level = (int)(READ_PROTECTION);
  if (!blsys_flash_read_protect(rdp_level)) {
    fatal_error("Cannot set read protection to 'Level %i'", rdp_level);
  }
#endif

  bl_status_t status = bl_status_normal_exit;
  const char* file_name = find_file(UPGRADE_PATH, UPGRADE_FILES);
  if (file_name) {
    if (bl_run_kats()) {
      if (do_upgrade(file_name, p_args, flags)) {
        status = bl_status_upgrade_complete;
      }
    } else {
      status = bl_status_err_internal;
    }
  }

  if (bl_status_normal_exit == status &&
      find_file(UPGRADE_PATH, SHOW_VERSION_FILE)) {
    show_version(p_args, flags);
  }

  return status;
}

bl_status_t bootloader_run(const bl_args_t* p_args, uint32_t flags) {
  if (blsys_init()) {
    bl_status_t status = bootloader_run_initialized(p_args, flags);
    blsys_media_umount();
    blsys_deinit();
    return status;
  }
  return bl_status_err_platform;
}

const char* bootloader_status_text(bl_status_t status) {
  static const char* unknown = "unknown";
  int idx = (int)status;
  if (idx >= 0 && idx < bl_n_statuses_ && status_text[idx]) {
    return status_text[idx];
  }
  return unknown;
}
