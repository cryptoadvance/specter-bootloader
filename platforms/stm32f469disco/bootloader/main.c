/**
 * @file       main.c
 * @brief      Main source code file for STM32F469I-DISCO platform
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include "bootloader.h"
#include "bl_util.h"
#include "bl_integrity_check.h"
#include "startup_mailbox.h"
#include "linker_vars.h"
#include "bl_memmap.h"

/// Reset modes of the MicroPython firmware
typedef enum upy_reset_mode_t {
  /// Normal reset mode
  upy_reset_mode_normal = 1,
  /// Safe mode, skipping "boot.py" and "main.py"
  upy_reset_mode_safe = 2,
  /// Format all non-removable storage devices on boot
  upy_reset_mode_format = 3,
  /// DFU mode used by Mboot
  upy_reset_mode_dfu = 4
} upy_reset_mode_t;

/// Version in the format parced by upgrade-generator
static const char version_tag[] BL_ATTRS((used)) =
    "<version:tag10>0100000199</version:tag10>";

/// Embedded memory map record
// clang-format off
static const bl_memmap_rec_t memory_map_rec BL_ATTRS((used)) = {
    BL_MEMMAP_REC_PREDEFINED,
    .bootloader_size     = LV_VALUE(_bl_sect_size),
    .main_firmware_start = LV_VALUE(_main_firmware_start),
    .main_firmware_size  = LV_VALUE(_main_firmware_size)};
// clang-format on

/**
 * Handles fatal error
 *
 * This is a blocking function, not returning control to calling code.
 *
 * @param text  error text
 */
//! @cond Doxygen_Suppress
BL_ATTRS((noreturn))
//! @endcond
static void fatal_error(const char* text) {
  blsys_init();
  blsys_fatal_error(text);
}

/**
 * Program entry point
 *
 * @return  exit code (unused)
 */
int main(void) {
  bl_keep_variable(&version_tag);
  bl_keep_variable(&memory_map_rec);

  // Obtain arguments passed by the Start-up code
  bl_args_t args;
  if (!bl_read_args(LV_PTR(_startup_mailbox), &args)) {
    fatal_error("Internal error (bad arguments passed from the Start-up code)");
  }

  // Alow RC (release candidate) versions only if Bootloader is RC itself
  uint32_t bootloader_flags = 0;
  uint32_t bootloader_ver = bl_decode_version_tag(version_tag);
  if (bl_version_is_rc(bootloader_ver)) {
    bootloader_flags |= bl_flag_allow_rc_versions;
  }

  // Run the Bootloader
  bl_status_t status = bootloader_run(&args, bootloader_flags);
  if (bootloader_has_error(status)) {
    fatal_error(bootloader_status_text(status));
  }

  // Check integrity of the Main Firmware
  if (!bl_icr_verify(LV_VALUE(_main_firmware_start),
                     LV_VALUE(_main_firmware_size), NULL)) {
    fatal_error("No valid firmware found");
  }

  // Start the application, normally this call should not return
  (void)blsys_start_firmware(LV_VALUE(_main_firmware_start),
                             upy_reset_mode_normal);

  // Something bad happened with the firmware
  fatal_error("Firmware is corrupted or has wrong format");
  while (1) {  // Should not get there
    __asm volatile(" nop");
  }
}
