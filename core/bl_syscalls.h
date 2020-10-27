/**
 * @file       bl_syscalls.h
 * @brief      System abstraction layer for Bootloader core
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef BL_SYSCALLS_H_INCLUDED
/// Avoids multiple inclusion of the same file
#define BL_SYSCALLS_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#ifdef BL_NO_FATFS
// User provided configuration header for file system definitions
#include "bl_syscalls_fs.h"
#else
#include "ff.h"
#endif
#include "bootloader.h"

/// Infinite time
#define BL_FOREVER UINT32_MAX
/// Maximum possible value stored in bl_addr_t
#define BL_ADDR_MAX UINTPTR_MAX

/// Type for absolute address in memory
typedef uintptr_t bl_addr_t;

// If FatFs support is disabled, it is expected that user provides a header,
// named "bl_syscalls_fs.h" with definition of the following symbols:
#ifndef BL_NO_FATFS
/// Type for file size, unsigned
typedef FSIZE_t bl_fsize_t;
/// File object
typedef FIL bl_file_obj_t;
/// File handle
typedef FIL* bl_file_t;

#if defined(FF_FS_EXFAT) && FF_FS_EXFAT
/// Type for file offset, signed
typedef int64_t bl_foffset_t;
#else
/// Type for file offset, signed
typedef int32_t bl_foffset_t;
#endif

/// Context of file searching functions
typedef struct bl_ffind_ctx_struct {
  DIR dj;       ///< FatFs directory object
  FILINFO fno;  ///< FatFs file information
} bl_ffind_ctx_t;
#endif  // !BL_NO_FATFS

/// Identifiers of items in flash memory map
typedef enum bl_flash_map_item_t_ {
  bl_flash_firmware_base = 0,      ///< Base address of the Main Firmware
  bl_flash_firmware_size,          ///< Size reserved for the Main Firmware
  bl_flash_bootloader_image_base,  ///< Base address of Bootloader in HEX file
  bl_flash_bootloader_copy1_base,  ///< Base address of Bootloader copy 1
  bl_flash_bootloader_copy2_base,  ///< Base address of Bootloader copy 2
  bl_flash_bootloader_size,        ///< Size reserved for of Bootloader copy
  bl_flash_map_nitems              ///< Number of enum items (not an item)
} bl_flash_map_item_t;

/// Alert type
typedef enum blsys_alert_type_t_ {
  bl_alert_info = 0,  ///< Informative message (default)
  bl_alert_warning,   ///< Warning
  bl_alert_error,     ///< Error
  bl_nalerts          ///< Number of alert items (not an alert)
} blsys_alert_type_t;

/// Alert status
typedef enum bl_alert_status_t_ {
  bl_alert_terminated = 0,  ///< Alert indication is terminated by timer
  bl_alert_dismissed,       ///< Alert is dismissed by user
  bl_alert_nstatuses        ///< Number of alert status items (not a status)
} bl_alert_status_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns a string identifying the platform
 *
 * NOTE: This function does not require prior initialization of the system.
 *
 * @return  a constant string identifying the platform, always valid
 */
const char* blsys_platform_id(void);

/**
 * Initialisation of system and platform resources
 *
 * This function is guaranteed to be called by the Bootloader before any other
 * system calls occur. Typically called once at start-up of Bootloader.
 *
 * @return true  if initialisation is successful
 */
bool blsys_init(void);

/**
 * De-initialisation of system and platform resources
 *
 * It is guaranteed that after calling this function none of system calls will
 * occur. Typically called once before normal termination of Bootloader.
 *
 * This function is not called before non-returning functions, including
 * blsys_alert() with BL_FOREVER argument and blsys_fatal_error(). It is on the
 * responsibility of external code to release resources before the reboot if it
 * is planned in these functions.
 */
void blsys_deinit(void);

/**
 * Requests a number of items from flash memory map
 *
 * For each of requested items, this function takes a pair of arguments:
 * (int item_id, bl_addr_t* p_item). Where item_id is an item identifier which
 * should be one of bl_flash_map_item_t values, and p_item points to a variable
 * filled on return (if item is available).
 *
 * @param items  number of items to get
 * @param ...    pair of arguments (item_id, p_item) for each requested item
 * @return       true if successful
 */
bool blsys_flash_map_get_items(int items, ...);

/**
 * Erases area of flash memory
 *
 * @param addr  starting address of erased area
 * @param size  size of erased area
 * @return      true if successful
 */
bool blsys_flash_erase(bl_addr_t addr, size_t size);

/**
 * Reads a block of data from flash memory
 *
 * @param addr  source address in flash memory
 * @param buf   buffer receiving data
 * @param len   number of bytes to read
 * @return      true if successful
 */
bool blsys_flash_read(bl_addr_t addr, void* buf, size_t len);

/**
 * Writes a block of data to flash memory
 *
 * @param addr  destination address in flash memory
 * @param buf   buffer containing data to write
 * @param len   number of bytes to write
 * @return      true if successful
 */
bool blsys_flash_write(bl_addr_t addr, const void* buf, size_t len);

/**
 * Calculates CRC32 over a block of data from flash memory
 *
 * To increase the speed it is recommended to use direct access to flash memory
 * if it's memory-mapped on the target platform.
 *
 * @param p_crc  pointer to variable containing initial value of CRC, filled
 *               with updated CRC value on return
 * @param addr   source address in flash memory
 * @param len    number of bytes to read
 * @return       true if successful
 */
bool blsys_flash_crc32(uint32_t* p_crc, bl_addr_t addr, size_t len);

/**
 * Enables or disables write protection of flash memory
 *
 * This function does nothing if requested write protection state is unchanged,
 * simply returning true.
 *
 * @param addr    starting address of erased area
 * @param size    size of erased area
 * @param enable  protection state:
 *                  * true - write protection is enabled
 *                  * false - write protection is disabled
 * @return        true if successful
 */
bool blsys_flash_write_protect(bl_addr_t addr, size_t size, bool enable);

/**
 * Enables read protection for the whole chip
 *
 * Typically this function is called when a preprocessor macro, READ_PROTECTION
 * is defined, passing value of this macro as an argument.
 *
 * This function does nothing if requested read protection level is unchanged,
 * simply returning true.
 *
 * @param level  protection level (platform dependent)
 * @return       true if successful
 */
bool blsys_flash_read_protect(int level);

/**
 * Returns current level of the read protection for the whole chip
 *
 * @return  protection level (platform dependent), or -1 if not available
 */
int blsys_flash_get_read_protection_level(void);

/**
 * Returns a number of media devices searched for upgrade files
 *
 * The bootloader uses returned value to scan all available devices sequentially
 * searching for an upgrade file.
 *
 * @return  number of media devices
 */
uint32_t blsys_media_devices(void);

/**
 * Returns name of media device
 *
 * @param device_idx  zero-based index of media device
 * @return            constant null-terminated string, always valid and non-NULL
 */
const char* blsys_media_name(uint32_t device_idx);

/**
 * Checks if external media is available for mounting
 *
 * @param device_idx  zero-based index of media device
 * @return            true if media device is available to mount (e.g. inserted)
 */
bool blsys_media_check(uint32_t device_idx);

/**
 * Mounts an external media device
 *
 * @param device_idx  zero-based index of media device
 * @return            true if successful
 */
bool blsys_media_mount(uint32_t device_idx);

/**
 * Unmounts currently mounted external media device (if any)
 *
 * NOTE: The Bootloader calls this function as a part of exit cleanup, even if
 * no media was mounted ever. This should not have any bad consequences.
 */
void blsys_media_umount(void);

/**
 * Find first file matching given pattern
 *
 * Call blsys_ffind_close() to terminate file searching and release resources.
 *
 * @param ctx      pointer to pre-allocated context structure, contents are
 *                 don't care
 * @param path     the directory name
 * @param pattern  the name matching pattern
 * @return         file name, or NULL if not found
 */
const char* blsys_ffind_first(bl_ffind_ctx_t* ctx, const char* path,
                              const char* pattern);

/**
 * Find next file matching earlier specified pattern
 *
 * @param ctx  context initialized with blsys_ffind_first()
 * @return     file name, or NULL if not found
 */
const char* blsys_ffind_next(bl_ffind_ctx_t* ctx);

/**
 * Terminates file searching releasing resources
 *
 * @param ctx  context initialized with blsys_ffind_first()
 */
void blsys_ffind_close(bl_ffind_ctx_t* ctx);

/**
 * Opens a file
 *
 * @param p_file_obj  pointer to pre-allocated file object, contents are don't
 *                    care
 * @param filename    name of the file to be opened
 * @param mode        string containing POSIX file access mode
 * @return            file handle if successful, NULL if failed
 */
bl_file_t blsys_fopen(bl_file_obj_t* p_file_obj, const char* filename,
                      const char* mode);

/**
 * Read block of data from file
 *
 * @param ptr    pointer to output buffer, size at least (size*count) bytes
 * @param size   size in bytes of each element to be read
 * @param count  number of elements, each one with a size of size bytes
 * @param file   file handle
 * @return       total number of elements successfully read
 */
size_t blsys_fread(void* ptr, size_t size, size_t count, bl_file_t file);

/**
 * Returns the current file read/write pointer
 *
 * @param file  file handle
 * @return      current value of read/write pointer if successful, -1 if failed
 */
bl_foffset_t blsys_ftell(bl_file_t file);

/**
 * Repositions file read/write pointer
 *
 * @param file    file handle
 * @param offset  number of bytes to offset from origin
 * @param origin  position used as reference for the offset, available options:
 *                SEEK_SET, SEEK_CUR, SEEK_END
 * @return        zero if successful
 */
int blsys_fseek(bl_file_t file, bl_foffset_t offset, int origin);

/**
 * Returns the size of the file in bytes
 *
 * @param file  file handle
 * @return      size of the file in bytes
 */
bl_fsize_t blsys_fsize(bl_file_t file);

/**
 * Check end-of-file indicator
 *
 * @param file  file handle
 * @return      a non-zero value if end-of-file is reached
 */
int blsys_feof(bl_file_t file);

/**
 * Closes the file
 *
 * @param file  file handle
 * @return      0 if successful, EOF otherwise
 */
int blsys_fclose(bl_file_t file);

/**
 * Handles fatal error
 *
 * This is a blocking function, not returning control to calling code.
 *
 * @param text  error text
 */
void blsys_fatal_error(const char* text) BL_ATTRS((noreturn));

/**
 * Indicates an alert in device-dependant way
 *
 * Depending on device capabilities it uses display, console, LED or beeper to
 * produce feedback to the user. This function is blocking and returns when
 * indication time passes or when indication is dismissed by user.
 *
 * When argument time_ms is set to BL_FOREVER the function never returns.
 * Typically in this case the indication is continued until reboot or until
 * user confirmation, followed with reboot.
 *
 * @param type     alert type
 * @param caption  alert caption, like "Downgrade Attempt"
 * @param text     alert text, like "Firmware upgrade stopped because..."
 * @param time_ms  indication time in milliseconds or BL_FOREVER
 * @param flags    flags, should be 0, reserved
 * @return         alert termination status
 */
bl_alert_status_t blsys_alert(blsys_alert_type_t type, const char* caption,
                              const char* text, uint32_t time_ms,
                              uint32_t flags);

/**
 * Reports current progress of firmware upgrading
 *
 * @param caption       caption text, like "Upgrading Bootloader to v.1.2.3"
 * @param operation     current operation, like "Verifying signature"
 * @param percent_x100  percent of completeness in 0.01% units
 */
void blsys_progress(const char* caption, const char* operation,
                    uint32_t percent_x100);

/**
 * Starts the firmware from given address in the flash memory
 *
 * @param start_addr  start address of the firmware in flash memory
 * @param argument    argument passed to the executable module
 * @return            false in case of failure, otherwise the function does not
 *                    return
 */
bool blsys_start_firmware(bl_addr_t start_addr, uint32_t argument);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // BL_SYSCALLS_H_INCLUDED
