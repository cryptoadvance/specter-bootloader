/**
 * @file       linker_vars.h
 * @brief      Declaration of linker-defined variables
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 *
 * NOTE: These variables cannot be accessed directly; to obtain assigned value
 * take address of corresponding symbol. It is recommend to use LV_VALUE() and
 * LV_PTR() macros for this purpose.
 */

#ifndef LINKER_VARS_H_INCLUDED
#define LINKER_VARS_H_INCLUDED

#include <stdint.h>

#ifdef __cplusplus
/// Extern qualifier for variables
#define LV_EXTERN extern "C"
#else
/// Extern qualifier for variables
#define LV_EXTERN extern
#endif

/// Returns integer value of a linker variable
#define LV_VALUE(x) ((uintptr_t)&x)
/// Returns void* pointer of a linker variable
#define LV_PTR(x) ((void*)&x)

/// End of stack
LV_EXTERN char _estack;
/// Starting address of Bootloader code in RAM
LV_EXTERN char _ram_code_start;
/// Ending address of Bootloader code in RAM
LV_EXTERN char _ram_code_end;
/// Starting address of Bootloader code in Flash
LV_EXTERN char _flash_code_start;
/// Starting address of Bootloader code in RAM
LV_EXTERN char _ram_code_start;
/// Start of the Main Firmware
LV_EXTERN char _main_firmware_start;
/// Size of the Main Firmware
LV_EXTERN char _main_firmware_size;
/// Size of flash memory sector where the Bootloader is stored
LV_EXTERN char _bl_sect_size;
/// Start of the Bootloader copy 1, stored in the flash memory
LV_EXTERN char _bl_copy1_start;
/// Start of the Bootloader copy 2, stored in the flash memory
LV_EXTERN char _bl_copy2_start;
/// Base address of Bootloader in HEX file
LV_EXTERN char _bl_image_base;
/// Mailbox used to pass parameters to the Bootloader
LV_EXTERN char _startup_mailbox;
/// Start of the Start-up code
LV_EXTERN char _startup_code_start;
/// Size of the Start-up code
LV_EXTERN char _startup_code_size;

#endif  // LINKER_VARS_H_INCLUDED