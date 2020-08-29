/**
 * @file       memory_map.ld
 * @brief      Linker script defining memory map and address constants
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

/* Start of RAM, non-remapped address */
_ram_start = 0x20000000;
/* Highest address of the user mode stack */
_estack = 0x20050000;     /* end of RAM */
/* Size of integrity check record, always 32 bytes */
_icr_size = 32;
/* Start-up mailbox size */
_startup_mailbox_size = _icr_size;
/* Size of flash memory sector where the Bootloader is stored */
_bl_sect_size = 128K;
/* Size of Bootloader code, smaller than sector size because only first 112kB of
SRAM1 are remapped */
_bl_code_size = 112K;


MEMORY
{
  /* Dummy start-up code used for debuging Bootloader in RAM */
  FLASH_STARTUP (rx) : ORIGIN = 0x08000000,  LENGTH = 16K
  /* Key storage */
  FLASH_KEY_STOR(r)  : ORIGIN = 0x08004000,  LENGTH = 16K
  /* MicroPython file system */
  FLASH_UPY_FS(r)    : ORIGIN = 0x08008000,  LENGTH = 96K
  /* Main Firmware */
  FLASH_MAIN_FW(rx)  : ORIGIN = 0x08020000,  LENGTH = 1664K
  /* Bootloader copy 1, stored in the flash memory */
  FLASH_BL1 (rx)     : ORIGIN = 0x081C0000,  LENGTH = _bl_sect_size
  /* Bootloader copy 2, stored in the flash memory */
  FLASH_BL2 (rx)     : ORIGIN = 0x081E0000,  LENGTH = _bl_sect_size
  /* SRAM1: code remapped to 0x00000000 */
  RAM_CODE (xrw)     : ORIGIN = 0x00000000,  LENGTH = _bl_code_size
  /* SRAM2: mailbox used to pass parameters to the Bootloader */
  RAM_MAILBOX (rw)   : ORIGIN = 0x2001C000,  LENGTH = _startup_mailbox_size
  /* SRAM3: uninitialized data, heap and stack */
  RAM (rw)           : ORIGIN = 0x20020000,  LENGTH = 128K
}
