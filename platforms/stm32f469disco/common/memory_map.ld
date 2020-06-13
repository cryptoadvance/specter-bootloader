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

MEMORY
{
  /* Dummy start-up code used for debuging Bootloader in RAM */
  FLASH_STARTUP (rx) : ORIGIN = 0x08000000,  LENGTH = 16K
  /* Bootloader copy 1, stored in Flash memory */
  FLASH_BL1 (rx)     : ORIGIN = 0x081C0000,  LENGTH = (128K - _icr_size)
  /* Bootloader copy 2, stored in Flash memory */
  FLASH_BL2 (rx)     : ORIGIN = 0x081C0000,  LENGTH = (128K - _icr_size)
  /* Code in RAM, remapped to 0x00000000 */
  RAM_CODE (xrw)     : ORIGIN = 0x00000000,  LENGTH = (128K - _icr_size)
  /* Mailbox used by the Start-up code to pass parameters to the Bootloader */
  RAM_MAILBOX (rw)   : ORIGIN = 0x2001FFE0,  LENGTH = _startup_mailbox_size
  /* Non-remapped RAM region used for uninitialized data, heap and stack */
  RAM (rw)           : ORIGIN = 0x20020000,  LENGTH = 192K
}


