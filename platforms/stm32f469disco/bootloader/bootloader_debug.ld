/**
 * @file       bootloader_debug.ld
 * @brief      Linker script for debugging of the Bootloader in the RAM
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

/* Redefine entry point to dummy start-up code */
ENTRY(debug_startup)

/* Additional sections containing dummy start-up code */
SECTIONS
{
  /* ISR vectors of the Start-up code */
  .startup.isr_vector :
  {
    . = ALIGN(4);
    KEEP(*(.startup.isr_vector))
    . = ALIGN(4);
  } >FLASH_STARTUP

  /* Start-up code */
  .startup.text :
  {
    . = ALIGN(4);
    *(.startup.text)
  } >FLASH_STARTUP

  /* Start-up constants */
  .startup.const :
  {
    . = ALIGN(4);
    *(.startup.const)
  } >FLASH_STARTUP
}
