/**
 * @file       bootloader.ld
 * @brief      Linker script for building Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

/* Default entry point (redefined in debug build) */
ENTRY(Reset_Handler)

/* Generate a link error if heap and stack don't fit into RAM */
_min_heap_size  = 4K;  /* required amount of heap  */
_min_stack_size = 32K;  /* required amount of stack */

/* Start of code in RAM, non-remapped address */
_ram_code_start   = _ram_start;
/* End of code in RAM */
_ram_code_end     = _ram_code_start + LENGTH(RAM_CODE);
/* Start of code in Flash, the Bootloader is always linked as copy 1 */
_flash_code_start = ORIGIN(FLASH_BL1);
/* Start of the Main Firmware */
_main_firmware_start = ORIGIN(FLASH_MAIN_FW);
/* Size of the Main Firmware */
_main_firmware_size = LENGTH(FLASH_MAIN_FW);
/* Start of the Bootloader copy 1, stored in Flash memory */
_bl_copy1_start = ORIGIN(FLASH_BL1);
/* Start of the Bootloader copy 2, stored in Flash memory */
_bl_copy2_start = ORIGIN(FLASH_BL2);
/* Base address of Bootloader in HEX file */
_bl_image_base = _bl_copy1_start;

SECTIONS
{
  /* Mailbox used by the Start-up code to pass parameters to the Bootloader */
  .startup_mailbox :
  {
    . = ALIGN(4);
    *(.startup_mailbox)
  } >RAM_MAILBOX

  /* Main startup code in RAM */
  .isr_vector :
  {
    . = ALIGN(4);
    _bootloader_start = .;
    KEEP(*(.isr_vector)) /* Startup code */
    . = ALIGN(4);
  } >RAM_CODE AT>FLASH_BL1

  /* The program code and other data goes into RAM */
  .text :
  {
    . = ALIGN(4);
    *(.text)           /* .text sections (code) */
    *(.text*)          /* .text* sections (code) */
    *(.glue_7)         /* glue arm to thumb code */
    *(.glue_7t)        /* glue thumb to arm code */
    *(.eh_frame)

    KEEP (*(.init))
    KEEP (*(.fini))

    . = ALIGN(4);
    _etext = .;        /* define a global symbols at end of code */
  } >RAM_CODE AT>FLASH_BL1

  /* Constant data goes into RAM */
  .rodata :
  {
    . = ALIGN(4);
    *(.rodata)         /* .rodata sections (constants, strings, etc.) */
    *(.rodata*)        /* .rodata* sections (constants, strings, etc.) */
    . = ALIGN(4);
  } >RAM_CODE AT>FLASH_BL1

  .ARM.extab   : { *(.ARM.extab* .gnu.linkonce.armextab.*) } >RAM
  .ARM : {
    __exidx_start = .;
    *(.ARM.exidx*)
    __exidx_end = .;
  } >RAM_CODE AT>FLASH_BL1

  .preinit_array     :
  {
    PROVIDE_HIDDEN (__preinit_array_start = .);
    KEEP (*(.preinit_array*))
    PROVIDE_HIDDEN (__preinit_array_end = .);
  } >RAM_CODE AT>FLASH_BL1
  .init_array :
  {
    PROVIDE_HIDDEN (__init_array_start = .);
    KEEP (*(SORT(.init_array.*)))
    KEEP (*(.init_array*))
    PROVIDE_HIDDEN (__init_array_end = .);
  } >RAM_CODE AT>FLASH_BL1
  .fini_array :
  {
    PROVIDE_HIDDEN (__fini_array_start = .);
    KEEP (*(SORT(.fini_array.*)))
    KEEP (*(.fini_array*))
    PROVIDE_HIDDEN (__fini_array_end = .);
  } >RAM_CODE AT>FLASH_BL1

  /* Initialized data sections goes into RAM, load LMA copy after code */
  .data :
  {
    . = ALIGN(4);
    *(.data)           /* .data sections */
    *(.data*)          /* .data* sections */
    . = ALIGN(4);
  } >RAM_CODE AT>FLASH_BL1

  /* Uninitialized data section */
  . = ALIGN(4);
  .bss :
  {
    /* This is used by the startup in order to initialize the .bss secion */
    _sbss = .;         /* define a global symbol at bss start */
    __bss_start__ = _sbss;
    *(.bss)
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;         /* define a global symbol at bss end */
    __bss_end__ = _ebss;
  } >RAM

  /* User_heap_stack section, used to check that there is enough RAM left */
  ._user_heap_stack :
  {
    . = ALIGN(4);
    PROVIDE ( end = . );
    PROVIDE ( _end = . );
    . = . + _min_heap_size;
    . = . + _min_stack_size;
    . = ALIGN(4);
  } >RAM

  /* Remove information from the standard libraries */
  /DISCARD/ :
  {
    libc.a ( * )
    libm.a ( * )
    libgcc.a ( * )
  }

  .ARM.attributes 0 : { *(.ARM.attributes) }
}


