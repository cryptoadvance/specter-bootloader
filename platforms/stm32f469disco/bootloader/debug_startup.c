/**
 * @file       debug_startup.c
 * @brief      Dummy start-up code used for debuging Bootloader in RAM
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include "stm32f4xx_hal.h"
#include "startup_mailbox.h"

/** @defgroup linker_vars Linker variables
 * @{ */
/// End of stack
extern char _estack;
/// Starting address of Bootloader code in RAM
extern char _ram_code_start;
/// Ending address of Bootloader code in RAM
extern char _ram_code_end;
/// Starting address of Bootloader code in Flash
extern char _flash_code_start;
/** @} */

/// Bootloader arguments
__attribute__ ((section (".startup.const")))
static const bl_args_t bl_args = {
  .loaded_from = (uint32_t)&_flash_code_start
};

/**
 * Executes binary application
 *
 * @param l_code_addr  start address, an ISR table
 */
__attribute__ ((section (".startup.text")))
static void bin_exec(void* l_code_addr) {
    // Both r0 and r1 will hold address of ISR table
    __asm volatile (" mov  r1, r0");
    // Read entry point into r0
    __asm volatile (" ldr  r0, [r1, #4]");
    // Initialize stack pointer
    __asm volatile (" ldr  sp, [r1]");
    // Branch to entry point of an application
    __asm volatile (" blx  r0");
}

/**
 * Copies a number of 32 bit word in memory
 *
 * @param dst  destination address, must be 4-byte aligned
 * @param src  source address, must be 4-byte aligned
 * @param len  length of copied block, must be multiple of 4
 */
__attribute__ ((section (".startup.text")))
__attribute__((optimize("O2")))
static inline void memcpy32(void *dst, const void *src, size_t len) {
  uint32_t* p_dst = dst;
  const uint32_t* p_src = src;
  size_t len32 = len >> 2;

  while(len32--) {
    *p_dst++ = *p_src++;
  }
}

/**
 * Dummy start-up code used for debuging Bootloader in RAM
 */
__attribute__ ((section (".startup.text")))
void debug_startup(void) {
  // Initialize stack pointer
  __asm volatile (" ldr  r0, =_estack");
  __asm volatile (" msr  msp, r0");

  // Copy Bootloader code from Flash to RAM
  memcpy32( &_ram_code_start, &_flash_code_start,
            (uint32_t)(&_ram_code_end) - (uint32_t)(&_ram_code_start) );

  // Enable clock for SYSCFG
  RCC->APB2ENR |= RCC_APB2ENR_SYSCFGEN;
  while(0U == (RCC->APB2ENR & RCC_APB2ENR_SYSCFGEN)) {
    __asm volatile (" nop");
  }

  // Remap SRAM to 0x00000000 using SYSCFG
  __DSB();
  __ISB();
  __HAL_SYSCFG_REMAPMEMORY_SRAM();
  __DSB();
  __ISB();

  // Start the Bootloader at 0x00000000 with default arguments
  if(bl_write_args(&bl_args)) {
    bin_exec(0x00000000U);
  }

  while(1) {
    __asm volatile (" nop"); // Error
  }
}

/// Interrupt vectors of the dummy start-up code
__attribute__ ((section (".startup.isr_vector")))
__attribute__((used))
static void (* const vectors_flash[240])(void) =
{
  (void (*)(void))((uint32_t)&_estack), // Initial value of stack pointer
  debug_startup                         // Reset handler
};
