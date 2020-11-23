/**
 * @file       startup.c
 * @brief      Start-up code for the Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include <string.h>
#include "crc32.h"
#include "stm32469i_discovery.h"
#include "bl_util.h"
#include "bl_integrity_check.h"
#include "startup_mailbox.h"
#include "linker_vars.h"

/// CPU clock frequency in Hz
#define CPU_CLOCK 16000000U  // HSI 16MHz is selected at reset
/// Number of CPU clocks in 1 millisecond
#define CLOCKS_PER_MS ((CPU_CLOCK + 500U) / 1000U)
/// GPIO port of the red LED
#define ERR_LED_GPIO_PORT LED3_GPIO_PORT
/// GPIO pin of the red LED
#define ERR_LED_GPIO_PIN LED3_PIN
/// Enables clock to GPIO module to which the red LED is connected
#define ERR_LED_GPIO_CLK_ENABLE() LED3_GPIO_CLK_ENABLE()

/// Start-up errors, indicated by blinks of the red LED
typedef enum startup_error_t {
  /// Internal error: 1 blink
  startup_error_internal = 1,
  /// No valid bootloader found: 2 blinks
  startup_error_no_bootloader = 2
} startup_error_t;

/// Version tag in XML format
/*static*/ const char version_tag[] BL_ATTRS((section(".startup_ver"), used)) =
    "<version:tag10>0000000001</version:tag10>";

/**
 * Reads a block of data from flash memory
 *
 * @param addr  source address in flash memory
 * @param buf   buffer receiving data
 * @param len   number of bytes to read
 * @return      true if successful
 */
bool blsys_flash_read(bl_addr_t addr, void* buf, size_t len) {
  if (buf && len) {
    memcpy(buf, (const void*)addr, len);
    return true;
  }
  return false;
}

bool blsys_flash_crc32(uint32_t* p_crc, bl_addr_t addr, size_t len) {
  if (p_crc && len) {
    *p_crc = crc32_fast((const void*)addr, len, *p_crc);
    return true;
  }
  return false;
}

/**
 * Executes a binary application
 *
 * @param l_code_addr  start address, an ISR table
 */
//! @cond Doxygen_Suppress
BL_ATTRS((noreturn))
//! @endcond
static void bin_exec(const void* l_code_addr) {
  // Both r0 and r1 will hold address of ISR table
  __asm volatile(" mov  r1, r0");
  // Read entry point into r0
  __asm volatile(" ldr  r0, [r1, #4]");
  // Initialize stack pointer
  __asm volatile(" ldr  sp, [r1]");
  // Branch to entry point of an application
  __asm volatile(" blx  r0");

  // We should not get there
  while (1) {
    __asm volatile(" nop");
  }
}

/**
 * Returns elapsed CPU clocks taiking into account possible counter overflow
 *
 * @param clock       current timestamp
 * @param prev_clock  previous timestamp
 * @return            elapsed clocks
 */
static inline uint32_t elapsed_clocks(uint32_t clock, uint32_t prev_clock) {
  return (clock >= prev_clock) ? clock - prev_clock
                               : UINT32_MAX - prev_clock + clock + 1U;
}

/**
 * Provides a delay expressed in milliseconds
 *
 * @param time_ms  time in milliseconds
 */
//! @cond Doxygen_Suppress
BL_ATTRS((optimize("O2")))
//! @endcond
static void delay_ms(uint32_t time_ms) {
  uint32_t rm_time = time_ms;
  while (rm_time) {
    for (int idx = 0; idx < (CLOCKS_PER_MS / 10U); ++idx) {
      __asm volatile(" nop");
      __asm volatile(" nop");
      __asm volatile(" nop");
      __asm volatile(" nop");
      __asm volatile(" nop");
      __asm volatile(" nop");
      __asm volatile(" nop");
      __asm volatile(" nop");
      __asm volatile(" nop");
    }
    --rm_time;
  }
}

/**
 * Controls the LED used for error indication
 *
 * @param enable  if true turns on the LED
 */
static inline void err_led_on(bool enable) {
  HAL_GPIO_WritePin(ERR_LED_GPIO_PORT, ERR_LED_GPIO_PIN,
                    enable ? GPIO_PIN_RESET : GPIO_PIN_SET);
}

/**
 * Hadles fatal error
 *
 * @param error  error code
 */
//! @cond Doxygen_Suppress
BL_ATTRS((noreturn))
//! @endcond
static void fatal_error(startup_error_t error) {
  // Initialize the LED for error indication
  ERR_LED_GPIO_CLK_ENABLE();
  GPIO_InitTypeDef gpio_led = {.Pin = ERR_LED_GPIO_PIN,
                               .Mode = GPIO_MODE_OUTPUT_PP,
                               .Pull = GPIO_PULLUP,
                               .Speed = GPIO_SPEED_HIGH};
  (void)HAL_GPIO_Init(ERR_LED_GPIO_PORT, &gpio_led);
  err_led_on(false);

  // Blink forever until manual reset
  int n_blinks = ((int)error > 0) ? (int)error : (int)startup_error_internal;
  while (1) {
    for (int idx = 0; idx < n_blinks; ++idx) {
      err_led_on(true);
      delay_ms(100U);
      err_led_on(false);
      delay_ms(400U);
    }
    delay_ms(1500U);
  }
}

/**
 * Starts the Bootloader
 *
 * @param bl_addr  start address of the Bootloader in the flash memory
 * @param p_args   pointer to arguments passed to the Bootloader
 */
BL_ATTRS((noreturn))
static void start_bootloader(bl_addr_t start_addr, const bl_args_t* p_args) {
  // Save the arguments
  if (bl_write_args(LV_PTR(_startup_mailbox), p_args)) {
    // Copy Bootloader code from Flash to RAM
    memcpy(LV_PTR(_ram_code_start), (const void*)start_addr,
           LV_VALUE(_ram_code_end) - LV_VALUE(_ram_code_start));

    // Enable clock for SYSCFG
    RCC->APB2ENR |= RCC_APB2ENR_SYSCFGEN;
    while (0U == (RCC->APB2ENR & RCC_APB2ENR_SYSCFGEN)) {
      __asm volatile(" nop");
    }

    // Remap SRAM to 0x00000000 using SYSCFG
    __DSB();
    __ISB();
    __HAL_SYSCFG_REMAPMEMORY_SRAM();
    __DSB();
    __ISB();

    // Start the Bootloader at 0x00000000
    bin_exec(0x00000000U);
  }

  // Something went wrong
  fatal_error(startup_error_internal);
}

/**
 * Selects a copy of the Bootloader to run, ensuring that it is valid
 *
 * NOTE: In case no valid copy found, this function calls fatal_error() which
 * never returns.
 *
 * @return  address of the selected bootloader
 */
bl_addr_t select_bootloader(void) {
  const int n_copies = 2;
  static const bl_addr_t bl_addr[] = {LV_VALUE(_bl_copy1_start),
                                      LV_VALUE(_bl_copy2_start)};
  uint32_t version[n_copies];
  int selected = -1;

  // Find a copy with the latest version
  for (int idx = 0; idx < n_copies; ++idx) {
    version[idx] = BL_VERSION_NA;
    if (bl_icr_get_version(bl_addr[idx], LV_VALUE(_bl_sect_size),
                           &version[idx])) {
      if (-1 == selected || version[idx] > version[selected]) {
        selected = idx;
      }
    }
  }

  // Verify selected copy
  if (selected >= 0) {
    if (bl_icr_verify(bl_addr[selected], LV_VALUE(_bl_sect_size), NULL)) {
      return bl_addr[selected];  // Copy is valid, return it
    }
  }

  // Try to find a replacement copy with the same version
  for (int idx = 0; idx < n_copies; ++idx) {
    if (idx != selected && version[idx] == version[selected] &&
        bl_icr_verify(bl_addr[idx], LV_VALUE(_bl_sect_size), NULL)) {
      return bl_addr[idx];  // Alternate copy found with valid contents
    }
  }

  // No valid Bootloader
  fatal_error(startup_error_no_bootloader);
}

/**
 * Main function of the Start-up code
 *
 * @return  exit code (used for error indication)
 */
int main(void) {
  bl_keep_variable(&version_tag);

  // Start the Bootloader
  bl_addr_t bl_addr = select_bootloader();
  bl_args_t bl_args = {.loaded_from = bl_addr,
                       .startup_version = bl_decode_version_tag(version_tag)};
  start_bootloader(bl_addr, &bl_args);
}

/**
 * Entry point for the Start-up code
 */
void startup_entry(void) {
  // Initialize stack pointer
  __asm volatile(" ldr  r0, =_estack");
  __asm volatile(" msr  msp, r0");

  // Execute main() and handle error if something went wrong
  int ret_code = main();
  fatal_error((startup_error_t)ret_code);
}

/// Interrupt vectors of the dummy start-up code
__attribute__((section(".isr_vector")))
__attribute__((used)) static void (*const vectors_flash[240])(void) = {
    (void (*)(void))LV_PTR(_estack),  // Initial value of stack pointer
    startup_entry                     // Reset handler
};
