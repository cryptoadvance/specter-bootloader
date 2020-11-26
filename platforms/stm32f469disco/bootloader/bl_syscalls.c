/**
 * @file       bl_syscalls.c
 * @brief      System abstraction layer for STM32F469I-DISCO platform
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 *
 * System abstraction layer for STM32F469I-DISCO platform. These functions are
 * called from core of Bootloader to obtain platform parameters and to perform
 * platform-specific operations.
 *
 * Flash sector mapping is taken from the MicroPython project. Original license
 * and copyright notice are provided at the end of file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crc32.h"
#include "bl_util.h"
#include "bl_syscalls.h"
#include "stm32469i_discovery.h"
#include "stm32469i_discovery_sd.h"
#include "stm32469i_discovery_lcd.h"
#include "ff.h"
#include "ff_gen_drv.h"
#include "sd_diskio.h"
#include "gui.h"
#include "linker_vars.h"

/// Index of the
#define DEVICE_IDX_MICROSD 0U
/// Base address of flash memory region to which Bootloader has access
#define FLASH_WR_BASE (bl_flash_map[bl_flash_firmware_base])
/// Size of flash memory region to which Bootloader has access
#define FLASH_WR_SIZE                     \
  (bl_flash_map[bl_flash_firmware_size] + \
   2U * bl_flash_map[bl_flash_bootloader_size])
/// All flash memory error flags
#define FLASH_FLAG_ALL_ERRORS_                                                 \
  (FLASH_FLAG_EOP | FLASH_FLAG_OPERR | FLASH_FLAG_WRPERR | FLASH_FLAG_PGAERR | \
   FLASH_FLAG_PGPERR | FLASH_FLAG_PGSERR)
/// Error LED
#define ERROR_LED LED_RED
/// Text with request to rebbot the device
#define REBOOT_PROMPT "Press power button to reboot"
/// First sector in the Bank 1
#define FLASH_BANK2_FIRST_SECTOR 12U
/// Selection of protection mode: 0 - write protection, 1 - PCROP
#define FLASH_SPRMOD_BIT (1U << 15)

/// GPIO port of nPWR_BUTTON line
#define NPWR_BUTTON_GPIO_PORT ((GPIO_TypeDef*)GPIOB)
/// GPIO pin of nPWR_BUTTON line
#define NPWR_BUTTON_GPIO_PIN ((uint32_t)GPIO_PIN_1)
/// Enables clock to GPIO module to which nPWR_BUTTON line is connected
#define NPWR_BUTTON_GPIO_CLK_ENABLE() __HAL_RCC_GPIOB_CLK_ENABLE()
/// GPIO port of PWR_HOLD2 line
#define PWR_HOLD2_GPIO_PORT ((GPIO_TypeDef*)GPIOB)
/// GPIO pin of PWR_HOLD2 line
#define PWR_HOLD2_GPIO_PIN ((uint32_t)GPIO_PIN_15)
/// Enables clock to GPIO module to which PWR_HOLD2 line is connected
#define PWR_HOLD2_GPIO_CLK_ENABLE() __HAL_RCC_GPIOB_CLK_ENABLE()

/// Prototype for the start_firmware() function
typedef bool (*blsys_start_firmware_t)(bl_addr_t, uint32_t);

/// Indexes of the media devices
typedef enum media_device_idx_t {
  media_micro_sd = 0,  ///< microSD card slot
  media_n_devices,     ///< Number of media devices, not a device index
  media_none = -1      ///< Reserved "no media" value
} media_device_idx_t;

/// Flash memory layout entry
typedef struct {
  bl_addr_t base_address;  ///< Base address of the sector
  bl_addr_t sector_size;   ///< Size of the sector
  uint32_t sector_count;   ///< Number of sectors having the same size
} flash_layout_t;

/// Area in the flash memory defined by address and size
typedef struct flash_area_t {
  bl_addr_t addr;  ///< Starting address
  size_t size;     ///< Size in bytes
} flash_area_t;

/// Iterator over sectors in the flash memory
typedef flash_area_t flash_sect_iter_t;

/// Map of flash memory sectors
typedef uint32_t sec_bitmap_t;

/// Layout of flash memory
// clang-format off
static const flash_layout_t flash_layout[] = {
  { 0x08000000, 0x04000, 4 },
  { 0x08010000, 0x10000, 1 },
  { 0x08020000, 0x20000, 3 },
  #if defined(FLASH_SECTOR_8)
  { 0x08080000, 0x20000, 4 },
  #endif
  #if defined(FLASH_SECTOR_12)
  { 0x08100000, 0x04000, 4 },
  { 0x08110000, 0x10000, 1 },
  { 0x08120000, 0x20000, 7 },
  #endif
};
// clang-format on

/// Flash memory map
// clang-format off
const bl_addr_t bl_flash_map[bl_flash_map_nitems] = {
  [bl_flash_firmware_base]         = LV_VALUE(_main_firmware_start),
  [bl_flash_firmware_size]         = LV_VALUE(_main_firmware_size),
  [bl_flash_firmware_part1_size]   = LV_VALUE(_main_firmware_part1_size),
  [bl_flash_bootloader_image_base] = LV_VALUE(_bl_image_base),
  [bl_flash_bootloader_copy1_base] = LV_VALUE(_bl_copy1_start),
  [bl_flash_bootloader_copy2_base] = LV_VALUE(_bl_copy2_start),
  [bl_flash_bootloader_size]       = LV_VALUE(_bl_sect_size)};
// clang-format on

/// Names of media devices
static const char* media_name[media_n_devices] = {[media_micro_sd] = "microSD"};

/// Statically allocated local context
static struct {
  /// File system object for currently mounted media device
  FATFS fs_obj;
  /// Media logical drive path
  char media_path[4];
  /// Currently mounted media device
  media_device_idx_t mounted_media;
} ctx;

/// Flag indicating that the system is initialized
static bool system_initialized = false;

/**
 * Returns information about flash memory sector specified by address
 *
 * @param addr        address within flash memory range
 * @param start_addr  pointer to variable receiving start address of the sector,
 *                    ignored if NULL
 * @param size        pointer to variable receiving size of the sector,
 *                    ignored if NULL
 * @return            sector index, or -1 if address is incorrect
 */
static int flash_get_sector_info(bl_addr_t addr, bl_addr_t* start_addr,
                                 bl_addr_t* size) {
  if (addr >= flash_layout[0].base_address) {
    int sector_index = 0;
    for (int i = 0; i < sizeof(flash_layout) / sizeof(flash_layout[0]); ++i) {
      for (int j = 0; j < flash_layout[i].sector_count; ++j) {
        bl_addr_t sector_start_next = flash_layout[i].base_address +
                                      (j + 1) * flash_layout[i].sector_size;
        if (addr < sector_start_next) {
          if (start_addr != NULL) {
            *start_addr =
                flash_layout[i].base_address + j * flash_layout[i].sector_size;
          }
          if (size != NULL) {
            *size = flash_layout[i].sector_size;
          }
          return sector_index;
        }
        ++sector_index;
      }
    }
  }
  return -1;
}

/**
 * Initializes the SD Detect pin
 */
static inline void sd_detect_init(void) {
  SD_DETECT_GPIO_CLK_ENABLE();

  // GPIO configuration in input for uSD_Detect signal
  GPIO_InitTypeDef pin_dsc = {.Pin = SD_DETECT_PIN,
                              .Mode = GPIO_MODE_INPUT,
                              .Pull = GPIO_PULLUP,
                              .Speed = GPIO_SPEED_HIGH};
  HAL_GPIO_Init(SD_DETECT_GPIO_PORT, &pin_dsc);
}

/**
 * Checks if SD card present in the slot using SD Detect pin
 *
 * @return true  if card present
 */
static inline bool sd_detect_state(void) {
  return HAL_GPIO_ReadPin(SD_DETECT_GPIO_PORT, SD_DETECT_PIN) == GPIO_PIN_RESET;
}

/**
 * Returns state of power button
 *
 * @return  true if power button is pressed
 */
static bool power_btn_state(void) {
  int activation_counter = 0;
  for (int i = 0; i < 5; ++i) {  // 5ms debounce
    if (HAL_GPIO_ReadPin(NPWR_BUTTON_GPIO_PORT, NPWR_BUTTON_GPIO_PIN) ==
        GPIO_PIN_RESET) {
      ++activation_counter;
    }
    HAL_Delay(1U);  // 1ms delay
  }
  return activation_counter >= 3;
}

/**
 * Controls power hold pin
 *
 * @param enable  if true sets power hold pin to active state
 */
static inline void power_hold(bool enable) {
  HAL_GPIO_WritePin(PWR_HOLD2_GPIO_PORT, PWR_HOLD2_GPIO_PIN,
                    enable ? GPIO_PIN_SET : GPIO_PIN_RESET);
}

/**
 * Initializes pins related to power management and confirms power on
 */
static void power_pins_init(void) {
  // Initialize nPWR_BUTTON input
  NPWR_BUTTON_GPIO_CLK_ENABLE();
  GPIO_InitTypeDef button_dsc = {.Pin = NPWR_BUTTON_GPIO_PIN,
                                 .Mode = GPIO_MODE_INPUT,
                                 .Pull = GPIO_PULLUP,
                                 .Speed = GPIO_SPEED_HIGH};
  HAL_GPIO_Init(NPWR_BUTTON_GPIO_PORT, &button_dsc);

  // Initialize PWR_HOLD2 output
  PWR_HOLD2_GPIO_CLK_ENABLE();
  GPIO_InitTypeDef hold_dsc = {.Pin = PWR_HOLD2_GPIO_PIN,
                               .Mode = GPIO_MODE_OUTPUT_PP,
                               .Pull = GPIO_NOPULL,
                               .Speed = GPIO_SPEED_HIGH};
  HAL_GPIO_Init(PWR_HOLD2_GPIO_PORT, &hold_dsc);
  power_hold(true);
}

BL_ATTRS((noreturn)) void blsys_wait_power_down(void) {
  // Let's explain the compiler that we need the following loops to be preserved
  volatile int inert = 0;

  // Wait until power button is released if the user still holds it after
  // turning on the device.
  while (power_btn_state()) {
    ++inert;
    (void)inert;
  }

  // Wait for a short press of power button to turn off the device
  while (1) {
    if (power_btn_state()) {
      power_hold(false);
      HAL_Delay(500U);         // Wait for 500ms for the power down
      HAL_NVIC_SystemReset();  // Just reboot the MCU if unsuccessful
      while (1) {              // Should not get there
        ++inert;
        (void)inert;
      }
    }
    ++inert;
    (void)inert;
  }
}

/**
 * Configures system clocks
 *
 * @return true if successful
 */
static bool configure_system_clocks(void) {
  RCC_ClkInitTypeDef RCC_ClkInitStruct;
  RCC_OscInitTypeDef RCC_OscInitStruct;
  RCC_PeriphCLKInitTypeDef PeriphClkInitStruct = {};

  // Enable Power Control clock
  __HAL_RCC_PWR_CLK_ENABLE();

  // The voltage scaling allows optimizing the power consumption when the device
  // is clocked below the maximum system frequency, to update the voltage
  // scaling value regarding system frequency refer to product datasheet.
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  // Enable HSE Oscillator and activate PLL with HSE as source
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
#if defined(USE_STM32469I_DISCO_REVA)
  RCC_OscInitStruct.PLL.PLLM = 25;
#else
  RCC_OscInitStruct.PLL.PLLM = 8;
#endif  // USE_STM32469I_DISCO_REVA
  RCC_OscInitStruct.PLL.PLLN = 360;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  RCC_OscInitStruct.PLL.PLLR = 2;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) {
    return false;
  }

  // Activate the OverDrive to reach the 180 MHz Frequency
  if (HAL_PWREx_EnableOverDrive() != HAL_OK) {
    return false;
  }

  // Select PLLSAI output as SD clock source
  PeriphClkInitStruct.PeriphClockSelection =
      RCC_PERIPHCLK_SDIO | RCC_PERIPHCLK_CK48;
  PeriphClkInitStruct.SdioClockSelection = RCC_SDIOCLKSOURCE_CK48;
  PeriphClkInitStruct.Clk48ClockSelection = RCC_CK48CLKSOURCE_PLLSAIP;
  PeriphClkInitStruct.PLLSAI.PLLSAIN = 384;
  PeriphClkInitStruct.PLLSAI.PLLSAIQ = 7;
  PeriphClkInitStruct.PLLSAI.PLLSAIP = RCC_PLLSAIP_DIV8;
  if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInitStruct) != HAL_OK) {
    return false;
  }

  // Select PLL as system clock source and configure the HCLK, PCLK1 and PCLK2
  // clocks dividers
  RCC_ClkInitStruct.ClockType = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK |
                                 RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2);
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;
  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK) {
    return false;
  }
  return true;
}

bool blsys_init(void) {
  if (!system_initialized) {
    memset(&ctx, 0, sizeof(ctx));
    ctx.mounted_media = media_none;
    HAL_Init();
    if (!configure_system_clocks()) {
      return false;
    }
    power_pins_init();
    sd_detect_init();
    BSP_LED_Init(ERROR_LED);
    BSP_LED_Off(ERROR_LED);
    gui_init();
#ifdef WRITE_PROTECTION
    // Apply write protection to the Start-up code if needed
    if (!blsys_flash_write_protect(LV_VALUE(_startup_code_start),
                                   LV_VALUE(_startup_code_size), true)) {
      return false;
    }
#endif  // WRITE_PROTECTION
    system_initialized = true;
  }
  return true;
}

void blsys_deinit(void) {
  if (system_initialized) {
    blsys_media_umount();
    BSP_SD_DeInit();
    gui_deinit();
    system_initialized = false;
  }
}

/**
 * Provides accurate delay (in milliseconds) based on SysTick counter flag
 *
 * NOTE: This function is declared as __weak to be overwritten in case of other
 * implementations in user file.
 *
 * @param Delay: specifies the delay time length, in milliseconds.
 */
void HAL_Delay(__IO uint32_t Delay) {
  while (Delay) {
    if (SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk) {
      Delay--;
    }
  }
}

/**
 * Checks if area in flash memory falls in valid address range
 *
 * @param addr  starting address
 * @param size  area size
 * @return      true if successful
 */
static bool check_flash_area(bl_addr_t addr, size_t size) {
  if (addr >= FLASH_WR_BASE && addr <= SIZE_MAX - size &&
      addr + size <= FLASH_WR_BASE + FLASH_WR_SIZE) {
    return true;
  }
  return false;
}

bool blsys_flash_erase(bl_addr_t addr, size_t size) {
  if (size && check_flash_area(addr, size)) {
    bl_addr_t first_s_addr = 0U;
    int first_s_idx = flash_get_sector_info(addr, &first_s_addr, NULL);
    bl_addr_t last_s_addr = 0U;
    bl_addr_t last_s_size = 0U;
    int last_s_idx =
        flash_get_sector_info(addr + size - 1U, &last_s_addr, &last_s_size);
    if (first_s_idx >= 0 && last_s_idx >= first_s_idx && first_s_addr == addr &&
        (addr + size) == (last_s_addr + last_s_size)) {
      if (HAL_OK == HAL_FLASH_Unlock()) {
        __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_ALL_ERRORS_);
        FLASH_EraseInitTypeDef erase_cmd = {
            .TypeErase = TYPEERASE_SECTORS,
            .VoltageRange = VOLTAGE_RANGE_3,
            .Sector = first_s_idx,
            .NbSectors = last_s_idx - first_s_idx + 1U,
        };
        uint32_t erase_err = 0;
        int erase_status = HAL_FLASHEx_Erase(&erase_cmd, &erase_err);
        return (HAL_OK == HAL_FLASH_Lock()) && (HAL_OK == erase_status);
      }
    }
  }
  return false;
}

bool blsys_flash_read(bl_addr_t addr, void* buf, size_t len) {
  if (buf && len && check_flash_area(addr, len)) {
    memcpy(buf, (const void*)addr, len);
    return true;
  }
  return false;
}

bool blsys_flash_write(bl_addr_t addr, const void* buf, size_t len) {
  if (buf && len && check_flash_area(addr, len) && sizeof(uint64_t) > 1U) {
    if (HAL_OK == HAL_FLASH_Unlock()) {
      uint32_t curr_addr = (uint32_t)addr;
      const uint8_t* p_buf = buf;
      const uint8_t* p_end = buf + len;
      bool ok = true;

      // Write the first part of data that is not 32-bit aligned
      while (ok && (curr_addr & (sizeof(uint32_t) - 1U)) && p_buf != p_end) {
        ok = ok &&
             (HAL_OK == HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, curr_addr++,
                                          (uint64_t)*p_buf++));
      }

      // Write the middle part of data, aligned to 32-bit boundary
      size_t rm_words = (p_end - p_buf) >> 2;
      while (ok && rm_words) {
        ok = ok &&
             (HAL_OK == HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, curr_addr,
                                          *(const uint32_t*)p_buf));
        curr_addr += sizeof(uint32_t);
        p_buf += sizeof(uint32_t);
        --rm_words;
      }

      // Write the last part of data that is not 64-bit aligned
      while (ok && p_buf != p_end) {
        ok = ok &&
             (HAL_OK == HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, curr_addr++,
                                          (uint64_t)*p_buf++));
      }

      return (HAL_OK == HAL_FLASH_Lock()) && ok &&
             bl_memeq((const void*)addr, buf, len);
    }
  }
  return false;
}

bool blsys_flash_crc32(uint32_t* p_crc, bl_addr_t addr, size_t len) {
  if (p_crc && len && check_flash_area(addr, len)) {
    *p_crc = crc32_fast((const void*)addr, len, *p_crc);
    return true;
  }
  return false;
}

/**
 * Creates a new iterator over flash memory sectors
 *
 * @param addr  starting address
 * @param size  size of the area in bytes
 * @return      iterator
 */
static inline flash_sect_iter_t flash_sect_iter(bl_addr_t addr, size_t size) {
  return (flash_sect_iter_t){.addr = addr, .size = size};
}

/**
 * Iterates over flash sectors within defined area in flash memory
 *
 * Before the first call the variable pinted by *p_iter* must be initialized
 * with valid starting address and area size by calling flash_sect_iter().
 *
 * @param p_iter  pointer to externally stored state variable, updated
 * @return         iteration result:
 *                   * >= 0 - number of the next sector
 *                   * -1 - there are no more sectors or in case of failure
 */
static int flash_next_sector(flash_sect_iter_t* p_iter) {
  if (p_iter && p_iter->size) {
    bl_addr_t start_addr = 0U;
    bl_addr_t size = 0U;
    int sector = flash_get_sector_info(p_iter->addr, &start_addr, &size);
    if (sector >= 0 && start_addr == p_iter->addr && size <= p_iter->size) {
      p_iter->addr += size;
      p_iter->size -= size;
      return sector;
    }
  }
  return -1;
}

/**
 * Returns bit map of flash memory sectors within the given area
 *
 * This function returns a bit map of flash sectors where each bit
 * corresponds to flash sector with the same number.
 *
 * @param p_map  pointer to destination structure receiving the sector map
 * @param addr   starting address
 * @param size   area size
 * @return       result:
 *                 * >= 0 - bit map of flash sectors
 *                 * -1 - failed
 */
static bool flash_sector_bitmap(sec_bitmap_t* p_bitmap, bl_addr_t addr,
                                size_t size) {
  if (p_bitmap && size) {
    sec_bitmap_t bitmap = 0;
    const int max_sector = sizeof(bitmap) * 8U - 1U;

    flash_sect_iter_t iter = flash_sect_iter(addr, size);
    int sector = flash_next_sector(&iter);
    while (sector >= 0) {
      sec_bitmap_t sect_bit = (sec_bitmap_t)1U << sector;
      if (sector > max_sector || !IS_OB_WRP_SECTOR(sect_bit)) {
        return false;
      }
      bitmap |= sect_bit;
      sector = flash_next_sector(&iter);
    }
    *p_bitmap = bitmap;
    return true;
  }
  return false;
}

/**
 * Returns state of write protection as a bitmap of sectors
 *
 * In resulting bitmap each bit holds write protection state of corresponding
 * sector: 0 - disabled, 1 - enabled.
 *
 * This function returns false if PCROP is enabled.
 *
 * @param p_sect_bitmap  pointer to variable receiving bitmap of sectors
 * @return               true if successful
 */
static bool flash_get_write_protection_state(sec_bitmap_t* p_sect_bitmap) {
  const uint32_t mask = (1U << FLASH_BANK2_FIRST_SECTOR) - 1U;
  if (p_sect_bitmap) {
    FLASH_OBProgramInitTypeDef config = {0};
    HAL_FLASHEx_OBGetConfig(&config);
    if ((config.OptionType & OPTIONBYTE_WRP) &&
        !(config.WRPSector & FLASH_SPRMOD_BIT)) {
      uint32_t bank1_sectors = (config.WRPSector & mask) ^ mask;
      uint32_t bank2_sectors = (HAL_FLASHEx_OB_GetBank2WRP() & mask) ^ mask;
      *p_sect_bitmap = bank1_sectors | ((sec_bitmap_t)bank2_sectors
                                        << FLASH_BANK2_FIRST_SECTOR);
      return true;
    }
  }
  return false;
}

/**
 * Enables or disables write protection of a flash memory bank
 *
 * In the bitmap of sectors each bit corresponds to a flash memory sector, e.g.
 * bit 0 corresponds to sector 0.
 *
 * @param sect_bitmap  bitmap of sectors that needs to be re-configured
 * @param enable       protection state:
 *                       * true - write protection is enabled
 *                       * false - write protection is disabled
 * @return             true if successful
 */
static bool flash_set_write_protection_state(sec_bitmap_t sect_bitmap,
                                             bool enable) {
  const sec_bitmap_t mask = (1U << FLASH_BANK2_FIRST_SECTOR) - 1U;

  // Unlock access to flash memory and option bytes
  bool ok = (HAL_OK == HAL_FLASH_Unlock());
  ok = ok && (HAL_OK == HAL_FLASH_OB_Unlock());

  // Program Bank 2
  FLASH_OBProgramInitTypeDef config = {
      .OptionType = OPTIONBYTE_WRP,
      .WRPState = enable ? OB_WRPSTATE_ENABLE : OB_WRPSTATE_DISABLE,
      .WRPSector = sect_bitmap & (mask << FLASH_BANK2_FIRST_SECTOR),
      .Banks = FLASH_BANK_2};
  ok = ok && (HAL_OK == HAL_FLASHEx_OBProgram(&config));

  // Program Bank 1
  config = (FLASH_OBProgramInitTypeDef){
      .OptionType = OPTIONBYTE_WRP,
      .WRPState = enable ? OB_WRPSTATE_ENABLE : OB_WRPSTATE_DISABLE,
      .WRPSector = sect_bitmap & mask,
      .Banks = FLASH_BANK_1};
  ok = ok && (HAL_OK == HAL_FLASHEx_OBProgram(&config));

  // Request reloading of option bytes
  ok = ok && (HAL_OK == HAL_FLASH_OB_Launch());

  // Lock access to flash memory and option bytes
  ok = ok && (HAL_OK == HAL_FLASH_OB_Lock());
  ok = ok && (HAL_OK == HAL_FLASH_Lock());
  return ok;
}

/**
 * Enables or disables write protection for all sectors of the flash memory
 *
 * @param enable       protection state:
 *                       * true - write protection is enabled
 *                       * false - write protection is disabled
 * @return             true if successful
 */
static bool flash_set_write_protection_state_global(bool enable) {
  // Unlock access to flash memory and option bytes
  bool ok = (HAL_OK == HAL_FLASH_Unlock());
  ok = ok && (HAL_OK == HAL_FLASH_OB_Unlock());

  // Program both Banks
  FLASH_OBProgramInitTypeDef config = {
      .OptionType = OPTIONBYTE_WRP,
      .WRPState = enable ? OB_WRPSTATE_ENABLE : OB_WRPSTATE_DISABLE,
      .WRPSector = OB_WRP_SECTOR_All,
      .Banks = FLASH_BANK_BOTH};
  ok = ok && (HAL_OK == HAL_FLASHEx_OBProgram(&config));

  // Request reloading of option bytes
  ok = ok && (HAL_OK == HAL_FLASH_OB_Launch());

  // Lock access to flash memory and option bytes
  ok = ok && (HAL_OK == HAL_FLASH_OB_Lock());
  ok = ok && (HAL_OK == HAL_FLASH_Lock());
  return ok;
}

/**
 * Returns RDP (read protection) level
 *
 * @param p_rdp_level  pointer to variable receiving RDP level, a value of
 *                     @ref FLASHEx_Option_Bytes_Read_Protection
 * @return             true if successful
 */
static bool flash_get_rdp_level(uint32_t* p_rdp_level) {
  if (p_rdp_level) {
    FLASH_OBProgramInitTypeDef config = {0};
    HAL_FLASHEx_OBGetConfig(&config);
    if ((config.OptionType & OPTIONBYTE_RDP)) {
      *p_rdp_level = config.RDPLevel;
      return true;
    }
  }
  return false;
}

/**
 * Programs read protection level
 *
 * WARNING: Programming Level 2 (OB_RDP_LEVEL_2) is irreversible!
 *
 * @param rdp_level  requited read protection level, a value of
 *                   @ref FLASHEx_Option_Bytes_Read_Protection
 * @return           true if successful
 */
static bool flash_set_rdp_level(uint32_t rdp_level) {
  if (IS_OB_RDP_LEVEL(rdp_level)) {
    // Unlock access to flash memory and option bytes
    bool ok = (HAL_OK == HAL_FLASH_Unlock());
    ok = ok && (HAL_OK == HAL_FLASH_OB_Unlock());

    // Program option byte(s)
    FLASH_OBProgramInitTypeDef config = {.OptionType = OPTIONBYTE_RDP,
                                         .RDPLevel = rdp_level};
    ok = ok && (HAL_OK == HAL_FLASHEx_OBProgram(&config));

    // Request reloading of option bytes
    ok = ok && (HAL_OK == HAL_FLASH_OB_Launch());

    // Lock access to flash memory and option bytes
    ok = ok && (HAL_OK == HAL_FLASH_OB_Lock());
    ok = ok && (HAL_OK == HAL_FLASH_Lock());
    return ok;
  }
  return false;
}

bool blsys_flash_write_protect(bl_addr_t addr, size_t size, bool enable) {
  sec_bitmap_t sect_map = 0U;
  if (flash_sector_bitmap(&sect_map, addr, size)) {
    uint32_t rdp_level = OB_RDP_LEVEL_0;
    sec_bitmap_t curr_state = 0U;
    bool ok = flash_get_rdp_level(&rdp_level);
    ok = ok && flash_get_write_protection_state(&curr_state);
    // We don't try to modify write protection bits in RDP Level 2
    if (ok && rdp_level != OB_RDP_LEVEL_2) {
      sec_bitmap_t new_state = curr_state;
      if (enable) {
        new_state |= sect_map;
      } else {
        new_state &= ~sect_map;
      }
      // Check if we need to re-program bits for Bank 1
      if (new_state != curr_state) {
        ok = ok && flash_set_write_protection_state(sect_map, enable);
        // Verify that configuration is programmed successfully
        ok = ok && flash_get_write_protection_state(&curr_state);
        ok = ok && curr_state == new_state;
      }
#ifdef DEBUG
      bl_keep_variable(&sect_map);
      bl_keep_variable(&rdp_level);
      bl_keep_variable(&new_state);
#endif
    }
    return ok;
  }
  return false;
}

bool blsys_flash_read_protect(int level_) {
  uint32_t new_rdp_level = OB_RDP_LEVEL_0;
  switch (level_) {
    case 1:
      new_rdp_level = OB_RDP_LEVEL_1;
      break;
// RDP Level 2 is intentionally disabled. If misused may brick your board!
#if 0
    case 2:
      new_rdp_level = OB_RDP_LEVEL_2;
      break;
#endif
    default:
      return false;
  }

  uint32_t curr_rdp_level = OB_RDP_LEVEL_0;
  bool ok = flash_get_rdp_level(&curr_rdp_level);
  if (curr_rdp_level != new_rdp_level) {
    if (OB_RDP_LEVEL_2 == new_rdp_level) {
      // Remove write protection from all the sectors because option bytes
      // become unmodifiable after enabling RDP Level 2.
      ok = ok && flash_set_write_protection_state_global(false);
#ifdef WRITE_PROTECTION
      // Re-apply write protection to the Start-up code
      ok = ok && blsys_flash_write_protect(LV_VALUE(_startup_code_start),
                                           LV_VALUE(_startup_code_size), true);
#endif  // WRITE_PROTECTION
    }
    ok = ok && flash_set_rdp_level(new_rdp_level);
    ok = ok && flash_get_rdp_level(&curr_rdp_level);
    ok = ok && curr_rdp_level == new_rdp_level;
    if (ok) {
      if (0 == level_) {
        (void)blsys_alert(bl_alert_info, "Read protection",
                          "Read protection is disabled", BL_FOREVER, 0U);
      } else {
        char msg[64];
        int len = snprintf(msg, sizeof(msg),
                           "Read protection is now: Level %i", level_);
        if (len > 0) {
          (void)blsys_alert(bl_alert_info, "Read protection", msg, BL_FOREVER,
                            0U);
        }
      }
      // Reboot the MCU if unsuccessful
      HAL_NVIC_SystemReset();
    }
  }
  return ok;
}

int blsys_flash_get_read_protection_level(void) {
  uint32_t curr_rdp_level = OB_RDP_LEVEL_0;
  if (flash_get_rdp_level(&curr_rdp_level)) {
    switch (curr_rdp_level) {
      case OB_RDP_LEVEL_0:
        return 0;
      case OB_RDP_LEVEL_1:
        return 1;
      case OB_RDP_LEVEL_2:
        return 2;
      default:
        return -1;
    }
  }
  return -1;
}

uint32_t blsys_media_devices(void) { return media_n_devices; }

const char* blsys_media_name(uint32_t device_idx) {
  static const char* invalid = "<invalid>";
  if (device_idx < media_n_devices && media_name[device_idx]) {
    return media_name[device_idx];
  }
  return invalid;
}

bool blsys_media_check(uint32_t device_idx) {
  if (media_micro_sd == device_idx) {
    return sd_detect_state();
  }
  return false;
}

bool blsys_media_mount(uint32_t device_idx) {
  if (media_micro_sd == device_idx) {
    if (sd_detect_state()) {
      if (media_none == ctx.mounted_media) {
        if (FATFS_LinkDriver(&SD_Driver, ctx.media_path) == 0 &&
            f_mount(&ctx.fs_obj, (TCHAR const*)ctx.media_path, 0) == FR_OK) {
          ctx.mounted_media = media_micro_sd;
        }
      }
      return media_micro_sd == ctx.mounted_media;
    }
  }
  return false;
}

void blsys_media_umount(void) {
  if (media_micro_sd == ctx.mounted_media) {
    (void)f_mount(0, "", 0);  // Unmount the default drive
    (void)FATFS_UnLinkDriver(ctx.media_path);
  }
  ctx.mounted_media = media_none;
}

/**
 * Handles GUI failure rebooting the device
 */
BL_ATTRS((noreturn)) static void handle_gui_fail(void) {
  BSP_LED_On(ERROR_LED);
  HAL_Delay(2000U);
  HAL_NVIC_SystemReset();
  blsys_wait_power_down();
}

BL_ATTRS((noreturn)) void blsys_fatal_error(const char* text) {
  blsys_media_umount();
  blsys_deinit();
  BSP_LED_On(ERROR_LED);
  if (!gui_show_alert(bl_alert_error, "Bootloader Error", text,
                      REBOOT_PROMPT)) {
    handle_gui_fail();
  }
  blsys_wait_power_down();
}

bl_alert_status_t blsys_alert(blsys_alert_type_t type, const char* caption,
                              const char* text, uint32_t time_ms,
                              uint32_t flags) {
  if (!gui_show_alert(type, caption, text,
                      BL_FOREVER == time_ms ? REBOOT_PROMPT : NULL)) {
    handle_gui_fail();
  }

  if (BL_FOREVER == time_ms) {
    blsys_wait_power_down();
  }

  HAL_Delay(time_ms);
  return bl_alert_terminated;
}

void blsys_progress(const char* caption, const char* operation,
                    uint32_t percent_x100) {
  if (!gui_update_progress(caption, operation, percent_x100)) {
    blsys_fatal_error("Unable to update the progress bar");
  }
}

/**
 * Starts the firmware from given address in the flash memory
 *
 * @param start_addr  start address of the firmware in flash memory
 * @param argument    argument passed to the executable module
 * @return            false in case of failure, otherwise the function does not
 *                    return
 */
static bool start_firmware(bl_addr_t start_addr, uint32_t argument) {
  // At the moment only execution of the Main Firmware is allowed
  if (bl_flash_map[bl_flash_firmware_base] == start_addr) {
    // Get pointer to vector table and check that it is valid
    volatile uint32_t* vectors = (volatile uint32_t*)start_addr;
    uint32_t msp = vectors[0];
    uint32_t entry_addr = vectors[1];
    void (*entry)(uint32_t) = (void (*)(uint32_t))entry_addr;

    // Check if valid firmware present at given address
    if (msp != 0xFFFFFFFFU &&
        entry_addr > bl_flash_map[bl_flash_firmware_base] &&
        entry_addr < (bl_flash_map[bl_flash_firmware_base] +
                      bl_flash_map[bl_flash_firmware_size])) {
      // Disable all interrupts
      __disable_irq();

      // Remap Main Flash memory to 0x00000000 using SYSCFG
      __DSB();
      __ISB();
      __HAL_SYSCFG_REMAPMEMORY_FLASH();
      __DSB();
      __ISB();

      // Remap the vector table
      SCB->VTOR = start_addr;

      // Start the firmware
      __set_MSP(msp);
      __enable_irq();  // MicroPython expects that interrupts are enabled
      entry(argument);

      // Should not get there
      while (1) {
        __asm volatile(" nop");
      }
    }
  }
  return false;
}

bool blsys_start_firmware(bl_addr_t start_addr, uint32_t argument) {
  // Calculate physical address of start_firmware() in RAM
  blsys_start_firmware_t start_fn = (blsys_start_firmware_t)(
      (uintptr_t)&start_firmware + (uintptr_t)&_ram_code_start);

  // De-initialize the hardware
  blsys_deinit();
  BSP_LCD_Reset();

  // Start the firmware
  return start_fn(start_addr, argument);
}

/*
 * Flash sector mapping is taken from the MicroPython project,
 * http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2013, 2014 Damien P. George
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */