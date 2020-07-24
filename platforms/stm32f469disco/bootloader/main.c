/**
 * Minimal display example
 */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "stm32469i_discovery_lcd.h"

/// Version in format parced by upgrade-generator
static const char version_tag[] __attribute__((used)) =
    "<version:tag10>0302213456</version:tag10>";

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
#define BLACK 0xFF000000
#define BLUE 0xFF5267FF
#define PROGRESS_WIDTH 380
#define PROGRESS_Y 250
#define LCD_WIDTH 480
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
FATFS SDFatFs;  /* File system object for SD disk logical drive */
FIL MyFile;     /* File object */
char SDPath[4]; /* SD disk logical drive path */
static uint8_t buffer[FF_MAX_SS]; /* a work buffer for the f_mkfs() */
/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void Error_Handler(void);

/* Private functions ---------------------------------------------------------*/

/**
 * No-op function used to keep variable from removal by compiler and linker
 *
 * It exists because "volatile" and "__attribute__((used))" do not work in 100%
 * of cases and modification of linker script is inconvenient and may break
 * existing projects.
 *
 * @param ptr  pointer to a variable
 */
static inline void keep_variable(volatile const void* ptr) {
  (void)*(volatile const char*)ptr;
}

static void lcd_init() {
  BSP_LCD_Init();
  BSP_LCD_InitEx(LCD_ORIENTATION_PORTRAIT);
  BSP_LCD_LayerDefaultInit(LTDC_ACTIVE_LAYER_BACKGROUND, LCD_FB_START_ADDRESS);
  BSP_LCD_SelectLayer(LTDC_ACTIVE_LAYER_BACKGROUND);
  BSP_LCD_Clear(BLACK);
  BSP_LCD_SetBackColor(BLACK);
  BSP_LCD_SetTextColor(BLUE);
}

static void show_progress(int progress) {
  uint16_t x0 = (LCD_WIDTH - PROGRESS_WIDTH) / 2;
  uint16_t active_width = progress * PROGRESS_WIDTH / 100;
  uint16_t inactive_width = PROGRESS_WIDTH - active_width;

  BSP_LCD_SetTextColor(BLUE);
  BSP_LCD_FillRect(x0, PROGRESS_Y, progress * PROGRESS_WIDTH / 100, 20);
  BSP_LCD_SetTextColor(BLACK);
  BSP_LCD_FillRect(x0 + active_width, PROGRESS_Y, inactive_width, 20);
  BSP_LCD_SetTextColor(BLUE);
}

//#if 0 // TODO: remove
static void test_sd_card(void) {
  FRESULT res;                      /* FatFs function common result code */
  uint32_t byteswritten, bytesread; /* File write/read counts */
  uint8_t wtext[] = "This is STM32 working with FatFs"; /* File write buffer */
  uint8_t rtext[100];                                   /* File read buffer */

  /*##-1- Link the SD disk I/O driver ########################################*/
  if (FATFS_LinkDriver(&SD_Driver, SDPath) == 0) {
    /*##-2- Register the file system object to the FatFs module ##############*/
    if (f_mount(&SDFatFs, (TCHAR const*)SDPath, 0) != FR_OK) {
      /* FatFs Initialization Error */
      Error_Handler();
    } else {
      /*##-3- Create a FAT file system (format) on the logical drive #########*/
      if (0)  //!!!! f_mkfs((TCHAR const*)SDPath, NULL, buffer, sizeof(buffer))
              //!!= FR_OK)
      {
        Error_Handler();
      } else {
        /*##-4- Create and Open a new text file object with write access #####*/
        if (f_open(&MyFile, "STM32.TXT", FA_CREATE_ALWAYS | FA_WRITE) !=
            FR_OK) {
          /* 'STM32.TXT' file Open for write Error */
          Error_Handler();
        } else {
          /*##-5- Write data to the text file ################################*/
          res = f_write(&MyFile, wtext, sizeof(wtext), (void*)&byteswritten);

          if ((byteswritten == 0) || (res != FR_OK)) {
            /* 'STM32.TXT' file Write or EOF Error */
            Error_Handler();
          } else {
            /*##-6- Close the open text file #################################*/
            f_close(&MyFile);

            /*##-7- Open the text file object with read access ###############*/
            if (f_open(&MyFile, "STM32.TXT", FA_READ) != FR_OK) {
              /* 'STM32.TXT' file Open for read Error */
              Error_Handler();
            } else {
              /*##-8- Read data from the text file ###########################*/
              res = f_read(&MyFile, rtext, sizeof(rtext), (UINT*)&bytesread);

              if ((bytesread == 0) || (res != FR_OK)) /* EOF or Error */
              {
                /* 'STM32.TXT' file Read or EOF Error */
                Error_Handler();
              } else {
                /*##-9- Close the open text file #############################*/
                f_close(&MyFile);

                /*##-10- Compare read data with the expected data ############*/
                if ((bytesread != byteswritten)) {
                  /* Read data is different from the expected data */
                  Error_Handler();
                } else {
                  /* Success of the demo: no error occurrence */
                  BSP_LED_On(LED1);
                }
              }
            }
          }
        }
      }
    }
  }

  /*##-11- Unlink the SD disk I/O driver ####################################*/
  FATFS_UnLinkDriver(SDPath);
}
//#endif

/**
 * @brief  Main program
 * @param  None
 * @retval None
 */
int main(void) {
  keep_variable(&version_tag);

  /* STM32F469xx HAL library initialization */
  HAL_Init();

  /* Configure the System clock to have a frequency of 180 MHz */
  SystemClock_Config();

  /* Configure LED1 and LED3 */
  BSP_LED_Init(LED1);
  BSP_LED_Init(LED3);

  lcd_init();
  BSP_LCD_DisplayStringAt(0, 200, (uint8_t*)"Verifying firmware", CENTER_MODE);
  // BSP_LCD_DisplayStringAt(0, 300, (uint8_t *)version_tag, CENTER_MODE); //
  // !!!!

  // TODO: remove
  test_sd_card();

  int progress = 0;
  show_progress(progress);

  while (1) {
    HAL_Delay(30);

    progress = (progress + 1) % 100;
    show_progress(progress);
  }
}

/**
 * @brief  System Clock Configuration
 *         The system Clock is configured as follow :
 *            System Clock source            = PLL (HSE)
 *            SYSCLK(Hz)                     = 180000000
 *            HCLK(Hz)                       = 180000000
 *            AHB Prescaler                  = 1
 *            APB1 Prescaler                 = 4
 *            APB2 Prescaler                 = 2
 *            HSE Frequency(Hz)              = 8000000
 *            PLL_M                          = 8
 *            PLL_N                          = 360
 *            PLL_P                          = 2
 *            PLL_Q                          = 7
 *            PLL_R                          = 2
 *            VDD(V)                         = 3.3
 *            Main regulator output voltage  = Scale1 mode
 *            Flash Latency(WS)              = 5
 *         The USB clock configuration from PLLSAI:
 *            PLLSAIM                        = 8
 *            PLLSAIN                        = 384
 *            PLLSAIP                        = 8
 * @param  None
 * @retval None
 */
void SystemClock_Config(void) {
  RCC_ClkInitTypeDef RCC_ClkInitStruct;
  RCC_OscInitTypeDef RCC_OscInitStruct;
  RCC_PeriphCLKInitTypeDef PeriphClkInitStruct = {};

  // TODO: check return values for errors

  /* Enable Power Control clock */
  __HAL_RCC_PWR_CLK_ENABLE();

  /* The voltage scaling allows optimizing the power consumption when the device
     is clocked below the maximum system frequency, to update the voltage
     scaling value regarding system frequency refer to product datasheet.  */
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /* Enable HSE Oscillator and activate PLL with HSE as source */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
#if defined(USE_STM32469I_DISCO_REVA)
  RCC_OscInitStruct.PLL.PLLM = 25;
#else
  RCC_OscInitStruct.PLL.PLLM = 8;
#endif /* USE_STM32469I_DISCO_REVA */
  RCC_OscInitStruct.PLL.PLLN = 360;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  RCC_OscInitStruct.PLL.PLLR = 2;
  HAL_RCC_OscConfig(&RCC_OscInitStruct);

  /* Activate the OverDrive to reach the 180 MHz Frequency */
  HAL_PWREx_EnableOverDrive();

  /* Select PLLSAI output as SD clock source */
  PeriphClkInitStruct.PeriphClockSelection =
      RCC_PERIPHCLK_SDIO | RCC_PERIPHCLK_CK48;
  PeriphClkInitStruct.SdioClockSelection = RCC_SDIOCLKSOURCE_CK48;
  PeriphClkInitStruct.Clk48ClockSelection = RCC_CK48CLKSOURCE_PLLSAIP;
  PeriphClkInitStruct.PLLSAI.PLLSAIN = 384;
  PeriphClkInitStruct.PLLSAI.PLLSAIQ = 7;
  PeriphClkInitStruct.PLLSAI.PLLSAIP = RCC_PLLSAIP_DIV8;
  HAL_RCCEx_PeriphCLKConfig(&PeriphClkInitStruct);

  /* Select PLL as system clock source and configure the HCLK, PCLK1 and PCLK2
     clocks dividers */
  RCC_ClkInitStruct.ClockType = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK |
                                 RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2);
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;
  HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5);
}

/**
 * @brief This function provides accurate delay (in milliseconds) based
 *        on SysTick counter flag.
 * @note This function is declared as __weak to be overwritten in case of other
 *       implementations in user file.
 * @param Delay: specifies the delay time length, in milliseconds.
 * @retval None
 */

void HAL_Delay(__IO uint32_t Delay) {
  while (Delay) {
    if (SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk) {
      Delay--;
    }
  }
}

/**
 * @brief  This function is executed in case of error occurrence.
 * @param  None
 * @retval None
 */
static void Error_Handler(void) {
  /* Turn LED3 on */
  BSP_LED_On(LED3);
  while (1) {
  }
}

#ifdef USE_FULL_ASSERT
/**
 * @brief  Reports the name of the source file and the source line number
 *         where the assert_param error has occurred.
 * @param  file: pointer to the source file name
 * @param  line: assert_param error line source number
 * @retval None
 */
void assert_failed(uint8_t* file, uint32_t line) {
  /* User can add his own implementation to report the file name and line
     number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */

  /* Infinite loop */
  while (1) {
  }
}
#endif

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
