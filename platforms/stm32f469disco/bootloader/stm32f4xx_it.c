/**
 * @file       stm32f4xx_it.c
 * @brief      Main Interrupt Service Routines
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include "main.h"
#include "stm32f4xx_it.h"

extern SD_HandleTypeDef uSdHandle;

/******************************************************************************/
/*            Cortex-M4 Processor Exceptions Handlers                         */
/******************************************************************************/

/**
 * @brief  This function handles NMI exception.
 * @param  None
 * @return None
 */
void NMI_Handler(void) {
}

/**
 * @brief  This function handles Hard Fault exception.
 * @param  None
 * @return None
 */
void HardFault_Handler(void) {
  // Go to infinite loop when Hard Fault exception occurs
  while(1) {
  }
}

/**
 * @brief  This function handles Memory Manage exception.
 * @param  None
 * @return None
 */
void MemManage_Handler(void) {
  // Go to infinite loop when Memory Manage exception occurs
  while(1) {
  }
}

/**
 * @brief  This function handles Bus Fault exception.
 * @param  None
 * @return None
 */
void BusFault_Handler(void)
{
  // Go to infinite loop when Bus Fault exception occurs
  while(1) {
  }
}

/**
 * @brief  This function handles Usage Fault exception.
 * @param  None
 * @return None
 */
void UsageFault_Handler(void)
{
  // Go to infinite loop when Usage Fault exception occurs
  while(1) {
  }
}

/**
 * @brief  This function handles SVCall exception.
 * @param  None
 * @return None
 */
void SVC_Handler(void) {
}

/**
 * @brief  This function handles Debug Monitor exception.
 * @param  None
 * @return None
 */
void DebugMon_Handler(void) {
}

/**
 * @brief  This function handles PendSVC exception.
 * @param  None
 * @return None
 */
void PendSV_Handler(void) {
}

/**
 * @brief  This function handles SysTick Handler.
 * @param  None
 * @return None
 */
void SysTick_Handler(void) {
  HAL_IncTick();
}

/******************************************************************************/
/*                 STM32F4xx Peripherals Interrupt Handlers                   */
/*  Add here the Interrupt Handler for the used peripheral(s) (PPP), for the  */
/*  available peripheral interrupt handler's name please refer to the startup */
/*  file (startup_stm32f4xx.s).                                               */
/******************************************************************************/

/**
 * @brief  This function handles DMA2 Stream 3 interrupt request.
 * @param  None
 * @return None
 */
void BSP_SD_DMA_Rx_IRQHandler(void) {
  HAL_DMA_IRQHandler(uSdHandle.hdmarx);
}

/**
 * @brief  This function handles DMA2 Stream 6 interrupt request.
 * @param  None
 * @return None
 */
void BSP_SD_DMA_Tx_IRQHandler(void) {
  HAL_DMA_IRQHandler(uSdHandle.hdmatx);
}

/**
 * @brief  This function handles SDIO interrupt request.
 * @param  None
 * @return None
 */
void SDIO_IRQHandler(void) {
  HAL_SD_IRQHandler(&uSdHandle);
}

/**
 * @brief  This function handles PPP interrupt request.
 * @param  None
 * @return None
 */
#if 0
void PPP_IRQHandler(void) {
}
#endif // 0
