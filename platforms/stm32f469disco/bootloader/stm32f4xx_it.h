/**
 * @file       stm32f4xx_it.h
 * @brief      Main Interrupt Service Routines
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef STM32F4XX_IT_H_INCLUDED
/// Avoids multiple inclusion of this file
#define STM32F4XX_IT_H_INCLUDED

#include "main.h"

#ifdef __cplusplus
extern "C" {
#endif

void NMI_Handler(void);
void HardFault_Handler(void);
void MemManage_Handler(void);
void BusFault_Handler(void);
void UsageFault_Handler(void);
void SVC_Handler(void);
void DebugMon_Handler(void);
void PendSV_Handler(void);
void SysTick_Handler(void);
void BSP_SD_DMA_Rx_IRQHandler(void);
void BSP_SD_DMA_Tx_IRQHandler(void);
void SDIO_IRQHandler(void);

#ifdef __cplusplus
}
#endif

#endif  // STM32F4XX_IT_H_INCLUDED
