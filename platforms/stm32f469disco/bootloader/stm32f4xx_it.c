/**
 * @file       stm32f4xx_it.c
 * @brief      Main Interrupt Service Routines and exceptions handlers
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include "stm32469i_discovery.h"

/// Handle of microSD device
extern SD_HandleTypeDef uSdHandle;

/**
 * Handles NMI exception.
 */
void NMI_Handler(void) {}

/**
 * Handles Hard Fault exception
 */
void HardFault_Handler(void) {
  // Go to infinite loop when Hard Fault exception occurs
  while (1) {
    __asm volatile(" nop");
  }
}

/**
 * Handles Memory Manage exception
 */
void MemManage_Handler(void) {
  // Go to infinite loop when Memory Manage exception occurs
  while (1) {
    __asm volatile(" nop");
  }
}

/**
 * Handles Bus Fault exception
 */
void BusFault_Handler(void) {
  // Go to infinite loop when Bus Fault exception occurs
  while (1) {
    __asm volatile(" nop");
  }
}

/**
 * Handles Usage Fault exception
 */
void UsageFault_Handler(void) {
  // Go to infinite loop when Usage Fault exception occurs
  while (1) {
    __asm volatile(" nop");
  }
}

/**
 * Handles SVCall exception
 */
void SVC_Handler(void) {}

/**
 * Handles Debug Monitor exception
 */
void DebugMon_Handler(void) {}

/**
 * Handles PendSVC exception
 */
void PendSV_Handler(void) {}

/**
 * SysTick Handler
 */
void SysTick_Handler(void) { HAL_IncTick(); }

/**
 * Handles DMA2 Stream 3 interrupt request
 */
void BSP_SD_DMA_Rx_IRQHandler(void) { HAL_DMA_IRQHandler(uSdHandle.hdmarx); }

/**
 * Handles DMA2 Stream 6 interrupt request
 */
void BSP_SD_DMA_Tx_IRQHandler(void) { HAL_DMA_IRQHandler(uSdHandle.hdmatx); }

/**
 * Handles SDIO interrupt request
 */
void SDIO_IRQHandler(void) { HAL_SD_IRQHandler(&uSdHandle); }
