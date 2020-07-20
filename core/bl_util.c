/**
 * @file       bl_util.c
 * @brief      Utility functions for Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include "bl_util.h"

bool bl_memvcmp(const void* ptr, int value, size_t num) {
  if(ptr && num) {
    const uint8_t* p_mem = (const uint8_t*)ptr;
    size_t rm_bytes = num;
    while(rm_bytes--) {
      if(*p_mem++ != value) {
        return false;
      }
    }
    return true;
  }
  return false;
}
