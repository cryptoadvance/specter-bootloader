/**
 * @file       flash_buf.hpp
 * @brief      Utility class emulating flash memory using buffer in RAM
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef FLASH_BUF_HPP_INCLUDED
/// Avoids multiple inclusion of the same file
#define FLASH_BUF_HPP_INCLUDED

#include "bl_syscalls.h"

// External variables
extern "C" const bl_addr_t flash_emu_base;
extern "C" uint8_t* flash_emu_buf;
extern "C" size_t flash_emu_size;

/// Emulates flash memory using buffer in RAM
class FlashBuf {
 public:
  inline FlashBuf(const uint8_t* pl_buf, uint32_t pl_size) {
    if (!flash_emu_buf) {
      flash_emu_buf = new uint8_t[pl_size];
      flash_emu_size = pl_size;
      if (pl_buf) {
        memcpy(flash_emu_buf, pl_buf, pl_size);
      } else {
        memset(flash_emu_buf, 0xFF, pl_size);
      }
    } else {
      INFO("ERROR: flash emulation buffer already created");
      REQUIRE(false);  // Abort test
    }
  }

  inline ~FlashBuf() {
    if (flash_emu_buf) {
      delete flash_emu_buf;
      flash_emu_buf = NULL;
      flash_emu_size = 0U;
    }
  }

  inline operator uint8_t*() const { return flash_emu_buf; }

  inline uint8_t& operator[](int index) { return flash_emu_buf[index]; }
};

#endif  // FLASH_BUF_HPP_INCLUDED