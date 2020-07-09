/**
 * @file       bootloader.h
 * @brief      Main include file for Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef BOOTLOADER_H_INCLUDED
/// Avoids multiple inclusion of the same file
#define BOOTLOADER_H_INCLUDED

#if defined(__GNUC__) || defined(__clang__)
  /// Compiler attribute
  #define BL_ATTRS(x)                   __attribute__(x)
#else
  /// Compiler attribute (empty macro)
  #define BL_ATTRS(x)
#endif

#endif // BOOTLOADER_H_INCLUDED
