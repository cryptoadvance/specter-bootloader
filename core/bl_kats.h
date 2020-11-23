/**
 * @file       bl_kats.h
 * @brief      Bootloader known answer tests (KATs) for cryptographic functions
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef BL_KATS_H_INCLUDED
/// Avoids multiple inclusion of the same file
#define BL_KATS_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Runs a suite of known answer tests for all cryptographic functions in use
 *
 * @return true  if all tests passed successfully
 */
bool bl_run_kats(void);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // BL_KATS_H_INCLUDED