/**
 * @file       ext_callbacks.c
 * @brief      External callbacks for libsecp256k1 library
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include "bl_syscalls.h"

/**
 * Callback function called when an illegal argument is passed to an API call
 *
 * @param str   error mesage
 * @param data  user-defined parameter
 */
void secp256k1_default_illegal_callback_fn(const char* str, void* data) {
  blsys_fatal_error(str);
}

/**
 * Callback function to be called when an internal consistency check fail
 *
 * @param str   error mesage
 * @param data  user-defined parameter
 */
void secp256k1_default_error_callback_fn(const char* str, void* data) {
  blsys_fatal_error(str);
}
