/**
 * @file       ext_callbacks.c
 * @brief      External callbacks for libsecp256k1 library
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include "bl_syscalls.h"

void secp256k1_default_illegal_callback_fn(const char* str, void* data) {
  blsys_fatal_error(str);
}

void secp256k1_default_error_callback_fn(const char* str, void* data) {
  blsys_fatal_error(str);
}
