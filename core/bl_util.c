/**
 * @file       bl_util.c
 * @brief      Utility functions for Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include "bl_util.h"

/// Statically allocated contex
static struct {
  /// Callback function called to report progress of operations
  bl_cb_progress_t cb_progress;
  /// User-provided context for callback functions
  void* cb_ctx;
} ctx = {.cb_progress = NULL};

bool bl_memveq(const void* ptr, int value, size_t num) {
  if (ptr && num) {
    const uint8_t* p_mem = (const uint8_t*)ptr;
    size_t rm_bytes = num;
    while (rm_bytes--) {
      if (*p_mem++ != value) {
        return false;
      }
    }
    return true;
  }
  return false;
}

void bl_set_progress_callback(bl_cb_progress_t cb_progress, void* user_ctx) {
  ctx.cb_progress = cb_progress;
  ctx.cb_ctx = user_ctx;
}

/**
 * Reports progress by calling a callback function if it is initialized
 *
 * @param arg       argument passed to callback function
 * @param total     total number of steps
 * @param complete  number of complete steps
 */
void bl_report_progress(bl_cbarg_t arg, uint32_t total, uint32_t complete) {
  if (ctx.cb_progress) {
    ctx.cb_progress(ctx.cb_ctx, arg, total, complete);
  }
}