/**
 * @file       bl_util.c
 * @brief      Utility functions for Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#include <stdio.h>
#include "bl_util.h"

/// Number of decimal digits in the XML version tag
#define VTAG_DIGITS 10U
/// Opening part of the XML version tag
#define VTAG_OPENING "<version:tag10>"
/// Length of the opening part of the XML version tag
#define VTAG_OPENING_LEN (sizeof(VTAG_OPENING) - 1U)
/// Closing part of XML version tag
#define VTAG_CLOSING "</version:tag10>"
/// Length of the closing part of the XML version tag
#define VTAG_CLOSING_LEN (sizeof(VTAG_CLOSING) - 1U)
/// Length of the XML version tag string
#define VTAG_LEN (VTAG_OPENING_LEN + VTAG_DIGITS + VTAG_CLOSING_LEN)

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

// TODO add tests
uint32_t bl_percent_x100(uint32_t total, uint32_t complete) {
  if (complete >= total) {
    return 10000U;
  } else {
    return (uint32_t)((uint64_t)complete * 10000U / total);
  }
}

bool bl_version_to_str(uint32_t version, char* buf, size_t buf_size) {
  if (buf && buf_size) {
    if (BL_VERSION_NA == version) {
      *buf = '\0';
      return true;
    } else if (version <= BL_VERSION_MAX) {
      uint32_t major = version / (100U * 1000U * 1000U);
      uint32_t minor = version / (100U * 1000U) % 1000U;
      uint32_t patch = version / 100U % 1000U;
      uint32_t rc_rev = version % 100U;

      int res = -1;
      if (99U == rc_rev) {
        res = snprintf(buf, buf_size, "%u.%u.%u", (unsigned)major,
                       (unsigned)minor, (unsigned)patch);
      } else {
        res = snprintf(buf, buf_size, "%u.%u.%u-rc%u", (unsigned)major,
                       (unsigned)minor, (unsigned)patch, (unsigned)rc_rev);
      }
      return (res > 0);
    }
  }
  return false;
}

// TODO test
uint32_t bl_decode_version_tag(const char* tag) {
  if (tag && strlen(tag) == VTAG_LEN) {
    if (0 == strncmp(tag, VTAG_OPENING, VTAG_OPENING_LEN) &&
        0 == strncmp(tag + VTAG_OPENING_LEN + VTAG_DIGITS, VTAG_CLOSING,
                     VTAG_CLOSING_LEN)) {
      uint32_t version = 0U;
      const char* p_digit = tag + VTAG_OPENING_LEN;
      for (int i = 0; i < VTAG_DIGITS; ++i) {
        if (*p_digit < '0' || *p_digit > '9') {
          return BL_VERSION_NA;
        }
        version = version * 10U + (*p_digit++) - '0';
      }
      return (version <= BL_VERSION_MAX) ? version : BL_VERSION_NA;
    }
  }
  return BL_VERSION_NA;
}
