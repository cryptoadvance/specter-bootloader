/**
 * @file       bl_util.c
 * @brief      Utility functions for Bootloader
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */
// TODO test

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "bl_util.h"

/// Number of decimal digits in the XML version tag
#define VTAG_DIGITS 10U
/// Offset of the first digit from the beginning of the tag
#define VTAG_DIGITS_OFFSET 15U
/// Version tag pattern
#define VTAG_PATTERN "<vErSiOn:tAg10>..........</VeRsIoN:TaG10>"  // Mixed case
// is used to avoid this string to be threated as a version tag itself

/// Version format identifier
typedef enum version_fmt_t {
  version_fmt_display,   ///< Format for display
  version_fmt_signature  ///< Format for signature message
} version_fmt_t;

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

bool bl_strcat_checked(char *dst, size_t dst_size, const char *src) {
  if(dst && src && dst_size > 1U) {
    size_t dst_len = strlen(dst);
    size_t src_len = strlen(src);
    if(dst_len + src_len + 1U <= dst_size) {
      // Copy src string after dst string including terminating null-character
      memcpy(dst + dst_len, src, src_len + 1U);
      return true;
    }
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

/**
 * Returns version string from version number
 *
 * Provided buffer should have size at least BL_VERSION_STR_MAX bytes to be able
 * to receive any possible version string.
 *
 * @param version      version number, as stored in header
 * @param buf          buffer where version null-terminated string will be
 *                     placed
 * @param buf_size     size of provided buffer in bytes
 * @param version_fmt  version format
 * @return             true if successful
 */
static bool version_to_str(uint32_t version, char* buf, size_t buf_size,
                           version_fmt_t version_fmt) {
  if (buf && buf_size &&
      (version_fmt_display == version_fmt ||
       version_fmt_signature == version_fmt)) {
    if (BL_VERSION_NA == version) {
      if (version_fmt_display == version_fmt) {
        *buf = '\0';
        return true;
      }
      return false;
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
        res = snprintf(buf, buf_size,
                       (version_fmt_display == version_fmt) ? "%u.%u.%u-rc%u"
                                                            : "%u.%u.%urc%u",
                       (unsigned)major, (unsigned)minor, (unsigned)patch,
                       (unsigned)rc_rev);
      }
      return (res > 0);
    }
  }
  return false;
}

bool bl_version_to_str(uint32_t version, char* buf, size_t buf_size) {
  return version_to_str(version, buf, buf_size, version_fmt_display);
}

bool bl_version_to_sig_str(uint32_t version, char* buf, size_t buf_size) {
  return version_to_str(version, buf, buf_size, version_fmt_signature);
}

/**
 * Matches a string to a pattern ignoring case
 *
 * This matcher supports only one special character: '.', replacing any
 * character in the matched string.
 *
 * @param pattern  pattern to match
 * @param str      string to match
 * @return         true if the string matches the pattern
 */
static bool match_pattern_ignore_case(const char* pattern, const char* str) {
  if (pattern && str) {
    size_t len = strlen(pattern);
    if (strlen(str) == len) {
      for (size_t idx = 0; idx < len; ++idx) {
        if (pattern[idx] != '.' && toupper(str[idx]) != toupper(pattern[idx])) {
          return false;
        }
      }
      return true;
    }
  }
  return false;
}

// TODO test
uint32_t bl_decode_version_tag(const char* tag) {
  if (tag && match_pattern_ignore_case(VTAG_PATTERN, tag)) {
    uint32_t version = 0U;
    const char* p_digit = tag + VTAG_DIGITS_OFFSET;
    for (int i = 0; i < VTAG_DIGITS; ++i) {
      if (*p_digit < '0' || *p_digit > '9') {
        return BL_VERSION_NA;
      }
      version = version * 10U + (*p_digit++) - '0';
    }
    return (version <= BL_VERSION_MAX) ? version : BL_VERSION_NA;
  }
  return BL_VERSION_NA;
}
