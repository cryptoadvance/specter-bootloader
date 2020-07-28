/**
 * @file       bl_section.c
 * @brief      Bootloader sections and operations on them
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 *
 * WARNING: This code is not expected to be thread-safe, as Bootloader always
 * runs non-concurrently!
 *
 * NOTE: Only little-endian machines are supported. Support of natively
 * big-endian machines is not planned.
 */

#include <string.h>
#include "crc32.h"
#include "sha2.h"
#include "bl_section.h"
#include "bl_util.h"

/// Name used to identify signature section
#define BL_SIGNATURE_SECT_NAME "sign"
/// Size of statically allocated shared IO buffer
#define IO_BUF_SIZE 512U

/// Statically allocated contex
static struct {
  // IO buffer
  uint8_t io_buf[IO_BUF_SIZE];
} ctx;

/**
 * Checks if given character is a digit
 *
 * @param chr  character to test
 * @return     true if character is a digit
 */
static inline bool is_digit(char chr) { return chr >= '0' && chr <= '9'; }

/**
 * Checks if given character is a latin letter of either case
 *
 * @param chr  character to test
 * @return     true if character is a letter
 */
static inline bool is_letter(char chr) {
  return ((chr >= 'a' && chr <= 'z') || (chr >= 'A' && chr <= 'Z'));
}

/**
 * Validates section name stored in a fixed-size buffer
 *
 * This function checks that:
 *   - string is not empty and begins with a latin letter
 *   - string contains only latin letters and/or numbers
 *   - string is null-terminated
 *   - reamaining space of the buffer is filled with zero bytes
 *
 * @param str       null-terminated string
 * @param buf_size  size of the buffer containing the string
 * @return          true if string is valid
 */
BL_STATIC_NO_TEST bool validate_section_name(const char* str, size_t buf_size) {
  if (str && buf_size && is_letter(*str)) {
    for (const char* p_chr = str + 1U; p_chr < str + buf_size; ++p_chr) {
      if (!*p_chr) {
        // Check if remaining bytes are all zeroes
        return bl_memveq(p_chr, 0, str + buf_size - p_chr);
      }
      if (!is_letter(*p_chr) && !is_digit(*p_chr)) {
        return false;
      }
    }
  }
  return false;
}

/**
 * Validates attribute list
 *
 * This function checks that:
 *   - last attribute fits in the buffer completely
 *   - reamaining space of the buffer is filled with zero bytes
 *
 * @param attr_list  attribute list
 * @param buf_size   size of the buffer containing attribute list
 * @return           true if attribute list is valid
 */
BL_STATIC_NO_TEST bool validate_attributes(const uint8_t* attr_list,
                                           size_t buf_size) {
  if (attr_list && buf_size >= 2) {
    const uint8_t* p_list = attr_list;
    const uint8_t* p_end = attr_list + buf_size;
    while (p_list < p_end) {
      uint8_t key = *p_list++;
      if (key) {
        if (p_list + 1U > p_end) {
          // No space for size byte
          return false;
        }
        uint8_t size = *p_list++;
        if (p_list + size > p_end) {
          // No space for value
          return false;
        }
        p_list += size;
      } else if (p_list < p_end) {
        // Check if remaining bytes are all zeroes
        return bl_memveq(p_list, 0, p_end - p_list);
      }
    }
    return true;
  }
  return false;
}

bool blsect_validate_header(const bl_section_t* p_hdr) {
  if (p_hdr) {
    if (BL_SECT_MAGIC == p_hdr->magic &&
        BL_SECT_STRUCT_REV == p_hdr->struct_rev) {
      uint32_t crc = crc32_fast(p_hdr, offsetof(bl_section_t, struct_crc), 0U);
      if (crc == p_hdr->struct_crc &&
          validate_section_name(p_hdr->name, sizeof(p_hdr->name)) &&
          p_hdr->pl_ver <= BL_VERSION_MAX && p_hdr->pl_size &&
          p_hdr->pl_size <= BL_PAYLOAD_SIZE_MAX &&
          validate_attributes(p_hdr->attr_list, sizeof(p_hdr->attr_list))) {
        return true;
      }
    }
  }
  return false;
}

bool blsect_validate_payload(const bl_section_t* p_hdr, const uint8_t* pl_buf,
                             uint32_t pl_size) {
  if (p_hdr && pl_buf && pl_size && pl_size <= BL_PAYLOAD_SIZE_MAX) {
    if (p_hdr->pl_size == pl_size) {
      return p_hdr->pl_crc == crc32_fast(pl_buf, pl_size, 0U);
    }
  }
  return false;
}

bool blsect_validate_payload_from_file(const bl_section_t* p_hdr,
                                       bl_file_t file, bl_cbarg_t progr_arg) {
  if (p_hdr && p_hdr->pl_size && p_hdr->pl_size <= BL_PAYLOAD_SIZE_MAX &&
      file) {
    size_t rm_bytes = p_hdr->pl_size;
    uint32_t crc = 0U;

    bl_report_progress(progr_arg, p_hdr->pl_size, 0U);
    while (rm_bytes) {
      if (blsys_feof(file)) {
        return false;
      }
      size_t read_len = (rm_bytes < IO_BUF_SIZE) ? rm_bytes : IO_BUF_SIZE;
      size_t got_len = blsys_fread(ctx.io_buf, 1U, read_len, file);
      if (got_len != read_len) {
        return false;
      }
      crc = crc32_fast(ctx.io_buf, read_len, crc);
      rm_bytes -= read_len;
      bl_report_progress(progr_arg, p_hdr->pl_size, p_hdr->pl_size - rm_bytes);
    }
    return crc == p_hdr->pl_crc;
  }
  return false;
}

bool blsect_validate_payload_from_flash(const bl_section_t* p_hdr,
                                        bl_addr_t addr, bl_cbarg_t progr_arg) {
  if (p_hdr && p_hdr->pl_size && p_hdr->pl_size <= BL_PAYLOAD_SIZE_MAX) {
    size_t rm_bytes = p_hdr->pl_size;
    bl_addr_t curr_addr = addr;
    uint32_t crc = 0U;

    bl_report_progress(progr_arg, p_hdr->pl_size, 0U);
    while (rm_bytes) {
      size_t read_len = (rm_bytes < IO_BUF_SIZE) ? rm_bytes : IO_BUF_SIZE;
      if (!blsys_flash_read(curr_addr, ctx.io_buf, read_len)) {
        return false;
      }
      crc = crc32_fast(ctx.io_buf, read_len, crc);
      curr_addr += read_len;
      rm_bytes -= read_len;
      bl_report_progress(progr_arg, p_hdr->pl_size, p_hdr->pl_size - rm_bytes);
    }
    return crc == p_hdr->pl_crc;
  }
  return false;
}

bool blsect_is_payload(const bl_section_t* p_hdr) {
  if (p_hdr) {
    return !blsect_is_signature(p_hdr);
  }
  return false;
}

bool blsect_is_signature(const bl_section_t* p_hdr) {
  if (p_hdr) {
    return bl_streq(p_hdr->name, BL_SIGNATURE_SECT_NAME);
  }
  return false;
}

/**
 * Searches for the attribute in attribute list
 *
 * This function returns index of the size byte within attribute list (array) if
 * the attribute is found. If the size is non-zero, the following byte(s)
 * contain attribute's value.
 *
 * @param attr_list  attribute list
 * @param buf_size   size of the buffer containing attribute list
 * @param attr_id    attribute identifier
 * @return           index of size byte, or -1 if attribute not found
 */
static int find_attribute(const uint8_t* attr_list, size_t buf_size,
                          bl_attr_t attr_id) {
  if (attr_list && buf_size) {
    const uint8_t* p_list = attr_list;
    const uint8_t* p_end = attr_list + buf_size;
    while (p_list < p_end) {
      uint8_t key = *p_list++;
      if (key) {
        if (p_list + 1U > p_end) {
          // No space for size byte
          return -1;
        }
        uint8_t size = *p_list++;
        if (p_list + size > p_end) {
          // No space for value
          return -1;
        }
        if (key == (int)attr_id) {
          return (int)(p_list - 1U - attr_list);
        }
        p_list += size;
      } else {
        // Zero key encountered => end of list
        return -1;
      }
    }
  }
  // Key not found
  return -1;
}

bool blsect_get_attr_uint(const bl_section_t* p_hdr, bl_attr_t attr_id,
                          bl_uint_t* p_value) {
  if (p_hdr && p_value) {
    int idx =
        find_attribute(p_hdr->attr_list, sizeof(p_hdr->attr_list), attr_id);
    if (idx >= 0) {
      uint8_t size = p_hdr->attr_list[idx];
      if (size <= sizeof(bl_uint_t)) {
        // data points to the most significant byte of value (if there are any)
        const uint8_t* src = &p_hdr->attr_list[idx + size];
        *p_value = 0;
        for (int i = 0; i < (int)size; ++i) {
          *p_value = *p_value << 8 | *src--;
        }
        return true;
      }
    }
  }
  return false;
}

bool blsect_get_attr_str(const bl_section_t* p_hdr, bl_attr_t attr_id,
                         char* buf, size_t buf_size) {
  if (p_hdr && buf && buf_size) {
    int idx =
        find_attribute(p_hdr->attr_list, sizeof(p_hdr->attr_list), attr_id);
    if (idx >= 0) {
      uint8_t size = p_hdr->attr_list[idx];
      if (size + 1U <= buf_size) {
        // src points to the first character of string (if there are any)
        const char* src = (const char*)(&p_hdr->attr_list[idx + 1]);
        char* dst = buf;

        for (int i = 0; i < (int)size; ++i) {
          if ('\0' == *src) {
            return false;
          }
          *dst++ = *src++;
        }
        *dst = '\0';
        return true;
      }
    }
  }
  return false;
}

bool blsect_version_to_str(uint32_t version, char* buf, size_t buf_size) {
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

bool blsect_hash_sentence_from_flash(const bl_section_t* p_hdr,
                                     bl_addr_t pl_addr,
                                     bl_hash_sentence_t* p_result,
                                     bl_cbarg_t progr_arg) {
  const size_t sentence_size =
      sizeof(p_hdr->name) + sizeof(p_hdr->pl_ver) + SHA256_DIGEST_LENGTH;

  if (p_hdr && blsect_is_payload(p_hdr) && p_result &&
      sentence_size == sizeof(p_result->bytes)) {
    uint8_t* p_out = p_result->bytes;
    // Copy section name
    memcpy(p_out, p_hdr->name, sizeof(p_hdr->name));
    p_out += sizeof(p_hdr->name);

    // Copy payload version
    memcpy(p_out, &p_hdr->pl_ver, sizeof(p_hdr->pl_ver));
    p_out += sizeof(p_hdr->pl_ver);

    // Calculate hash reading data from flash memory
    size_t rm_bytes = p_hdr->pl_size;
    bl_addr_t curr_addr = pl_addr;
    SHA256_CTX context;
    sha256_Init(&context);

    sha256_Update(&context, (const uint8_t*)p_hdr, sizeof(bl_section_t));
    bl_report_progress(progr_arg, p_hdr->pl_size, 0U);
    while (rm_bytes) {
      size_t read_len = (rm_bytes < IO_BUF_SIZE) ? rm_bytes : IO_BUF_SIZE;
      if (!blsys_flash_read(curr_addr, ctx.io_buf, read_len)) {
        return false;
      }
      sha256_Update(&context, ctx.io_buf, read_len);
      curr_addr += read_len;
      rm_bytes -= read_len;
      bl_report_progress(progr_arg, p_hdr->pl_size, p_hdr->pl_size - rm_bytes);
    }
    sha256_Final(&context, p_out);
    return true;
  }
  return false;
}
