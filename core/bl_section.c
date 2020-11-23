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
#include "segwit_addr.h"

/// Name used to identify signature section
#define BL_SIGNATURE_SECT_NAME "sign"
#ifdef BL_IO_BUF_SIZE
/// Size of statically allocated shared IO buffer
#define IO_BUF_SIZE BL_IO_BUF_SIZE
#else
/// Size of statically allocated shared IO buffer
#define IO_BUF_SIZE 4096U
#endif

/// Maximum size of human readable part of signature message (including '\0')
#define SIG_MSG_HRP_MAX (sizeof("b77.777.777rc77-77.777.777rc77-"))

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

bool blsect_validate_payload(const bl_section_t* p_hdr, const uint8_t* pl_buf) {
  if (p_hdr && pl_buf && p_hdr->pl_size &&
      p_hdr->pl_size <= BL_PAYLOAD_SIZE_MAX) {
    return p_hdr->pl_crc == crc32_fast(pl_buf, p_hdr->pl_size, 0U);
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
    const size_t crc_block_size = 4096U;  // Size of processed block

    bl_report_progress(progr_arg, p_hdr->pl_size, 0U);
    while (rm_bytes) {
      size_t proc_len = (rm_bytes < crc_block_size) ? rm_bytes : crc_block_size;
      if (!blsys_flash_crc32(&crc, curr_addr, proc_len)) {
        return false;
      }
      curr_addr += proc_len;
      rm_bytes -= proc_len;
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

bool blsect_hash_over_flash(const bl_section_t* p_hdr, bl_addr_t pl_addr,
                            bl_hash_t* p_result, bl_cbarg_t progr_arg) {
  if (p_hdr && blsect_is_payload(p_hdr) && p_result &&
      sizeof(p_result->digest) == SHA256_DIGEST_LENGTH &&
      sizeof(p_result->sect_name) == sizeof(p_hdr->name)) {
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

    // Save calculated digest
    sha256_Final(&context, p_result->digest);
    // Save additional information
    memcpy(p_result->sect_name, p_hdr->name, sizeof(p_result->sect_name));
    p_result->pl_ver = p_hdr->pl_ver;
    return true;
  }
  return false;
}

/**
 * Returns brief section name
 *
 * @param sect_name  section name
 * @return           pointer to null-terminated string if successfull of NULL if
 *                   failed
 */
static const char* brief_section_name(const char* sect_name) {
  static const char* brief_boot = "b";
  static const char* brief_main = "";

  if (bl_streq(sect_name, "boot")) {
    return brief_boot;
  } else if (bl_streq(sect_name, "main")) {
    return brief_main;
  }
  return NULL;
}

/**
 * Converts binary data into an array of 5-bit values
 *
 * @param dst         destination buffer where produced array is placed
 * @param p_dst_size  pointer to variable holding capacity of the destination
 *                    buffer, filled with actual array size on return
 * @param src         source buffer holding input data
 * @param src_size    size of input data
 * @return            true if successful
 */
BL_STATIC_NO_TEST bool bytes_to_5bit(uint8_t* dst, size_t* p_dst_size,
                                     const uint8_t* src, size_t src_size) {
  if (dst && src && src_size && src_size < (SIZE_MAX / 8U - 4U) && p_dst_size &&
      *p_dst_size >= (src_size * 8U + 4U) / 5U) {
    uint8_t* p_dst = dst;
    int dst_bit = 4;
    *p_dst = 0U;

    const uint8_t* p_src = src;
    while (p_src != src + src_size) {
      for (int src_bit = 7; src_bit >= 0; --src_bit) {
        if (dst_bit < 0) {
          dst_bit = 4;
          *(++p_dst) = 0U;
        }
        *p_dst |= (*p_src >> src_bit & 1) << dst_bit--;
      }
      ++p_src;
    }
    *p_dst_size = p_dst - dst + 1U;
    return true;
  }
  return false;
}

bool blsect_make_signature_message(uint8_t* msg_buf, size_t* p_msg_size,
                                   const bl_hash_t* p_hashes,
                                   size_t hash_items) {
  if (msg_buf && p_msg_size && *p_msg_size && p_hashes && hash_items) {
    SHA256_CTX sha_ctx;            // SHA-256 context
    char hrp[SIG_MSG_HRP_MAX];     // Human readable part
    char ver[BL_VERSION_STR_MAX];  // Buffer for version string
    sha256_Init(&sha_ctx);
    hrp[0] = '\0';

    // Process all hash items
    bool ok = true;
    const bl_hash_t* p_hash = p_hashes;
    while (ok && p_hash < p_hashes + hash_items) {
      const char* brief_name = brief_section_name(p_hash->sect_name);
      ok = ok && brief_name;
      ok = ok && bl_strcat_checked(hrp, sizeof(hrp), brief_name);
      ok = ok && bl_version_to_sig_str(p_hash->pl_ver, ver, sizeof(ver));
      ok = ok && bl_strcat_checked(hrp, sizeof(hrp), ver);
      ok = ok && bl_strcat_checked(hrp, sizeof(hrp), "-");
      sha256_Update(&sha_ctx, p_hash->digest, sizeof(p_hash->digest));
      ++p_hash;
    }

    // Create Bech32 message
    if (ok) {
      // Create digest and convert it to 5-bit values
      uint8_t digest[SHA256_DIGEST_LENGTH];
      sha256_Final(&sha_ctx, digest);
      uint8_t digest_5bit[(SHA256_DIGEST_LENGTH * 8U + 4U) / 5U];
      size_t digest_5bit_len = sizeof(digest_5bit);
      ok = bytes_to_5bit(digest_5bit, &digest_5bit_len, digest, sizeof(digest));

      // Create Bech32 message
      size_t msg_size = strlen(hrp) + digest_5bit_len + 8U;
      ok = ok && *p_msg_size >= msg_size;
      ok = ok && 1 == bech32_encode((char*)msg_buf, hrp, digest_5bit,
                                    digest_5bit_len);
      *p_msg_size = msg_size - 1U;
      return ok;
    }
  }
  return false;
}
