/**
 * @file       crc32.h
 * @brief      API for the "Fast CRC32" implementation by Stephan Brumme
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef CRC32_H_INCLUDED
/// Avoids multiple inclusion of header file
#define CRC32_H_INCLUDED

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Computes CRC32 using the fastest algorithm for large datasets on modern CPUs
 *
 * @param data           data block to process
 * @param length         length of data block to brocess
 * @param previousCrc32  previous CRC value or 0 for the first block
 * @return uint32_t
 */
uint32_t crc32_fast(const void* data, size_t length, uint32_t previousCrc32);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // CRC32_H_INCLUDED
