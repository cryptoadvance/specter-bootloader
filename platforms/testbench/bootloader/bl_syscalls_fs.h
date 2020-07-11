/**
 * @file       bl_syscalls_fs.h
 * @brief      File system-specific definitions included when FatFs is disabled
 * @author     Mike Tolkachev <contact@miketolkachev.dev>
 * @copyright  Copyright 2020 Crypto Advance GmbH. All rights reserved.
 */

#ifndef BL_SYSCALLS_FS_H_INCLUDED
#define BL_SYSCALLS_FS_H_INCLUDED

#ifdef _WIN32
  #include "dirent_win.h"
#else
  #include <dirent.h>
#endif

/// Type for file size, unsigned
typedef unsigned long int bl_fsize_t;
/// Type for file offset, signed
typedef long int bl_foffset_t;
/// File object, unused
typedef int bl_file_obj_t;
/// File handle
typedef FILE* bl_file_t;

/// Context of file searching functions
typedef struct bl_ffind_ctx_struct {
  DIR *dir; ///< POSIX directory object
} bl_ffind_ctx_t;

#endif // BL_SYSCALLS_FS_H_INCLUDED
