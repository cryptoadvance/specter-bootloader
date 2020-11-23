"""Bootloader integrity check functions."""

from ctypes import *
import zlib
from .blsection import *

# Types representing sequence of bytes, for type checking
_byteslike = (bytes, bytearray)

# Magic word, "INTG" in LE
_BL_ICR_MAGIC = 0x47544E49
# Structure revision
_STRUCT_REV = 1
# Size of integrity check record
_BL_ICR_SIZE = 32
# Size of version check record
_BL_VCR_SIZE = 32
# Total overhead from all metadata stored together with firmware
BL_FW_SECT_OVERHEAD = (_BL_ICR_SIZE+_BL_VCR_SIZE)
# Offset of ICR record from the end of firmware section
BL_ICR_OFFSET_FROM_END = (_BL_ICR_SIZE+_BL_VCR_SIZE)


class _bl_icr_sect_t(LittleEndianStructure):
    """One section of integrity check record."""

    _pack_ = 1        # Pack structure
    _fields_ = [('pl_size', c_uint32),
                ('pl_crc', c_uint32)]


class _bl_integrity_check_rec_t(LittleEndianStructure):
    """Integrity check record."""

    _pack_ = 1        # Pack structure
    _CRC_SIZE = 4     # CRC32 size in bytes
    _fields_ = [('magic', c_uint32),
                ('struct_rev', c_uint32),
                ('pl_ver', c_uint32),
                ('main_sect', _bl_icr_sect_t),
                ('aux_sect',  _bl_icr_sect_t),
                ('struct_crc', c_uint32)]

    def __init__(self):
        super(_bl_integrity_check_rec_t, self).__init__(
            magic=_BL_ICR_MAGIC,
            struct_rev=_STRUCT_REV,
            pl_ver=VERSION_NA,
            main_sect=_bl_icr_sect_t(pl_size=0, pl_crc=0),
            aux_sect=_bl_icr_sect_t(pl_size=0, pl_crc=0),
            struct_crc=0)

    def serialize(self):
        data = bytes(self)[:sizeof(self) - self._CRC_SIZE]
        self.struct_crc = zlib.crc32(data)
        return bytes(self)


def icr_create(firmware):
    """Creates and returns integrity check record for the firmware"""

    if not isinstance(firmware, _byteslike):
        raise TypeError("Firmware should be bytes-like")

    icr = _bl_integrity_check_rec_t()
    icr.pl_ver = find_payload_version(firmware)
    icr.main_sect.pl_size = len(firmware)
    icr.main_sect.pl_crc = zlib.crc32(firmware)
    return icr.serialize()
