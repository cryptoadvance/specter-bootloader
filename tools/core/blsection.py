#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Data structures for Bootloader sections"""

from abc import ABC, abstractmethod
import pytest
from ctypes import *
import zlib
import sys
import hashlib

# Section magic word
BL_SECT_MAGIC = 0x54434553 # "SECT" in LE
# Structure revision
STRUCT_REV = 1

# Minimum allowed value ov version number
VERSION_MIN = 1
# Maximum allowed value ov version number
VERSION_MAX = 4199999999
# Version tag embedded somewhere inside payload firmware
VERSION_TAG = b'PAYLOADVERSION>>>'
# Number of decimal digits in ASCII encoding, following the version tag
VERSION_DIGITS = 10

# Mapping between attribute name and its (code, type)
_attributes = { 'bl_attr_algorithm' : (1, str) }
# Reverse lookup by attribute code
_attribute_names = {v[0]: k for k, v in _attributes.items()}

# Registers additional attributes for testing
@pytest.fixture()
def _add_test_attributes():
    global _attributes, _attribute_names
    _attributes = { **_attributes,
                    'a2': (0xa2, None),
                    'a3': (0xa3, int),
                    'a4': (0xa4, str) }
    _attribute_names = {v[0]: k for k, v in _attributes.items() }

def version_to_str(version_num):
    if version_num == 0:
        return ""
    elif version_num < VERSION_MIN or version_num > VERSION_MAX:
        raise ValueError("Version number is out of range")
    major  = version_num // (100 * 1000 * 1000)
    minor  = version_num // (100 * 1000) % 1000
    patch  = version_num // 100 % 1000
    rc_rev = version_num % 100
    ver_str = f"{major}.{minor}.{patch}"
    if rc_rev != 99:
        ver_str += f"-rc{rc_rev}"
    return ver_str

# /// Section header
# ///
# /// This structure has fixed size of 256 bytes. All 32-bit words are stored in
# /// little-endian format. CRC is calculated over first 252 bytes of this
# /// structure.
# typedef struct __attribute__((packed)) bl_section_ {
#   uint32_t magic;         ///< Magic word, BL_SECT_MAGIC
#   uint32_t struct_rev;    ///< Revision of structure format
#   char name[16];          ///< Name, zero terminated
#   uint32_t pl_ver;        ///< Payload version, 0 if not available
#   uint32_t pl_size;       ///< Payload size
#   uint32_t pl_crc;        ///< Payload CRC
#   uint8_t attr_list[216]; ///< Attributes, list of: { key, size [, value] }
#   uint32_t struct_crc;    ///< CRC of this structure using LE representation
# } bl_section_t;
class bl_section_t(LittleEndianStructure):
    _pack_ = 1        # Pack structure
    _CRC_SIZE = 4     # CRC32 size in bytes
    _PL_VER_SIZE = 4  # Size of payload version in bytes
    _NAME_SIZE = 16   # Name size in bytes

    _fields_ = [('magic',      c_uint32),
                ('struct_rev', c_uint32),
                ('name',       c_char * _NAME_SIZE),
                ('pl_ver',     c_uint32),
                ('pl_size',    c_uint32),
                ('pl_crc',     c_uint32),
                ('attr_list',  c_uint8 * 216),
                ('struct_crc', c_uint32)]

    def __init__(self):
        super(bl_section_t, self).__init__(magic = BL_SECT_MAGIC,
                                           struct_rev = STRUCT_REV)

    @staticmethod
    def _encode_int(value):
        return value.to_bytes((value.bit_length() + 7) // 8,
                              byteorder='little')

    def set_attributes(self, attributes):
        attr_list = []
        for key, value in attributes.items():
            key_byte, _ = _attributes[key]
            attr_list.append(key_byte)
            if value is None:
                data = []
            elif isinstance(value, int):
                data = list(self._encode_int(value))
            elif isinstance(value, str):
                data = list(value.encode('ascii'))
            else:
                data = list(value)
            if len(data) > 255:
                raise ValueError("Attribute size exceeded")
            attr_list.append(len(data))
            attr_list.extend(data)

        arr_size = sizeof(self.attr_list)
        if len(attr_list) <= arr_size:
            for i in range(arr_size):
                self.attr_list[i] = 0 if i >= len(attr_list) else attr_list[i]
        else:
            raise ValueError("Attributes do not fit in array")

    def get_attributes(self):
        attributes = {}
        attr_list = bytes(self.attr_list)
        while len(attr_list) > 0:
            key_byte, len_byte = attr_list[:2]
            if not key_byte:
                break
            value_buf = attr_list[2:2 + len_byte]
            attr_list = attr_list[2 + len_byte:]

            try:
                key = _attribute_names[key_byte]
                _, attr_type = _attributes[key]
            except KeyError:
                continue # Unknown attribute, skip it

            # Handle attribute according to its type
            if attr_type is None or not len_byte:
                attributes[key] = None
            elif attr_type is int:
                attributes[key] = int.from_bytes(value_buf, byteorder='little')
            elif attr_type is str:
                attributes[key] = value_buf.decode('ascii')
            else:
                attributes[key] = attr_type(value_buf)

        return attributes

    def calc_crc(self):
        data = bytes(self)[:sizeof(self) - self._CRC_SIZE]
        self.struct_crc = zlib.crc32(data)

    def check_crc(self):
        data = bytes(self)[:sizeof(self) - self._CRC_SIZE]
        crc = zlib.crc32(data)
        return crc == self.struct_crc

    def set_name_str(self, name_str):
        self.name = name_str.encode('ascii')

    def get_name_str(self):
        return self.name.decode('ascii')

    def serialize_name(self):
        return self.name + bytes(self._NAME_SIZE - len(self.name))

    def get_pl_ver_str(self):
        return version_to_str(self.pl_ver)

    def serialize_pl_ver(self):
        return self.pl_ver.to_bytes(self._PL_VER_SIZE, byteorder='little')

    def serialize(self):
        return bytes(self)


class bl_signature_rec_t(LittleEndianStructure):
    _pack_ = 1    # Pack structure
    _fields_ = [('fingerprint', c_uint8 * 16),
                ('signature',   c_uint8 * 64)]

class Section(ABC):
    def __init__(self):
        self._header = bl_section_t()
        super().__init__()

    @abstractmethod
    def _update_header(self):
        pass

    def get_hash_sentence(self):
        hash = hashlib.sha256(self.serialize()).digest()
        name_bytes = self._header.serialize_name()
        version_bytes = self._header.serialize_pl_ver()
        return name_bytes + version_bytes + hash

    @abstractmethod
    def _serialize_payload(self):
        pass

    def get_version_num(self):
        return self._header.pl_ver

    def get_version_str(self):
        return self._header.get_pl_ver_str()

    def serialize(self):
        self._update_header()
        return self._header.serialize() + self._serialize_payload()

class PayloadSection(Section):
    def __init__(self, name = "", payload = b'', attributes = None):
        super().__init__()

        if isinstance(name, str):
            self._header.name = name.encode('ascii')
        elif isinstance(name, bytes):
            self._header.name = name
        else:
            raise ValueError("Name must be str or bytes")

        if attributes is not None:
            self._header.set_attributes(attributes)

        if not isinstance(payload, bytes):
            raise TypeError("Payload must be of type bytes")

        self._payload = payload
        self._version_unknown = True
        self._update_header()

    def _find_payload_version(self):
        # Search for version tag in payload
        idx = self._payload.find(VERSION_TAG)
        if idx < 0:
            return 0 # Version is not available

        # Ensure that there is no more version tags
        idx2 = self._payload.find(VERSION_TAG, idx + 1)
        if idx2 >= 0:
            raise ValueError("Payload contains more than one version tag")

        # Skip version tag and decode digits
        idx += len(VERSION_TAG)
        if len(self._payload) < idx + VERSION_DIGITS:
            raise ValueError("Corrupted varsion tag in payload")
        version_num = int(self._payload[idx : (idx + VERSION_DIGITS)])
        if version_num < 0 or version_num > VERSION_MAX:
            raise ValueError("Version number is out of range")
        return version_num

    def _update_header(self):
        if self._version_unknown:
            self._version_unknown = False
            self._header.pl_ver = self._find_payload_version()
        self._header.pl_size = len(self._payload)
        self._header.pl_crc = zlib.crc32(self._payload)
        self._header.calc_crc()

    def _serialize_payload(self):
        return self._payload


if __name__ == '__main__':
    payload = b'Something useless' + VERSION_TAG + b'0102213405' + b'end'
    sect = PayloadSection("boot", payload)

    print(bytes(sect._header))
    print(bytes(sect._payload))

    print("name     =", sect._header.name)
    print("name    b=", bytes(sect._header.serialize_name()))
    print("version  =", sect._header.pl_ver)
    print("version b=", bytes(sect._header.serialize_pl_ver()))

    p = sect.get_hash_sentence()
    print(p)
    print(p.hex(), "len:", len(p))
    print("pl_size:", sect._header.pl_size, "pl_crc:", hex(sect._header.pl_crc))
    print("struct_crc:", hex(sect._header.struct_crc))
    print("header:", bytes(sect._header).hex())
