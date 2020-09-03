import pytest
from .memmap import *

# Reference firmware containing embedded memory map
ref_firmware = (b'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'
                b'<memory_map:lebin>'  # .opening
                b'\x04'                # .elem_size
                b'\x51\x86\xf6\x00'    # .bootloader_size
                b'\x4b\xca\x9b\xa3'    # .main_firmware_start
                b'\x7c\xe6\xe9\x00'    # .main_firmware_size
                b'</memory_map:lebin>'  # .closing
                b'Sed ornare tincidunt pharetra. Mauris at molestie quam, et')

# Reference memory map
ref_memmap = {
    'bootloader_size': 0x00f68651,
    'main_firmware_start': 0xa39bca4b,
    'main_firmware_size': 0x00e9e67c
}


def test_get_memmap_valid():
    memmap = get_memmap(ref_firmware)
    assert memmap == ref_memmap
