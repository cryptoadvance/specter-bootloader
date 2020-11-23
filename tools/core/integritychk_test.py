import pytest
from .integritychk import *

#Reference firmware containing embedded version tag
ref_firmware = (b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed "
                b"ornare tincidunt pharetra. Mauris at molestie quam, et "
                b"<version:tag10>0102213405</version:tag10>"
                b"placerat justo. Aenean maximus quam tortor, vel pellentesque "
                b"sapien tincidunt lacinia. Vivamus id dui at magna lacinia "
                b"lacinia porttitor eu justo. Phasellus scelerisque porta "
                b"augue. Vestibulum id diam vulputate, sagittis nibh eu, "
                b"egestas mi. Proin congue imperdiet dictum.")

# Reference integrity check record
ref_icr = bytes.fromhex(
    '494e5447'  # .magic
    '01000000'  # .struct_rev
    '1da71706'  # .pl_ver
    'ad010000'  # .main_sect.pl_size
    '22b922c7'  # .main_sect.pl_crc
    '00000000'  # .aux_sect.pl_size
    '00000000'  # .aux_sect.pl_crc
    '31731df9'  # .struct_crc
)


def test_icr_create():
    icr = icr_create(ref_firmware)
    assert icr == ref_icr
