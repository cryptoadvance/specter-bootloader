#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Script making firmware for one-step initial programming"""

from intelhex import IntelHex
import click
from core.integritychk import *
from core.memmap import *
from core.blsection import MAX_PAYLOAD_SIZE
__author__ = "Mike Tolkachev <contact@miketolkachev.dev>"
__copyright__ = "Copyright 2020 Crypto Advance GmbH. All rights reserved"
__version__ = "1.0.0"

# Types representing sequence of bytes, for type checking
_byteslike = (bytes, bytearray)


@click.group()
@click.version_option(__version__, message="%(version)s")
def cli():
    """Makes firmware for one-step initial programming."""


@cli.command()
@click.option(
    '-s', '--startup', 'startup_hex',
    required=True,
    type=click.File('r'),
    help='Intel HEX file containing the Start-up code.',
    metavar='<file.hex>'
)
@click.option(
    '-b', '--bootloader', 'bootloader_hex',
    required=True,
    type=click.File('r'),
    help='Intel HEX file containing the Bootloader.',
    metavar='<file.hex>'
)
@click.option(
    '-f', '--firmware', 'firmware_hex',
    type=click.File('r'),
    help='Intel HEX file containing the Main Firmware.',
    metavar='<file.hex>'
)
@click.option(
    '-bin', '--bin-output', 'bin_out',
    required=False,
    is_flag=True,
    default=False,
    help='Outputs firmware in raw binary format.'
)
@click.argument(
    'out_file',
    required=True,
    type=click.STRING,
    metavar='<output_file_name>'
)
def combine(out_file, startup_hex, bootloader_hex, firmware_hex, bin_out):
    """This command makes a firmare file for initial programming of a "clean"
    defice. The firmware file is made by combining together the Start-up code,
    the Bootloader, and, optionally, the Main Firmware.
    """

    # Create initial firmware: begin with a HEX file of the Start-up code
    out_ih = IntelHex(startup_hex)

    # Read and process a HEX file of the Bootloader
    bootloader_ih = IntelHex(bootloader_hex)
    memmap = get_memmap(intelhex_to_bytes(bootloader_ih))
    intelhex_add_icr(bootloader_ih, memmap['bootloader_size'])
    out_ih.merge(bootloader_ih, overlap='ignore')

    # Read and process a HEX file of the Main Firmware if specified
    if firmware_hex:
        main_ih = IntelHex(firmware_hex)
        if main_ih.minaddr() != memmap['main_firmware_start']:
            raise click.ClickException(
                "Main Firmware is incomatible with the Bootloader")
        intelhex_add_icr(main_ih, memmap['main_firmware_size'])
        out_ih.merge(main_ih, overlap='ignore')

    # Write resulting firmware in HEX or binary format
    if bin_out:
      file_obj = open(out_file, "wb")
      file_obj.write(intelhex_to_bytes(out_ih))
      file_obj.close()
    else:
      out_ih.write_hex_file(out_file)


def intelhex_to_bytes(ih_obj):
    """Converts IntelHex object to raw bytes with size checking."""

    if not isinstance(ih_obj, IntelHex):
        raise TypeError("Storage object should be IntelHex")
    data_len = ih_obj.maxaddr() - ih_obj.minaddr() + 1
    if data_len > MAX_PAYLOAD_SIZE:
        raise click.ClickException(f"Error while parsing '{hex_file.name}'")
    return ih_obj.tobinstr()


def intelhex_add_data(ih_obj, addr, data):
    """ Writes bytes-like data to IntelHex object at given address."""

    if not isinstance(ih_obj, IntelHex):
        raise TypeError("Storage object should be IntelHex")
    if not isinstance(data, _byteslike):
        raise TypeError("Data should be bytes-like")
    curr_addr = addr
    for byte in data:
        ih_obj[curr_addr] = byte
        curr_addr += 1
    pass


def intelhex_add_icr(ih_obj, storage_size):
    """Adds an integrity check record to to IntelHex object at address
    calculated using provided storage size.
    """

    if not isinstance(ih_obj, IntelHex):
        raise TypeError("Storage object should be IntelHex")

    data_len = ih_obj.maxaddr() - ih_obj.minaddr() + 1
    if data_len > MAX_PAYLOAD_SIZE or data_len + BL_ICR_SIZE > storage_size:
        raise click.ClickException(f"Error while parsing '{hex_file.name}'")

    icr = icr_create(intelhex_to_bytes(ih_obj))
    addr = ih_obj.minaddr() + storage_size - BL_ICR_SIZE
    intelhex_add_data(ih_obj, addr, icr)


if __name__ == '__main__':
    combine()
