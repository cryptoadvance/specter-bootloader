#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Upgrade file generator"""

__author__    = "Mike Tolkachev <contact@miketolkachev.dev>"
__copyright__ = "Copyright 2020 Crypto Advance GmbH. All rights reserved"
__version__   = "1.0.0"

from core.blsection import *
import core.signature as sig

import click
from tqdm import tqdm
from intelhex import IntelHex
import getpass

@click.group()
@click.version_option(__version__, message="%(version)s")
#@click.command(no_args_is_help=True)
def cli():
    """Upgrade file generator."""

@cli.command(
    'gen',
    short_help='generate a new upgrade file'
)
@click.option(
    '-b', '--bootloader', 'bootloader_hex',
    type=click.File('r'),
    help='Intel HEX file containing Bootloader.',
    metavar='<file.hex>'
)
@click.option(
    '-f', '--firmware', 'firmware_hex',
    type=click.File('r'),
    help='Intel HEX file containing Firmware.',
    metavar='<file.hex>'
)
@click.option(
    '-k', '--private-key', 'key_pem',
    type=click.File('rb'),
    help='Private key in PEM container.',
    metavar='<file.pem>'
)
@click.argument(
    'upgrade_file',
    required=True,
    type=click.File('wb+'),
    metavar='<upgrade_file.bin>'
)
def generate(upgrade_file, bootloader_hex, firmware_hex, key_pem):
    """This command generates an upgrade file from given firmware files
    in Intel HEX format. It is required to specify at least one firmware
    file: Firmware or Bootloader.

    In addition, if a private key is provided it is used to sign produced
    upgrade file. Private key should be in PEM container with or without
    encryption.
    """

    if not (bootloader_hex or firmware_hex):
        raise click.ClickException("No input file specified")

    # TODO: Create payload sections from HEX files
    # TODO: Serialize sections to .bin file

    # Sign created file if requested
    if key_pem:
        upgrade_file.seek(0)
        sign(upgrade_file, key_pem)
    else:
        upgrade_file.close()

@cli.command(
    'sign',
    short_help='sign existing upgrade file'
)
@click.option(
    '-k', '--private-key', 'key_pem',
    required=True,
    type=click.File('rb'),
    help='Private key in PEM container used to sign produced upgrade file.',
    metavar='<filename.pem>'
)
@click.argument(
    'upgrade_file',
    required=True,
    type=click.File('rb+'),
    metavar='<upgrade_file.bin>'
)
def sign(upgrade_file, key_pem):
    """This command adds a signature to an existing firmware file. Private key
    should be provided in PEM container with or without encryption.

    The signature is checked for duplication, and any duplicating signatures
    are removed automatically.
    """

    # TODO: Load sections from .bin file
    # TODO: Create signature section if absent
    # TODO: Add signature if not existant yet with given key
    # TODO: Serialize sections to .bin file
    pass

@cli.command(
    'dump',
    short_help='dump sections and signatures from upgrade file'
)
@click.argument(
    'upgrade_file',
    required=True,
    type=click.File('rb'),
    metavar='<upgrade_file.bin>'
)
def dump(upgrade_file):
    """ This command dumps information regarding firmware sections and lists
    signatures with public key fingerprints.
    """

    # TODO: Load sections from .bin file
    # TODO: Dump information about payload sections
    # TODO: Dump contents of signature section
    pass

def load_seckey(key_pem):
    if not key_pem:
        return None
    data = key_pem.read()
    if(sig.is_pem_encrypted(key_pem)):
        password = getpass.getpass("Passphrase:")
        return sig.seckey_from_pem(data, password)
    return sig.seckey_from_pem(data)

def create_payload_section(hex_file):
    pass

if __name__ == '__main__':
    cli()
