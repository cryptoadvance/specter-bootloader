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

@click.command(no_args_is_help=True)
@click.version_option(__version__, message="%(version)s")
@click.option(
    '-b', '--bootloader',
    type=click.File('r'),
    help='Intel HEX file containing Bootloader. '
         'If not provided, an upgrade file will contain only the Firmware.',
)
@click.option(
    '-f', '--firmware',
    type=click.File('r'),
    help='Intel HEX file containing Firmware. '
         'If not provided, an upgrade file will contain only the Bootloader.',
)
@click.option(
    '-s', '--sign',
    type=click.File('rb'),
    help='Sign with a private key provided in a PEM file. '
         'This option may be used without HEX files to add a signature to '
         'an existing upgrade file.',
)
@click.option(
    '-p', '--passphrase',
    help='Passphrase used to decrypt the private key. '
         'Results in error if the private key is not encrypted.',
)
@click.option(
    '-a', '--ask-passphrase', 'ask_passphrase',
    flag_value=True, default=False,
    help='Requests a passphrase when it is needed to decrypt the private key.'
)
def upgrade_generator(bootloader, firmware, sign, passphrase, ask_passphrase):
    """Upgrade file generator"""

    print("Processing...")

if __name__ == '__main__':
    upgrade_generator()
