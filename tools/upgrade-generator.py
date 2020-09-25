#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Upgrade file generator"""

import getpass
from intelhex import IntelHex
import click
import core.signature as sig
from core.blsection import *
__author__ = "Mike Tolkachev <contact@miketolkachev.dev>"
__copyright__ = "Copyright 2020 Crypto Advance GmbH. All rights reserved"
__version__ = "1.0.0"


@click.group()
@click.version_option(__version__, message="%(version)s")
# @click.command(no_args_is_help=True)
def cli():
    """Upgrade file generator."""


@cli.command(
    'gen',
    short_help='generate a new upgrade file'
)
@click.option(
    '-b', '--bootloader', 'bootloader_hex',
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
    '-k', '--private-key', 'key_pem',
    type=click.File('rb'),
    help='Private key in PEM container.',
    metavar='<file.pem>'
)
@click.option(
    '-p', '--platform',
    type=str,
    help='Platform identifier, i.e. stm32f469disco.',
    metavar='<platform>'
)
@click.argument(
    'upgrade_file',
    required=True,
    type=click.File('wb'),
    metavar='<upgrade_file.bin>'
)
def generate(upgrade_file, bootloader_hex, firmware_hex, platform, key_pem):
    """This command generates an upgrade file from given firmware files
    in Intel HEX format. It is required to specify at least one firmware
    file: Firmware or Bootloader.

    In addition, if a private key is provided it is used to sign produced
    upgrade file. Private key should be in PEM container with or without
    encryption.
    """

    # Load private key if needed
    seckey = None
    if key_pem:
        seckey = load_seckey(key_pem)

    # Create payload sections from HEX files
    sections = []
    if bootloader_hex:
        sections.append(create_payload_section(
            bootloader_hex, 'boot', platform))
    if firmware_hex:
        sections.append(create_payload_section(
            firmware_hex, 'main', platform))
    if not len(sections):
        raise click.ClickException("No input file specified")

    # Sign firmware if requested
    if seckey:
        do_sign(sections, seckey)

    # Write upgrade file to disk
    write_sections(upgrade_file, sections)


@ cli.command(
    'sign',
    short_help='sign an existing upgrade file'
)
@ click.option(
    '-k', '--private-key', 'key_pem',
    required=True,
    type=click.File('rb'),
    help='Private key in PEM container used to sign produced upgrade file.',
    metavar='<filename.pem>'
)
@ click.argument(
    'upgrade_file',
    required=True,
    type=click.File('rb+'),
    metavar='<upgrade_file.bin>'
)
def sign(upgrade_file, key_pem):
    """This command adds a signature to an existing upgrade file. Private key
    should be provided in PEM container with or without encryption.

    The signature is checked for duplication, and any duplicating signatures
    are removed automatically.
    """

    # Load sections from firmware file
    sections = load_sections(upgrade_file)

    # Load private key and sign firmware
    seckey = load_seckey(key_pem)
    do_sign(sections, seckey)

    # Write new upgrade file to disk
    upgrade_file.truncate(0)
    upgrade_file.seek(0)
    write_sections(upgrade_file, sections)


@ cli.command(
    'dump',
    short_help='dump sections and signatures from upgrade file'
)
@ click.argument(
    'upgrade_file',
    required=True,
    type=click.File('rb'),
    metavar='<upgrade_file.bin>'
)
def dump(upgrade_file):
    """ This command dumps information regarding firmware sections and lists
    signatures with public key fingerprints.
    """

    sections = load_sections(upgrade_file)
    for s in sections:
        version_str = s.version_str
        print(f'SECTION "{s.name}"')
        print(f'  attributes: {s.attributes_str}')
        if s.version_str:
            print(f'  version: {s.version_str}')
        if isinstance(s, SignatureSection):
            sigs = [f"{f.hex()}: {s.hex()}" for f, s in s.signatures.items()]
            print("  signatures:\n    " + "\n    ".join(sigs))


def create_payload_section(hex_file, section_name, platform):
    ih = IntelHex(hex_file)
    attr = {'bl_attr_base_addr': ih.minaddr()}
    if platform:
        attr['bl_attr_platform'] = platform
    entry = ih.start_addr.get('EIP', ih.start_addr.get('IP', None))
    if isinstance(entry, int):
        attr['bl_attr_entry_point'] = entry
    exp_len = ih.maxaddr() - ih.minaddr() + 1
    if exp_len > MAX_PAYLOAD_SIZE:
        raise click.ClickException(f"Error while parsing '{hex_file.name}'")
    pl_bytes = ih.tobinstr()
    if len(pl_bytes) != exp_len:
        raise click.ClickException(f"Error while parsing '{hex_file.name}'")
    return PayloadSection(name=section_name, payload=pl_bytes, attributes=attr)


def load_seckey(key_pem):
    data = key_pem.read()
    if(sig.is_pem_encrypted(data)):
        password = getpass.getpass("Passphrase:").encode('ascii')
        try:
            seckey = sig.seckey_from_pem(data, password)
        except InvalidPassword:
            raise click.ClickException("Passphrase invalid")
        return seckey
    return sig.seckey_from_pem(data)


def write_sections(upgrade_file, sections):
    for sect in sections:
        upgrade_file.write(sect.serialize())


def load_sections(upgrade_file):
    file_data = upgrade_file.read()
    offset = 0
    sections = []
    while offset < len(file_data):
        sect, offset = Section.deserialize(file_data, offset)
        sections.append(sect)
    return sections


def do_sign(sections, seckey):
    # Check sections
    if not len(sections):
        raise click.ClickException("Upgrade file is empty")
    if not isinstance(sections[-1], SignatureSection):
        sections.append(SignatureSection())
    sig_section = sections[-1]
    pl_sections = sections[:-1]
    for sect in pl_sections:
        if not isinstance(sect, PayloadSection):
            err = "Unexpected section within payload sections"
            raise click.ClickException(err)

    # Sign payload sections and store signature in signature section
    msg = make_signature_message(pl_sections)
    fp = pubkey_fingerprint_from_seckey(seckey)
    if fp in sig_section.signatures:
        err = "Upgrade file is already signed using this key"
        raise click.ClickException(err)
    sig_section.signatures[fp] = sig.sign(msg, seckey)


if __name__ == '__main__':
    cli()
