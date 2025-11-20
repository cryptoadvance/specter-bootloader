#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Binary introspection tool for signature validation"""

import click
import sys
import os
from core.blsection import *
from core.signature import verify, pubkey_fingerprint
from core.integritychk import *
from parse_pubkeys import get_pubkey_info

# Import functions from upgrade-generator
import importlib.util
spec = importlib.util.spec_from_file_location("upgrade_generator", 
    os.path.join(os.path.dirname(__file__), "upgrade-generator.py"))
upgrade_gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade_gen)

# Import the needed functions
load_sections = upgrade_gen.load_sections
parse_sections = upgrade_gen.parse_sections
make_signature_message = upgrade_gen.make_signature_message

# Default signature thresholds
DEFAULT_BOOTLOADER_THRESHOLD = 2
DEFAULT_MAIN_FW_THRESHOLD = 1

@click.command()
@click.option(
    '--pubkeys', 'pubkeys_file',
    type=click.Path(exists=True),
    help='Path to pubkeys.c file (default: ../keys/production/pubkeys.c)'
)
@click.option(
    '--boot-threshold', 'boot_threshold',
    type=int,
    default=2,
    help='Required signatures for bootloader updates (default: 2)'
)
@click.option(
    '--main-threshold', 'main_threshold',
    type=int,
    default=1,
    help='Required signatures for main firmware updates (default: 1)'
)
@click.option(
    '--type', 'file_type',
    type=click.Choice(['upgrade', 'initial', 'auto']),
    default='auto',
    help='Binary file type (default: auto-detect)'
)
@click.option(
    '--debug', 'debug_mode',
    is_flag=True,
    help='Enable debug output with detailed information'
)
@click.argument(
    'binary_file',
    required=True,
    type=click.File('rb'),
    metavar='<binary_file>'
)
def introspect(binary_file, pubkeys_file, boot_threshold, main_threshold, file_type, debug_mode):
    """Introspects a binary file for signature validation."""
    
    # Default pubkeys file location
    if not pubkeys_file:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        pubkeys_file = os.path.join(script_dir, '../keys/production/pubkeys.c')
    
    # Load public keys
    try:
        pubkey_info = get_pubkey_info(pubkeys_file)
        print(f"📋 Loaded keys from: {pubkeys_file}")
        print(f"   Vendor keys: {len(pubkey_info['vendor'])}")
        print(f"   Maintainer keys: {len(pubkey_info['maintainer'])}")
        
        if debug_mode:
            print(f"\n🔍 Debug - Key details:")
            for key_type in ['vendor', 'maintainer']:
                print(f"   {key_type.title()} keys:")
                for owner, fp_hex, pubkey in pubkey_info[key_type]:
                    print(f"     {owner}: {fp_hex}")
                    print(f"       Key length: {len(pubkey)} bytes")
                    print(f"       Key starts: {pubkey[:8].hex()}")
                    print(f"       Key ends: {pubkey[-8:].hex()}")
    except Exception as e:
        print(f"❌ Failed to load public keys: {e}")
        sys.exit(1)
    
    # Handle file type detection/processing
    if file_type == 'upgrade':
        sections = load_sections(binary_file)
        analyze_upgrade_file(sections, pubkey_info, boot_threshold, main_threshold, debug_mode)
    elif file_type == 'initial':
        binary_data = binary_file.read()
        analyze_initial_firmware(binary_data, pubkey_info, debug_mode)
    else:  # auto-detect
        try:
            sections = load_sections(binary_file)
            analyze_upgrade_file(sections, pubkey_info, boot_threshold, main_threshold, debug_mode)
        except Exception as e:
            if debug_mode:
                print(f"🔍 Debug - Failed to parse as upgrade file: {e}")
            print("🔄 Trying as initial firmware binary...")
            binary_file.seek(0)
            try:
                binary_data = binary_file.read()
                analyze_initial_firmware(binary_data, pubkey_info, debug_mode)
            except Exception as e2:
                print(f"❌ Failed to parse as initial firmware: {e2}")
                if debug_mode:
                    print(f"🔍 Debug - Original upgrade file error: {e}")
                sys.exit(1)

def analyze_upgrade_file(sections, pubkey_info, boot_threshold, main_threshold, debug_mode):
    """Analyze upgrade file sections for signatures"""
    
    payload_sections, sig_section = parse_sections(sections)
    
    if not sig_section:
        print("❌ No signature section found")
        sys.exit(1)
    
    print(f"\n📦 Upgrade file analysis:")
    print(f"   Payload sections: {len(payload_sections)}")
    
    # Determine if this is bootloader or main firmware
    is_bootloader = any(s.name == 'boot' for s in payload_sections)
    threshold = boot_threshold if is_bootloader else main_threshold
    section_type = "Bootloader" if is_bootloader else "Main Firmware"
    
    print(f"   Type: {section_type}")
    print(f"   Required signatures: {threshold}")
    
    # Get signature message
    sig_message = make_signature_message(payload_sections)
    print(f"   Message hash: {sig_message.decode('ascii')}")
    
    if debug_mode:
        print(f"\n🔍 Debug - Payload sections:")
        for section in payload_sections:
            print(f"     Section '{section.name}': {len(section.payload)} bytes")
            print(f"       First 16 bytes: {section.payload[:16].hex()}")
    
    # Analyze signatures
    signatures = sig_section.signatures
    print(f"\n🔐 Signature analysis:")
    print(f"   Found {len(signatures)} signature(s)")
    
    if debug_mode:
        print(f"\n🔍 Debug - Raw signature data:")
        for i, (fingerprint, signature) in enumerate(signatures.items()):
            print(f"   Signature {i+1}:")
            print(f"     Fingerprint: {fingerprint.hex()}")
            print(f"     Signature length: {len(signature)} bytes")
            print(f"     Signature hex: {signature.hex()}")
    
    valid_sigs = 0
    used_keys = []
    
    # Create fingerprint lookup with owner names
    fingerprint_to_key = {}
    for key_type in ['vendor', 'maintainer']:
        for owner, fp_hex, pubkey in pubkey_info[key_type]:
            fingerprint_to_key[bytes.fromhex(fp_hex)] = (key_type, owner, pubkey)
    
    print(f"\n🔐 Signature verification:")
    for fingerprint, signature in signatures.items():
        fp_hex = fingerprint.hex()
        
        if fingerprint in fingerprint_to_key:
            key_type, owner, pubkey = fingerprint_to_key[fingerprint]
            
            # Verify signature
            try:
                is_valid = verify(signature, sig_message, pubkey)
                status = "✅" if is_valid else "❌"
                
                if is_valid:
                    valid_sigs += 1
                    used_keys.append((key_type, owner))
                
                print(f"   {status} {key_type} ({owner}): {fp_hex}")
                
                if debug_mode and is_valid:
                    print(f"       Signature verified successfully")
                elif debug_mode:
                    print(f"       Signature verification failed")
                
            except Exception as e:
                print(f"   ❌ {key_type} ({owner}): {fp_hex} (verification failed: {e})")
                if debug_mode:
                    print(f"       Error details: {e}")
        else:
            print(f"   ❓ Unknown: {fp_hex} (key not in pubkeys.c)")
    
    # Check threshold
    threshold_met = valid_sigs >= threshold
    status = "✅" if threshold_met else "❌"
    print(f"\n{status} Threshold verification:")
    print(f"   Valid signatures: {valid_sigs}/{threshold}")

    if used_keys:
        key_list = [f"{owner}({t})" for t, owner in used_keys]
        print(f"   Signed by: {', '.join(key_list)}")

    if threshold_met:
        print(f"   Result: Upgrade file is valid and can be installed")
    else:
        print(f"   Result: Upgrade file is invalid (insufficient signatures)")

    # Analyze embedded public keys in payload sections (do this before exit)
    analyze_embedded_keys(payload_sections, pubkey_info, debug_mode)

    # Exit with error if threshold not met
    if not threshold_met:
        sys.exit(1)

def analyze_embedded_keys(payload_sections, pubkey_info, debug_mode):
    """Analyze embedded public keys in payload sections"""

    print(f"\n🔑 Public key analysis:")
    print(f"   Searching for embedded keys in payload sections...")

    keys_found = {}  # Use dict to avoid duplicates by fingerprint
    is_bootloader = any(s.name == 'boot' for s in payload_sections)

    # Search through all payload sections
    for section in payload_sections:
        section_data = section.payload

        if debug_mode:
            print(f"\n🔍 Debug - Searching in section '{section.name}' ({len(section_data)} bytes)")

        for key_type in ['vendor', 'maintainer']:
            for owner, fp_hex, pubkey in pubkey_info[key_type]:
                # Search for the full public key (65 bytes)
                pos = section_data.find(pubkey)
                if pos >= 0:
                    if fp_hex not in keys_found:
                        keys_found[fp_hex] = {
                            'owner': owner,
                            'section': section.name,
                            'position': pos,
                            'types': set()
                        }
                    keys_found[fp_hex]['types'].add(key_type)

    if keys_found:
        print(f"   Found {len(keys_found)} embedded public key(s):")
        for fp_hex, info in keys_found.items():
            types_str = '/'.join(sorted(info['types']))
            print(f"   ✅ {info['owner']} ({types_str}): {fp_hex}")
            if debug_mode:
                print(f"       Section: '{info['section']}'")
                print(f"       Offset: 0x{info['position']:08x}")

        print(f"\n✅ Key verification:")
        print(f"   Result: Upgrade contains the public keys needed for future upgrade verification")
    else:
        if is_bootloader:
            print("   ❌ No known public keys found in bootloader upgrade")
            print("   Warning: This bootloader upgrade does not contain expected public keys!")
        else:
            print("   ℹ️  No public keys found (expected for main firmware upgrades)")
            print("   Note: Main firmware upgrades don't include the bootloader.")
            print("         Public keys remain in the existing bootloader and continue")
            print("         to verify future upgrades.")

def analyze_initial_firmware(binary_data, pubkey_info, debug_mode):
    """Analyze initial firmware binary"""

    print(f"\n📦 Initial firmware analysis:")
    print(f"   Binary size: {len(binary_data)} bytes")
    
    # Look for ICR (Integrity Check Record) at the end
    if len(binary_data) < 32:
        print("❌ Binary too small to contain ICR")
        return
    
    # Check for INTG magic (from integritychk.py)
    intg_magic = int.from_bytes(binary_data[-32:-28], 'little')
    if intg_magic == 0x47544E49:  # "INTG" in little endian
        print("✅ Found ICR (Integrity Check Record)")
        
        # Parse ICR structure (simplified)
        struct_rev = int.from_bytes(binary_data[-28:-24], 'little')
        print(f"   ICR structure revision: {struct_rev}")
        
        if debug_mode:
            pl_ver = int.from_bytes(binary_data[-24:-20], 'little')
            pl_size = int.from_bytes(binary_data[-20:-16], 'little')
            pl_crc = int.from_bytes(binary_data[-16:-12], 'little')
            
            print(f"\n🔍 Debug - ICR details:")
            print(f"   Payload version: {pl_ver}")
            print(f"   Payload size: {pl_size} bytes")
            print(f"   Payload CRC32: 0x{pl_crc:08x}")
            
            # Verify CRC if possible
            if pl_size <= len(binary_data) - 32:
                import zlib
                actual_crc = zlib.crc32(binary_data[:pl_size]) & 0xffffffff
                crc_valid = actual_crc == pl_crc
                status = "✅" if crc_valid else "❌"
                print(f"   CRC verification: {status} (calculated: 0x{actual_crc:08x})")
        
        # Search for embedded public keys
        print(f"\n� Public key analysis:")
        print(f"   Searching for embedded keys...")
        
        keys_found = {}  # Use dict to avoid duplicates by fingerprint
        
        for key_type in ['vendor', 'maintainer']:
            for owner, fp_hex, pubkey in pubkey_info[key_type]:
                # Search for the full public key (65 bytes)
                pos = binary_data.find(pubkey)
                if pos >= 0:
                    if fp_hex not in keys_found:
                        keys_found[fp_hex] = {
                            'owner': owner,
                            'position': pos,
                            'types': set()
                        }
                    keys_found[fp_hex]['types'].add(key_type)
        
        if keys_found:
            print(f"   Found {len(keys_found)} embedded public keys:")
            for fp_hex, info in keys_found.items():
                types_str = '/'.join(sorted(info['types']))
                print(f"   ✅ {info['owner']} ({types_str}): {fp_hex}")
                if debug_mode:
                    print(f"       Location: 0x{info['position']:08x}")
                    
                    # Show context around the key
                    pos = info['position']
                    context_start = max(0, pos - 32)
                    context_end = min(len(binary_data), pos + 65 + 32)
                    context = binary_data[context_start:context_end]
                    
                    print(f"       Context around key:")
                    for i in range(0, min(len(context), 128), 16):  # Show first 8 lines
                        chunk = context[i:i+16]
                        hex_str = ' '.join(f'{b:02x}' for b in chunk)
                        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                        offset = context_start + i
                        marker = " <-- KEY START" if context_start + i == pos else ""
                        print(f"         {offset:08x}: {hex_str:<48} {ascii_str}{marker}")
            
            print(f"\n✅ Key verification:")
            print(f"   Result: Initial firmware contains the public keys needed for upgrade verification")
            
        else:
            print("❌ No known public keys found in initial firmware")
            print("   Result: This firmware may not support signed upgrades")
        
    else:
        print("❌ No valid ICR found")
        print("   Result: This may not be a valid initial firmware binary")

if __name__ == '__main__':
    introspect()
