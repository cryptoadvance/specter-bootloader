#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Parse public keys from bootloader/pubkeys.c file"""

import re
import hashlib
from typing import List, Dict, Tuple

def parse_pubkeys_c(file_path: str) -> Dict[str, List[Tuple[str, bytes]]]:
    """Parse public keys from pubkeys.c file
    
    Returns:
        Dict with 'vendor' and 'maintainer' keys, each containing list of (owner, key_bytes) tuples
    """
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Find vendor keys
    vendor_match = re.search(
        r'static const bl_pubkey_t vendor_pubkey_list\[\]\s*=\s*\{(.*?)\};',
        content, 
        re.DOTALL
    )
    
    # Find maintainer keys  
    maintainer_match = re.search(
        r'static const bl_pubkey_t maintainer_pubkey_list\[\]\s*=\s*\{(.*?)\};',
        content,
        re.DOTALL
    )
    
    result = {
        'vendor': [],
        'maintainer': []
    }
    
    if vendor_match:
        result['vendor'] = parse_key_array(vendor_match.group(1))
    
    if maintainer_match:
        result['maintainer'] = parse_key_array(maintainer_match.group(1))
    
    return result

def parse_key_array(array_content: str) -> List[Tuple[str, bytes]]:
    """Parse array of bl_pubkey_t structures with owner comments
    
    Returns:
        List of (owner_name, key_bytes) tuples
    """
    
    keys = []
    
    # Split content into lines for easier parsing
    lines = array_content.split('\n')
    current_owner = "Unknown"
    
    for i, line in enumerate(lines):
        # Look for comment lines that indicate owner
        comment_match = re.search(r'//\s*(.+)', line.strip())
        if comment_match:
            current_owner = extract_owner_from_comment(line)
        
        # Look for key structure start
        if '{.bytes = {' in line:
            # Collect all hex bytes for this key across multiple lines
            hex_values = []
            j = i
            while j < len(lines) and '}}' not in lines[j]:
                hex_matches = re.findall(r'0x([0-9A-Fa-f]{2})U?', lines[j])
                hex_values.extend(hex_matches)
                j += 1
            
            # Get the closing line too
            if j < len(lines):
                hex_matches = re.findall(r'0x([0-9A-Fa-f]{2})U?', lines[j])
                hex_values.extend(hex_matches)
            
            if len(hex_values) == 65:  # Uncompressed public key
                key_bytes = bytes([int(h, 16) for h in hex_values])
                keys.append((current_owner, key_bytes))
                current_owner = "Unknown"  # Reset for next key
    
    return keys

def extract_owner_from_comment(comment_line):
    """Extract owner name from comment line"""
    # Remove // and strip whitespace
    comment = comment_line.strip().replace('//', '').strip()
    
    # Replace whitespace with underscores for consistency
    comment = comment.replace(' ', '_')
    
    # Skip generic comments (but not "Backup m/99h" style comments)
    if any(skip in comment.lower() for skip in ['corresponding', 'the_following', 'bip39']):
        return 'Unknown'
    
    return comment

def pubkey_to_fingerprint(pubkey_bytes: bytes) -> str:
    """Convert public key to fingerprint (hash160)"""
    
    if len(pubkey_bytes) != 65 or pubkey_bytes[0] != 0x04:
        raise ValueError("Invalid uncompressed public key format")
    
    # Use SHA256 first 16 bytes like core.signature does
    sha256_hash = hashlib.sha256(pubkey_bytes).digest()
    return sha256_hash[:16]  # Return first 16 bytes, not RIPEMD160

def get_pubkey_info(file_path: str) -> Dict[str, List[Tuple[str, str, bytes]]]:
    """Get public key info with fingerprints and owners
    
    Returns:
        Dict with 'vendor' and 'maintainer' keys, each containing list of (owner, fingerprint_hex, pubkey_bytes)
    """
    
    keys = parse_pubkeys_c(file_path)
    
    result = {
        'vendor': [],
        'maintainer': []
    }
    
    for key_type in ['vendor', 'maintainer']:
        for owner, pubkey in keys[key_type]:
            fingerprint = pubkey_to_fingerprint(pubkey)
            result[key_type].append((owner, fingerprint.hex(), pubkey))
    
    return result

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pubkeys.c>")
        sys.exit(1)
    
    pubkey_info = get_pubkey_info(sys.argv[1])
    
    print("Vendor Keys:")
    for i, (owner, fingerprint, pubkey) in enumerate(pubkey_info['vendor']):
        print(f"  {i+1}. {owner}: {fingerprint} ({len(pubkey)} bytes)")
    
    print("\nMaintainer Keys:")
    for i, (owner, fingerprint, pubkey) in enumerate(pubkey_info['maintainer']):
        print(f"  {i+1}. {owner}: {fingerprint} ({len(pubkey)} bytes)")
