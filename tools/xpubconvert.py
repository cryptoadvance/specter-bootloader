"""Convert xpub string to uncompressed public key array ready to copy-paste into pubkeys.c file"""
import sys
from embit import bip32

def xpub_to_pubarray(xpub):
    xpub = bip32.HDKey.from_string(xpub)
    pub = xpub.key
    pub.compressed = False
    arr = pub.serialize()
    key_string = (", ".join([f"0x{b:02X}U" for b in arr]))
    print("{.bytes = {" + key_string + "}};")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} xpub_string")
        sys.exit(1)
    xpub_to_pubarray(sys.argv[1])
