# recoverable signatures and messagesigning stuff
# Requires secp256k1 with a flag
# ./configure --enable-module-recovery

from . import secp256k1
from binascii import b2a_base64, a2b_base64
from hashlib import sha256
from io import BytesIO

def compact_encode(i:int) -> bytes:
    """Encodes an integer as a compact int"""
    if i < 0:
        raise ValueError("integer can't be negative: {}".format(i))
    order = 0
    while (i>>(8*(2**order))):
        order += 1
    if order == 0:
        if i < 0xfd:
            return bytes([i])
        order = 1
    if order > 3:
        raise ValueError("integer too large: {}".format(i))
    return bytes([0xfc+order]) + i.to_bytes(2**order, 'little')

def compact_decode(b:bytes) -> int:
    """Converts bytes with compact int to int"""
    stream = io.BytesIO(b)
    i = stream.read(1)[0]
    if i >= 0xfd:
        bytes_to_read = 2**(i-0xfc)
        return int.from_bytes(stream.read(bytes_to_read), 'little')
    else:
        return i

def get_message_hash(msg: bytes) -> bytes:
    """Sign message with private key"""
    msghash = sha256(
        sha256(
            b'\x18Bitcoin Signed Message:\n' +
            compact_encode(len(msg)) + msg
        ).digest()
    ).digest()
    return msghash

def sign_recoverable(msg: bytes, prv: bytes, compressed:bool=True) -> str:
    msghash = get_message_hash(msg)
    res = secp256k1.ecdsa_sign_recoverable(msghash, prv)
    compact, flag = secp256k1.ecdsa_recoverable_signature_serialize_compact(res)
    c = 4 if compressed else 0
    first = bytes([27+flag+c])
    ser = first + compact
    return b2a_base64(ser).strip().decode()

def recover_pubkey(b64sig, msg):
    msghash = get_message_hash(msg)
    res = a2b_base64(b64sig)
    # convert first byte
    first = res[0]-27
    compressed = (first >= 4)
    flag = first % 4
    # compact signature
    sig_compact = res[1:]
    # secp signature
    sig = secp256k1.ecdsa_recoverable_signature_parse_compact(sig_compact, flag)
    # get pubkey
    pub = secp256k1.ecdsa_recover(sig, msghash)
    return pub
