"""Signature functions compliant with the format of Bootloader upgrade file."""

from . import secp256k1
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# Types representing sequence of bytes, for type checking
_byteslike = (bytes, bytearray)

# Length of public key signature in bytes
FINGERPRINT_LEN = 16
# Length of compact signature in bytes
SIGNATURE_LEN = 64
# Digital signature algorithm: secp256k1-sha256
DSA_SECP256K1_SHA256 = 'secp256k1-sha256'

class InvalidPassword(Exception):
    pass

def _validate_seckey(seckey):
    if not isinstance(seckey, _byteslike):
        raise TypeError("Private key should be bytes-like")
    if len(seckey) != 32:
        raise ValueError("Private key should be 32 bytes long")

def _validate_pubkey(pubkey):
    if not isinstance(pubkey, _byteslike):
        raise TypeError("Public key should be bytes-like")
    if len(pubkey) != 65:
        raise ValueError("Public key should be 65 bytes long")
    if pubkey[0] != 0x04:
        raise ValueError("Uncompressed pubkey should start with 0x04")

def _validate_message(message):
    if not isinstance(message, _byteslike):
        raise TypeError("Private key should be bytes-like")
    if not len(message):
        raise ValueError("Message should not be empty")

def _validate_signature(signature):
    if not isinstance(signature, _byteslike):
        raise TypeError("Signature should be bytes-like")
    if len(signature) != 64:
        raise ValueError("Signature should be empty 64 bytes long")

def _to_bytes(value):
    if isinstance(value, bytes):
        return value
    return bytes(value)

def _sha256(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    return digest.finalize()

def is_pem_encrypted(data):
    """Checks if PEM source is encrypted."""
    try:
        seckey_from_pem(data, password=None)
    except InvalidPassword:
        return True
    return False

def seckey_from_pem(data, password=None):
    """Loads a private key from PEM source and returns it as byte string."""
    try:
        key = serialization.load_pem_private_key(
            data, password, backend=default_backend() )
    except TypeError:
        raise InvalidPassword
    key_int = key.private_numbers().private_value
    return key_int.to_bytes(key.key_size // 8, byteorder='big')

def pubkey_from_seckey(seckey):
    """Returns a public key derived from given private key."""
    _validate_seckey(seckey)
    pubkey_ext = secp256k1.ec_pubkey_create(_to_bytes(seckey))
    return secp256k1.ec_pubkey_serialize(pubkey_ext, secp256k1.EC_UNCOMPRESSED)

def pubkey_fingerprint(pubkey):
    """Returns 128-bit fingerprint of a public key"""
    _validate_pubkey(pubkey)
    return (_sha256(pubkey))[:FINGERPRINT_LEN]

def pubkey_fingerprint_from_seckey(seckey):
    """Returns 128-bit fingerprint of a public key derived from given private
    key."""
    return pubkey_fingerprint(pubkey_from_seckey(seckey))

def sign(message, seckey):
    """Signs a message with given private key."""
    _validate_seckey(seckey)
    _validate_message(message)
    sig_obj = secp256k1.ecdsa_sign(_sha256(message), _to_bytes(seckey))
    return secp256k1.ecdsa_signature_serialize_compact(sig_obj)

def verify(signature, message, pubkey):
    """Verifies signature of a message with given public key."""
    _validate_signature(signature)
    _validate_message(message)
    _validate_pubkey(pubkey)
    pubkey_obj = secp256k1.ec_pubkey_parse(_to_bytes(pubkey))
    sig_obj = secp256k1.ecdsa_signature_parse_compact(_to_bytes(signature))
    hashcode = _sha256(message)
    return secp256k1.ecdsa_verify(sig_obj, hashcode, pubkey_obj)
