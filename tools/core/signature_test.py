import pytest
from .signature import *
from . import secp256k1
from .blsection import PayloadSection

# Contents of PEM file, secp256k1 private key
secp256k1_seckey_pem = b"""
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIJe7XIVhQjs4qUROmg2b+Mkh1bZByyX+PHKrBd967041oAcGBSuBBAAK
oUQDQgAEC2FtQD1JVuarAHo24qelcxn6gjYZd7swc4D6Q/+PgyYktXBCJrsMh9+P
SbS/Rj0YvCkrzv2D8p9bgeDJAsZeIQ==
-----END EC PRIVATE KEY-----"""

# Contents of an encrypted PEM file, storing the same private key
# Passphrase is b'123456'
secp256k1_seckey_pem_encrypted = b"""
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,74F68651A39BCA4BE9E67CA3C7BBBD66

D1c8kc6tHhn7h9qCzaS335qT2RYatpOzQjE+iTZljinaaZc40WS7jNTgfn5jkPdE
9rM6jvdX0s/PbmZBy+1iX4OxzXn0lSStuXezleavVFMLeW/me7/vvX+oVmEaYkrv
r46GddMecCBW1Ur3wXHq77tr/+DaDZdZAJGSfuCWAY4=
-----END EC PRIVATE KEY-----
"""

# Reference private key, dumped using OpenSSL
ref_seckey = bytes([0x97, 0xbb, 0x5c, 0x85, 0x61, 0x42, 0x3b, 0x38,
                    0xa9, 0x44, 0x4e, 0x9a, 0x0d, 0x9b, 0xf8, 0xc9,
                    0x21, 0xd5, 0xb6, 0x41, 0xcb, 0x25, 0xfe, 0x3c,
                    0x72, 0xab, 0x05, 0xdf, 0x7a, 0xef, 0x4e, 0x35])

# Reference public key, dumped using OpenSSL
ref_pubkey = bytes([0x04,
                    0x0b, 0x61, 0x6d, 0x40, 0x3d, 0x49, 0x56, 0xe6,
                    0xab, 0x00, 0x7a, 0x36, 0xe2, 0xa7, 0xa5, 0x73,
                    0x19, 0xfa, 0x82, 0x36, 0x19, 0x77, 0xbb, 0x30,
                    0x73, 0x80, 0xfa, 0x43, 0xff, 0x8f, 0x83, 0x26,
                    0x24, 0xb5, 0x70, 0x42, 0x26, 0xbb, 0x0c, 0x87,
                    0xdf, 0x8f, 0x49, 0xb4, 0xbf, 0x46, 0x3d, 0x18,
                    0xbc, 0x29, 0x2b, 0xce, 0xfd, 0x83, 0xf2, 0x9f,
                    0x5b, 0x81, 0xe0, 0xc9, 0x02, 0xc6, 0x5e, 0x21])

# Fingerprint of the reference public key
ref_pubkey_fingerprint = bytes.fromhex('0576c1a90e1c9015563a283c7bb7e0f8')

# Wrong private key (differs by the last bit)
wrong_seckey = ref_seckey[:-1] + bytes([ref_seckey[len(ref_seckey) - 1] ^ 1])
# Public key corresponding to the wrong private key
wrong_pubkey = secp256k1.ec_pubkey_serialize(
    secp256k1.ec_pubkey_create(wrong_seckey), secp256k1.EC_UNCOMPRESSED)

# Reference message for signing
ref_message = (b"b77.777.777rc77-77.777.777rc77-1tudm93ag6fu6y7x4q6s87ar6zskyc"
               b"pmceltrmt7s577aa94yzan9zeyvfd")


def test_selfcheck():
    assert len(wrong_seckey) == 32
    assert len(wrong_pubkey) == 65
    assert wrong_seckey != ref_seckey
    assert wrong_pubkey != ref_pubkey


def test_is_pem_encrypted():
    assert not is_pem_encrypted(secp256k1_seckey_pem)
    assert is_pem_encrypted(secp256k1_seckey_pem_encrypted)


def test_seckey_from_pem():
    seckey = seckey_from_pem(secp256k1_seckey_pem)
    assert seckey == ref_seckey
    pubkey_ext = secp256k1.ec_pubkey_create(seckey)
    pubkey = secp256k1.ec_pubkey_serialize(pubkey_ext,
                                           secp256k1.EC_UNCOMPRESSED)
    assert pubkey == ref_pubkey
    seckey_dec = seckey_from_pem(secp256k1_seckey_pem_encrypted, b'123456')
    assert seckey_dec == ref_seckey


def test_pubkey_fingerprint():
    fp = pubkey_fingerprint(ref_pubkey)
    assert isinstance(fp, bytes)
    assert len(fp) == FINGERPRINT_LEN
    assert fp == ref_pubkey_fingerprint
    assert fp == pubkey_fingerprint_from_seckey(ref_seckey)
    assert pubkey_fingerprint(wrong_pubkey) != fp


def test_pubkey_fingerprint_from_seckey():
    fp = pubkey_fingerprint_from_seckey(ref_seckey)
    assert isinstance(fp, bytes)
    assert len(fp) == FINGERPRINT_LEN
    assert fp == ref_pubkey_fingerprint
    assert pubkey_fingerprint_from_seckey(wrong_seckey) != fp

def test_sign_verify():
    signature = sign(ref_message, ref_seckey)
    assert isinstance(signature, bytes)
    assert len(signature) == SIGNATURE_LEN
    assert verify(signature, ref_message, ref_pubkey)
    assert not verify(signature, ref_message, wrong_pubkey)
    wrong_signature = sign(ref_message, wrong_seckey)
    assert not verify(wrong_signature, ref_message, ref_pubkey)
