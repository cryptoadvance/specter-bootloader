#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Generator of test vectors used in known answer tests

We are using the "secp256k1" library for signing because "cryptography"
(OpenSSL) does not support deterministic signatures yet. Produced signature is
verified by the "cryptography" library as a countermeasure against possible
implementation-dependent issues. E.g. the produced signature is invalid but
considered as "valid" by the same library that used for signing. That is
important because the same "secp256k1" library is used in Bootloader as well.
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from core import secp256k1

# Contents of PEM file, secp256k1 private key
secp256k1_seckey_pem = b"""
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIJe7XIVhQjs4qUROmg2b+Mkh1bZByyX+PHKrBd967041oAcGBSuBBAAK
oUQDQgAEC2FtQD1JVuarAHo24qelcxn6gjYZd7swc4D6Q/+PgyYktXBCJrsMh9+P
SbS/Rj0YvCkrzv2D8p9bgeDJAsZeIQ==
-----END EC PRIVATE KEY-----"""

ref_message = (b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed "
               b"ornare tincidunt pharetra. Mauris at molestie quam, et "
               b"placerat justo. Aenean maximus quam tortor, vel pellentesque "
               b"sapien tincidunt lacinia. Vivamus id dui at magna lacinia "
               b"lacinia porttitor eu justo. Phasellus scelerisque porta "
               b"augue. Vestibulum id diam vulputate, sagittis nibh eu, "
               b"egestas mi. Proin congue imperdiet dictum.")


def c_array(data):
    data_str = "0x" + ",0x".join("{:02X}U".format(b) for b in bytes(data))
    return "{" + data_str + "}"


def sig_to_compact(sig_der):
    sig_int = utils.decode_dss_signature(sig_der)
    r = sig_int[0].to_bytes(ec.SECP256K1().key_size // 8, byteorder='big')
    s = sig_int[1].to_bytes(ec.SECP256K1().key_size // 8, byteorder='big')
    return r + s


def sec_key_to_raw(sec_key):
    key_int = sec_key.private_numbers().private_value
    return key_int.to_bytes(sec_key.key_size // 8, byteorder='big')


def pub_key_to_raw(pub_key):
    key_int = pub_key.public_numbers()
    x = key_int.x.to_bytes(ec.SECP256K1().key_size // 8, byteorder='big')
    y = key_int.y.to_bytes(ec.SECP256K1().key_size // 8, byteorder='big')
    return b'\x04' + x + y


def ecdsa_secp256k1_vectors():
    sec_key = serialization.load_pem_private_key(
        secp256k1_seckey_pem, None, backend=default_backend())
    sec_key_raw = sec_key_to_raw(sec_key)
    pub_key = sec_key.public_key()
    pub_key_raw = pub_key_to_raw(pub_key)

    hash_algo = hashes.SHA256()
    hasher = hashes.Hash(hash_algo, default_backend())
    hasher.update(ref_message)
    digest = hasher.finalize()

    sig_obj = secp256k1.ecdsa_sign(digest, sec_key_raw)
    sig_der = secp256k1.ecdsa_signature_serialize_der(sig_obj)

    pub_key.verify(sig_der, digest, ec.ECDSA(utils.Prehashed(hash_algo)))
    sig_compact = sig_to_compact(sig_der)

    print("// ECDSA secp256k1 test vectors")
    print(f"static const uint8_t ref_digest[]={c_array(digest)};")
    print(f"static const uint8_t ref_seckey[]={c_array(sec_key_raw)};")
    print(f"static const uint8_t ref_pubkey[]={c_array(pub_key_raw)};")
    print(f"static const uint8_t ref_signature[]={c_array(sig_compact)};")


if __name__ == '__main__':
    ecdsa_secp256k1_vectors()
