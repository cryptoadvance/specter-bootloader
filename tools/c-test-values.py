#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Generator of test values for test/test_bl_signature.cpp
"""

import core.signature as sig
import core.secp256k1 as secp256k1

REF_N_SIGS = 3

# Contents of "vend1.pem" test key
vend1_pem = b"""
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIC4JxykDEKwS+n4eOGav5BnBvAqUbu6qJxmQOlVXwB2ooAcGBSuBBAAK
oUQDQgAExBE/LJYfycUlI0T2JmyKszTUHW1/6SN5UVFSL3xmlsbfAImab5aZ8f/T
mG4LwN558d/wBcVVlW0lFSG8WKwamw==
-----END EC PRIVATE KEY-----"""

# Contents of "vend2.pem" test key
vend2_pem = b"""
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIKMojR+vpvibosaRNnVcJLTyPzFKVACKxf+7Bc2FbNvtoAcGBSuBBAAK
oUQDQgAEWYaV0VeKsfut61No4xO2xjuD0w41MAcykUzsPNmN4r3mTiykPb/0PtU7
8qxACJbnTDaZnbw24UYp2P1YrnvtgA==
-----END EC PRIVATE KEY-----"""

# Contents of "vend3.pem" test key
vend3_pem = b"""
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIIA01AAab7WqgbZGWR6KOmn0kFs14TRVGC6gcpclsK9doAcGBSuBBAAK
oUQDQgAET8aLjKXOdMZQxGkKYlXdhvMlZqEzYguDTGAJb9I/wB+g5xmLFjnkZSB6
sXd3cgo1h+MVis5WrWkUqbhYE3LeXg==
-----END EC PRIVATE KEY-----"""

# Secret keys
sec_key_pems = [vend1_pem, vend2_pem, vend3_pem]

# Reference message for signing
ref_message = (b"b77.777.777rc77-77.777.777rc77-1tudm93ag6fu6y7x4q6s87ar6zskyc"
               b"pmceltrmt7s577aa94yzan9zeyvfd")

btc_pubkey_banner = """
// The following public keys are exported from a BIP32 wallet with the seed:
// "ripple ask sword jaguar federal fork awake hundred galaxy sadness ice live"
"""

btc_pubkey1 = (("03c1034adc4b7e3ac065537cf9f3a9f6525b53edbda8384f23f376087bef"
                "939d32"),
               "Corresponds to m/0/0, 1H1Yk1PBigBezZZ1712pyoguX6G2uznySV")

btc_pubkey2 = (("02c67707514c44bce9a4e08608219f9aca26a7b8d402eb6bf08cf0eb5aca"
                "0aa68b"),
               "Corresponds to m/0/1, 1M6CfqkahaHJvPhp34QFMGEsTmdLATgkPf")

# Corresponds to m/0/2, 17PW4JcbNnRwKCaCPadgnnevWhgQN6oSY6
btc_pubkey3 = (("03fc83dff8b84e13425e9bb60fac5579bd5b10d727692eab1eb8e40f61ad"
                "5dae29"),
               "Corresponds to m/0/2, 17PW4JcbNnRwKCaCPadgnnevWhgQN6oSY6")

# Bitcoin public keys
btc_pubkeys = [btc_pubkey1, btc_pubkey2, btc_pubkey3]


def c_array(data):
    data_str = "0x" + ",0x".join("{:02X}U".format(b) for b in bytes(data))
    return "{" + data_str + "}"


def bl_signature_test_values():
    assert REF_N_SIGS == len(sec_key_pems)
    print("// The reference contents of Signature section (signature records)")
    print("static const signature_rec_t ref_multisig_sigrecs[REF_N_SIGS] = {")
    for pem in sec_key_pems:
        sec_key = sig.seckey_from_pem(pem)
        fp = sig.pubkey_fingerprint_from_seckey(sec_key)
        s = sig.sign(ref_message, sec_key)
        print("{" + f".fingerprint={c_array(fp)},")
        print(f".signature={c_array(s)}" + "},")
    print("};")


def convert_btc_pubkeys():
    print(btc_pubkey_banner)
    for key_item in btc_pubkeys:
        print("// " + key_item[1])
        pubkey_obj = secp256k1.ec_pubkey_parse(bytes.fromhex(key_item[0]))
        pubkey = secp256k1.ec_pubkey_serialize(
            pubkey_obj, secp256k1.EC_UNCOMPRESSED)
        print("{" + f".bytes={c_array(pubkey)}" + "},")


if __name__ == '__main__':
    bl_signature_test_values()
    convert_btc_pubkeys()
