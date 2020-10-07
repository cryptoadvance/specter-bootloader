#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Generator of test values for test/test_bl_signature.cpp
"""

import core.signature as sig

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
sec_key_pems = [ vend1_pem, vend2_pem, vend3_pem]

# Reference message for signing
ref_message = (b"b77.777.777rc77-77.777.777rc77-1tudm93ag6fu6y7x4q6s87ar6zskyc"
               b"pmceltrmt7s577aa94yzan9zeyvfd")


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

if __name__ == '__main__':
    bl_signature_test_values()
