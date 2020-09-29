import pytest
from .recovery import *

def test_recovery():
    # message hash to sign
    msg = b"Hello world"
    # private key to sign with
    pk = b"1"*32
    # get message signing
    b64sig = sign_recoverable(msg, pk)
    assert b64sig == "IKe84tb3CO7KPw7laQsh6Bjk0qNp5s1lId/iLcRBWmE1Nn8t6drArd1oiEkuPushNuDqQs8WB0kqxZ+MDmXBruQ="

    # recover pubkey from b64sig
    pub = recover_pubkey(b64sig, msg)
    assert pub == secp256k1.ec_pubkey_create(pk)
