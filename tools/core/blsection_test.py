import pytest
from .blsection import *
from .blsection import _add_test_attributes

def test_version_to_str():
    assert version_to_str(102213405) == "1.22.134-rc5"
    assert version_to_str(1200001599) == "12.0.15"
    assert version_to_str(1) == "0.0.0-rc1"
    assert version_to_str(4199999999) == "41.999.999"
    assert version_to_str(0) == ""
    with pytest.raises(ValueError):
        version_to_str(VERSION_MAX + 1)
    with pytest.raises(ValueError):
        version_to_str(-1)

class Test_bl_section_t:
    def test_attributes(self, _add_test_attributes):
        attr = { 'bl_attr_algorithm' : "secp256k1-sha256",
                'a2' : None,
                'a3' : 123456789012,
                'a4' : "This is a simple text. END" }

        sect = bl_section_t()
        sect.set_attributes(attr)
        attr2 = sect.get_attributes()
        assert attr2 == attr

    def test_crc(self):
        sect = bl_section_t()
        sect.struct_crc = 0
        sect.calc_crc()
        assert sect.struct_crc != 0
        assert sect.check_crc()
        sect.struct_crc ^= 1
        assert not sect.check_crc()

    def test_name_op(self):
        sect = bl_section_t()
        sect.set_name_str("boot")
        assert sect.name == b'boot'
        assert sect.get_name_str() == "boot"
        ref_name_buf = b'boot\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        assert sect.serialize_name() == ref_name_buf

    def test_pl_ver_op(self):
        sect = bl_section_t()
        sect.pl_ver = 102213405 # 1.22.134-rc5
        assert sect.get_pl_ver_str() == "1.22.134-rc5"
        assert sect.serialize_pl_ver() == b'\x1d\xa7\x17\x06'

class TestPayloadSection:
    def test_get_version(self):
        payload = b'Something useless' + VERSION_TAG + b'0102213405' + b'end'
        sect = PayloadSection("boot", payload)
        assert sect.get_version_num() == 102213405
        assert sect.get_version_str() == "1.22.134-rc5"

    def test_get_hash_sentence(self):
        # p1 - valid payload
        # p2 - different version
        # p3 - different data (first byte changed)
        # p4 - different data (last byte missing)
        p1 = b'Something useless' + VERSION_TAG + b'0102213405' + b'end'
        p2 = b'Something useless' + VERSION_TAG + b'0102213406' + b'end'
        p3 = b'$omething useless' + VERSION_TAG + b'0102213405' + b'end'
        p4 = b'Something useless' + VERSION_TAG + b'0102213405' + b'en'

        # Reference hash sentence for p1 payload
        ref_sentence = ( b'boot\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                         b'\x00\x1d\xa7\x17\x06e\xf1\x93\xd0ax\xec\xdb\xbfK'
                         b'\xcc\xc9\xac\x1fS\x89\xc1\xfaS#M/V1~\x89E\t\x9cG'
                         b'\x95~' )

        assert PayloadSection("boot", p1).get_hash_sentence() == ref_sentence
        assert PayloadSection("boot", p2).get_hash_sentence() != ref_sentence
        assert PayloadSection("boot", p3).get_hash_sentence() != ref_sentence
        assert PayloadSection("boot", p4).get_hash_sentence() != ref_sentence
