import pytest
from .blsection import *
from .blsection import _bl_section_t
from .blsection import _bl_signature_rec_t
from .blsection import _add_test_attributes
from .blsection import _max_payload_size
from .signature import *

def test_version_to_str():
    assert version_to_str(102213405) == "1.22.134-rc5"
    assert version_to_str(1200001599) == "12.0.15"
    assert version_to_str(1) == "0.0.0-rc1"
    assert version_to_str(4199999999) == "41.999.999"
    assert version_to_str(VERSION_NA) == ""
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

        sect = _bl_section_t()
        sect.set_attributes(attr)
        attr2 = sect.get_attributes()
        assert attr2 == attr

    def test_crc(self):
        sect = _bl_section_t()
        sect.struct_crc = 0
        sect.calc_crc()
        assert sect.struct_crc != 0
        assert sect.check_crc()
        sect.struct_crc ^= 1
        assert not sect.check_crc()

    def test_name_op(self):
        sect = _bl_section_t()
        sect.set_name("boot")
        assert sect.name == b'boot'
        assert sect.get_name() == "boot"
        ref_name_buf = b'boot\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        assert sect.serialize_name() == ref_name_buf

    def test_pl_ver_op(self):
        sect = _bl_section_t()
        sect.pl_ver = 102213405 # 1.22.134-rc5
        assert sect.get_pl_ver_str() == "1.22.134-rc5"
        assert sect.serialize_pl_ver() == b'\x1d\xa7\x17\x06'

    def test_validate_correct(self):
        sect = _bl_section_t()
        sect.calc_crc()
        sect.validate()

    def test_validate_wrong_magic(self):
        sect = _bl_section_t()
        sect.magic = 12345
        sect.calc_crc()
        with pytest.raises(ValueError):
            sect.validate()

    def test_validate_wrong_struct_rev(self):
        sect = _bl_section_t()
        sect.struct_rev = 12345
        sect.calc_crc()
        with pytest.raises(ValueError):
            sect.validate()

    def test_validate_wrong_name(self):
        sect = _bl_section_t()
        sect.name = b'1234567890123456'
        sect.calc_crc()
        with pytest.raises(ValueError):
            sect.validate()

    def test_validate_wrong_pl_ver(self):
        sect = _bl_section_t()
        sect.pl_ver = VERSION_MAX + 1
        sect.calc_crc()
        with pytest.raises(ValueError):
            sect.validate()

    def test_validate_wrong_pl_size(self):
        sect = _bl_section_t()
        sect.pl_size = _max_payload_size + 1
        sect.calc_crc()
        with pytest.raises(ValueError):
            sect.validate()

    def test_validate_attr_list_overflow(self):
        sect = _bl_section_t()
        # Set key byte = 'bl_attr_algorithm', valid
        sect.attr_list[0] = 1
        # Set len byte, > remaining bytes
        sect.attr_list[1] = sizeof(sect.attr_list) - 1
        sect.calc_crc()
        with pytest.raises(ValueError):
            sect.validate()


class TestPayloadSection:
    def test_name(self):
        sect = PayloadSection("test_abcd")
        assert sect.name == "test_abcd"
        sect.name = "123456789012345"
        assert sect.name == "123456789012345"
        with pytest.raises(ValueError):
            sect.name = "1234567890123456"
        assert sect.name == "123456789012345"

    def test_attributes(self, _add_test_attributes):
        sect = PayloadSection("test")
        attr = { 'bl_attr_algorithm' : "secp256k1-sha256",
                 'a2' : None,
                 'a3' : 123456789012,
                 'a4' : "This is a simple text. END" }
        sect.attributes = attr
        assert sect.attributes == attr
        with pytest.raises(KeyError):
            sect.attributes = { 'something' : "AAA" }
        with pytest.raises(TypeError):
            sect.attributes = { 'a2' : "should be none" }
        with pytest.raises(TypeError):
            sect.attributes = { 'a3' : None }
        with pytest.raises(TypeError):
            sect.attributes = { 'a4' : 12345 }

    def test_version(self):
        payload = b'Something useless<version:tag10>0102213405</version:tag10>'
        sect = PayloadSection("boot", payload)
        assert sect.version == 102213405
        assert sect.version_str == "1.22.134-rc5"
        # Test that version tag is checked for duplication
        with pytest.raises(ValueError):
            sect = PayloadSection("boot", payload + payload)

    def test_serialization_valid(self, _add_test_attributes):
        payload = b'Something useless<version:tag10>0102213405</version:tag10>'
        a = PayloadSection("boot", payload, attributes={'a3' : 123})
        dummy = b'dummy data before section'
        data = dummy + a.serialize()
        b, offset = Section.deserialize(data, len(dummy))
        assert offset == len(data)
        assert isinstance(b, PayloadSection)
        assert b.name       == a.name
        assert b.version    == a.version
        assert b.attributes == a.attributes
        assert b.payload    == a.payload
        assert b            == a # Also tests __eq__()

    def test_serialization_corrupted_header(self, _add_test_attributes):
        a = PayloadSection("test", payload=b'abcdefgh')
        data = bytearray(a.serialize())
        Section.deserialize(data, 0) # Should not raise exception
        data[100] ^= 1
        with pytest.raises(ValueError):
            Section.deserialize(data, 0)

    def test_serialization_corrupted_payload(self, _add_test_attributes):
        a = PayloadSection("test", payload=b'abcdefgh')
        data = bytearray(a.serialize())
        Section.deserialize(data, 0) # Should not raise exception
        data[sizeof(_bl_section_t) + 3] ^= 1
        with pytest.raises(ValueError):
            Section.deserialize(data, 0)

    def test_get_hash_sentence(self):
        # p1 - valid payload
        # p2 - different version
        # p3 - different data (first byte changed)
        # p4 - different data (last byte missing)
        p1 = b'Lorem ipsum<version:tag10>0102213405</version:tag10>dolor sit'
        p2 = b'Lorem ipsum<version:tag10>0102213406</version:tag10>dolor sit'
        p3 = b'lorem ipsum<version:tag10>0102213405</version:tag10>dolor sit'
        p4 = b'Lorem ipsum<version:tag10>0102213405</version:tag10>dolor si'

        # Reference hash sentence for p1 payload
        ref_sentence = ( b'boot\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                         b'\x00\x1d\xa7\x17\x06\x01\x97\xb8\x0cE\x9f\x99\x1f'
                         b'\xe7p\xec=(\xa0j\xc5q\xf0\x838@\x16k/L\x11\xac\xc5'
                         b'\x80\x1e\xa9w' )

        assert PayloadSection("boot", p1).get_hash_sentence() == ref_sentence
        assert PayloadSection("boot", p2).get_hash_sentence() != ref_sentence
        assert PayloadSection("boot", p3).get_hash_sentence() != ref_sentence
        assert PayloadSection("boot", p4).get_hash_sentence() != ref_sentence

class TestSignatureSection:
    def test_creation(self):
        sect = SignatureSection(dsa_algorithm='secp256k1-sha256')
        assert sect.name == 'sign'
        assert sect.version == VERSION_NA
        assert sect.attributes['bl_attr_algorithm'] == 'secp256k1-sha256'
        assert not sect.signatures
        with pytest.raises(ValueError):
            sect2 = SignatureSection(dsa_algorithm='unsupported-algorithm')

    def test_signatures_valid(self):
        sect = SignatureSection()
        sigs = { b'a' * FINGERPRINT_LEN : b'1' * SIGNATURE_LEN,
                 b'b' * FINGERPRINT_LEN : b'2' * SIGNATURE_LEN,
                 b'c' * FINGERPRINT_LEN : b'3' * SIGNATURE_LEN }
        sect.signatures = sigs
        assert sect.signatures == sigs

    def test_signatures_wrong_type(self):
        sect = SignatureSection()
        with pytest.raises(TypeError):
            sect.signatures = { b'a' * FINGERPRINT_LEN : '1' * SIGNATURE_LEN }
        with pytest.raises(TypeError):
            sect.signatures = { b'a' * FINGERPRINT_LEN : 12345 }
        with pytest.raises(TypeError):
            sect.signatures = { 'a' * FINGERPRINT_LEN : b'1' * SIGNATURE_LEN }
        with pytest.raises(TypeError):
            sect.signatures = { 12345 : b'1' * SIGNATURE_LEN }

    def test_signatures_wrong_len(self):
        sect = SignatureSection()
        fp_len = FINGERPRINT_LEN
        sig_len = SIGNATURE_LEN
        sect.signatures = { b'a' * fp_len : b'1' * sig_len } # Shouldn't raise
        with pytest.raises(ValueError):
            sect.signatures = { b'a' * (fp_len + 1) : b'1' * sig_len }
        with pytest.raises(ValueError):
            sect.signatures = { b'a' * (fp_len - 1) : b'1' * sig_len }
        with pytest.raises(ValueError):
            sect.signatures = { b'a' * fp_len : b'1' * (sig_len + 1) }
        with pytest.raises(ValueError):
            sect.signatures = { b'a' * fp_len : b'1' * (sig_len - 1) }

    def test_serialization_valid(self):
        sigs = { b'a' * FINGERPRINT_LEN : b'1' * SIGNATURE_LEN,
                 b'b' * FINGERPRINT_LEN : b'2' * SIGNATURE_LEN,
                 b'c' * FINGERPRINT_LEN : b'3' * SIGNATURE_LEN }
        a = SignatureSection()
        a.signatures = sigs
        dummy = b'dummy data before section'
        serialized = a.serialize()
        data = dummy + serialized + b'dummy data at the end'
        b, offset = Section.deserialize(data, len(dummy))
        assert offset == len(dummy) + len(serialized)
        assert isinstance(b, SignatureSection)
        assert b.name       == a.name
        assert b.version    == a.version
        assert b.attributes == a.attributes
        assert b.signatures == a.signatures
        assert b            == a # Also tests __eq__()

    def test_serialization_corrupted_header(self, _add_test_attributes):
        a = SignatureSection()
        a.signatures = { b'a' * FINGERPRINT_LEN : b'1' * SIGNATURE_LEN }
        data = bytearray(a.serialize())
        Section.deserialize(data, 0) # Shouldn't not raise exception
        data[sizeof(_bl_section_t)//2] ^= 1
        with pytest.raises(ValueError):
            Section.deserialize(data, 0)

    def test_serialization_corrupted_payload(self, _add_test_attributes):
        a = SignatureSection()
        a.signatures = { b'a' * FINGERPRINT_LEN : b'1' * SIGNATURE_LEN }
        data = bytearray(a.serialize())
        Section.deserialize(data, 0) # Shouldn't raise exception
        data[sizeof(_bl_section_t) + 3] ^= 1
        with pytest.raises(ValueError):
            Section.deserialize(data, 0)

def test_make_signature_message():
    s = [PayloadSection('boot'), PayloadSection('internal')]
    m = make_signature_message(s)
    assert m == s[0].get_hash_sentence() + s[1].get_hash_sentence()
    s.append(SignatureSection())
    with pytest.raises(TypeError):
        m = make_signature_message(s)
