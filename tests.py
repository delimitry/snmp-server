#!/usr/bin/env python
#-*- coding: utf8 -*-

import unittest
snmp_server = __import__('snmp-server')  # import a module with dash

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


class Test(unittest.TestCase):
    """
    Test SNMP server functions
    """

    def test_encode_to_7bit(self):
        """Test encode_to_7bit"""
        self.assertEqual(encode_to_7bit(0x00), [0x00])
        self.assertEqual(encode_to_7bit(0x7f), [0x7f])
        self.assertEqual(encode_to_7bit(0x80), [0x81, 0x00])
        self.assertEqual(encode_to_7bit(0xffff), [0x83, 0xff, 0x7f])
        self.assertEqual(encode_to_7bit(0xffffff), [0x87, 0xff, 0xff, 0x7f])
        self.assertEqual(encode_to_7bit(0xffffffff), [0x8f, 0xff, 0xff, 0xff, 0x7f])

    def test_oid_to_bytes_list(self):
        """Test oid_to_bytes_list"""
        self.assertEqual(oid_to_bytes_list('iso.3.6'), [43, 6])
        self.assertEqual(oid_to_bytes_list('1.3.6'), [43, 6])
        self.assertEqual(oid_to_bytes_list('.1.3.6'), [43, 6])
        self.assertEqual(oid_to_bytes_list('iso.3'), [43])
        self.assertEqual(oid_to_bytes_list('1.3'), [43])
        self.assertEqual(oid_to_bytes_list('.1.3'), [43])
        with self.assertRaises(Exception):
            oid_to_bytes_list('')
        with self.assertRaises(Exception):
            oid_to_bytes_list('1')
        with self.assertRaises(Exception):
            oid_to_bytes_list('iso')

    def test_oid_to_bytes(self):
        """Test oid_to_bytes"""
        self.assertEqual(oid_to_bytes('iso.3.6'), '\x2b\x06')
        self.assertEqual(oid_to_bytes('1.3.6'), '\x2b\x06')
        self.assertEqual(oid_to_bytes('.1.3.6'), '\x2b\x06')
        self.assertEqual(oid_to_bytes('1.3.6.0.255'), '\x2b\x06\x00\x81\x7f')
        self.assertEqual(oid_to_bytes('1.3.6.0.1.2.3.4'), '\x2b\x06\x00\x01\x02\x03\x04')

    def test_bytes_to_oid(self):
        """Test bytes_to_oid"""
        self.assertEqual(bytes_to_oid('\x2b\x06'), '1.3.6')
        self.assertEqual(bytes_to_oid('\x2b\x06\x00'), '1.3.6.0')
        self.assertEqual(bytes_to_oid('\x2b\x06\x00\x7f'), '1.3.6.0.127')
        self.assertEqual(bytes_to_oid('\x2b\x06\x00\x7f\x81\x7f'), '1.3.6.0.127.255')

    def test_timeticks_to_str(self):
        """Test timeticks_to_str"""
        self.assertEqual(timeticks_to_str(0), '00:00:00.00')
        self.assertEqual(timeticks_to_str(1), '00:00:00.01')
        self.assertEqual(timeticks_to_str(10), '00:00:00.10')
        self.assertEqual(timeticks_to_str(100), '00:00:01.00')
        self.assertEqual(timeticks_to_str(6000), '00:01:00.00')
        self.assertEqual(timeticks_to_str(360000), '01:00:00.00')

    def test_int_to_ip(self):
        """Test int_to_ip"""
        self.assertEqual(int_to_ip(0x00000000), '0.0.0.0')
        self.assertEqual(int_to_ip(0x7f000001), '127.0.0.1')
        self.assertEqual(int_to_ip(0xffffffff), '255.255.255.255')

    def test_twos_complement(self):
        """Test twos_complement"""
        self.assertEqual(twos_complement(0, 1), 0)
        self.assertEqual(twos_complement(1, 8), 1)
        self.assertEqual(twos_complement(0b1111, 8), 0b1111)

    def test_read_byte(self):
        """Test _read_byte"""
        self.assertEqual(_read_byte(StringIO('\x00')), 0x00)
        self.assertEqual(_read_byte(StringIO('\xaa\xbb')), 0xaa)
        with self.assertRaises(Exception):
            _read_byte(StringIO(''))

    def test_read_int_len(self):
        """Test _read_int_len"""
        self.assertEqual(_read_int_len(StringIO('\x00'), 1), 0x00)
        self.assertEqual(_read_int_len(StringIO('\x7f'), 1), 0x7f)
        self.assertEqual(_read_int_len(StringIO('\x80'), 1, signed=True), -0x80)
        self.assertEqual(_read_int_len(StringIO('\xff\xff\xff\xff'), 4), 0xffffffff)

    def test_write_int(self):
        """Test _write_int"""
        self.assertEqual(_write_int(0x00), b'\x00')
        self.assertEqual(_write_int(0x80), b'\x80')
        self.assertEqual(_write_int(0xffff), b'\xff\xff')
        self.assertEqual(_write_int(0xffffffff), b'\xff\xff\xff\xff')
        self.assertEqual(_write_int(0xffffffffff), b'\xff\xff\xff\xff\xff')

    def test_parse_snmp_asn1(self):
        """Test _parse_snmp_asn1"""
        with self.assertRaises(ProtocolError):
            _parse_snmp_asn1(StringIO(''))
        with self.assertRaises(ProtocolError):
            _parse_snmp_asn1(StringIO('\x30\x27\x02\x01\x01\x04\x06public'))
        self.assertEqual(
            _parse_snmp_asn1(
                StringIO(
                    '\x30\x27'
                    '\x02\x01\x01'  # version
                    '\x04\x06public'  # community
                    '\xa1\x1a'  # GetNextRequest PDU
                    '\x02\x01\x05'  # request id
                    '\x02\x01\x00'  # error status
                    '\x02\x01\x00'  # error index
                    '\x30\x0c\x30\x0a'
                    '\x06\x06\x2b\x06\x01\x02\x03\x04'  # OID
                    '\x05\x00'
                )
            ), [
                ('INTEGER', 0x01),
                ('STRING', 'public'),
                ('ASN1_GET_NEXT_REQUEST_PDU', ASN1_GET_NEXT_REQUEST_PDU),
                ('INTEGER', 0x05),
                ('INTEGER', 0x00),
                ('INTEGER', 0x00),
                ('OID', '1.3.6.1.2.3.4')
            ]
        )
        with self.assertRaises(ProtocolError):  # swap community and version fields
            _parse_snmp_asn1(
                StringIO(
                    '\x30\x27'
                    '\x04\x06public'  # community
                    '\x02\x01\x01'  # version
                    '\xa1\x1a'  # GetNextRequest PDU
                    '\x02\x01\x05'  # request id
                    '\x02\x01\x00'  # error status
                    '\x02\x01\x00'  # error index
                    '\x30\x0c\x30\x0a'
                    '\x06\x06\x2b\x06\x01\x02\x03\x04'  # OID
                    '\x05\x00'
                )
            )

    def test_get_next_oid(self):
        """Test get_next_oid"""
        self.assertEqual(get_next_oid('1.3.6.1.1'), '1.3.6.2.1')
        self.assertEqual(get_next_oid('1.3.6.1'), '1.3.7.1')
        self.assertEqual(get_next_oid('1.3.6'), '1.4.6')
        self.assertEqual(get_next_oid('1.3'), '2.3')
        self.assertEqual(get_next_oid('1'), '2')
        self.assertEqual(get_next_oid('0'), '1')

    def test_write_tlv(self):
        """Test write_tlv"""
        self.assertEqual(write_tlv(0, 0, b''), b'\x00\x00')
        self.assertEqual(write_tlv(255, 5, b'value'), b'\xff\x05value')
        self.assertEqual(write_tlv(255, 255, b'value'), b'\xff\xffvalue')
        # TODO: add
        # self.assertEqual(write_tlv(255, 256, b'value'), b'\xff\x82\x00value')

    def test_write_tv(self):
        """Test write_tv"""
        self.assertEqual(write_tv(0, b''), b'\x00\x00')
        self.assertEqual(write_tv(255, b'value'), b'\xff\x05value')


if __name__ == '__main__':
    globals().update(vars(snmp_server))  # hack for access all from 'snmp-server' module
    logger.setLevel(logging.ERROR)
    unittest.main(verbosity=2)
