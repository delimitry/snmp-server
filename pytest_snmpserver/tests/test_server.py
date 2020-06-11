#!/usr/bin/env python
#-*- coding: utf8 -*-

import unittest
from pytest_snmpserver.snmp_server import *
from pytest_snmpserver.snmp_server import (_parse_asn1_length, _parse_snmp_asn1, _read_byte,
                                           _read_int_len, _write_asn1_length, _write_int)

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
        self.assertEqual(_write_int(-0x01), b'\xff')
        self.assertEqual(_write_int(0x80), b'\x80')
        self.assertEqual(_write_int(0xffff), b'\xff\xff')
        self.assertEqual(_write_int(0xffffffff), b'\xff\xff\xff\xff')
        self.assertEqual(_write_int(0xffffffffff), b'\xff\xff\xff\xff\xff')

    def test_write_asn1_length(self):
        """Test _parse_asn1_length"""
        self.assertEqual(_write_asn1_length(0x00), b'\x00')
        self.assertEqual(_write_asn1_length(0x7f), b'\x7f')
        self.assertEqual(_write_asn1_length(0x80), b'\x81\x80')
        self.assertEqual(_write_asn1_length(0xffff), b'\x82\xff\xff')
        self.assertEqual(_write_asn1_length(0xffffff), b'\x83\xff\xff\xff')
        self.assertEqual(_write_asn1_length(0xffffffff), b'\x84\xff\xff\xff\xff')
        with self.assertRaises(Exception):
            _write_asn1_length(0x100000000)

    def test_parse_asn1_length(self):
        """Test _parse_asn1_length"""
        self.assertEqual(_parse_asn1_length(StringIO('\x00')), 0x00)
        self.assertEqual(_parse_asn1_length(StringIO('\x01')), 0x01)
        self.assertEqual(_parse_asn1_length(StringIO('\x7f')), 0x7f)
        self.assertEqual(_parse_asn1_length(StringIO('\x81\x00')), 0x00)
        self.assertEqual(_parse_asn1_length(StringIO('\x81\xff')), 0xff)
        self.assertEqual(_parse_asn1_length(StringIO('\x82\x00\x00')), 0x00)
        self.assertEqual(_parse_asn1_length(StringIO('\x82\xff\x00')), 0xff00)
        self.assertEqual(_parse_asn1_length(StringIO('\x83\x00\x00\x00')), 0x00)
        self.assertEqual(_parse_asn1_length(StringIO('\x83\x12\x34\x56')), 0x123456)
        self.assertEqual(_parse_asn1_length(StringIO('\x84\x00\x00\x00\x00')), 0x00)
        self.assertEqual(_parse_asn1_length(StringIO('\x84\x12\x34\x56\x78')), 0x12345678)
        with self.assertRaises(Exception):
            _parse_asn1_length(StringIO('\x80\x00'))
        with self.assertRaises(Exception):
            _parse_asn1_length(StringIO('\x85\x00\x00\x00\x00\x00'))
        self.assertEqual(_parse_asn1_length(StringIO(_write_asn1_length(12345678).decode('latin'))), 12345678)

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
        self.assertEqual(get_next_oid('1.3.6'), '1.4.1')
        self.assertEqual(get_next_oid('1.3'), '2.1')
        self.assertEqual(get_next_oid('1'), '2')
        self.assertEqual(get_next_oid('0'), '1')

    def test_write_tlv(self):
        """Test write_tlv"""
        self.assertEqual(write_tlv(0, 0, b''), b'\x00\x00')
        self.assertEqual(write_tlv(255, 5, b'value'), b'\xff\x05value')
        self.assertEqual(write_tlv(255, 0x7f, b'value'), b'\xff\x7fvalue')
        self.assertEqual(write_tlv(255, 0x80, b'value'), b'\xff\x81\x80value')
        self.assertEqual(write_tlv(255, 0xff, b'value'), b'\xff\x81\xffvalue')
        self.assertEqual(write_tlv(255, 0x0100, b'value'), b'\xff\x82\x01\x00value')
        self.assertEqual(write_tlv(255, 0xffff, b'value'), b'\xff\x82\xff\xffvalue')
        self.assertEqual(write_tlv(255, 0xffff, b'value'), b'\xff\x82\xff\xffvalue')

    def test_write_tv(self):
        """Test write_tv"""
        self.assertEqual(write_tv(0, b''), b'\x00\x00')
        self.assertEqual(write_tv(255, b'value'), b'\xff\x05value')

    def test_boolean(self):
        """Test boolean"""
        self.assertEqual(boolean(True), b'\x01\x01\xff')
        self.assertEqual(boolean(False), b'\x01\x01\x00')

    def test_integer(self):
        """Test integer"""
        self.assertEqual(integer(0), b'\x02\x08\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(integer(0xffff), b'\x02\x08\x00\x00\x00\x00\x00\x00\xff\xff')
        self.assertEqual(integer(0x12345678), b'\x02\x08\x00\x00\x00\x00\x124Vx')
        self.assertEqual(integer(-1), b'\x02\x01\xff')
        self.assertEqual(integer(-0x12345678), b'\x02\x04\xed\xcb\xa9\x88')

    def test_octet_string(self):
        """Test octet string"""
        self.assertEqual(octet_string(''), b'\x04\x00')
        self.assertEqual(octet_string('abc'), b'\x04\x03abc')
        self.assertEqual(octet_string('\x00\x01\x02'), b'\x04\x03\x00\x01\x02')

    def test_null(self):
        """Test null"""
        self.assertEqual(null(), b'\x05\x00')

    def test_object_identifier(self):
        """Test OID"""
        self.assertEqual(object_identifier('1.3.6'), b'\x06\x02\x2b\x06')
        self.assertEqual(object_identifier('1.3.6.7.8.9'), b'\x06\x05\x2b\x06\x07\x08\x09')

    def test_real(self):
        """Test real"""
        self.assertEqual(real(0.0), b'\x44\x07\x9f\x78\x04\x00\x00\x00\x00')
        self.assertEqual(real(float('inf')), b'\x44\x07\x9f\x78\x04\x7f\x80\x00\x00')
        self.assertEqual(real(float('-inf')), b'\x44\x07\x9f\x78\x04\xff\x80\x00\x00')
        self.assertEqual(real(float('nan')), b'\x44\x07\x9f\x78\x04\x7f\xc0\x00\x00')
        self.assertEqual(real(float('-nan')), b'\x44\x07\x9f\x78\x04\xff\xc0\x00\x00')
        self.assertEqual(real(123.456), b'\x44\x07\x9f\x78\x04\x42\xf6\xe9\x79')

    def test_double(self):
        """Test double"""
        self.assertEqual(double(0.0), b'\x44\x0b\x9f\x79\x08\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(double(float('inf')), b'\x44\x0b\x9f\x79\x08\x7f\xf0\x00\x00\x00\x00\x00\x00')
        self.assertEqual(double(float('-inf')), b'\x44\x0b\x9f\x79\x08\xff\xf0\x00\x00\x00\x00\x00\x00')
        self.assertEqual(double(float('nan')), b'\x44\x0b\x9f\x79\x08\x7f\xf8\x00\x00\x00\x00\x00\x00')
        self.assertEqual(double(float('-nan')), b'\x44\x0b\x9f\x79\x08\xff\xf8\x00\x00\x00\x00\x00\x00')
        self.assertEqual(double(123.456), b'\x44\x0b\x9f\x79\x08\x40\x5e\xdd\x2f\x1a\x9f\xbe\x77')

    def test_ip_address(self):
        """Test IP address"""
        self.assertEqual(ip_address('0.0.0.0'), b'\x40\x04\x00\x00\x00\x00')
        self.assertEqual(ip_address('127.0.0.1'), b'\x40\x04\x7f\x00\x00\x01')
        self.assertEqual(ip_address('255.254.253.252'), b'\x40\x04\xff\xfe\xfd\xfc')

    def test_timeticks(self):
        """Test timeticks"""
        self.assertEqual(timeticks(0), b'\x43\x01\x00')
        self.assertEqual(timeticks(255), b'\x43\x01\xff')
        self.assertEqual(timeticks(0xffff), b'\x43\x02\xff\xff')
        self.assertEqual(timeticks(0xffffffff), b'\x43\x04\xff\xff\xff\xff')
        with self.assertRaises(Exception):
            timeticks(0xffffffffff)

    def test_gauge32(self):
        """Test gauge32"""
        self.assertEqual(gauge32(0), b'\x42\x08\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(gauge32(255), b'\x42\x08\x00\x00\x00\x00\x00\x00\x00\xff')
        self.assertEqual(gauge32(0xffff), b'\x42\x08\x00\x00\x00\x00\x00\x00\xff\xff')
        self.assertEqual(gauge32(0xffffffff), b'\x42\x08\x00\x00\x00\x00\xff\xff\xff\xff')
        with self.assertRaises(Exception):
            gauge32(0xffffffffff)

    def test_counter32(self):
        """Test counter32"""
        self.assertEqual(counter32(0), b'\x41\x01\x00')
        self.assertEqual(counter32(255), b'\x41\x01\xff')
        self.assertEqual(counter32(0xffff), b'\x41\x02\xff\xff')
        self.assertEqual(counter32(0xffffffff), b'\x41\x04\xff\xff\xff\xff')
        with self.assertRaises(Exception):
            counter32(0xffffffffff)

    def test_counter64(self):
        """Test counter64"""
        self.assertEqual(counter64(0), b'\x46\x01\x00')
        self.assertEqual(counter64(255), b'\x46\x01\xff')
        self.assertEqual(counter64(0xffff), b'\x46\x02\xff\xff')
        self.assertEqual(counter64(0xffffffff), b'\x46\x04\xff\xff\xff\xff')
        with self.assertRaises(Exception):
            gauge32(0xffffffffffffffffff)

