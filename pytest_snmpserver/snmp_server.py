#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Simple SNMP server in pure Python
"""


import argparse
import fnmatch
import functools
import logging
import socket
import string
import struct
import sys
import threading
import time
import types

from collections import Iterable

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

__version__ = '1.0.5'

PY3 = sys.version_info[0] == 3

logging.basicConfig(format='[%(levelname)s] %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.WARNING)

# ASN.1 tags
ASN1_BOOLEAN = 0x01
ASN1_INTEGER = 0x02
ASN1_BIT_STRING = 0x03
ASN1_OCTET_STRING = 0x04
ASN1_NULL = 0x05
ASN1_OBJECT_IDENTIFIER = 0x06
ASN1_UTF8_STRING = 0x0c
ASN1_PRINTABLE_STRING = 0x13
ASN1_IA5_STRING = 0x16
ASN1_BMP_STRING = 0x1e
ASN1_SEQUENCE = 0x30
ASN1_SET = 0x31
ASN1_IPADDRESS = 0x40
ASN1_COUNTER32 = 0x41
ASN1_GAUGE32 = 0x42
ASN1_TIMETICKS = 0x43
ASN1_OPAQUE = 0x44
ASN1_COUNTER64 = 0x46
ASN1_NO_SUCH_OBJECT = 0x80
ASN1_NO_SUCH_INSTANCE = 0x81
ASN1_END_OF_MIB_VIEW = 0x82
ASN1_GET_REQUEST_PDU = 0xA0
ASN1_GET_NEXT_REQUEST_PDU = 0xA1
ASN1_GET_RESPONSE_PDU = 0xA2
ASN1_SET_REQUEST_PDU = 0xA3
ASN1_GET_BULK_REQUEST_PDU = 0xA5

# error statuses
ASN1_ERROR_STATUS_NO_ERROR = 0x00
ASN1_ERROR_STATUS_TOO_BIG = 0x01
ASN1_ERROR_STATUS_NO_SUCH_NAME = 0x02
ASN1_ERROR_STATUS_BAD_VALUE = 0x03
ASN1_ERROR_STATUS_READ_ONLY = 0x04
ASN1_ERROR_STATUS_GEN_ERR = 0x05
ASN1_ERROR_STATUS_WRONG_VALUE = 0x0A

# some ASN.1 opaque special types
ASN1_CONTEXT = 0x80  # context-specific
ASN1_EXTENSION_ID = 0x1F  # 0b11111 (fill tag in first octet)
ASN1_OPAQUE_TAG1 = ASN1_CONTEXT | ASN1_EXTENSION_ID  # 0x9f
ASN1_OPAQUE_TAG2 = 0x30  # base tag value
ASN1_APPLICATION = 0x40
ASN1_APP_FLOAT = ASN1_APPLICATION | 0x08  # application-specific type 0x08
ASN1_APP_DOUBLE = ASN1_APPLICATION | 0x09  # application-specific type 0x09
ASN1_APP_INT64 = ASN1_APPLICATION | 0x0A  # application-specific type 0x0A
ASN1_APP_UINT64 = ASN1_APPLICATION | 0x0B  # application-specific type 0x0B
ASN1_OPAQUE_FLOAT = ASN1_OPAQUE_TAG2 | ASN1_APP_FLOAT
ASN1_OPAQUE_DOUBLE = ASN1_OPAQUE_TAG2 | ASN1_APP_DOUBLE
ASN1_OPAQUE_INT64 = ASN1_OPAQUE_TAG2 | ASN1_APP_INT64
ASN1_OPAQUE_UINT64 = ASN1_OPAQUE_TAG2 | ASN1_APP_UINT64
ASN1_OPAQUE_FLOAT_BER_LEN = 7
ASN1_OPAQUE_DOUBLE_BER_LEN = 11
ASN1_OPAQUE_INT64_BER_LEN = 4
ASN1_OPAQUE_UINT64_BER_LEN = 4

SNMP_VERSIONS = {
    1: 'v1',
    2: 'v2c',
    3: 'v3',
}

SNMP_PDUS = (
    'version',
    'community',
    'PDU-type',
    'request-id',
    'error-status',
    'error-index',
    'variable bindings',
)


class ProtocolError(Exception):
    """Raise when SNMP protocol error occured"""


class ConfigError(Exception):
    """Raise when config error occured"""


class BadValueError(Exception):
    """Raise when bad value error occured"""


class WrongValueError(Exception):
    """Raise when wrong value (e.g. value not in available range) error occured"""


def encode_to_7bit(value):
    """Encode to 7 bit"""
    if value > 0x7f:
        res = []
        res.insert(0, value & 0x7f)
        while value > 0x7f:
            value >>= 7
            res.insert(0, (value & 0x7f) | 0x80)
        return res
    return [value]


def oid_to_bytes_list(oid):
    """Convert OID str to bytes list"""
    if oid.startswith('iso'):
        oid = oid.replace('iso', '1')
    try:
        oid_values = [int(x) for x in oid.split('.') if x]
        first_val = 40 * oid_values[0] + oid_values[1]
    except (ValueError, IndexError):
        raise Exception('Could not parse OID value "{}"'.format(oid))
    result_values = [first_val]
    for node_num in oid_values[2:]:
        result_values += encode_to_7bit(node_num)
    return result_values


def oid_to_bytes(oid):
    """Convert OID str to bytes"""
    return ''.join([chr(x) for x in oid_to_bytes_list(oid)])


def bytes_to_oid(data):
    """Convert bytes to OID str"""
    values = [ord(x) for x in data]
    first_val = values.pop(0)
    res = []
    res += divmod(first_val, 40)
    while values:
        val = values.pop(0)
        if val > 0x7f:
            huges = []
            huges.append(val)
            while True:
                next_val = values.pop(0)
                huges.append(next_val)
                if next_val < 0x80:
                    break
            huge = 0
            for i, huge_byte in enumerate(huges):
                huge += (huge_byte & 0x7f) << (7 * (len(huges) - i - 1))
            res.append(huge)
        else:
            res.append(val)
    return '.'.join(str(x) for x in res)


def timeticks_to_str(ticks):
    """Return "days, hours, minutes, seconds and ms" string from ticks"""
    days, rem1 = divmod(ticks, 24 * 60 * 60 * 100)
    hours, rem2 = divmod(rem1, 60 * 60 * 100)
    minutes, rem3 = divmod(rem2, 60 * 100)
    seconds, milliseconds = divmod(rem3, 100)
    ending = 's' if days > 1 else ''
    days_fmt = '{} day{}, '.format(days, ending) if days > 0 else ''
    return '{}{:-02}:{:-02}:{:-02}.{:-02}'.format(days_fmt, hours, minutes, seconds, milliseconds)


def int_to_ip(value):
    """Int to IP"""
    return socket.inet_ntoa(struct.pack("!I", value))


def twos_complement(value, bits):
    """Calculate two's complement"""
    mask = 2 ** (bits - 1)
    return -(value & mask) + (value & ~mask)


def _read_byte(stream):
    """Read byte from stream"""
    read_byte = stream.read(1)
    if not read_byte:
        raise Exception('No more bytes!')
    return ord(read_byte)


def _read_int_len(stream, length, signed=False):
    """Read int with length"""
    result = 0
    sign = None
    for _ in range(length):
        value = _read_byte(stream)
        if sign is None:
            sign = value & 0x80
        result = (result << 8) + value
    if signed and sign:
        result = twos_complement(result, 8 * length)
    return result


def _write_int(value, strip_leading_zeros=True):
    """Write int"""
    if abs(value) > 0xffffffffffffffff:
        raise Exception('Int value must be in [0..18446744073709551615]')
    if value < 0:
        if abs(value) <= 0x7f:
            result = struct.pack('>b', value)
        elif abs(value) <= 0x7fff:
            result = struct.pack('>h', value)
        elif abs(value) <= 0x7fffffff:
            result = struct.pack('>i', value)
        elif abs(value) <= 0x7fffffffffffffff:
            result = struct.pack('>q', value)
    else:
        result = struct.pack('>Q', value)
    # strip first null bytes, if all are null - leave one
    result = result.lstrip(b'\x00') if strip_leading_zeros else result
    return result or b'\x00'


def _write_asn1_length(length):
    """Write ASN.1 length"""
    if length > 0x7f:
        if length <= 0xff:
            packed_length = 0x81
        elif length <= 0xffff:
            packed_length = 0x82
        elif length <= 0xffffff:
            packed_length = 0x83
        elif length <= 0xffffffff:
            packed_length = 0x84
        else:
            raise Exception('Length is too big!')
        return struct.pack('B', packed_length) + _write_int(length)
    return struct.pack('B', length)


def _parse_asn1_length(stream):
    """Parse ASN.1 length"""
    length = _read_byte(stream)
    # handle long length
    if length > 0x7f:
        data_length = length - 0x80
        if not 0 < data_length <= 4:
            raise Exception('Data length must be in [1..4]')
        length = _read_int_len(stream, data_length)
    return length


def _parse_asn1_octet_string(stream):
    """Parse ASN.1 octet string"""
    length = _parse_asn1_length(stream)
    value = stream.read(length)
    # if any char is not printable - convert string to hex
    if any([c not in string.printable for c in value]):
        return ' '.join(['%02X' % ord(x) for x in value])
    return value


def _parse_asn1_opaque_float(stream):
    """Parse ASN.1 opaque float"""
    length = _parse_asn1_length(stream)
    value = _read_int_len(stream, length, signed=True)
    # convert int to float
    float_value = struct.unpack('>f', struct.pack('>l', value))[0]
    logger.debug('ASN1_OPAQUE_FLOAT: %s', round(float_value, 5))
    return 'FLOAT', round(float_value, 5)


def _parse_asn1_opaque_double(stream):
    """Parse ASN.1 opaque double"""
    length = _parse_asn1_length(stream)
    value = _read_int_len(stream, length, signed=True)
    # convert long long to double
    double_value = struct.unpack('>d', struct.pack('>q', value))[0]
    logger.debug('ASN1_OPAQUE_DOUBLE: %s', round(double_value, 5))
    return 'DOUBLE', round(double_value, 5)


def _parse_asn1_opaque_int64(stream):
    """Parse ASN.1 opaque int64"""
    length = _parse_asn1_length(stream)
    value = _read_int_len(stream, length, signed=True)
    logger.debug('ASN1_OPAQUE_INT64: %s', value)
    return 'INT64', value


def _parse_asn1_opaque_uint64(stream):
    """Parse ASN.1 opaque uint64"""
    length = _parse_asn1_length(stream)
    value = _read_int_len(stream, length)
    logger.debug('ASN1_OPAQUE_UINT64: %s', value)
    return 'UINT64', value


def _parse_asn1_opaque(stream):
    """Parse ASN.1 opaque"""
    length = _parse_asn1_length(stream)
    opaque_tag = _read_byte(stream)
    opaque_type = _read_byte(stream)
    if (length == ASN1_OPAQUE_FLOAT_BER_LEN and
            opaque_tag == ASN1_OPAQUE_TAG1 and
            opaque_type == ASN1_OPAQUE_FLOAT):
        return _parse_asn1_opaque_float(stream)
    elif (length == ASN1_OPAQUE_DOUBLE_BER_LEN and
          opaque_tag == ASN1_OPAQUE_TAG1 and
          opaque_type == ASN1_OPAQUE_DOUBLE):
        return _parse_asn1_opaque_double(stream)
    elif (length >= ASN1_OPAQUE_INT64_BER_LEN and
          opaque_tag == ASN1_OPAQUE_TAG1 and
          opaque_type == ASN1_OPAQUE_INT64):
        return _parse_asn1_opaque_int64(stream)
    elif (length >= ASN1_OPAQUE_UINT64_BER_LEN and
          opaque_tag == ASN1_OPAQUE_TAG1 and
          opaque_type == ASN1_OPAQUE_UINT64):
        return _parse_asn1_opaque_uint64(stream)
    # for simple opaque - rewind 2 bytes back (opaque tag and type)
    stream.seek(stream.tell() - 2)
    return stream.read(length)


def _parse_snmp_asn1(stream):
    """Parse SNMP ASN.1
    After |IP|UDP| headers and "sequence" tag, SNMP protocol data units (PDUs) are the next:
    |version|community|PDU-type|request-id|error-status|error-index|variable bindings|
    """
    result = []
    wait_oid_value = False
    pdu_index = 0
    while True:
        read_byte = stream.read(1)
        if not read_byte:
            if pdu_index < 7:
                raise ProtocolError('Not all SNMP protocol data units are read!')
            return result
        tag = ord(read_byte)
        # check protocol's tags at indices
        if (
                pdu_index in [1, 4, 5, 6] and tag != ASN1_INTEGER or
                pdu_index == 2 and tag != ASN1_OCTET_STRING or
                pdu_index == 3 and tag not in [
                    ASN1_GET_REQUEST_PDU,
                    ASN1_GET_NEXT_REQUEST_PDU,
                    ASN1_SET_REQUEST_PDU,
                    ASN1_GET_BULK_REQUEST_PDU,
                ]
        ):
            raise ProtocolError('Invalid tag for PDU unit "{}"'.format(SNMP_PDUS[pdu_index]))
        if tag == ASN1_SEQUENCE:
            length = _parse_asn1_length(stream)
            logger.debug('ASN1_SEQUENCE: %s', 'length = {}'.format(length))
        elif tag == ASN1_INTEGER:
            length = _read_byte(stream)
            value = _read_int_len(stream, length, True)
            logger.debug('ASN1_INTEGER: %s', value)
            # pdu_index is version, request-id, error-status, error-index
            if wait_oid_value or pdu_index in [1, 4, 5, 6]:
                result.append(('INTEGER', value))
                wait_oid_value = False
        elif tag == ASN1_OCTET_STRING:
            value = _parse_asn1_octet_string(stream)
            logger.debug('ASN1_OCTET_STRING: %s', value)
            if wait_oid_value or pdu_index == 2:  # community
                result.append(('STRING', value))
                wait_oid_value = False
        elif tag == ASN1_OBJECT_IDENTIFIER:
            length = _read_byte(stream)
            value = stream.read(length)
            logger.debug('ASN1_OBJECT_IDENTIFIER: %s', bytes_to_oid(value))
            result.append(('OID', bytes_to_oid(value)))
            wait_oid_value = True
        elif tag == ASN1_PRINTABLE_STRING:
            length = _parse_asn1_length(stream)
            value = stream.read(length)
            logger.debug('ASN1_PRINTABLE_STRING: %s', value)
        elif tag == ASN1_GET_REQUEST_PDU:
            length = _parse_asn1_length(stream)
            logger.debug('ASN1_GET_REQUEST_PDU: %s', 'length = {}'.format(length))
            if pdu_index == 3:  # PDU-type
                result.append(('ASN1_GET_REQUEST_PDU', tag))
        elif tag == ASN1_GET_NEXT_REQUEST_PDU:
            length = _parse_asn1_length(stream)
            logger.debug('ASN1_GET_NEXT_REQUEST_PDU: %s', 'length = {}'.format(length))
            if pdu_index == 3:  # PDU-type
                result.append(('ASN1_GET_NEXT_REQUEST_PDU', tag))
        elif tag == ASN1_GET_BULK_REQUEST_PDU:
            length = _parse_asn1_length(stream)
            logger.debug('ASN1_GET_BULK_REQUEST_PDU: %s', 'length = {}'.format(length))
            if pdu_index == 3:  # PDU-type
                result.append(('ASN1_GET_BULK_REQUEST_PDU', tag))
        elif tag == ASN1_GET_RESPONSE_PDU:
            length = _parse_asn1_length(stream)
            logger.debug('ASN1_GET_RESPONSE_PDU: %s', 'length = {}'.format(length))
        elif tag == ASN1_SET_REQUEST_PDU:
            length = _parse_asn1_length(stream)
            logger.debug('ASN1_SET_REQUEST_PDU: %s', 'length = {}'.format(length))
            if pdu_index == 3:  # PDU-type
                result.append(('ASN1_SET_REQUEST_PDU', tag))
        elif tag == ASN1_TIMETICKS:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            logger.debug('ASN1_TIMETICKS: %s (%s)', value, timeticks_to_str(value))
            if wait_oid_value:
                result.append(('TIMETICKS', value))
                wait_oid_value = False
        elif tag == ASN1_IPADDRESS:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            logger.debug('ASN1_IPADDRESS: %s (%s)', value, int_to_ip(value))
            if wait_oid_value:
                result.append(('IPADDRESS', int_to_ip(value)))
                wait_oid_value = False
        elif tag == ASN1_COUNTER32:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            logger.debug('ASN1_COUNTER32: %s', value)
            if wait_oid_value:
                result.append(('COUNTER32', value))
                wait_oid_value = False
        elif tag == ASN1_GAUGE32:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            logger.debug('ASN1_GAUGE32: %s', value)
            if wait_oid_value:
                result.append(('GAUGE32', value))
                wait_oid_value = False
        elif tag == ASN1_OPAQUE:
            value = _parse_asn1_opaque(stream)
            logger.debug('ASN1_OPAQUE: %r', value)
            if wait_oid_value:
                result.append(('OPAQUE', value))
                wait_oid_value = False
        elif tag == ASN1_COUNTER64:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            logger.debug('ASN1_COUNTER64: %s', value)
            if wait_oid_value:
                result.append(('COUNTER64', value))
                wait_oid_value = False
        elif tag == ASN1_NULL:
            value = _read_byte(stream)
            logger.debug('ASN1_NULL: %s', value)
        elif tag == ASN1_NO_SUCH_OBJECT:
            value = _read_byte(stream)
            logger.debug('ASN1_NO_SUCH_OBJECT: %s', value)
            result.append('No Such Object')
        elif tag == ASN1_NO_SUCH_INSTANCE:
            value = _read_byte(stream)
            logger.debug('ASN1_NO_SUCH_INSTANCE: %s', value)
            result.append('No Such Instance with OID')
        elif tag == ASN1_END_OF_MIB_VIEW:
            value = _read_byte(stream)
            logger.debug('ASN1_END_OF_MIB_VIEW: %s', value)
            return (('', ''), ('', ''))
        else:
            logger.debug('?: %s', hex(ord(read_byte)))
        pdu_index += 1
    return result


def get_next_oid(oid):
    """Get the next OID parent's node"""
    # increment pre last node, e.g.: "1.3.6.1.1" -> "1.3.6.2.1"
    oid_vals = oid.rsplit('.', 2)
    if len(oid_vals) < 2:
        oid_vals[-1] = str(int(oid_vals[-1]) + 1)
    else:
        oid_vals[-2] = str(int(oid_vals[-2]) + 1)
        oid_vals[-1] = '1'
    oid_next = '.'.join(oid_vals)
    return oid_next


def write_tlv(tag, length, value):
    """Write TLV (Tag-Length-Value)"""
    return struct.pack('B', tag) + _write_asn1_length(length) + value


def write_tv(tag, value):
    """Write TV (Tag-Value) and calculate length from value"""
    return write_tlv(tag, len(value), value)


def boolean(value):
    """Get Boolean"""
    return write_tlv(ASN1_BOOLEAN, 1, b'\xff' if value else b'\x00')


def integer(value, enum=None):
    """Get Integer"""
    if enum and isinstance(enum, Iterable):
        if not value in enum:
            raise WrongValueError('Integer value {} is outside the range of enum values'.format(value))
    if not (-2147483648 <= value <= 2147483647):
        raise Exception('Integer value must be in [-2147483648..2147483647]')
    if not enum:
        return write_tv(ASN1_INTEGER, _write_int(value, False))
    return write_tv(ASN1_INTEGER, _write_int(value, False)), enum


def bit_string(value):
    """
    Get BitString
    For example, if the input value is '\xF0\xF0'
    F0 F0 in hex = 11110000 11110000 in binary
    And in binary bits 0, 1, 2, 3, 8, 9, 10, 11 are set, so these bits are added to the output
    Therefore the SNMP response is: F0 F0 0 1 2 3 8 9 10 11
    """
    return write_tlv(ASN1_BIT_STRING, len(value), value.encode('latin') if PY3 else value)


def octet_string(value):
    """Get OctetString"""
    return write_tv(ASN1_OCTET_STRING, value.encode('latin') if PY3 else value)


def null():
    """Get Null"""
    return write_tv(ASN1_NULL, b'')


def object_identifier(value):
    """Get OID"""
    value = oid_to_bytes(value)
    return write_tv(ASN1_OBJECT_IDENTIFIER, value.encode('latin') if PY3 else value)


def real(value):
    """Get real"""
    # opaque tag | len | tag1 | tag2 | len | data
    float_value = struct.pack('>f', value)
    opaque_type_value = struct.pack(
        'BB', ASN1_OPAQUE_TAG1, ASN1_OPAQUE_FLOAT
    ) + _write_asn1_length(len(float_value)) + float_value
    return write_tv(ASN1_OPAQUE, opaque_type_value)


def double(value):
    """Get double"""
    # opaque tag | len | tag1 | tag2 | len | data
    double_value = struct.pack('>d', value)
    opaque_type_value = struct.pack(
        'BB', ASN1_OPAQUE_TAG1, ASN1_OPAQUE_DOUBLE
    ) + _write_asn1_length(len(double_value)) + double_value
    return write_tv(ASN1_OPAQUE, opaque_type_value)


def int64(value):
    """Get int64"""
    # opaque tag | len | tag1 | tag2 | len | data
    int64_value = struct.pack('>q', value)
    opaque_type_value = struct.pack(
        'BB', ASN1_OPAQUE_TAG1, ASN1_OPAQUE_INT64
    ) + _write_asn1_length(len(int64_value)) + int64_value
    return write_tv(ASN1_OPAQUE, opaque_type_value)


def uint64(value):
    """Get uint64"""
    # opaque tag | len | tag1 | tag2 | len | data
    uint64_value = struct.pack('>Q', value)
    opaque_type_value = struct.pack(
        'BB', ASN1_OPAQUE_TAG1, ASN1_OPAQUE_UINT64
    ) + _write_asn1_length(len(uint64_value)) + uint64_value
    return write_tv(ASN1_OPAQUE, opaque_type_value)



def utf8_string(value):
    """Get UTF8String"""
    return write_tv(ASN1_UTF8_STRING, value.encode('latin') if PY3 else value)


def printable_string(value):
    """Get PrintableString"""
    return write_tv(ASN1_PRINTABLE_STRING, value.encode('latin') if PY3 else value)


def ia5_string(value):
    """Get IA5String"""
    return write_tv(ASN1_IA5_STRING, value.encode('latin') if PY3 else value)


def bmp_string(value):
    """Get BMPString"""
    return write_tv(ASN1_BMP_STRING, value.encode('utf-16-be'))


def ip_address(value):
    """Get IPAddress"""
    return write_tv(ASN1_IPADDRESS, socket.inet_aton(value))


def timeticks(value):
    """Get Timeticks"""
    if value > 0xffffffff:
        raise Exception('Timeticks value must be in [0..4294967295]')
    return write_tv(ASN1_TIMETICKS, _write_int(value))


def gauge32(value):
    """Get Gauge32"""
    if value > 0xffffffff:
        raise Exception('Gauge32 value must be in [0..4294967295]')
    return write_tv(ASN1_GAUGE32, _write_int(value, strip_leading_zeros=False))


def counter32(value):
    """Get Counter32"""
    if value > 0xffffffff:
        raise Exception('Counter32 value must be in [0..4294967295]')
    return write_tv(ASN1_COUNTER32, _write_int(value))


def counter64(value):
    """Get Counter64"""
    if value > 0xffffffffffffffff:
        raise Exception('Counter64 value must be in [0..18446744073709551615]')
    return write_tv(ASN1_COUNTER64, _write_int(value))


def replace_wildcards(value):
    """Replace wildcards with some possible big values"""
    return value.replace('?', '9').replace('*', str(0xffffffff))


def oid_cmp(oid1, oid2):
    """OIDs comparator function"""
    oid1 = replace_wildcards(oid1)
    oid2 = replace_wildcards(oid2)
    oid1 = [int(x) for x in oid1.replace('iso', '1').strip('.').split('.')]
    oid2 = [int(x) for x in oid2.replace('iso', '1').strip('.').split('.')]
    if oid1 < oid2:
        return -1
    elif oid1 > oid2:
        return 1
    return 0


def get_next(oids, oid):
    """Get next OID from the OIDs list"""
    for val in sorted(oids, key=functools.cmp_to_key(oid_cmp)):
        # return first if compared with empty oid
        if not oid:
            return val
        # if oid < val, return val (i.e. first oid value after oid)
        elif oid_cmp(oid, val) < 0:
            return val
    # return empty when no more oids available
    return ''


def parse_config(filename):
    """Read and parse a config"""
    oids = {}
    try:
        with open(filename, 'rb') as conf_file:
            data = conf_file.read()
            out_locals = {}
            exec(data, globals(), out_locals)
            oids = out_locals['DATA']
            for value in oids.values():
                if isinstance(value, types.FunctionType):
                    if value.__code__.co_argcount != 1:
                        raise ConfigError('"{}" must have one argument'.format(value.__name__))
            return oids
    except Exception as ex:
        raise ConfigError('Config parsing error: {}'.format(ex))
    return oids


def find_oid_and_value_with_wildcard(oids, oid):
    """Find OID and OID value with wildcards"""
    wildcard_keys = [x for x in oids.keys() if '*' in x or '?' in x]
    out = []
    for wck in wildcard_keys:
        if fnmatch.filter([oid], wck):
            value = oids[wck](oid)
            out.append((wck, value,))
    return out


def handle_get_request(oids, oid):
    """Handle GetRequest PDU"""
    error_status = ASN1_ERROR_STATUS_NO_ERROR
    error_index = 0
    oid_value = null()
    found = oid in oids
    if found:
        # TODO: check this
        oid_value = oids[oid]
        if not oid_value:
            oid_value = struct.pack('BB', ASN1_NO_SUCH_OBJECT, 0)
    else:
        # now check wildcards
        results = find_oid_and_value_with_wildcard(oids, oid)
        if len(results) > 1:
            logger.warning('Several results found with wildcards for OID: %s', oid)
        if results:
            _, oid_value = results[0]
            if oid_value:
                found = True
    if not found:
        error_status = ASN1_ERROR_STATUS_NO_SUCH_NAME
        error_index = 1
        # TODO: check this
        oid_value = struct.pack('BB', ASN1_NO_SUCH_INSTANCE, 0)
    return error_status, error_index, oid_value


def handle_get_next_request(oids, oid):
    """Handle GetNextRequest"""
    error_status = ASN1_ERROR_STATUS_NO_ERROR
    error_index = 0
    oid_value = null()
    new_oid = None
    if oid in oids:
        new_oid = get_next(oids, oid)
        if not new_oid:
            oid_value = struct.pack('BB', ASN1_END_OF_MIB_VIEW, 0)  #null()
        else:
            oid_value = oids.get(new_oid)
    else:
        # now check wildcards
        results = find_oid_and_value_with_wildcard(oids, oid)
        if len(results) > 1:
            logger.warning('Several results found with wildcards for OID: %s', oid)
        if results:
            # if found several results get first one
            oid_key, oid_value = results[0]
            # and get the next oid from oids
            new_oid = get_next(oids, oid_key)
        else:
            new_oid = get_next(oids, oid)
        oid_value = oids.get(new_oid)
    if not oid_value:
        oid_value = null()
    # if new oid is found - get it, otherwise calculate possible next one
    if new_oid:
        oid = new_oid
    else:
        oid = get_next_oid(oid.rstrip('.0')) + '.0'
    # if wildcards are used in oid - replace them
    final_oid = replace_wildcards(oid)
    return error_status, error_index, final_oid, oid_value


def handle_set_request(oids, oid, type_and_value):
    """Handle SetRequest PDU"""
    error_status = ASN1_ERROR_STATUS_NO_ERROR
    error_index = 0
    value_type, value = type_and_value
    if value_type == 'INTEGER':
        enum_values = None
        if isinstance(oids[oid], tuple) and len(oids[oid]) > 1:
            enum_values = oids[oid][1]
        oids[oid] = integer(value, enum=enum_values)
    elif value_type == 'STRING':
        oids[oid] = octet_string(value if PY3 else value.encode('latin'))
    elif value_type == 'OID':
        oids[oid] = object_identifier(value)
    elif value_type == 'TIMETICKS':
        oids[oid] = timeticks(value)
    elif value_type == 'IPADDRESS':
        oids[oid] = ip_address(value)
    elif value_type == 'COUNTER32':
        oids[oid] = counter32(value)
    elif value_type == 'COUNTER64':
        oids[oid] = counter64(value)
    elif value_type == 'GAUGE32':
        oids[oid] = gauge32(value)
    elif value_type == 'OPAQUE':
        if value[0] == 'FLOAT':
            oids[oid] = real(value[1])
        elif value[0] == 'DOUBLE':
            oids[oid] = double(value[1])
        elif value[0] == 'UINT64':
            oids[oid] = uint64(value[1])
        elif value[0] == 'INT64':
            oids[oid] = int64(value[1])
        else:
            raise Exception('Unsupported type: {} ({})'.format(value_type, repr(value)))
    oid_value = oids[oid]
    return error_status, error_index, oid_value


def craft_response(version, community, request_id, error_status, error_index, oid_items):
    """Craft SNMP response"""
    response = write_tv(
        ASN1_SEQUENCE,
        # add version and community from request
        write_tv(ASN1_INTEGER, _write_int(version)) +
        write_tv(ASN1_OCTET_STRING, community.encode('latin') if PY3 else str(community)) +
        # add GetResponse PDU with get response fields
        write_tv(
            ASN1_GET_RESPONSE_PDU,
            # add response id, error status and error index
            write_tv(ASN1_INTEGER, _write_int(request_id)) +
            write_tlv(ASN1_INTEGER, 1, _write_int(error_status)) +
            write_tlv(ASN1_INTEGER, 1, _write_int(error_index)) +
            # add variable bindings
            write_tv(
                ASN1_SEQUENCE,
                b''.join(
                    # add OID and OID value
                    write_tv(
                        ASN1_SEQUENCE,
                        write_tv(
                            ASN1_OBJECT_IDENTIFIER,
                            oid_key.encode('latin') if PY3 else oid_key
                        ) +
                        oid_value
                    ) for (oid_key, oid_value) in oid_items
                )
            )
        )
    )
    return response


def generate_response(request_result, oids):

    # get required fields from request
    version = request_result[0][1]
    community = request_result[1][1]
    pdu_type = request_result[2][1]
    request_id = request_result[3][1]
    max_repetitions = request_result[5][1]
    logger.debug('max_repetitions %i', max_repetitions)

    error_status = ASN1_ERROR_STATUS_NO_ERROR
    error_index = 0
    oid_items = []
    oid_value = null()

    # handle protocol data units
    if pdu_type == ASN1_GET_REQUEST_PDU:
        requested_oids = request_result[6:]
        for _, oid in requested_oids:
            _, _, oid_value = handle_get_request(oids, oid)
            # if oid value is a function - call it to get the value
            if isinstance(oid_value, types.FunctionType):
                oid_value = oid_value(oid)
            if isinstance(oid_value, tuple):
                oid_value = oid_value[0]
            oid_items.append((oid_to_bytes(oid), oid_value))

    elif pdu_type == ASN1_GET_NEXT_REQUEST_PDU:
        oid = request_result[6][1]
        error_status, error_index, oid, oid_value = handle_get_next_request(oids, oid)
        if isinstance(oid_value, types.FunctionType):
            oid_value = oid_value(oid)
        if isinstance(oid_value, tuple):
            oid_value = oid_value[0]
        oid_items.append((oid_to_bytes(oid), oid_value))

    elif pdu_type == ASN1_GET_BULK_REQUEST_PDU:
        requested_oids = request_result[6:]
        for _ in range(0, max_repetitions):
            for idx, val in enumerate(requested_oids):
                oid = val[1]
                error_status, error_index, oid, oid_value = handle_get_next_request(oids, oid)
                if isinstance(oid_value, types.FunctionType):
                    oid_value = oid_value(oid)
                if isinstance(oid_value, tuple):
                    oid_value = oid_value[0]
                oid_items.append((oid_to_bytes(oid), oid_value))
                requested_oids[idx] = ('OID', oid)

    elif pdu_type == ASN1_SET_REQUEST_PDU:
        if len(request_result) < 8:
            raise Exception('Invalid ASN.1 parsed request length for SNMP set request!')
        oid = request_result[6][1]
        type_and_value = request_result[7]
        try:
            if isinstance(oids[oid], tuple) and len(oids[oid]) > 1:
                enum_values = oids[oid][1]
                new_value = type_and_value[1]
                if isinstance(enum_values, Iterable) and new_value not in enum_values:
                    raise WrongValueError('Value {} is outside the range of enum values'.format(new_value))
            error_status, error_index, oid_value = handle_set_request(oids, oid, type_and_value)
        except WrongValueError as ex:
            logger.error(ex)
            error_status = ASN1_ERROR_STATUS_WRONG_VALUE
            error_index = 0
        except Exception as ex:
            logger.error(ex)
            error_status = ASN1_ERROR_STATUS_BAD_VALUE
            error_index = 0
        # if oid value is a function - call it to get the value
        if isinstance(oid_value, types.FunctionType):
            oid_value = oid_value(oid)
        if isinstance(oid_value, tuple):
            oid_value = oid_value[0]
        oid_items.append((oid_to_bytes(oid), oid_value))

    # craft SNMP response
    response = craft_response(
        version, community, request_id, error_status, error_index, oid_items)
    return response

def send_response(sock, response, address):
    logger.debug('Sending %d bytes of response', len(response))
    try:
        sock.sendto(response, address)
    except socket.error as ex:
        logger.error('Failed to send %d bytes of response: %s', len(response), ex)
    logger.debug('')


class SNMPServer:
    DEFAULT_LISTEN_HOST = '0.0.0.0'
    DEFAULT_LISTEN_PORT = 1234

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.expected_messages = dict()
        self._is_running = True

    def __enter__(self):
        self.sock.bind((self.host, self.port))
        logger.info('SNMP server listening on {}:{}'.format(self.host, self.port))
        return self

    def __exit__(self, exception_type, exception_vale, traceback):
        self._is_running = False
        self.sock.close()

    def process_request(self):
        while self._is_running:
            request_data, address = self.sock.recvfrom(4096)
            logger.debug('Received %d bytes from %s', len(request_data), address)

            request_stream = StringIO(request_data.decode('latin'))
            request_result = _parse_snmp_asn1(request_stream)

            if len(request_result) < 7:
                raise Exception('Invalid ASN.1 parsed request length!')
            request = dict(request_result)
            print(request)

            _id = request['OID']
            if _id not in self.expected_messages:
                self.sock.close()
                raise ValueError(f'Request OID ({_id}) was not expected')

            response = generate_response(request_result, self.expected_messages)
            send_response(self.sock, response, address)

    def expect_request(self, request_id, reply_with, populate_parent=True):
        if isinstance(reply_with, str):
            reply = octet_string(reply_with)
        elif isinstance(reply_with, int):
            reply = integer(reply_with)
        elif isinstance(reply_with, list):
            reply = integer(reply_with[0], enum=reply_with)
        else:
            print('wtf!!', reply_with)
            reply = reply_with

        print(request_id, reply)
        self.expected_messages[request_id] = reply
        if populate_parent:
            parent = request_id.rpartition('.')[0]
            if parent not in self.expected_messages:
                self.expected_messages[parent] = None


def main():
    host = '0.0.0.0'
    port = 1234
    s = SNMPServer(host, port)
    s.start()
    print(s.expect_request('1.3.6.1.2.1.2.2.1.2'))
    s.stop()
    s.join()


if __name__ == '__main__':
    main()

