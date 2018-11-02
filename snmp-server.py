# -*- coding: utf-8 -*-
"""
SNMP server
"""

from __future__ import print_function

import logging
import socket
import string
import struct
import sys
from contextlib import closing
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

PY3 = sys.version_info[0] == 3

logging.basicConfig(format='[%(levelname)s] %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)  # set level to logging.DEBUG for debug info

# ASN.1 tags
ASN1_BOOLEAN = 0x01
ASN1_INTEGER = 0x02
ASN1_OCTET_STRING = 0x04
ASN1_NULL = 0x05
ASN1_OBJECT_IDENTIFIER = 0x06
ASN1_PRINTABLE_STRING = 0x13
ASN1_SEQUENCE = 0x30
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

# some ASN.1 opaque special types
ASN1_CONTEXT = 0x80
ASN1_EXTENSION_ID = 0x1F
ASN1_OPAQUE_TAG1 = ASN1_CONTEXT | ASN1_EXTENSION_ID
ASN1_OPAQUE_TAG2 = 0x30
ASN1_APPLICATION = 0x40
ASN1_APP_FLOAT = ASN1_APPLICATION | 8
ASN1_APP_DOUBLE = ASN1_APPLICATION | 9
ASN1_OPAQUE_FLOAT = ASN1_OPAQUE_TAG2 + ASN1_APP_FLOAT
ASN1_OPAQUE_DOUBLE = ASN1_OPAQUE_TAG2 + ASN1_APP_DOUBLE
ASN1_OPAQUE_FLOAT_BER_LEN = 7
ASN1_OPAQUE_DOUBLE_BER_LEN = 11

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
    for x in oid_values[2:]:
        result_values += encode_to_7bit(x)
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
        x = values.pop(0)
        if x > 0x7f:
            huges = []
            huges.append(x)
            while True:
                y = values.pop(0)
                huges.append(y)
                if y < 0x80:
                    break
            huge = 0
            for i, v in enumerate(huges):
                huge += (v & 0x7f) << (7 * (len(huges) - i - 1))
            res.append(huge)
        else:
            res.append(x)
    return '.'.join(str(x) for x in res)


def timeticks_to_str(ticks):
    """Return "days, hours, minutes, seconds and ms" string from ticks"""
    days, rem1 = divmod(ticks, 24 * 60 * 60 * 100)
    hours, rem2 = divmod(rem1, 60 * 60 * 100)
    minutes, rem3 = divmod(rem2, 60 * 100)
    seconds, ms = divmod(rem3, 100)
    ending = 's' if days > 1 else ''
    days_fmt = '{} day{}, '.format(days, ending) if days > 0 else ''
    return '{}{:-02}:{:-02}:{:-02}.{:-02}'.format(days_fmt, hours, minutes, seconds, ms)


def int_to_ip(value):
    """Int to IP"""
    return socket.inet_ntoa(struct.pack("!I", value))


def twos_complement(value, bits):
    """Calculate two's complement"""
    mask = 2 ** (bits - 1)
    return -(value & mask) + (value & ~mask)


def _read_byte(stream):
    """Read byte from stream"""
    b = stream.read(1)
    if not b:
        raise Exception('No more bytes!')
    return ord(b)


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
        result = twos_complement(result, 8 ** length)
    return result


def _write_int(value):
    """Write int"""
    if value < 0x80:
        result = chr(value)
    else:
        values = []
        while value:
            values.append(value & 0xff)
            value >>= 8
        values.reverse()
        result = ''.join([chr(x) for x in values])
    return bytes(result, 'latin') if PY3 else result


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
    value = _read_int_len(stream, length)
    # convert int to float
    float_value = struct.unpack('>f', struct.pack('>l', value))[0]
    logger.debug('ASN1_OPAQUE_FLOAT: %s', round(float_value, 5))
    return 'FLOAT', round(float_value, 5)


def _parse_asn1_opaque_double(stream):
    """Parse ASN.1 opaque double"""
    length = _parse_asn1_length(stream)
    value = _read_int_len(stream, length)
    # convert long long to double
    double_value = struct.unpack('>d', struct.pack('>q', value))[0]
    logger.debug('ASN1_OPAQUE_DOUBLE: %s', round(double_value, 5))
    return 'DOUBLE', round(double_value, 5)


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
        return _parse_asn1_opaque_float(stream)
    # for simple opaque - rewind 2 bytes back (opaque tag and type)
    stream.seek(stream.tell() - 2)
    return stream.read(length)


def _parse_asn1(stream):
    """Parse ASN.1
    After |IP|UDP| headers and "sequence" tag, SNMP protocol data units (PDUs) are the next:
    |version|community|PDU-type|request-id|error-status|error-index|variable bindings|
    """
    result = []
    wait_oid_value = False
    pdu_index = 0
    while True:
        b = stream.read(1)
        if not b:
            return result
        tag = ord(b)
        # check protocol's tags at indices
        if (
            pdu_index in [1, 4, 5, 6] and tag != ASN1_INTEGER or
            pdu_index == 2 and tag != ASN1_OCTET_STRING or
            pdu_index == 3 and tag not in [ASN1_GET_REQUEST_PDU, ASN1_GET_NEXT_REQUEST_PDU]
        ):
            raise ProtocolError('Invalid tag for PDU unit "{}"'.format(SNMP_PDUS[pdu_index]))
        if tag == ASN1_SEQUENCE:
            length = _parse_asn1_length(stream)
            logger.debug('ASN1_SEQUENCE: %s', 'length = {}'.format(length))
        elif tag == ASN1_INTEGER:
            length = _read_byte(stream)
            value = _read_int_len(stream, length, True)
            logger.debug('ASN1_INTEGER: %s', value)
            if wait_oid_value or pdu_index in [1, 4, 5, 6]:  # version, request-id, error-status, error-index
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
            length = _read_byte(stream)
            logger.debug('ASN1_GET_REQUEST_PDU: %s', 'length = {}'.format(length))
            if pdu_index == 3:  # PDU-type
                result.append(('ASN1_GET_REQUEST_PDU', tag))
        elif tag == ASN1_GET_NEXT_REQUEST_PDU:
            length = _read_byte(stream)
            logger.debug('ASN1_GET_NEXT_REQUEST_PDU: %s', 'length = {}'.format(length))
            if pdu_index == 3:  # PDU-type
                result.append(('ASN1_GET_NEXT_REQUEST_PDU', tag))
        elif tag == ASN1_GET_RESPONSE_PDU:
            length = _parse_asn1_length(stream)
            logger.debug('ASN1_GET_RESPONSE_PDU: %s', 'length = {}'.format(length))
        elif tag == ASN1_TIMETICKS:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            logger.debug('ASN1_TIMETICKS: %s', value, timeticks_to_str(value))
            if wait_oid_value:
                result.append(('TIMETICKS', '({}) {}'.format(value, timeticks_to_str(value))))
                wait_oid_value = False
        elif tag == ASN1_IPADDRESS:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            logger.debug('ASN1_IPADDRESS: %s', value, int_to_ip(value))
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
            logger.debug('ASN1_OPAQUE: %s', value)
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
            logger.debug('?', hex(ord(b)))
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
    oid_next = '.'.join(oid_vals)
    return oid_next


def write_tlv(tag, length, value):
    """Write TLV (Tag-Length-Value)"""
    if length > 255:
        raise NotImplementedError('TODO')
    return struct.pack('BB', tag, length) + value


def write_tv(tag, value):
    """Write TV (Tag-Value) and calculate length from value"""
    return write_tlv(tag, len(value), value)


def main():
    """Main"""
    host = '0.0.0.0'
    port = 161

    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            # snmp server main loop
            while True:
                request_data, address = sock.recvfrom(4096)
                logger.debug('Received %d bytes from %s', len(request_data), address)

                request_stream = StringIO(request_data.decode('latin'))
                request_result = _parse_asn1(request_stream)

                if len(request_result) < 7:
                    raise Exception('Invalid ASN.1 parse request result length!')

                # get required fields from request
                version = request_result[0][1]
                community = request_result[1][1]
                pdu_type = request_result[2][1]
                request_id = request_result[3][1]
                oid = request_result[6][1]

                if pdu_type == ASN1_GET_NEXT_REQUEST_PDU:
                    oid = get_next_oid(oid)

                oid_key = oid_to_bytes(oid)
                oid_value = '{}'.format(oid)

                # craft SNMP response
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
                        write_tlv(ASN1_INTEGER, 1, _write_int(0)) +
                        write_tlv(ASN1_INTEGER, 1, _write_int(0)) +
                        # add variable bindings
                        write_tv(
                            ASN1_SEQUENCE,
                            # add OID and OID value
                            write_tv(
                                ASN1_SEQUENCE,
                                write_tv(ASN1_OBJECT_IDENTIFIER, oid_key.encode('latin') if PY3 else oid_key) +
                                write_tv(ASN1_OCTET_STRING, oid_value.encode('latin') if PY3 else oid_value)
                            )
                        )
                    )
                )
                logger.debug('Sending %d bytes of response', len(response))
                logger.debug('==============================')
                sock.sendto(response, address)
    except KeyboardInterrupt:
        logger.debug('Interrupted by Ctrl+C')


if __name__ == '__main__':
    main()
