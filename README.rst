SNMP server
===========

|MIT license badge|

Description:
------------
Simple SNMP server in pure Python  

Usage with pytest:
-----------------

The fixture `snmpserver` has the `host` and `port` attributes, along with the `expect_request` method

::

  def test_request_replies_correctly(snmpserver):
      snmpserver.expect_request("1.3.6.1.2.1.2.2.1.2", "some description")
      command = shlex.split(f'{snmpget_command} {snmpserver.host}:{snmpserver.port} IF-MIB::ifDescr')
      p = subprocess.Popen(command, stdout=subprocess.PIPE)
      p.wait()
      assert 'IF-MIB::ifDescr some description' == p.stdout.read().decode('utf-8').strip()


Usage:
-----
::

  usage: snmp-server.py [-h] [-p PORT] [-c CONFIG] [-d] [-v]

  SNMP server

  optional arguments:
    -h, --help            show this help message and exit
    -p PORT, --port PORT  port (by default 161 - requires root privileges)
    -c CONFIG, --config CONFIG
                          OIDs config file
    -d, --debug           run in debug mode
    -v, --version         show program's version number and exit

**Examples:**

::

  # ./snmp-server.py -p 12345
  SNMP server listening on 0.0.0.0:12345
  # ./snmp-server.py
  SNMP server listening on 0.0.0.0:161

Without config file SNMP server works as a simple SNMP echo server:

::

  # snmpget -v 2c -c public 0.0.0.0:161 1.2.3.4.5.6.7.8.9.10.11
  iso.2.3.4.5.6.7.8.9.10.11 = STRING: "1.2.3.4.5.6.7.8.9.10.11"

It is possible to create a config file with values for specific OIDs.  

Config file - is a Python script and must have DATA dictionary with string OID keys and values.  

Values can be either ASN.1 types (e.g. :code:`integer(...)`, :code:`octet_string(...)`, etc) or any Python lambda/functions (with single argument - OID string), returning ASN.1 type.  

::

  DATA = {
    '1.3.6.1.4.1.1.1.0': integer(12345),
    '1.3.6.1.4.1.1.2.0': bit_string('\x12\x34\x56\x78'),
    '1.3.6.1.4.1.1.3.0': octet_string('test'),
    '1.3.6.1.4.1.1.4.0': null(),
    '1.3.6.1.4.1.1.5.0': object_identifier('1.3.6.7.8.9'),
    # notice the wildcards:
    '1.3.6.1.4.1.1.6.*': lambda oid: octet_string('* {}'.format(oid)),
    '1.3.6.1.4.1.1.?.0': lambda oid: octet_string('? {}'.format(oid)),
    '1.3.6.1.4.1.2.1.0': real(1.2345),
    '1.3.6.1.4.1.3.1.0': double(12345.2345),
  }

::

  # ./snmp-server.py -c config.py
  SNMP server listening on 0.0.0.0:161

With config file :code:`snmpwalk` command as well as :code:`snmpget` can be used:

::

  # snmpwalk -v 2c -c public 0.0.0.0:161 .1.3.6.1.4.1
  iso.3.6.1.4.1.1.1.0 = INTEGER: 12345
  iso.3.6.1.4.1.1.2.0 = BITS: 12 34 56 78 3 6 10 11 13 17 19 21 22 25 26 27 28
  iso.3.6.1.4.1.1.3.0 = STRING: "test"
  iso.3.6.1.4.1.1.4.0 = NULL
  iso.3.6.1.4.1.1.5.0 = OID: iso.3.6.7.8.9
  iso.3.6.1.4.1.1.6.4294967295 = STRING: "* 1.3.6.1.4.1.1.6.4294967295"
  iso.3.6.1.4.1.1.9.0 = STRING: "? 1.3.6.1.4.1.1.9.0"
  iso.3.6.1.4.1.2.1.0 = Opaque: Float: 1.234500
  iso.3.6.1.4.1.3.1.0 = Opaque: Float: 12345.234500
  iso.3.6.1.4.1.4.1.0 = No more variables left in this MIB View (It is past the end of the MIB tree)

Also :code:`snmpset` command can be used:

::

  # snmpset -v2c -c public 0.0.0.0:161 .1.3.6.1.4.1.1.3.0 s "new value"
  iso.3.6.1.4.1.1.3.0 = STRING: "new value"
  #
  # snmpget -v2c -c public 0.0.0.0:161 .1.3.6.1.4.1.1.3.0 
  iso.3.6.1.4.1.1.3.0 = STRING: "new value"

License:
--------
Released under `The MIT License`_.

.. |MIT license badge| image:: http://img.shields.io/badge/license-MIT-brightgreen.svg
.. _The MIT License: https://github.com/delimitry/snmp-server/blob/master/LICENSE
