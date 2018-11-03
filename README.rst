SNMP server
===========

|MIT license badge|

Description:
------------
Simple SNMP server in pure Python  

Usage:
-----
::

  usage: snmp-server.py [-h] [-p PORT] [-v]

  SNMP server

  optional arguments:
    -h, --help            show this help message and exit
    -p PORT, --port PORT  port (by default 161 - requires root privileges)
    -v, --version         show program's version number and exit

**Example:**

::

  # ./snmp-server.py
  # ./snmp-server.py -p 12345

License:
--------
Released under `The MIT License`_.

.. |MIT license badge| image:: http://img.shields.io/badge/license-MIT-brightgreen.svg
.. _The MIT License: https://github.com/delimitry/snmp-server/blob/master/LICENSE
