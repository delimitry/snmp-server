import os
import threading

import pytest
from .snmp_server import SNMPServer

@pytest.fixture
def snmpserver():
    host = os.environ.get("PYTEST_SNMPSERVER_HOST")
    port = os.environ.get("PYTEST_SNMPSERVER_PORT")
    if port:
        port = int(port)

    if not host:
        host = SNMPServer.DEFAULT_LISTEN_HOST
    if not port:
        port = SNMPServer.DEFAULT_LISTEN_PORT

    with SNMPServer(host, port) as server:
        t = threading.Thread(target=server.process_request)
        t.daemon = True
        t.start()
        yield server
