import subprocess
import shlex


snmpget_command = '/usr/bin/snmpget -Oq -v2c -t 1 -c public 127.0.0.1:1234'
snmpset_command = '/usr/bin/snmpset -Oq -v2c -t 1 -c public 127.0.0.1:1234'
snmpwalk_command = '/usr/bin/snmpwalk -Oq -v2c -t 1 -c public 127.0.0.1:1234'


def test_request_replies_correctly(snmpserver):
    snmpserver.expect_request("1.3.6.1.2.1.2.2.1.2", "qqq")
    p = subprocess.Popen(shlex.split(f'{snmpget_command} IF-MIB::ifDescr'), stdout=subprocess.PIPE)
    p.wait()
    assert 'IF-MIB::ifDescr qqq' == p.stdout.read().decode('utf-8').strip()


def test_dual_request_replies_correctly(snmpserver):
    snmpserver.expect_request("1.3.6.1.2.1.2.2.1.8.1005", 1)  # 1==up
    snmpserver.expect_request("1.3.6.1.2.1.2.2.1.2.1004", "some description")

    p = subprocess.Popen(shlex.split(f'{snmpget_command}  IF-MIB::ifOperStatus.1005 IF-MIB::ifDescr.1004'), stdout=subprocess.PIPE)
    p.wait()
    stdout = p.stdout.read().decode('utf-8')
    print(f'stdout: {stdout}')
    assert 'IF-MIB::ifOperStatus.1005 up\nIF-MIB::ifDescr.1004 some description' == stdout.strip()


def test_snmp_range_correctly(snmpserver):
    snmpserver.expect_request("1.3.6.1.2.1.2.2.1.7.1004", [2, 3])
    p = subprocess.Popen(shlex.split(f'{snmpset_command}  IF-MIB::ifAdminStatus.1004 i 7'),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p.wait()
    assert p.returncode != 0
    stderr = p.stderr.read().decode('utf-8')
    assert 'wrongValue' in stderr

def test_snmp_walk(snmpserver):
    snmpserver.expect_request("1.3.6.1.2.1.2.2.1.1.1004", [2, 3])
    snmpserver.expect_request("1.3.6.1.2.1.2.2.1.1.1005", [2, 3])
    p = subprocess.Popen(shlex.split(f'{snmpwalk_command}  IF-MIB::ifIndex'),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p.wait()
    stdout = p.stdout.read().decode('utf-8')
    assert '1004' in stdout
    assert '1005' in stdout
