"""Tests para parsers CSV, netstat, systeminfo y reg — sin archivos reales."""

import sqlite3
import tempfile
from pathlib import Path

import pytest

from nexus.schema import SCHEMA_SQL
from nexus.parsers.csv_parser import CsvParser
from nexus.parsers.netstat_parser import NetstatParser
from nexus.parsers.systeminfo_parser import SysteminfoParser
from nexus.parsers.reg_parser import RegExportParser


@pytest.fixture
def db_conn():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA_SQL)
    return conn


# ── CSV Parser ────────────────────────────────────────────────────────────────

TASKLIST_CSV = '''"Image Name","PID","Session Name","Session#","Mem Usage"
"System","4","Services","0","5,468 K"
"smss.exe","408","Services","0","1,200 K"
"cmd.exe","1234","Console","1","3,000 K"
'''

WMIC_CSV = (
    "Caption,CommandLine,ExecutablePath,ProcessId,ParentProcessId,WorkingSetSize\r\n"
    "cmd.exe,\"cmd.exe /c whoami\",C:\\Windows\\System32\\cmd.exe,1234,5678,3072000\r\n"
)

def test_tasklist_csv(db_conn, tmp_path):
    f = tmp_path / "tasklist.csv"
    f.write_text(TASKLIST_CSV)
    parser = CsvParser(db_conn)
    count = parser.parse(f)
    assert count == 3
    rows = db_conn.execute("SELECT pid, name FROM processes ORDER BY pid").fetchall()
    assert rows[0] == (4, "System")
    assert rows[1] == (408, "smss.exe")


def test_wmic_csv(db_conn, tmp_path):
    f = tmp_path / "wmic.csv"
    f.write_text(WMIC_CSV)
    parser = CsvParser(db_conn)
    count = parser.parse(f)
    assert count == 1
    row = db_conn.execute("SELECT pid, name, command_line FROM processes").fetchone()
    assert row[0] == 1234
    assert "cmd.exe" in row[1]


# ── Netstat Parser ────────────────────────────────────────────────────────────

NETSTAT_OUTPUT = """Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       952
  TCP    10.0.0.5:49731         152.236.2.63:443       ESTABLISHED     9052
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
"""

def test_netstat_parse(db_conn, tmp_path):
    f = tmp_path / "netstat.txt"
    f.write_text(NETSTAT_OUTPUT)
    parser = NetstatParser(db_conn)
    count = parser.parse(f)
    assert count == 3

    rows = db_conn.execute(
        "SELECT state, remote_address, remote_port, pid FROM network_connections ORDER BY pid"
    ).fetchall()

    established = [r for r in rows if r[0] == "ESTABLISHED"]
    assert len(established) == 1
    assert established[0][1] == "152.236.2.63"
    assert established[0][2] == 443
    assert established[0][3] == 9052


# ── SystemInfo Parser ─────────────────────────────────────────────────────────

SYSINFO_OUTPUT = """Host Name:                 WIN-QE52MMFSD3E
OS Name:                   Microsoft Windows Server 2019
OS Version:                10.0.17763 N/A Build 17763
System Boot Time:          1/5/2024, 10:22:31 AM
Domain:                    WORKGROUP
IP Address(es):            10.0.0.5
Hotfix(es):                3 Hotfix(s) Installed
                           [01]: KB5001567
"""

def test_systeminfo_parse(db_conn, tmp_path):
    f = tmp_path / "sysinfo.txt"
    f.write_text(SYSINFO_OUTPUT)
    parser = SysteminfoParser(db_conn)
    count = parser.parse(f)
    assert count == 1
    row = db_conn.execute("SELECT hostname, os_name, domain FROM sysinfo").fetchone()
    assert row[0] == "WIN-QE52MMFSD3E"
    assert "Windows Server 2019" in row[1]
    assert row[2] == "WORKGROUP"


# ── Reg Parser ────────────────────────────────────────────────────────────────

REG_CONTENT = """Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]
"SecurityHealth"="C:\\\\Windows\\\\system32\\\\SecurityHealthSystray.exe"
"MaliciousPersist"="C:\\\\Users\\\\Public\\\\svhost.exe"
"""

def test_reg_parser(db_conn, tmp_path):
    f = tmp_path / "run.reg"
    f.write_text(REG_CONTENT)
    parser = RegExportParser(db_conn)
    count = parser.parse(f)
    assert count == 2
    rows = db_conn.execute(
        "SELECT value_name, value_data FROM registry_keys ORDER BY value_name"
    ).fetchall()
    names = [r[0] for r in rows]
    assert "MaliciousPersist" in names
    assert "SecurityHealth" in names
