"""Tests para Ingestor — detección + carga + idempotencia."""

import sqlite3
import tempfile
from pathlib import Path

import pytest

from nexus.ingestor import Ingestor


NETSTAT_CONTENT = """Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       952
  TCP    10.0.0.5:49731         152.236.2.63:443       ESTABLISHED     9052
"""

SYSINFO_CONTENT = """Host Name:                 WIN-TEST
OS Name:                   Microsoft Windows 10
OS Version:                10.0.19041
"""


@pytest.fixture
def tmp_case(tmp_path):
    db = str(tmp_path / "test_case.db")
    return db, tmp_path


def test_ingest_netstat(tmp_case):
    db, tmp_path = tmp_case
    f = tmp_path / "netstat.txt"
    f.write_text(NETSTAT_CONTENT)

    ing = Ingestor(db)
    result = ing.ingest_file(f)
    ing.close()

    assert result["records"] == 2
    assert result["error"] is None
    assert result["type"] == "netstat"


def test_ingest_idempotent(tmp_case):
    """Ingestar el mismo archivo dos veces no debe duplicar registros."""
    db, tmp_path = tmp_case
    f = tmp_path / "netstat.txt"
    f.write_text(NETSTAT_CONTENT)

    ing = Ingestor(db)
    r1 = ing.ingest_file(f)
    r2 = ing.ingest_file(f)
    ing.close()

    assert r1["records"] == 2
    assert r2["records"] == 0  # skipped

    conn = sqlite3.connect(db)
    count = conn.execute("SELECT COUNT(*) FROM network_connections").fetchone()[0]
    conn.close()
    assert count == 2  # no duplicates


def test_ingest_directory(tmp_case):
    db, tmp_path = tmp_case
    (tmp_path / "netstat.txt").write_text(NETSTAT_CONTENT)
    (tmp_path / "sysinfo.txt").write_text(SYSINFO_CONTENT)

    ing = Ingestor(db)
    results = ing.ingest_directory(tmp_path)
    ing.close()

    parsed = [r for r in results if r["records"] > 0]
    assert len(parsed) == 2

    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM network_connections").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM sysinfo").fetchone()[0] == 1
    conn.close()


def test_evidence_files_registered(tmp_case):
    db, tmp_path = tmp_case
    f = tmp_path / "netstat.txt"
    f.write_text(NETSTAT_CONTENT)

    ing = Ingestor(db)
    ing.ingest_file(f)
    ing.close()

    conn = sqlite3.connect(db)
    row = conn.execute("SELECT filename, evidence_type FROM evidence_files").fetchone()
    conn.close()

    assert row[0] == "netstat.txt"
    assert row[1] == "netstat"
