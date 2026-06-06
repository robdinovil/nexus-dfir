"""Tests para Evidence Detector — sin dependencias externas."""

import tempfile
from pathlib import Path

import pytest

from nexus.detector import detect, EvidenceFile


def _write(path: Path, data: bytes):
    path.write_bytes(data)
    return path


# ── Magic bytes ────────────────────────────────────────────────────────────────

def test_evtx_magic(tmp_path):
    f = _write(tmp_path / "mystery.bin", b"ElfFile\x00" + b"\x00" * 100)
    ev = detect(f)
    assert ev.evidence_type == "evtx"
    assert ev.confidence == "high"
    assert ev.parser == "evtx_parser"


def test_pcap_magic(tmp_path):
    f = _write(tmp_path / "cap.bin", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    ev = detect(f)
    assert ev.evidence_type == "pcap"
    assert ev.confidence == "high"


def test_reg_hive_magic(tmp_path):
    f = _write(tmp_path / "hive.dat", b"regf" + b"\x00" * 50)
    ev = detect(f)
    assert ev.evidence_type == "reg_hive"
    assert ev.confidence == "high"


def test_pe_magic(tmp_path):
    f = _write(tmp_path / "sample.exe", b"MZ" + b"\x00" * 50)
    ev = detect(f)
    assert ev.evidence_type == "pe"


# ── Text-based detection ───────────────────────────────────────────────────────

def test_reg_export_utf16(tmp_path):
    content = "Windows Registry Editor Version 5.00\r\n[HKEY_LOCAL_MACHINE]\r\n"
    f = tmp_path / "run.reg"
    f.write_bytes(b"\xff\xfe" + content.encode("utf-16-le"))
    ev = detect(f)
    assert ev.evidence_type == "reg_export"
    assert ev.confidence == "high"


def test_netstat_detection(tmp_path):
    content = (
        "Active Connections\n\n"
        "  Proto  Local Address          Foreign Address        State\n"
        "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING\n"
    )
    f = _write(tmp_path / "netstat.txt", content.encode())
    ev = detect(f)
    assert ev.evidence_type == "netstat"
    assert ev.parser == "netstat_parser"


def test_systeminfo_detection(tmp_path):
    content = (
        "Host Name:                 WIN-TEST\n"
        "OS Name:                   Microsoft Windows 10\n"
        "OS Version:                10.0.19041\n"
    )
    f = _write(tmp_path / "sysinfo.txt", content.encode())
    ev = detect(f)
    assert ev.evidence_type == "systeminfo"
    assert ev.parser == "systeminfo_parser"


def test_tasklist_csv_detection(tmp_path):
    content = '"Image Name","PID","Session Name","Session#","Mem Usage"\n"System","4","Services","0","5,468 K"\n'
    f = _write(tmp_path / "tasklist.csv", content.encode("utf-8"))
    ev = detect(f)
    assert ev.evidence_type == "tasklist_csv"
    assert ev.parser == "csv_parser"


def test_unknown_file(tmp_path):
    f = _write(tmp_path / "random.bin", b"\x00\x01\x02\x03\x04\x05")
    ev = detect(f)
    assert ev.evidence_type == "unknown"


def test_nonexistent_file():
    with pytest.raises(FileNotFoundError):
        detect(Path("/tmp/does_not_exist_xyz.bin"))
