"""Tests para NexusCase — gestión de casos en ~/.nexus/cases/."""

import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from nexus.case import NexusCase


@pytest.fixture
def cases_dir(tmp_path):
    """Directorio temporal que reemplaza CASES_DIR durante el test."""
    d = tmp_path / "cases"
    d.mkdir()
    with patch("nexus.case.CASES_DIR", d):
        yield d


# ── NexusCase.create ──────────────────────────────────────────────────────────

def test_create_makes_directory(cases_dir):
    case = NexusCase.create("test_ir")
    assert Path(case.path).exists()


def test_create_writes_meta(cases_dir):
    case = NexusCase.create("test_ir")
    meta_file = Path(case.path) / "meta.json"
    assert meta_file.exists()
    data = json.loads(meta_file.read_text())
    assert data["name"] == "test_ir"
    assert "created" in data


def test_create_sets_db_path(cases_dir):
    case = NexusCase.create("test_ir")
    assert case.db_path.endswith("case.db")
    assert "test_ir" in case.db_path


def test_create_sets_store_path(cases_dir):
    case = NexusCase.create("test_ir")
    assert case.store_path.endswith("store.db")


def test_create_duplicate_raises(cases_dir):
    NexusCase.create("test_ir")
    with pytest.raises(FileExistsError):
        NexusCase.create("test_ir")


# ── NexusCase.open ────────────────────────────────────────────────────────────

def test_open_existing_case(cases_dir):
    NexusCase.create("my_case")
    case = NexusCase.open("my_case")
    assert case.name == "my_case"


def test_open_nonexistent_raises(cases_dir):
    with pytest.raises(FileNotFoundError):
        NexusCase.open("nonexistent")


def test_open_error_mentions_name(cases_dir):
    with pytest.raises(FileNotFoundError, match="ghost"):
        NexusCase.open("ghost")


# ── NexusCase.resolve ─────────────────────────────────────────────────────────

def test_resolve_by_name(cases_dir):
    NexusCase.create("resolve_test")
    case = NexusCase.resolve("resolve_test")
    assert case.name == "resolve_test"


def test_resolve_by_db_path(tmp_path):
    db_file = tmp_path / "evidence.db"
    db_file.write_bytes(b"")
    case = NexusCase.resolve(str(db_file))
    assert case.name == "evidence"
    assert case.db_path == str(db_file)


def test_resolve_nonexistent_name_raises(cases_dir):
    with pytest.raises(FileNotFoundError):
        NexusCase.resolve("nope")


# ── NexusCase.list_all ────────────────────────────────────────────────────────

def test_list_all_empty(cases_dir):
    result = NexusCase.list_all()
    assert result == []


def test_list_all_returns_created_cases(cases_dir):
    NexusCase.create("alpha")
    NexusCase.create("beta")
    cases = NexusCase.list_all()
    names = [c["name"] for c in cases]
    assert "alpha" in names
    assert "beta" in names


def test_list_all_sorted(cases_dir):
    NexusCase.create("zebra")
    NexusCase.create("alpha")
    cases = NexusCase.list_all()
    names = [c["name"] for c in cases]
    assert names == sorted(names)


def test_list_all_has_required_fields(cases_dir):
    NexusCase.create("ir_2024")
    cases = NexusCase.list_all()
    c = cases[0]
    assert "name" in c
    assert "created" in c
    assert "records" in c
    assert "has_db" in c


def test_list_all_records_zero_without_db(cases_dir):
    NexusCase.create("empty_case")
    cases = NexusCase.list_all()
    assert cases[0]["records"] == 0
    assert not cases[0]["has_db"]


def test_list_all_records_count_with_db(cases_dir):
    case = NexusCase.create("with_data")
    conn = sqlite3.connect(case.db_path)
    conn.executescript("""
        CREATE TABLE events (id INTEGER, event_id INTEGER, timestamp_utc TEXT,
            channel TEXT, username TEXT, source_ip TEXT, computer TEXT, description TEXT);
        INSERT INTO events VALUES (1, 4624, '2024-01-01', 'Security', 'admin', '10.0.0.1', 'PC', 'ok');
        INSERT INTO events VALUES (2, 4625, '2024-01-01', 'Security', 'bob',   '10.0.0.2', 'PC', 'ok');
    """)
    conn.close()
    cases = NexusCase.list_all()
    assert cases[0]["records"] == 2
    assert cases[0]["has_db"]


# ── print_cases ───────────────────────────────────────────────────────────────

def test_print_cases_no_crash(cases_dir, capsys):
    from nexus.case import print_cases
    NexusCase.create("alpha")
    NexusCase.create("beta")
    cases = NexusCase.list_all()
    print_cases(cases)
    out = capsys.readouterr().out
    assert "alpha" in out
    assert "beta" in out


def test_print_cases_empty(capsys):
    from nexus.case import print_cases
    print_cases([])
    out = capsys.readouterr().out
    assert len(out) > 0  # muestra mensaje de "sin casos"


def test_meta_missing_file(cases_dir):
    # Directorio sin meta.json → _read_meta devuelve {}
    orphan = Path(str(cases_dir)) / "orphan_case"
    orphan.mkdir()
    # No se crea meta.json
    cases = NexusCase.list_all()
    orphan_case = next((c for c in cases if c["name"] == "orphan_case"), None)
    assert orphan_case is not None
    assert orphan_case["created"] == ""  # campo vacío cuando no hay meta
