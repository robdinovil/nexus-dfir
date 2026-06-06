"""Tests para SQL Validator — detecta alucinaciones estructurales y referenciales."""

import sqlite3
import pytest

from nexus.validator import validate, build_correction_hint


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.executescript("""
        CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            timestamp_utc TEXT,
            event_id INTEGER,
            channel TEXT,
            username TEXT,
            source_ip TEXT,
            computer TEXT,
            description TEXT
        );
        INSERT INTO events VALUES (1, '2024-01-01', 4624, 'Security', 'admin', '10.0.0.1', 'HOST', 'desc');
        INSERT INTO events VALUES (2, '2024-01-02', 4625, 'Security', 'bob', '10.0.0.2', 'HOST', 'desc');

        CREATE TABLE processes (
            id INTEGER PRIMARY KEY,
            pid INTEGER,
            name TEXT,
            username TEXT
        );
    """)
    return c


# ── Valid queries ─────────────────────────────────────────────────────────────

def test_valid_simple(conn):
    r = validate("SELECT event_id, COUNT(*) FROM events GROUP BY event_id", conn)
    assert r.valid
    assert r.hallucination_type is None


def test_valid_join(conn):
    sql = "SELECT e.username, p.name FROM events e JOIN processes p ON e.username = p.username"
    r = validate(sql, conn)
    assert r.valid


def test_valid_with_where(conn):
    r = validate("SELECT * FROM events WHERE event_id = 4624", conn)
    assert r.valid


# ── Structural errors ──────────────────────────────────────────────────────────

def test_non_select_rejected(conn):
    r = validate("DELETE FROM events", conn)
    assert not r.valid
    assert r.hallucination_type == "structural"


def test_table_does_not_exist(conn):
    r = validate("SELECT * FROM network_connections", conn)
    assert not r.valid
    assert r.hallucination_type == "structural"
    assert "network_connections" in r.errors[0]


def test_column_does_not_exist(conn):
    r = validate("SELECT * FROM events WHERE logon_type = 3", conn)
    assert not r.valid
    assert r.hallucination_type == "structural"


# ── Referential errors ────────────────────────────────────────────────────────

def test_event_id_not_in_db(conn):
    r = validate("SELECT * FROM events WHERE event_id = 4688", conn)
    assert not r.valid
    assert r.hallucination_type == "referential"
    assert "4688" in r.errors[0]


def test_event_id_present_passes(conn):
    r = validate("SELECT * FROM events WHERE event_id = 4624", conn)
    assert r.valid


def test_event_id_in_list_partial_fail(conn):
    r = validate("SELECT * FROM events WHERE event_id IN (4624, 4688)", conn)
    assert not r.valid
    assert r.hallucination_type == "referential"


# ── Correction hints ──────────────────────────────────────────────────────────

def test_hint_generated_for_column_error(conn):
    r = validate("SELECT * FROM events WHERE logon_type = 3", conn)
    hint = build_correction_hint(r, conn)
    assert "logon_type" in hint


def test_hint_generated_for_event_id_error(conn):
    r = validate("SELECT * FROM events WHERE event_id = 9999", conn)
    hint = build_correction_hint(r, conn)
    assert "9999" in hint


def test_syntax_error_detected(conn):
    bad_sql = "SELECT source_ip FROM events WHERE username = 'admin' AND source_ip NOT LIKE '10.%\" GROUP BY source_ip"
    r = validate(bad_sql, conn)
    assert not r.valid
    assert r.hallucination_type == "structural"
    assert "syntax" in r.errors[0].lower()
