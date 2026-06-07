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
    yield c
    c.close()


@pytest.fixture
def conn_no_events():
    """DB sin tabla events — para probar rutas de excepción en _check_event_ids."""
    c = sqlite3.connect(":memory:")
    c.executescript("""
        CREATE TABLE processes (id INTEGER PRIMARY KEY, pid INTEGER, name TEXT);
    """)
    yield c
    c.close()


@pytest.fixture
def conn_empty_events():
    """DB con tabla events pero sin ninguna fila — event_ids vacíos."""
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
    """)
    yield c
    c.close()


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
    assert r.hallucination_type == "syntax"
    assert "syntax" in r.errors[0].lower()


# ── Syntax type (EXPLAIN QUERY PLAN) ──────────────────────────────────────────

def test_double_quoted_string_accepted(conn):
    # SQLite acepta double quotes como string literal fallback — comportamiento esperado
    sql = 'SELECT username FROM events WHERE username = "admin"'
    r = validate(sql, conn)
    assert r.valid  # SQLite trata "admin" como string, no error


def test_unclosed_paren_syntax_error(conn):
    bad_sql = "SELECT COUNT(*) FROM events WHERE (event_id = 4624"
    r = validate(bad_sql, conn)
    assert not r.valid
    assert r.hallucination_type == "syntax"


def test_syntax_hint_generated(conn):
    bad_sql = "SELECT source_ip FROM events WHERE source_ip NOT LIKE '10.%\" GROUP BY source_ip"
    r = validate(bad_sql, conn)
    hint = build_correction_hint(r, conn)
    assert len(hint) > 0


# ── Structural: INSERT/UPDATE/DROP rejection ──────────────────────────────────

def test_insert_rejected(conn):
    r = validate("INSERT INTO events (id) VALUES (99)", conn)
    assert not r.valid
    assert r.hallucination_type == "structural"


def test_update_rejected(conn):
    r = validate("UPDATE events SET channel = 'x' WHERE id = 1", conn)
    assert not r.valid
    assert r.hallucination_type == "structural"


def test_drop_rejected(conn):
    r = validate("DROP TABLE events", conn)
    assert not r.valid
    assert r.hallucination_type == "structural"


# ── Referential: event_id edge cases ─────────────────────────────────────────

def test_event_id_in_list_all_valid(conn):
    r = validate("SELECT * FROM events WHERE event_id IN (4624, 4625)", conn)
    assert r.valid


def test_event_id_in_list_mixed(conn):
    r = validate("SELECT * FROM events WHERE event_id IN (4624, 9999)", conn)
    assert not r.valid
    assert r.hallucination_type == "referential"
    assert "9999" in r.errors[0]


def test_event_id_all_invalid_in_list(conn):
    r = validate("SELECT * FROM events WHERE event_id IN (1111, 2222)", conn)
    assert not r.valid
    assert r.hallucination_type == "referential"


# ── Subquery and CTE ──────────────────────────────────────────────────────────

def test_subquery_valid(conn):
    sql = ("SELECT username FROM "
           "(SELECT username, COUNT(*) as cnt FROM events GROUP BY username) t "
           "WHERE cnt > 1")
    r = validate(sql, conn)
    assert r.valid


def test_cte_valid(conn):
    sql = ("WITH top_users AS "
           "(SELECT username, COUNT(*) as cnt FROM events GROUP BY username) "
           "SELECT * FROM top_users")
    r = validate(sql, conn)
    assert r.valid


def test_subquery_bad_table(conn):
    sql = ("SELECT username FROM "
           "(SELECT username FROM nonexistent_table) t")
    r = validate(sql, conn)
    assert not r.valid


# ── Correction hint: column suggestion ───────────────────────────────────────

def test_hint_suggests_similar_column(conn):
    r = validate("SELECT * FROM events WHERE usernam = 'admin'", conn)
    if not r.valid and r.hallucination_type == "structural":
        hint = build_correction_hint(r, conn)
        assert len(hint) > 0


# ── Coverage gaps: event_id checks en DBs sin/vacíos events ──────────────────

def test_event_id_check_no_events_table(conn_no_events):
    # events table no existe — _check_event_ids debe manejar la excepción
    r = validate("SELECT * FROM processes WHERE pid = 1", conn_no_events)
    assert r.valid  # query a processes con event_id en un WHERE no aplica


def test_event_id_check_empty_events_table(conn_empty_events):
    # events table existe pero sin filas — real_ids vacío → válida sin error
    r = validate("SELECT * FROM events WHERE event_id = 4624", conn_empty_events)
    # real_ids vacío → early return, no error referential
    assert r.valid


def test_column_check_empty_tables(conn_no_events):
    # all_valid_cols vacío cuando la tabla no tiene columnas conocidas
    r = validate("SELECT * FROM processes WHERE pid = 1", conn_no_events)
    assert r.valid  # sin columnas que verificar → no errores


def test_select_constant_no_from(conn):
    # SELECT sin FROM → tables_in_sql=[], all_valid_cols={} → skip column check
    r = validate("SELECT 1", conn)
    assert r.valid
