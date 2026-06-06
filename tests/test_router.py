"""Tests del NexusRouter — routing accuracy e IOC extraction. Sin LLM."""

import sqlite3
import pytest
import pandas as pd
from nexus.router import detect_intent, extract_ioc, tool_threat_hunt, tool_ioc_correlate


# ── Intent detection ──────────────────────────────────────────────────────────

INTENT_CASES = [
    # threat_hunt
    ("¿hay malware en el sistema?",           "threat_hunt"),
    ("busca patrones de malware",              "threat_hunt"),
    ("hay ransomware?",                        "threat_hunt"),
    ("hunting de TTPs",                        "threat_hunt"),
    ("infected processes?",                    "threat_hunt"),
    ("analiza amenazas del sistema",           "threat_hunt"),
    ("detecta virus",                          "threat_hunt"),
    ("yara scan",                              "threat_hunt"),
    # ioc — IP literal
    ("busca la IP 185.220.101.45",             "ioc"),
    ("correlaciona 10.0.0.5",                  "ioc"),
    ("pivot on 192.168.1.100",                 "ioc"),
    ("qué hay sobre 8.8.8.8",                  "ioc"),
    ("¿qué sé de la IP 172.16.0.1?",           "ioc"),
    # ioc — hash
    ("traza el hash a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "ioc"),
    # sql — default
    ("¿qué conexiones externas hay?",          "sql"),
    ("dame los procesos como SYSTEM",          "sql"),
    ("logons fallidos por IP",                 "sql"),
    ("¿cuántos eventos 4624 hay?",             "sql"),
    ("scheduled tasks habilitadas",            "sql"),
    ("¿qué usuarios se autenticaron?",         "sql"),
    ("conexiones a puerto 443",                "sql"),
    ("¿cuál es el rango de fechas?",           "sql"),
    ("dame el timeline",                       "sql"),
]


@pytest.mark.parametrize("question,expected", INTENT_CASES)
def test_intent_detection(question, expected):
    assert detect_intent(question) == expected, (
        f"'{question}' → esperaba '{expected}', got '{detect_intent(question)}'"
    )


# ── IOC extraction ────────────────────────────────────────────────────────────

IOC_CASES = [
    ("busca la IP 185.220.101.45",              "185.220.101.45"),
    ("correlaciona 10.0.0.5",                   "10.0.0.5"),
    ("pivot on 192.168.1.100",                  "192.168.1.100"),
    ("qué hay sobre 8.8.8.8",                   "8.8.8.8"),
    ("traza a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"),
    ("busca svchost.exe",                       "svchost.exe"),
]


@pytest.mark.parametrize("question,expected", IOC_CASES)
def test_ioc_extraction(question, expected):
    assert extract_ioc(question) == expected


# ── Threat hunt sobre DB real ─────────────────────────────────────────────────

LOCKBIT_DB = "lockbit_case.db"


@pytest.fixture(scope="module")
def lockbit_conn():
    import os
    db = os.path.join(os.path.dirname(__file__), "..", LOCKBIT_DB)
    if not os.path.exists(db):
        pytest.skip(f"DB no encontrada: {db}")
    conn = sqlite3.connect(db)
    yield conn
    conn.close()


def test_threat_hunt_returns_hits(lockbit_conn):
    hits = tool_threat_hunt(lockbit_conn)
    assert len(hits) > 0, "El caso LockBit debe tener al menos 1 hallazgo"


def test_threat_hunt_has_c2(lockbit_conn):
    hits = tool_threat_hunt(lockbit_conn)
    c2_rules = [h for h in hits if "C2" in h["name"] or "Outbound" in h["name"]]
    assert len(c2_rules) > 0, "LockBit debe mostrar conexiones C2 externas"


def test_threat_hunt_structure(lockbit_conn):
    hits = tool_threat_hunt(lockbit_conn)
    for h in hits:
        assert "rule_id" in h
        assert "severity" in h
        assert "name" in h
        assert isinstance(h["rows"], pd.DataFrame)
        assert h["count"] > 0


def test_ioc_correlate_known_ip(lockbit_conn):
    # Buscar cualquier IP externa que exista en la DB
    rows = lockbit_conn.execute(
        "SELECT DISTINCT source_ip FROM events "
        "WHERE source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' "
        "AND source_ip NOT LIKE '127.%' AND source_ip IS NOT NULL AND source_ip != '' "
        "LIMIT 1"
    ).fetchone()
    if not rows:
        pytest.skip("No hay IPs externas en la DB")

    ip = rows[0]
    results = tool_ioc_correlate(ip, lockbit_conn)
    assert len(results) > 0, f"IP externa {ip} debe aparecer en al menos una tabla"


def test_ioc_correlate_no_results(lockbit_conn):
    results = tool_ioc_correlate("1.2.3.4", lockbit_conn)
    # Si no hay resultados, debe devolver dict vacío (no crash)
    assert isinstance(results, dict)
