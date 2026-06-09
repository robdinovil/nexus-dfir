"""Stats comunes para triage y report — SQL puro, cero LLM."""

import sqlite3
from datetime import datetime as dt


def collect_basic_stats(conn: sqlite3.Connection) -> dict:
    """
    Scalars comunes usados por triage y report.
    Evita duplicar las mismas ~15 queries en ambos agentes.
    """

    def q1(sql: str) -> int | str:
        try:
            row = conn.execute(sql).fetchone()
            return row[0] if row else 0
        except Exception:
            return 0

    s: dict = {}

    # Volumen
    s["total_events"]     = q1("SELECT COUNT(*) FROM events")
    s["unique_event_ids"] = q1("SELECT COUNT(DISTINCT event_id) FROM events")
    s["unique_users"]     = q1("SELECT COUNT(DISTINCT username) FROM events WHERE username IS NOT NULL AND username != ''")
    s["unique_ips"]       = q1("SELECT COUNT(DISTINCT source_ip) FROM events WHERE source_ip IS NOT NULL AND source_ip != ''")
    s["unique_machines"]  = q1("SELECT COUNT(DISTINCT computer) FROM events WHERE computer IS NOT NULL AND computer != ''")
    s["processes"]        = q1("SELECT COUNT(*) FROM processes")
    s["net_connections"]  = q1("SELECT COUNT(*) FROM network_connections")
    s["sched_tasks"]      = q1("SELECT COUNT(*) FROM scheduled_tasks")
    s["registry_keys"]    = q1("SELECT COUNT(*) FROM registry_keys")
    s["evidence_files"]   = q1("SELECT COUNT(*) FROM evidence_files")

    # Rango temporal
    s["first_event"] = q1("SELECT MIN(timestamp_utc) FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != ''") or ""
    s["last_event"]  = q1("SELECT MAX(timestamp_utc) FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != ''") or ""
    s["has_timestamps"] = bool(s["first_event"])

    dwell = 0
    if s["first_event"] and s["last_event"]:
        try:
            t0 = dt.fromisoformat(str(s["first_event"]).replace(" ", "T")[:19])
            t1 = dt.fromisoformat(str(s["last_event"]).replace(" ", "T")[:19])
            dwell = (t1 - t0).days
        except Exception:
            pass
    s["dwell_days"] = dwell

    # Señales de ataque frecuentemente consultadas
    s["brute_force_total"] = q1("SELECT COUNT(*) FROM events WHERE event_id IN (4625,4771,4776,18456)")
    s["log_clearing"]      = q1("SELECT COUNT(*) FROM events WHERE event_id IN (1102, 104)")
    s["priv_assigned"]     = q1("SELECT COUNT(*) FROM events WHERE event_id = 4672")
    s["lsass_access"]      = q1("SELECT COUNT(*) FROM events WHERE event_id = 10 AND description LIKE '%lsass%'")

    return s
