"""
Schema SQLite unificado de Nexus.
Todas las tablas tienen timestamp_utc, source_file, y evidence_type para trazabilidad.
"""

SCHEMA_SQL = """
-- Registro de todos los archivos ingestados
CREATE TABLE IF NOT EXISTS evidence_files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    filename      TEXT NOT NULL,
    filepath      TEXT NOT NULL UNIQUE,
    evidence_type TEXT NOT NULL,
    file_size_kb  REAL,
    sha256        TEXT,
    ingested_at   TEXT DEFAULT (datetime('now')),
    record_count  INTEGER DEFAULT 0
);

-- Eventos de logs (EVTX y similares)
CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc  TEXT,
    event_id       INTEGER,
    channel        TEXT,
    provider       TEXT,
    level          TEXT,
    computer       TEXT,
    username       TEXT,
    source_ip      TEXT,
    description    TEXT,
    raw_data       TEXT,
    source_file    TEXT
);

-- Procesos en ejecución (tasklist, wmic, ps)
CREATE TABLE IF NOT EXISTS processes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc   TEXT,
    pid             INTEGER,
    ppid            INTEGER,
    name            TEXT,
    command_line    TEXT,
    exe_path        TEXT,
    username        TEXT,
    session         TEXT,
    memory_kb       REAL,
    cpu_time        TEXT,
    status          TEXT,
    source_file     TEXT
);

-- Conexiones de red (netstat, pcap)
CREATE TABLE IF NOT EXISTS network_connections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc   TEXT,
    protocol        TEXT,
    local_address   TEXT,
    local_port      INTEGER,
    remote_address  TEXT,
    remote_port     INTEGER,
    state           TEXT,
    pid             INTEGER,
    process_name    TEXT,
    source_file     TEXT
);

-- Caché DNS
CREATE TABLE IF NOT EXISTS dns_cache (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc   TEXT,
    hostname        TEXT,
    record_type     TEXT,
    ttl             INTEGER,
    data            TEXT,
    source_file     TEXT
);

-- Tareas programadas
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_name       TEXT,
    task_path       TEXT,
    status          TEXT,
    last_run        TEXT,
    next_run        TEXT,
    author          TEXT,
    run_as          TEXT,
    command         TEXT,
    arguments       TEXT,
    enabled         INTEGER,
    source_file     TEXT
);

-- Claves de registro (Run keys, persistencia)
CREATE TABLE IF NOT EXISTS registry_keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hive            TEXT,
    key_path        TEXT,
    value_name      TEXT,
    value_type      TEXT,
    value_data      TEXT,
    modified_time   TEXT,
    source_file     TEXT
);

-- Información del sistema
CREATE TABLE IF NOT EXISTS sysinfo (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname        TEXT,
    os_name         TEXT,
    os_version      TEXT,
    architecture    TEXT,
    install_date    TEXT,
    last_boot       TEXT,
    domain          TEXT,
    ip_addresses    TEXT,
    hotfixes        TEXT,
    source_file     TEXT
);

-- Trazabilidad: log de cada query NL→SQL ejecutado
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT DEFAULT (datetime('now')),
    case_name       TEXT,
    question        TEXT,
    sql_generated   TEXT,
    success         INTEGER,
    row_count       INTEGER,
    hallucination   TEXT,
    autocorrected   INTEGER,
    latency_s       REAL
);

-- Conclusiones persistidas de agentes (EIL, triage)
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT DEFAULT (datetime('now')),
    case_name   TEXT,
    agent       TEXT,
    goal        TEXT,
    conclusion  TEXT,
    steps_used  INTEGER
);

-- Índices para queries forenses comunes
CREATE INDEX IF NOT EXISTS idx_events_timestamp   ON events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_event_id    ON events(event_id);
CREATE INDEX IF NOT EXISTS idx_events_username    ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_source_ip   ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_network_remote     ON network_connections(remote_address);
CREATE INDEX IF NOT EXISTS idx_network_pid        ON network_connections(pid);
CREATE INDEX IF NOT EXISTS idx_processes_pid      ON processes(pid);
CREATE INDEX IF NOT EXISTS idx_registry_path      ON registry_keys(key_path);
"""
