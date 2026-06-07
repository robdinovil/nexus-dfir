"""
Nexus Analyst — capa NL→SQL sobre cualquier caso Nexus.

No está hardcodeada a ningún caso. Lee el schema de la DB,
detecta qué tablas tienen datos, y construye el contexto
forense relevante para esas tablas.
"""

import re
import sqlite3
import json
from pathlib import Path

BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
RESET  = "\033[0m"

# ── Documentación DFIR por tabla ──────────────────────────────────────────────
# Se inyecta solo si la tabla existe y tiene datos.

TABLE_DOCS = {
    "events": [
        "The 'events' table contains Windows Event Log entries parsed from EVTX files.",
        "Column 'event_id' is the Windows Event ID (integer). Common forensic IDs: 4624=successful logon, 4625=failed logon, 4634=logoff, 4648=logon with explicit credentials, 4672=special privileges assigned, 4688=process creation, 4698=scheduled task created, 4720=user account created, 4726=user account deleted, 4776=NTLM authentication.",
        "Column 'timestamp_utc' is the event timestamp in UTC. Use datetime() and strftime() for time-based analysis.",
        "Column 'username' is the account name involved in the event. May include domain prefix (DOMAIN\\user).",
        "Column 'source_ip' is the remote IP address that originated the event (logon source, connection origin). NULL means local activity.",
        "Column 'channel' identifies the log source: 'Security', 'Application', 'System', 'Microsoft-Windows-Sysmon/Operational', etc.",
        "Column 'computer' is the hostname of the system where the event was recorded.",
        "Column 'description' contains key event fields as key=value pairs extracted from EventData.",
        "To detect brute force: count EID 4625 grouped by username and source_ip.",
        "EventId 21 = Remote Desktop Services session logon succeeded (RDP login).",
        "EventId 22 = Remote Desktop Services shell start notification (RDP session fully established).",
        "EventId 23 = Remote Desktop Services session logoff succeeded.",
        "EventId 24 = Remote Desktop Services session disconnected.",
        "For RDP analysis use EventId=21 to find successful RDP logons. column source_ip contains the originating IP.",
        "To detect lateral movement: find EID 4624 from external source_ip addresses (NOT LIKE '10.%', '192.168.%', '127.%'). WARNING: 'logon_type' is NOT a column in the events table — do NOT use it in any query.",
        "To detect privilege escalation: correlate EID 4672 with EID 4624 for the same logon session.",
        "External IPs are those NOT starting with 10., 192.168., 172.16-31., or 127.",
    ],
    "processes": [
        "The 'processes' table contains running process snapshots from tasklist or WMIC output.",
        "Column 'pid' is the Process ID (integer). Column 'ppid' is the Parent Process ID.",
        "Column 'name' is the process executable name (e.g. 'cmd.exe', 'powershell.exe').",
        "Column 'command_line' contains the full command line with arguments. Useful for detecting encoded payloads, suspicious flags, or LOLBins.",
        "Column 'exe_path' is the full path to the executable. Suspicious if not in System32, Program Files, or known directories.",
        "Column 'username' is the account running the process. SYSTEM/LOCAL SERVICE are normal for services. User accounts running system processes are suspicious.",
        "Column 'memory_kb' is memory usage in KB.",
        "LOLBins to watch: powershell.exe, cmd.exe, wscript.exe, cscript.exe, mshta.exe, certutil.exe, bitsadmin.exe, regsvr32.exe, rundll32.exe, schtasks.exe.",
        "Suspicious command line patterns: -EncodedCommand, -enc, Invoke-WebRequest, IEX, DownloadString, bypass, hidden.",
    ],
    "network_connections": [
        "The 'network_connections' table contains active network connections from netstat output.",
        "Column 'protocol' is TCP or UDP.",
        "Column 'local_address' and 'local_port' identify the local endpoint.",
        "Column 'remote_address' and 'remote_port' identify the remote endpoint. NULL remote means LISTENING.",
        "Column 'state' is the connection state: ESTABLISHED, LISTENING, TIME_WAIT, CLOSE_WAIT, etc.",
        "Column 'pid' links to the processes table for attribution.",
        "ESTABLISHED connections to external IPs are the most forensically relevant — they indicate active C2 or data exfiltration.",
        "Common C2 ports: 443 (HTTPS), 80 (HTTP), 8080, 4444, 1337. Legitimate services rarely use non-standard high ports.",
        "To find C2: SELECT remote_address, remote_port, pid FROM network_connections WHERE state='ESTABLISHED' AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '127.%'",
    ],
    "scheduled_tasks": [
        "The 'scheduled_tasks' table contains Windows scheduled tasks.",
        "Column 'task_name' is the task name. Column 'task_path' is the full path in Task Scheduler.",
        "Column 'command' is the executable or script the task runs.",
        "Column 'author' is who created the task. Column 'run_as' is the account it runs under.",
        "Column 'status' indicates if the task is Ready, Running, or Disabled.",
        "Suspicious tasks: those running from TEMP, AppData, or unusual paths; those running encoded PowerShell; tasks with random-looking names.",
        "Persistence via scheduled tasks is MITRE ATT&CK T1053.005.",
    ],
    "registry_keys": [
        "The 'registry_keys' table contains Windows Registry entries from .reg exports or hive parsing.",
        "Column 'hive' is the root key: HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, etc.",
        "Column 'key_path' is the full registry key path.",
        "Column 'value_name' is the value name within the key. Column 'value_data' is the value content.",
        "Common persistence locations: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run, HKCU\\...\\Run, HKLM\\SYSTEM\\CurrentControlSet\\Services.",
        "Persistence via Run keys is MITRE ATT&CK T1547.001.",
    ],
    "sysinfo": [
        "The 'sysinfo' table contains system information from systeminfo output.",
        "Column 'hostname' is the machine name. Column 'os_name' and 'os_version' describe the OS.",
        "Column 'last_boot' is the last system boot time — useful for establishing timeline.",
        "Column 'domain' is the Active Directory domain the machine belongs to.",
        "Column 'ip_addresses' lists all configured IP addresses.",
        "Column 'hotfixes' lists installed patches — missing patches indicate vulnerability exposure.",
    ],
}

# ── Pares pregunta-SQL genéricos ──────────────────────────────────────────────
# Usan solo el schema de Nexus — funcionan en cualquier caso.

GENERIC_QA = [
    # events
    ("How many events are there per event ID?",
     "SELECT event_id, COUNT(*) as count FROM events GROUP BY event_id ORDER BY count DESC"),

    ("Which usernames appear most frequently in logon events?",
     "SELECT username, COUNT(*) as logons FROM events WHERE event_id IN (4624,4625) AND username != '' GROUP BY username ORDER BY logons DESC"),

    ("Show all failed logon events with their source IPs",
     "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 4625 ORDER BY timestamp_utc"),

    ("Which external IPs appear in logon events?",
     "SELECT DISTINCT source_ip, COUNT(*) as count FROM events WHERE event_id = 4624 AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '127.%' AND source_ip != '' AND source_ip IS NOT NULL GROUP BY source_ip ORDER BY count DESC"),

    ("Show successful logons from external IPs",
     "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 4624 AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '127.%' AND source_ip IS NOT NULL AND source_ip != '' ORDER BY timestamp_utc"),

    ("How many failed vs successful logons are there?",
     "SELECT CASE event_id WHEN 4624 THEN 'successful' WHEN 4625 THEN 'failed' END as result, COUNT(*) as count FROM events WHERE event_id IN (4624,4625) GROUP BY event_id"),

    # network
    ("Show all established connections to external IPs",
     "SELECT protocol, remote_address, remote_port, pid, state FROM network_connections WHERE state = 'ESTABLISHED' AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '127.%' AND remote_address IS NOT NULL ORDER BY remote_port"),

    ("Which processes have network connections?",
     "SELECT DISTINCT p.name, p.pid, n.remote_address, n.remote_port, n.state FROM processes p JOIN network_connections n ON p.pid = n.pid WHERE n.state = 'ESTABLISHED' ORDER BY p.name"),

    ("What ports are listening on the system?",
     "SELECT local_port, protocol, pid FROM network_connections WHERE state = 'LISTENING' ORDER BY local_port"),

    # processes
    ("List all processes running as SYSTEM",
     "SELECT pid, name, command_line, exe_path FROM processes WHERE UPPER(username) LIKE '%SYSTEM%' ORDER BY name"),

    ("Show processes with suspicious command lines",
     "SELECT pid, name, command_line FROM processes WHERE command_line LIKE '%EncodedCommand%' OR command_line LIKE '%-enc %' OR command_line LIKE '%Invoke-WebRequest%' OR command_line LIKE '%IEX%' OR command_line LIKE '%DownloadString%' ORDER BY name"),

    # scheduled tasks
    ("List all enabled scheduled tasks and their commands",
     "SELECT task_name, command, run_as, status FROM scheduled_tasks WHERE enabled = 1 ORDER BY task_name"),

    ("Show scheduled tasks running from suspicious paths",
     "SELECT task_name, command, author, run_as FROM scheduled_tasks WHERE command LIKE '%Temp%' OR command LIKE '%AppData%' OR command LIKE '%Users%\\\\%' ORDER BY task_name"),

    # cross-table
    ("Correlate external connections with process names",
     "SELECT n.remote_address, n.remote_port, n.state, p.name, p.command_line FROM network_connections n LEFT JOIN processes p ON n.pid = p.pid WHERE n.remote_address NOT LIKE '10.%' AND n.remote_address NOT LIKE '192.168.%' AND n.state = 'ESTABLISHED' ORDER BY n.remote_address"),

    # Queries con filtros explícitos — mejoran la calidad del LLM
    ("What external established connections exist and which process owns them?",
     "SELECT n.remote_address, n.remote_port, p.name AS process_name, p.pid FROM network_connections n JOIN processes p ON n.pid = p.pid WHERE n.state = 'ESTABLISHED' AND n.remote_address NOT LIKE '10.%' AND n.remote_address NOT LIKE '192.168.%' AND n.remote_address NOT LIKE '127.%' AND n.remote_address IS NOT NULL ORDER BY n.remote_address"),

    ("¿Qué conexiones externas establecidas hay y qué proceso las tiene?",
     "SELECT n.remote_address, n.remote_port, p.name AS process_name, p.pid FROM network_connections n JOIN processes p ON n.pid = p.pid WHERE n.state = 'ESTABLISHED' AND n.remote_address NOT LIKE '10.%' AND n.remote_address NOT LIKE '192.168.%' AND n.remote_address NOT LIKE '127.%' AND n.remote_address IS NOT NULL ORDER BY n.remote_address"),

    ("Show failed logons grouped by source IP with count",
     "SELECT source_ip, COUNT(*) as failed_attempts FROM events WHERE event_id = 4625 AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY failed_attempts DESC"),

    ("¿Cuántos logons fallidos hubo y desde qué IPs?",
     "SELECT source_ip, COUNT(*) as intentos_fallidos FROM events WHERE event_id = 4625 AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY intentos_fallidos DESC"),

    ("Which scheduled tasks run from suspicious paths like Temp or AppData?",
     "SELECT task_name, command, author, run_as FROM scheduled_tasks WHERE (command LIKE '%Temp%' OR command LIKE '%AppData%' OR command LIKE '%\\Users\\%') AND enabled = 1 ORDER BY task_name"),

    ("Show processes with encoded PowerShell commands",
     "SELECT pid, name, command_line FROM processes WHERE command_line LIKE '%-EncodedCommand%' OR command_line LIKE '%-enc %' OR command_line LIKE '%FromBase64String%' OR command_line LIKE '%IEX%' ORDER BY name"),

    ("¿Qué IPs externas aparecen en los eventos?",
     "SELECT DISTINCT source_ip FROM events WHERE source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '172.16.%' AND source_ip NOT LIKE '127.%' ORDER BY source_ip"),

    ("¿Desde qué IPs se conectó el usuario administrator? ¿Desde qué IPs se autenticó un usuario específico?",
     "SELECT DISTINCT source_ip, COUNT(*) as count FROM events WHERE LOWER(username) = 'administrator' AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY count DESC"),

    ("Which IPs did a specific user connect from? Show logon IPs for a user.",
     "SELECT DISTINCT source_ip, COUNT(*) as logon_count FROM events WHERE username = 'Administrator' AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY logon_count DESC"),

    ("¿Desde qué IP hay más actividad? ¿Cuál es la IP con más eventos?",
     "SELECT source_ip, COUNT(*) as activity_count FROM events WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY activity_count DESC LIMIT 1"),

    ("Which IP address has the most events or activity?",
     "SELECT source_ip, COUNT(*) as activity_count FROM events WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY activity_count DESC LIMIT 1"),

    ("What external source IPs appear in the event log?",
     "SELECT DISTINCT source_ip, COUNT(*) as count FROM events WHERE source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '127.%' GROUP BY source_ip ORDER BY count DESC"),

    ("¿Hay actividad fuera de horario laboral, antes de las 8am o después de las 8pm?",
     "SELECT timestamp_utc, event_id, username, computer FROM events WHERE CAST(strftime('%H', timestamp_utc) AS INTEGER) < 8 OR CAST(strftime('%H', timestamp_utc) AS INTEGER) >= 20 ORDER BY timestamp_utc"),

    ("Show events that occurred outside business hours (before 8am or after 8pm)",
     "SELECT timestamp_utc, event_id, username, computer FROM events WHERE CAST(strftime('%H', timestamp_utc) AS INTEGER) < 8 OR CAST(strftime('%H', timestamp_utc) AS INTEGER) >= 20 ORDER BY timestamp_utc LIMIT 100"),

    ("¿Cuál es el rango de fechas de los eventos? ¿Cuándo empieza y termina el dataset?",
     "SELECT MIN(timestamp_utc) AS first_event, MAX(timestamp_utc) AS last_event FROM events"),

    ("What is the date range of events? What is the earliest and latest event?",
     "SELECT MIN(timestamp_utc) AS first_event, MAX(timestamp_utc) AS last_event FROM events"),

    # ── Network connections ───────────────────────────────────────────────────
    ("¿Qué conexiones de red estaban activas?",
     "SELECT protocol, local_address, local_port, remote_address, remote_port, state, pid FROM network_connections WHERE state IN ('ESTABLISHED', 'LISTENING') ORDER BY state, remote_port"),

    ("¿Cuáles son todas las conexiones de red activas en el sistema?",
     "SELECT protocol, local_address, local_port, remote_address, remote_port, state, pid FROM network_connections ORDER BY state"),

    ("What active network connections existed on the system?",
     "SELECT protocol, local_address, local_port, remote_address, remote_port, state, pid FROM network_connections WHERE state IN ('ESTABLISHED', 'LISTENING') ORDER BY remote_port"),

    ("¿Qué conexiones están en estado ESTABLISHED o LISTENING?",
     "SELECT protocol, local_address, local_port, remote_address, remote_port, state, pid FROM network_connections WHERE state IN ('ESTABLISHED', 'LISTENING') ORDER BY state"),

    # ── Attribution: proceso con más conexiones externas ─────────────────────
    ("¿Qué proceso tiene más conexiones externas establecidas?",
     "SELECT p.name, p.pid, COUNT(*) as ext_connections FROM network_connections n JOIN processes p ON n.pid = p.pid WHERE n.state = 'ESTABLISHED' AND n.remote_address NOT LIKE '10.%' AND n.remote_address NOT LIKE '192.168.%' AND n.remote_address NOT LIKE '127.%' GROUP BY p.name, p.pid ORDER BY ext_connections DESC LIMIT 1"),

    ("Which process has the most established external connections?",
     "SELECT p.name, p.pid, COUNT(*) as connections FROM network_connections n JOIN processes p ON n.pid = p.pid WHERE n.state = 'ESTABLISHED' GROUP BY p.pid ORDER BY connections DESC LIMIT 1"),

    # ── Timeline: primeros/últimos N eventos (sin filtro) ────────────────────
    # B05: ORDER BY timestamp_utc LIMIT N — NO WHERE clause. Model tends to add
    # unnecessary WHERE filters when all retrieved examples have event_id conditions.
    ("Muestra los primeros 10 eventos ordenados por fecha",
     "SELECT timestamp_utc, event_id, username, computer FROM events ORDER BY timestamp_utc LIMIT 10"),

    ("¿Cuáles son los 10 eventos más antiguos del log?",
     "SELECT timestamp_utc, event_id, username, computer FROM events ORDER BY timestamp_utc ASC LIMIT 10"),

    ("Show the first 10 events in chronological order",
     "SELECT timestamp_utc, event_id, username, computer FROM events ORDER BY timestamp_utc LIMIT 10"),

    ("List the earliest 5 events sorted by date",
     "SELECT timestamp_utc, event_id, username, computer FROM events ORDER BY timestamp_utc ASC LIMIT 5"),

    # ── Timeline: primer logon exitoso ────────────────────────────────────────
    ("¿Cuál fue el primer evento de logon exitoso registrado?",
     "SELECT MIN(timestamp_utc) AS first_logon, username, source_ip, computer FROM events WHERE event_id = 4624"),

    ("What was the first successful logon event?",
     "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 4624 ORDER BY timestamp_utc LIMIT 1"),

    ("¿Cuándo ocurrió el primer logon exitoso? ¿Cuál fue el primer acceso exitoso?",
     "SELECT MIN(timestamp_utc) AS primer_logon FROM events WHERE event_id = 4624"),

    # ── Anomaly: autenticación nocturna ───────────────────────────────────────
    ("¿Qué usuario se autenticó en horario nocturno, entre las 0 y las 6am?",
     "SELECT username, timestamp_utc FROM events WHERE event_id = 4624 AND CAST(strftime('%H', timestamp_utc) AS INTEGER) BETWEEN 0 AND 6 ORDER BY timestamp_utc"),

    ("Which users authenticated during nighttime hours between midnight and 6am?",
     "SELECT username, COUNT(*) as count FROM events WHERE event_id = 4624 AND CAST(strftime('%H', timestamp_utc) AS INTEGER) < 6 GROUP BY username ORDER BY count DESC"),

    # ── Persistence: tareas programadas y registro ────────────────────────────
    ("¿Qué tareas programadas existen en el sistema?",
     "SELECT task_name, trigger_type, scheduled_time, status FROM scheduled_tasks ORDER BY task_name"),

    ("List all scheduled tasks on the system",
     "SELECT task_name, trigger_type, scheduled_time, status FROM scheduled_tasks ORDER BY task_name"),

    ("¿Qué claves de registro de autorun o persistencia existen?",
     "SELECT key_path, value_name, value_data FROM registry_keys WHERE key_path LIKE '%Run%' OR key_path LIKE '%RunOnce%' OR key_path LIKE '%Services%' ORDER BY key_path"),

    ("Show registry autorun keys used for persistence",
     "SELECT key_path, value_name, value_data FROM registry_keys WHERE key_path LIKE '%Run%' OR key_path LIKE '%RunOnce%' ORDER BY key_path"),

    # ── Meta: evidencia disponible ────────────────────────────────────────────
    # evidence_files columns: id, filename, filepath, evidence_type, file_size_kb, ingested_at, record_count
    ("Resume la evidencia disponible: cuántos archivos, qué tipos, cuántos registros",
     "SELECT evidence_type, COUNT(*) as archivos, SUM(record_count) as registros FROM evidence_files GROUP BY evidence_type ORDER BY registros DESC"),

    ("¿Cuántos archivos de evidencia hay y de qué tipo?",
     "SELECT evidence_type, COUNT(*) as files, SUM(record_count) as total_rows FROM evidence_files GROUP BY evidence_type ORDER BY total_rows DESC"),

    # ── Cross-table: proceso por conexión de red ──────────────────────────────
    # JOIN must use n.pid = p.pid (OS process ID), NOT p.id (auto-increment primary key)
    # processes columns: id, pid, name — process_name does NOT exist in processes
    ("¿Qué proceso corresponde a cada conexión de red activa?",
     "SELECT p.name, p.pid, n.protocol, n.local_address, n.local_port, n.remote_address, n.remote_port, n.state FROM network_connections n JOIN processes p ON n.pid = p.pid WHERE n.state IN ('ESTABLISHED', 'LISTENING') ORDER BY n.state"),

    ("What process corresponds to each active network connection?",
     "SELECT p.name, p.pid, n.protocol, n.remote_address, n.remote_port, n.state FROM network_connections n JOIN processes p ON n.pid = p.pid WHERE n.state IN ('ESTABLISHED', 'LISTENING') ORDER BY n.state"),
]


class NexusAnalyst:
    def __init__(self, db_path: str, model: str = "qwen2.5:7b-instruct",
                 ollama_url: str = "http://localhost:11434", store_path: str = None):
        self.db_path = db_path
        self.model = model
        self.ollama_url = ollama_url
        self.case_name = Path(db_path).stem
        self.store_path = store_path or str(
            Path(db_path).parent / f"nexus_store_{self.case_name}.db"
        )

        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._active_tables = self._detect_active_tables()

        from .vectorstore import NexusVectorStore
        self._store = NexusVectorStore(self.store_path)

    def _detect_active_tables(self) -> list[str]:
        active = []
        for table in TABLE_DOCS.keys():
            try:
                count = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                if count > 0:
                    active.append(table)
            except Exception:
                pass
        return active

    def train(self, force: bool = False) -> int:
        """
        Carga el schema y contexto forense en el vector store.
        Idempotente — no duplica si ya está entrenado.
        """
        if self._store.count() > 0 and not force:
            total = self._store.count()
            print(f"  {YELLOW}Vector store ya tiene {total} items — usando existente{RESET}")
            print(f"  {YELLOW}Usa train(force=True) para reentrenar{RESET}")
            return 0

        if force:
            # Limpiar el store antes de reentrenar
            self._store.db.execute("DELETE FROM training_items")
            self._store.db.commit()

        count = 0
        print(f"\n  {BOLD}Tablas activas:{RESET} {', '.join(self._active_tables)}\n")

        # 1. DDL
        print(f"  {CYAN}[1/3] Schema (DDL)...{RESET}")
        for row in self.conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL AND type='table'"
        ):
            if row[0] in self._active_tables or row[0] == "evidence_files":
                self._store.add_ddl(row[1])
                count += 1

        # 2. Documentación DFIR por tabla activa + contexto dinámico de la DB
        print(f"  {CYAN}[2/3] Documentación DFIR...{RESET}")
        for table in self._active_tables:
            for doc in TABLE_DOCS.get(table, []):
                self._store.add_doc(doc)
                count += 1

        # Contexto dinámico: qué hay realmente en esta DB
        dynamic_docs = self._generate_dynamic_context()
        for doc in dynamic_docs:
            self._store.add_doc(doc)
            count += len(dynamic_docs)

        # 3. Pares Q-SQL relevantes — adaptados a los event IDs reales
        print(f"  {CYAN}[3/3] Pares pregunta-SQL...{RESET}")
        active_event_ids = self._get_active_event_ids()
        for question, sql in GENERIC_QA:
            if self._is_sql_relevant(sql):
                adapted_sql = _adapt_sql_to_event_ids(sql, active_event_ids)
                self._store.add_qa(question, adapted_sql)
                count += 1

        print(f"\n  {GREEN}✓ {count} items en vector store{RESET}\n")
        return count

    def _get_active_event_ids(self) -> list[int]:
        """Retorna los event_ids realmente presentes en la DB."""
        if "events" not in self._active_tables:
            return []
        rows = self.conn.execute(
            "SELECT DISTINCT event_id FROM events WHERE event_id IS NOT NULL ORDER BY event_id"
        ).fetchall()
        return [r[0] for r in rows if r[0]]

    def _generate_dynamic_context(self) -> list[str]:
        """Genera documentación específica basada en lo que hay en esta DB."""
        docs = []

        if "events" not in self._active_tables:
            return docs

        # Event IDs presentes
        event_ids = self._get_active_event_ids()
        if event_ids:
            id_list = ", ".join(str(i) for i in event_ids)
            docs.append(
                f"CRITICAL: The events table in THIS database contains ONLY these event_id values: {id_list}. "
                f"Do NOT use any other event_id in WHERE clauses. Never use event_ids not in this list."
            )

        # Tipo de log inferido por event IDs
        id_set = set(event_ids)
        if id_set <= {21, 22, 23, 24}:
            docs.append(
                "This database contains Terminal Services Local Session Manager (TSLSM) events. "
                "Use event_id=21 for RDP session logons (NOT 4624). "
                "Use event_id=23 for RDP logoffs (NOT 4634). "
                "Column source_ip contains the remote IP that connected via RDP."
            )
        elif {4624, 4625} & id_set:
            docs.append(
                "This database contains Windows Security Event Log entries. "
                "Use event_id=4624 for successful logons, event_id=4625 for failed logons."
            )
        elif id_set & {1, 3, 5, 7, 10, 11, 12, 13, 15, 17, 22, 25}:
            docs.append(
                "This database contains Sysmon events. "
                "EventId 1=process create, 3=network connection, 5=process terminate, "
                "7=image loaded, 10=process access, 11=file created, 22=DNS query."
            )

        # Columnas reales en events
        try:
            cursor = self.conn.execute("SELECT * FROM events LIMIT 1")
            cols = [d[0] for d in cursor.description]
            docs.append(
                f"The events table has ONLY these columns: {', '.join(cols)}. "
                f"Do NOT reference columns not in this list (e.g. logon_type, event_type, severity)."
            )
        except Exception:
            pass

        # Usuarios presentes
        if "events" in self._active_tables:
            try:
                users = self.conn.execute(
                    "SELECT DISTINCT username FROM events WHERE username IS NOT NULL AND username != '' LIMIT 20"
                ).fetchall()
                if users:
                    user_list = ", ".join(f"'{r[0]}'" for r in users)
                    docs.append(f"Usernames present in this database: {user_list}.")
            except Exception:
                pass

        # IPs externas detectadas automáticamente
        if "events" in self._active_tables:
            try:
                ext_ips = self.conn.execute(
                    "SELECT DISTINCT source_ip FROM events "
                    "WHERE source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' "
                    "AND source_ip NOT LIKE '127.%' AND source_ip IS NOT NULL AND source_ip != '' "
                    "LIMIT 10"
                ).fetchall()
                if ext_ips:
                    ip_list = ", ".join(r[0] for r in ext_ips)
                    docs.append(f"External (non-RFC1918) IPs detected in events: {ip_list}.")
            except Exception:
                pass

        return docs

    def _is_sql_relevant(self, sql: str) -> bool:
        sql_lower = sql.lower()
        for table in TABLE_DOCS.keys():
            if f"from {table}" in sql_lower or f"join {table}" in sql_lower:
                if table not in self._active_tables:
                    return False
        return True

    def ask(self, question: str, verbose: bool = True) -> dict:
        """Pregunta en lenguaje natural. Genera SQL, valida, y ejecuta con retry."""
        from .validator import validate, build_correction_hint

        if verbose:
            print(f"\n  {BOLD}Pregunta:{RESET} {question}")

        prompt = self._build_prompt(question)
        sql = _clean_sql(self._call_llm(prompt))

        if not sql:
            return {"question": question, "sql": None, "result": None,
                    "error": "LLM no generó SQL válido", "hallucination": None,
                    "retried": False, "self_corrected": False,
                    "first_hallucination_type": None}

        # Validar antes de ejecutar
        validation = validate(sql, self.conn)
        first_hallucination_type = None
        retried = False

        if not validation.valid:
            first_hallucination_type = validation.hallucination_type
            retried = True
            hint = build_correction_hint(validation, self.conn)
            if verbose:
                print(f"  {YELLOW}[{validation.hallucination_type}] Alucinación detectada:{RESET} {hint}")
                print(f"  {CYAN}Reintentando con corrección...{RESET}")

            correction_prompt = (
                self._build_prompt(question) +
                f"\n\nPREVIOUS ATTEMPT FAILED: {hint}\n"
                f"Previous SQL was: {sql}\n"
                f"Fix the error and generate a corrected SQL query:"
            )
            sql = _clean_sql(self._call_llm(correction_prompt))
            validation = validate(sql, self.conn)

            if not validation.valid and verbose:
                print(f"  {RED}Retry falló también: {validation.error_summary}{RESET}")

        self_corrected = retried and validation.valid

        if verbose:
            if self_corrected:
                print(f"  {GREEN}✓ Auto-corregido{RESET}")
            attempt_label = "" if validation.valid else f" {YELLOW}[con errores]{RESET}"
            print(f"  {GREEN}SQL generado{attempt_label}:{RESET}")
            for line in sql.strip().splitlines():
                print(f"    {line}")
            print()

        import pandas as pd
        try:
            df = pd.read_sql(sql, self.conn)
            if verbose:
                if len(df) == 0:
                    print(f"  {YELLOW}Sin resultados{RESET}")
                elif len(df) <= 50:
                    print(f"  {GREEN}Resultado ({len(df)} filas):{RESET}")
                    print(df.to_string(index=False))
                else:
                    print(f"  {GREEN}Resultado ({len(df)} filas — mostrando primeras 20):{RESET}")
                    print(df.head(20).to_string(index=False))
                    print(f"  ... y {len(df)-20} filas más")
            return {
                "question": question, "sql": sql, "result": df, "error": None,
                "hallucination": validation.hallucination_type,
                "retried": retried,
                "self_corrected": self_corrected,
                "first_hallucination_type": first_hallucination_type,
            }
        except Exception as e:
            if verbose:
                print(f"  {RED}Error ejecutando SQL:{RESET} {e}")
            return {
                "question": question, "sql": sql, "result": None, "error": str(e),
                "hallucination": validation.hallucination_type,
                "retried": retried,
                "self_corrected": self_corrected,
                "first_hallucination_type": first_hallucination_type,
            }

    def _build_prompt(self, question: str) -> str:
        """Construye el prompt con schema + docs + few-shot examples + pregunta."""
        parts = [
            "You are an expert DFIR analyst and SQLite query generator.",
            "Rules:",
            "- Generate ONLY a valid SQLite SELECT query. No explanation, no markdown, no comments.",
            "- ONLY use columns that exist in the schema shown below. NEVER invent columns.",
            "- ONLY use event_id values listed in the CONTEXT section. NEVER use other event_ids.",
            "- ALWAYS include WHERE clauses when the question mentions filters (external, established, failed, suspicious).",
            "- External IPs: NOT LIKE '10.%' AND NOT LIKE '192.168.%' AND NOT LIKE '127.%'",
            "- Follow the examples exactly — preserve all WHERE conditions from similar examples.",
            "",
        ]

        # Schema
        ddls = self._store.get_all_ddl()
        if ddls:
            parts.append("=== DATABASE SCHEMA ===")
            parts.extend(ddls[:10])
            parts.append("")

        # Docs más relevantes (top 5 por BM25)
        all_docs = self._store.get_all_docs()
        if all_docs:
            relevant_docs = _bm25_top_k(question, all_docs, k=5)
            if relevant_docs:
                parts.append("=== CONTEXT ===")
                parts.extend(relevant_docs)
                parts.append("")

        # Few-shot Q-SQL
        examples = self._store.get_similar_qa(question, top_k=3)
        if examples:
            parts.append("=== SIMILAR EXAMPLES ===")
            for ex in examples:
                parts.append(f"Q: {ex['question']}")
                parts.append(f"SQL: {ex['sql']}")
                parts.append("")

        parts.append(f"=== QUESTION ===\n{question}\n\nSQL:")
        return "\n".join(parts)

    def _call_llm(self, prompt: str) -> str:
        """Llama al LLM via Ollama API compatible con OpenAI."""
        import httpx
        from openai import OpenAI
        client = OpenAI(
            base_url=f"{self.ollama_url}/v1",
            api_key="ollama",
            timeout=httpx.Timeout(connect=10.0, read=600.0, write=10.0, pool=5.0),
            max_retries=0,
        )
        resp = client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=256,
        )
        return resp.choices[0].message.content or ""

    def describe_case(self) -> None:
        print(f"\n{CYAN}{BOLD}{'─'*60}{RESET}")
        print(f"{CYAN}{BOLD}  Nexus Analyst — {self.case_name}{RESET}")
        print(f"{CYAN}{BOLD}{'─'*60}{RESET}")
        print(f"  DB         : {self.db_path}")
        print(f"  Modelo     : {self.model}")
        print(f"  VectorStore: {self.store_path}")
        print()
        for table in self._active_tables:
            count = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            bar = "█" * min(count // 200, 25)
            print(f"  {table:<25} {BOLD}{count:>7,}{RESET}  {GREEN}{bar}{RESET}")
        rows = self.conn.execute(
            "SELECT filename, evidence_type, record_count FROM evidence_files ORDER BY evidence_type"
        ).fetchall()
        if rows:
            print(f"\n  {'Archivo':<35} {'Tipo':<22} {'Registros':>10}")
            print(f"  {'─'*33} {'─'*20} {'─'*10}")
            for r in rows:
                print(f"  {r[0]:<35} {r[1]:<22} {r[2]:>10,}")
        print()

    def close(self):
        self.conn.close()
        self._store.close()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _adapt_sql_to_event_ids(sql: str, active_ids: list[int]) -> str:
    """
    Reemplaza event IDs en Q-SQL pairs de entrenamiento por los IDs
    realmente presentes en la DB. Evita que el LLM memorice IDs incorrectos.
    """
    if not active_ids:
        return sql

    id_set = set(active_ids)

    # Si es DB TSLSM (solo 21-24), reemplazar EIDs de Security.evtx
    if id_set <= {21, 22, 23, 24}:
        replacements = {
            "event_id = 4624": "event_id = 21",
            "event_id = 4625": "event_id = 21",   # no hay failed logon en TSLSM — usar 21
            "event_id = 4634": "event_id = 23",
            "event_id IN (4624,4625)": "event_id IN (21, 23)",
            "event_id IN (4624, 4625)": "event_id IN (21, 23)",
        }
        for old, new in replacements.items():
            sql = sql.replace(old, new)

    return sql


def _clean_sql(raw: str) -> str:
    """Extrae la SQL limpia de la respuesta del LLM."""
    # Eliminar bloques markdown
    raw = re.sub(r"```sql\s*", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"```\s*", "", raw)

    # Si hay texto explicativo antes del SELECT, saltar hasta el SELECT
    all_lines = [l.strip() for l in raw.strip().splitlines()]
    select_start = next(
        (i for i, l in enumerate(all_lines) if l.upper().startswith("SELECT")),
        None,
    )
    if select_start is not None:
        all_lines = all_lines[select_start:]

    # Tomar líneas hasta el primer punto y coma o hasta el final, saltando prose
    lines = []
    for line in all_lines:
        if line and not line.lower().startswith(("here", "this", "the ", "note", "explan", "it seems", "however")):
            lines.append(line)
        if line.endswith(";"):
            break

    sql = "\n".join(lines).strip().rstrip(";")

    # Normalizar comillas mixtas: reemplazar " por ' dentro de literales de string SQL
    # (el modelo a veces termina un LIKE con " en lugar de ')
    sql = re.sub(r"'([^']*?)\"", lambda m: f"'{m.group(1)}'", sql)

    return sql


def _bm25_top_k(query: str, docs: list[str], k: int = 5) -> list[str]:
    from .vectorstore import _bm25_scores
    scores = _bm25_scores(query, docs)
    ranked = sorted(zip(scores, docs), key=lambda x: x[0], reverse=True)
    return [doc for score, doc in ranked[:k] if score > 0]
