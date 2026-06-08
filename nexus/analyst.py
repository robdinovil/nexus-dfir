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
        "EventId 1116 = Windows Defender found malware. EventId 1117 = Windows Defender took action against malware. Use channel LIKE '%Defender%' to filter these.",
        "EventId 4771 = Kerberos pre-authentication failed (brute force indicator). EventId 4776 = NTLM authentication attempt.",
        "EventId 4798 = A user's local group membership was enumerated (discovery/recon). EventId 4799 = A security-enabled local group membership was enumerated.",
        "EventId 5140 = A network share object was accessed. EventId 5145 = A network share object was checked. Both indicate lateral movement via SMB.",
        "EventId 4662 = An operation was performed on an AD object. EventId 5136 = A directory service object was modified (DCSync prep). EventId 4732 = A member was added to a security-enabled local group. EventId 4742 = A computer account was changed.",
        "Sysmon EventId 1 = Process creation (Image, CommandLine, ParentImage in description). EventId 3 = Network connection (Image, DestinationIp, DestinationPort in description). EventId 7 = Image loaded. EventId 10 = Process accessed. EventId 11 = File created.",
        "PowerShell EventId 4104 = Script Block Logging (full script content). EventId 800 = Pipeline execution details.",
        "EventId 1102 = Security log cleared (defense evasion indicator). EventId 4719 = System audit policy changed.",
        "EventId 21 = Remote Desktop Services session logon succeeded (RDP login).",
        "EventId 22 = Remote Desktop Services shell start notification (RDP session fully established).",
        "EventId 23 = Remote Desktop Services session logoff succeeded.",
        "EventId 24 = Remote Desktop Services session disconnected.",
        "For RDP analysis use EventId=21 to find successful RDP logons. column source_ip contains the originating IP.",
        "To detect lateral movement: find EID 4624 from external source_ip addresses (NOT LIKE '10.%', '192.168.%', '127.%'). WARNING: 'logon_type' is NOT a column in the events table — do NOT use it in any query.",
        "To detect privilege escalation: correlate EID 4672 with EID 4624 for the same logon session.",
        "External IPs are those NOT starting with 10., 192.168., 172.16-31., or 127.",
        "EventId 4698=scheduled task created, 4699=scheduled task deleted, 4702=scheduled task updated (Security.evtx). Use these when querying task activity in the events table.",
        "For process enumeration in events: use event_id=1 (Sysmon process creation, column description contains Image/CommandLine) or event_id=4688 (Windows process creation, column description contains NewProcessName/CommandLine). NEVER use source_file as a process name — source_file is the EVTX filename.",
        "CRITICAL SQL syntax: when filtering multiple NOT LIKE conditions, ALWAYS repeat the column name before each NOT LIKE. Example: source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '127.%'. NEVER write: source_ip NOT LIKE '10.%' AND NOT LIKE '192.168.%'.",
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
    "evidence_files": [
        "IoC extraction: to list all unique IPs use SELECT DISTINCT source_ip FROM events WHERE source_ip IS NOT NULL AND source_ip != '' ORDER BY source_ip.",
        "Attacker account identification: exclude SYSTEM, LOCAL SERVICE, NETWORK SERVICE, ANONYMOUS LOGON, and accounts ending in '$' (machine accounts). Filter: username NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON') AND username NOT LIKE '%$' AND username NOT LIKE 'NT AUTHORITY%'.",
        "Dwell time calculation: SELECT MIN(timestamp_utc) as start, MAX(timestamp_utc) as end FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != ''.",
        "Attack phase classification: event_ids map to ATT&CK phases — 4625/4771/4776/4768=Credential Access, 4624/4648=Initial Access/Lateral, 1/4688/4697=Execution, 5140/5145=Lateral Movement, 4698/5136/4662=Persistence, 1102/4719=Defense Evasion, 4672/4673/4674=Privilege Escalation.",
        "MITRE TTP mapping via CASE WHEN: use CASE WHEN event_id = X THEN 'TXxx Description' to map event IDs to technique names in SELECT queries.",
        "RDP events: 21=session logon, 22=shell start, 23=logoff, 24=disconnect. source_ip contains the connecting client IP.",
        "For executive/CISO summary: use COUNT(DISTINCT computer) as systems, COUNT(DISTINCT username) as accounts, COUNT(*) as total_events in a single SELECT.",
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

    # ── Bug 1 fix: "per source" — NO external filtering, correct NOT LIKE syntax ──
    ("How many events are there per source IP?",
     "SELECT source_ip, COUNT(*) as count FROM events WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY count DESC"),

    ("How many events per source?",
     "SELECT source_ip, COUNT(*) as count FROM events WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY count DESC"),

    ("Show event count grouped by source",
     "SELECT source_ip, COUNT(*) as count FROM events WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY count DESC"),

    ("¿Cuántos eventos hay por IP de origen?",
     "SELECT source_ip, COUNT(*) as count FROM events WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY count DESC"),

    ("Show events grouped by external source IP (correct NOT LIKE syntax example)",
     "SELECT source_ip, COUNT(*) as count FROM events WHERE source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '127.%' GROUP BY source_ip ORDER BY count DESC"),

    # ── Bug 2 fix: scheduled tasks via events when scheduled_tasks table is empty ──
    ("Find scheduled task creation events in the event log",
     "SELECT timestamp_utc, computer, username, description FROM events WHERE event_id IN (4698, 4699, 4702) ORDER BY timestamp_utc"),

    ("¿Qué eventos de creación de tareas programadas hay en el log de eventos?",
     "SELECT timestamp_utc, computer, username, description FROM events WHERE event_id IN (4698, 4699, 4702) ORDER BY timestamp_utc"),

    ("What scheduled task events exist? Look for task creation, deletion, update.",
     "SELECT timestamp_utc, computer, username, description FROM events WHERE event_id IN (4698, 4699, 4702) ORDER BY timestamp_utc"),

    # ── Bug 3 fix: process enumeration from events (no processes table) ──────────
    ("What unique processes ran on the system? Extract from Sysmon process create events.",
     "SELECT DISTINCT description FROM events WHERE event_id = 1 ORDER BY description LIMIT 50"),

    ("What unique processes are recorded in the event log?",
     "SELECT DISTINCT description FROM events WHERE event_id IN (1, 4688) ORDER BY description LIMIT 50"),

    ("List all processes seen in event logs",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1, 4688) ORDER BY timestamp_utc"),

    ("¿Qué procesos únicos hay registrados en los eventos?",
     "SELECT DISTINCT description FROM events WHERE event_id IN (1, 4688) ORDER BY description LIMIT 50"),

    # ── DFIR Analyst Core Questions ──────────────────────────────────────────

    # Brute force / credential access
    ("Which source IPs had the most failed logon attempts?",
     "SELECT source_ip, COUNT(*) as failed_attempts FROM events WHERE event_id IN (4625, 4771) AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY failed_attempts DESC LIMIT 10"),

    ("¿Qué IPs tuvieron más intentos de logon fallido? Detectar brute force.",
     "SELECT source_ip, COUNT(*) as intentos FROM events WHERE event_id IN (4625, 4771) AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY intentos DESC LIMIT 10"),

    ("Was there a successful logon from an IP that also had failed attempts? Brute force success.",
     "SELECT DISTINCT e1.source_ip, e1.username FROM events e1 WHERE e1.event_id = 4624 AND e1.source_ip IS NOT NULL AND e1.source_ip != '' AND EXISTS (SELECT 1 FROM events e2 WHERE e2.event_id = 4625 AND e2.source_ip = e1.source_ip) ORDER BY e1.source_ip"),

    ("Which accounts had successful logons and from what source IPs?",
     "SELECT username, source_ip, COUNT(*) as logon_count FROM events WHERE event_id = 4624 AND username IS NOT NULL AND username != '' GROUP BY username, source_ip ORDER BY logon_count DESC"),

    ("¿Qué cuentas tuvieron logons exitosos y desde qué IPs?",
     "SELECT username, source_ip, COUNT(*) as logons FROM events WHERE event_id = 4624 AND username IS NOT NULL AND username != '' GROUP BY username, source_ip ORDER BY logons DESC"),

    # Lateral movement — network shares
    ("What network shares were accessed and by which accounts?",
     "SELECT username, source_ip, computer, COUNT(*) as access_count FROM events WHERE event_id IN (5140, 5145) AND username IS NOT NULL AND username != '' GROUP BY username, source_ip, computer ORDER BY access_count DESC"),

    ("¿Qué shares de red fueron accedidos y por qué cuentas?",
     "SELECT username, source_ip, computer, COUNT(*) as accesos FROM events WHERE event_id IN (5140, 5145) GROUP BY username, source_ip, computer ORDER BY accesos DESC"),

    ("Show SMB share access events with source and destination",
     "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id IN (5140, 5145) ORDER BY timestamp_utc"),

    # Privilege escalation
    ("Which accounts were assigned special privileges?",
     "SELECT timestamp_utc, username, computer FROM events WHERE event_id = 4672 ORDER BY timestamp_utc"),

    ("¿Qué cuentas recibieron privilegios especiales (4672)?",
     "SELECT timestamp_utc, username, computer FROM events WHERE event_id = 4672 ORDER BY timestamp_utc"),

    ("Show all logons where special privileges were assigned",
     "SELECT timestamp_utc, username, computer, COUNT(*) as count FROM events WHERE event_id = 4672 GROUP BY username, computer ORDER BY count DESC"),

    # C2 / Sysmon network connections (event_id=3)
    ("What processes created external network connections? Show Sysmon network events.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id = 3 ORDER BY timestamp_utc LIMIT 30"),

    ("¿Qué procesos crearon conexiones de red externas? Eventos Sysmon de red.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id = 3 ORDER BY timestamp_utc LIMIT 30"),

    ("Show all Sysmon network connection events (event_id 3)",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id = 3 ORDER BY timestamp_utc LIMIT 50"),

    ("What external network connections did processes make? Sysmon event 3.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id = 3 ORDER BY timestamp_utc LIMIT 30"),

    ("Show Sysmon network connections — which processes connected where",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id = 3 ORDER BY timestamp_utc LIMIT 30"),

    # PowerShell execution
    ("What PowerShell scripts or commands were executed?",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (4104, 800) ORDER BY timestamp_utc LIMIT 20"),

    ("¿Qué scripts o comandos PowerShell se ejecutaron?",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (4104, 800) ORDER BY timestamp_utc LIMIT 20"),

    ("Show PowerShell script block logging events",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id = 4104 ORDER BY timestamp_utc LIMIT 20"),

    # Windows Defender alerts
    ("What malware or threats were detected by Windows Defender?",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1116, 1117) ORDER BY timestamp_utc"),

    ("¿Qué amenazas o malware detectó Windows Defender?",
     "SELECT timestamp_utc, computer, description FROM events WHERE channel LIKE '%Defender%' ORDER BY timestamp_utc"),

    ("Show Windows Defender detections and actions taken",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1116, 1117) ORDER BY timestamp_utc"),

    # Log clearing / defense evasion
    ("Were any event logs cleared?",
     "SELECT timestamp_utc, username, computer, description FROM events WHERE event_id = 1102 ORDER BY timestamp_utc"),

    ("¿Se borraron logs de eventos? Detectar evasión de defensas.",
     "SELECT timestamp_utc, username, computer FROM events WHERE event_id = 1102 ORDER BY timestamp_utc"),

    # Directory service modifications (persistence / DCSync prep)
    ("What directory service modifications were made?",
     "SELECT timestamp_utc, username, computer, description FROM events WHERE event_id IN (5136, 4662, 4732, 4742) ORDER BY timestamp_utc"),

    ("¿Qué modificaciones se hicieron en Active Directory?",
     "SELECT timestamp_utc, username, computer, description FROM events WHERE event_id IN (5136, 4662, 4732, 4742) ORDER BY timestamp_utc"),

    # User/group enumeration (discovery)
    ("What user and group memberships were enumerated?",
     "SELECT timestamp_utc, username, computer, COUNT(*) as enum_count FROM events WHERE event_id IN (4798, 4799) GROUP BY username, computer ORDER BY enum_count DESC"),

    ("¿Qué usuarios y grupos fueron enumerados? Detectar reconocimiento interno.",
     "SELECT timestamp_utc, username, computer FROM events WHERE event_id IN (4798, 4799) ORDER BY timestamp_utc"),

    # Suspicious process creation
    ("What processes were created with suspicious or encoded command lines?",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1, 4688) AND (description LIKE '%EncodedCommand%' OR description LIKE '%-enc %' OR description LIKE '%IEX%' OR description LIKE '%bypass%' OR description LIKE '%Invoke-WebRequest%' OR description LIKE '%DownloadString%') ORDER BY timestamp_utc"),

    ("¿Qué procesos se crearon con comandos sospechosos o codificados?",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1, 4688) AND (description LIKE '%EncodedCommand%' OR description LIKE '%-enc%' OR description LIKE '%IEX%' OR description LIKE '%Invoke%' OR description LIKE '%bypass%') ORDER BY timestamp_utc LIMIT 20"),

    ("Show all Sysmon process creation events (event_id 1)",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id = 1 ORDER BY timestamp_utc LIMIT 30"),

    # ── Incident correlation — kill chain queries ─────────────────────────────

    # Scope: all machines involved
    ("What machines were involved in this incident? Show all computers with event counts.",
     "SELECT computer, COUNT(*) as events, COUNT(DISTINCT event_id) as unique_event_types FROM events WHERE computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY events DESC LIMIT 15"),

    ("¿Qué máquinas participaron en el incidente? Resumen por equipo.",
     "SELECT computer, COUNT(*) as eventos FROM events WHERE computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY eventos DESC LIMIT 15"),

    # Initial access — credential attacks
    ("What were the first credential attacks? Show failed logons by source IP and target machine.",
     "SELECT source_ip, computer, COUNT(*) as attempts FROM events WHERE event_id IN (4625, 4771) AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip, computer ORDER BY attempts DESC LIMIT 10"),

    ("Show the attack progression: failed logons followed by successful logons from the same IP.",
     "SELECT DISTINCT e1.source_ip, e1.computer, e1.username FROM events e1 WHERE e1.event_id = 4624 AND e1.source_ip IS NOT NULL AND e1.source_ip != '' AND EXISTS (SELECT 1 FROM events e2 WHERE e2.event_id IN (4625, 4771) AND e2.source_ip = e1.source_ip) ORDER BY e1.source_ip"),

    # Lateral movement — account pivots
    ("Which accounts moved laterally between machines? Show logons and share access across systems.",
     "SELECT username, source_ip, computer, COUNT(*) as connections FROM events WHERE event_id IN (4624, 5140, 5145) AND source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '127.%' GROUP BY username, source_ip, computer ORDER BY connections DESC LIMIT 20"),

    ("¿Qué cuentas se usaron para movimiento lateral entre equipos?",
     "SELECT username, source_ip, computer, COUNT(*) as eventos FROM events WHERE event_id IN (4624, 5140, 5145) AND source_ip IS NOT NULL AND source_ip != '' GROUP BY username, source_ip, computer ORDER BY eventos DESC LIMIT 20"),

    # Privilege escalation
    ("Which accounts received special privileges during the incident?",
     "SELECT timestamp_utc, username, computer, COUNT(*) as count FROM events WHERE event_id = 4672 GROUP BY username, computer ORDER BY count DESC"),

    # Persistence — all mechanisms
    ("What persistence mechanisms were established? Show scheduled tasks, services, and AD changes.",
     "SELECT event_id, timestamp_utc, username, computer, description FROM events WHERE event_id IN (4698, 4702, 7045, 5136) ORDER BY timestamp_utc"),

    ("¿Qué mecanismos de persistencia se instalaron? Tareas, servicios y cambios en AD.",
     "SELECT event_id, timestamp_utc, username, computer, description FROM events WHERE event_id IN (4698, 4702, 7045, 5136) ORDER BY timestamp_utc"),

    # Defense evasion
    ("What defense evasion actions were taken? Show log clearing and audit policy changes.",
     "SELECT timestamp_utc, event_id, username, computer FROM events WHERE event_id IN (1102, 4719) ORDER BY timestamp_utc"),

    # Execution — processes and PowerShell
    ("What processes and commands were executed during the incident?",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1, 4688, 4104) ORDER BY timestamp_utc LIMIT 30"),

    # Full kill chain timeline
    ("Show the full incident timeline ordered by time. Include all key attack events.",
     "SELECT timestamp_utc, event_id, username, source_ip, computer FROM events WHERE event_id IN (4625, 4771, 4624, 5145, 4672, 4698, 7045, 5136, 1102, 4719, 1, 4688, 3, 4104) AND timestamp_utc IS NOT NULL AND timestamp_utc != '' ORDER BY timestamp_utc LIMIT 50"),

    ("¿Cuál es la línea de tiempo completa del incidente? Todos los eventos clave ordenados.",
     "SELECT timestamp_utc, event_id, username, source_ip, computer FROM events WHERE event_id IN (4625, 4771, 4624, 5145, 4672, 4698, 7045, 5136, 1102, 4719, 1, 4688) AND timestamp_utc IS NOT NULL ORDER BY timestamp_utc LIMIT 50"),

    # Actor identification
    ("Which user account appears most across attack phases? Find the primary threat actor.",
     "SELECT username, COUNT(DISTINCT event_id) as phases_covered, COUNT(*) as total_events FROM events WHERE username IS NOT NULL AND username != '' AND username NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON') GROUP BY username ORDER BY phases_covered DESC, total_events DESC LIMIT 10"),

    ("¿Qué cuenta de usuario aparece en más fases del ataque? Identificar al actor principal.",
     "SELECT username, COUNT(DISTINCT event_id) as fases, COUNT(*) as eventos_totales FROM events WHERE username IS NOT NULL AND username != '' AND username NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE') GROUP BY username ORDER BY fases DESC LIMIT 10"),

    # ── Cross-table: proceso por conexión de red ──────────────────────────────
    # JOIN must use n.pid = p.pid (OS process ID), NOT p.id (auto-increment primary key)
    # processes columns: id, pid, name — process_name does NOT exist in processes
    ("¿Qué proceso corresponde a cada conexión de red activa?",
     "SELECT p.name, p.pid, n.protocol, n.local_address, n.local_port, n.remote_address, n.remote_port, n.state FROM network_connections n JOIN processes p ON n.pid = p.pid WHERE n.state IN ('ESTABLISHED', 'LISTENING') ORDER BY n.state"),

    ("What process corresponds to each active network connection?",
     "SELECT p.name, p.pid, n.protocol, n.remote_address, n.remote_port, n.state FROM network_connections n JOIN processes p ON n.pid = p.pid WHERE n.state IN ('ESTABLISHED', 'LISTENING') ORDER BY n.state"),

    # ── IoC Extraction ────────────────────────────────────────────────────────
    # For both DFIR and CISO — extract indicators of compromise

    ("Extract all IP addresses seen in evidence — list every unique IP with occurrence count.",
     "SELECT source_ip, COUNT(*) as occurrences FROM events WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY occurrences DESC"),

    ("What are the external IP addresses (IoCs) seen in this incident?",
     "SELECT DISTINCT source_ip, COUNT(*) as hits FROM events WHERE source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '172.16.%' AND source_ip NOT LIKE '172.17.%' AND source_ip NOT LIKE '172.18.%' AND source_ip NOT LIKE '127.%' AND source_ip NOT LIKE '::1' AND source_ip NOT LIKE 'fe80%' GROUP BY source_ip ORDER BY hits DESC"),

    ("List all user accounts involved in the attack — exclude system and service accounts.",
     "SELECT username, COUNT(*) as event_count, MIN(timestamp_utc) as first_seen, MAX(timestamp_utc) as last_seen FROM events WHERE username IS NOT NULL AND username != '' AND username NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON','DWM-1','DWM-2','DWM-3') AND username NOT LIKE 'NT AUTHORITY%' AND username NOT LIKE '%$' GROUP BY username ORDER BY event_count DESC"),

    ("What are the suspicious process names seen in events? List process names from execution events.",
     "SELECT description, COUNT(*) as count FROM events WHERE event_id IN (1, 4688) AND description IS NOT NULL AND description != '' GROUP BY description ORDER BY count DESC LIMIT 20"),

    ("What domains, computers, or hostnames were targeted in this incident?",
     "SELECT computer, COUNT(*) as events, MIN(timestamp_utc) as first_seen, MAX(timestamp_utc) as last_seen FROM events WHERE computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY events DESC"),

    ("What files or services were created by the attacker?",
     "SELECT timestamp_utc, event_id, computer, username, description FROM events WHERE event_id IN (11, 4697, 7045) ORDER BY timestamp_utc"),

    # ── CISO / Executive Questions ────────────────────────────────────────────
    # Business impact, scope, duration — language for leadership

    ("What systems were compromised in this incident?",
     "SELECT computer, COUNT(*) as event_count, MIN(timestamp_utc) as first_activity, MAX(timestamp_utc) as last_activity FROM events WHERE computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY event_count DESC"),

    ("¿Qué sistemas fueron comprometidos en este incidente?",
     "SELECT computer, COUNT(*) as eventos, MIN(timestamp_utc) as primer_actividad, MAX(timestamp_utc) as ultima_actividad FROM events WHERE computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY eventos DESC"),

    ("How long was the attacker present in the environment? What is the dwell time?",
     "SELECT MIN(timestamp_utc) as attack_start, MAX(timestamp_utc) as attack_end, COUNT(*) as total_events, COUNT(DISTINCT computer) as systems_affected FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != ''"),

    ("¿Cuánto tiempo estuvo el atacante en el sistema? ¿Cuál es el dwell time del incidente?",
     "SELECT MIN(timestamp_utc) as inicio_ataque, MAX(timestamp_utc) as fin_ataque, COUNT(*) as total_eventos, COUNT(DISTINCT computer) as sistemas_afectados FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != ''"),

    ("What was the overall scope of the attack? Summarize systems, accounts, and event volume.",
     "SELECT COUNT(DISTINCT computer) as systems, COUNT(DISTINCT username) as accounts, COUNT(*) as total_events, COUNT(DISTINCT event_id) as event_types FROM events WHERE computer IS NOT NULL"),

    ("¿Cuál fue el alcance del ataque? Resume sistemas, cuentas y volumen de eventos.",
     "SELECT COUNT(DISTINCT computer) as sistemas, COUNT(DISTINCT username) as cuentas_involucradas, COUNT(*) as total_eventos, COUNT(DISTINCT event_id) as tipos_evento FROM events WHERE computer IS NOT NULL"),

    ("Were any credentials or accounts compromised? Show authentication failures and successes.",
     "SELECT event_id, COUNT(*) as count, COUNT(DISTINCT username) as users_targeted FROM events WHERE event_id IN (4625, 4771, 4776, 4768, 4624, 4648) GROUP BY event_id ORDER BY count DESC"),

    ("¿Se comprometieron credenciales o cuentas? Muestra intentos fallidos y accesos exitosos.",
     "SELECT event_id, COUNT(*) as intentos, COUNT(DISTINCT username) as usuarios_objetivo FROM events WHERE event_id IN (4625, 4771, 4776, 4768, 4624, 4648) GROUP BY event_id ORDER BY intentos DESC"),

    ("What was the business impact? What services or systems were affected?",
     "SELECT computer, COUNT(DISTINCT event_id) as attack_techniques, COUNT(*) as total_events FROM events WHERE computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY attack_techniques DESC"),

    # ── Incident Timeline & Narrative Reconstruction ──────────────────────────

    ("How did the attacker first gain access? Show the earliest attack events.",
     "SELECT timestamp_utc, event_id, username, source_ip, computer, description FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != '' ORDER BY timestamp_utc ASC LIMIT 15"),

    ("¿Cómo obtuvo acceso inicial el atacante? Muestra los primeros eventos del ataque.",
     "SELECT timestamp_utc, event_id, username, source_ip, computer FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != '' ORDER BY timestamp_utc ASC LIMIT 15"),

    ("What was the attack progression? Show the sequence of accounts, systems, and techniques over time.",
     "SELECT timestamp_utc, event_id, username, source_ip, computer FROM events WHERE username IS NOT NULL AND username != '' AND timestamp_utc IS NOT NULL ORDER BY timestamp_utc ASC LIMIT 40"),

    ("¿Cómo progresó el ataque? Muestra la secuencia de cuentas, sistemas y técnicas en el tiempo.",
     "SELECT timestamp_utc, event_id, username, source_ip, computer FROM events WHERE username IS NOT NULL AND timestamp_utc IS NOT NULL ORDER BY timestamp_utc ASC LIMIT 40"),

    ("What were the last attacker actions before detection or containment?",
     "SELECT timestamp_utc, event_id, username, source_ip, computer, description FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != '' ORDER BY timestamp_utc DESC LIMIT 15"),

    ("Recreate the incident timeline: show all events grouped by attack phase (auth, execution, lateral, persistence).",
     "SELECT CASE WHEN event_id IN (4625,4771,4776,4768) THEN 'credential_attack' WHEN event_id IN (4624,4648,4964) THEN 'authentication' WHEN event_id IN (1,4688,4697) THEN 'execution' WHEN event_id IN (5140,5145) THEN 'lateral_movement' WHEN event_id IN (4698,4699,5136,4662) THEN 'persistence' WHEN event_id IN (1102,4719) THEN 'defense_evasion' WHEN event_id IN (4672,4673,4674) THEN 'privilege_escalation' ELSE 'other' END as phase, COUNT(*) as events FROM events GROUP BY phase ORDER BY events DESC"),

    ("¿Cómo recrear el incidente? Clasifica todos los eventos por fase del ataque.",
     "SELECT CASE WHEN event_id IN (4625,4771,4776,4768) THEN 'acceso_credenciales' WHEN event_id IN (4624,4648,4964) THEN 'autenticacion' WHEN event_id IN (1,4688,4697) THEN 'ejecucion' WHEN event_id IN (5140,5145) THEN 'movimiento_lateral' WHEN event_id IN (4698,4699,5136,4662) THEN 'persistencia' WHEN event_id IN (1102,4719) THEN 'evasion_defensa' WHEN event_id IN (4672,4673,4674) THEN 'escalacion_privilegios' ELSE 'otro' END as fase, COUNT(*) as eventos FROM events GROUP BY fase ORDER BY eventos DESC"),

    # ── MITRE ATT&CK Mapping Queries ──────────────────────────────────────────

    ("What initial access techniques were used? Show credential attacks and exploitation.",
     "SELECT event_id, COUNT(*) as count, COUNT(DISTINCT username) as targets, COUNT(DISTINCT source_ip) as sources FROM events WHERE event_id IN (4625, 4771, 4776, 4768, 4648, 5145, 5140) GROUP BY event_id ORDER BY count DESC"),

    ("What execution techniques are in evidence? Show process creation and service installation.",
     "SELECT event_id, computer, description, COUNT(*) as count FROM events WHERE event_id IN (1, 4688, 4697, 7045, 4698) GROUP BY event_id, computer ORDER BY count DESC"),

    ("What privilege escalation events occurred? Show special privilege use.",
     "SELECT timestamp_utc, event_id, username, computer, description FROM events WHERE event_id IN (4672, 4673, 4674, 4964) ORDER BY timestamp_utc"),

    ("What persistence mechanisms were established by the attacker?",
     "SELECT timestamp_utc, event_id, username, computer, description FROM events WHERE event_id IN (4698, 4699, 4702, 5136, 4662, 7045, 4697, 13) ORDER BY timestamp_utc"),

    ("¿Qué mecanismos de persistencia dejó el atacante?",
     "SELECT timestamp_utc, event_id, username, computer, description FROM events WHERE event_id IN (4698, 4699, 4702, 5136, 4662, 7045, 4697) ORDER BY timestamp_utc"),

    ("What defense evasion techniques were used? Show log clearing and suspicious activity.",
     "SELECT timestamp_utc, event_id, username, computer, description FROM events WHERE event_id IN (1102, 4719, 4688, 1) AND (event_id = 1102 OR description LIKE '%clear%' OR description LIKE '%delete%' OR description LIKE '%wevtutil%') ORDER BY timestamp_utc"),

    ("What lateral movement techniques are evident? Show SMB access and remote logons.",
     "SELECT timestamp_utc, event_id, username, source_ip, computer FROM events WHERE event_id IN (5140, 5145, 4624, 4648) ORDER BY timestamp_utc"),

    ("Map all observed TTPs to MITRE ATT&CK — what techniques does this evidence cover?",
     "SELECT event_id, COUNT(*) as occurrences, CASE event_id WHEN 4625 THEN 'T1110 Brute Force' WHEN 4771 THEN 'T1110.003 Password Spray (Kerberos)' WHEN 4776 THEN 'T1110 Brute Force (NTLM)' WHEN 4624 THEN 'T1078 Valid Accounts' WHEN 4648 THEN 'T1550.002 Pass the Hash' WHEN 5140 THEN 'T1021.002 SMB/Windows Admin Shares' WHEN 5145 THEN 'T1021.002 SMB File Transfer' WHEN 4698 THEN 'T1053.005 Scheduled Task' WHEN 4697 THEN 'T1543.003 Windows Service' WHEN 5136 THEN 'T1484 Domain Policy Modification' WHEN 4662 THEN 'T1003.006 DCSync / AD Access' WHEN 1102 THEN 'T1070.001 Clear Windows Event Logs' WHEN 4672 THEN 'T1134 Access Token Manipulation' WHEN 1 THEN 'T1059 Command Execution (Sysmon)' WHEN 3 THEN 'T1071 C2 Network Connection (Sysmon)' WHEN 7 THEN 'T1574 DLL Side-Loading (Sysmon)' WHEN 11 THEN 'T1105 Ingress Tool Transfer (Sysmon)' ELSE 'Other' END as mitre_technique FROM events GROUP BY event_id ORDER BY occurrences DESC"),

    # ── RDP-specific (for563_rdp) ──────────────────────────────────────────────

    ("Which users connected via RDP and from which source IPs?",
     "SELECT username, source_ip, COUNT(*) as sessions, MIN(timestamp_utc) as first_seen, MAX(timestamp_utc) as last_seen FROM events WHERE event_id IN (21, 22, 131) AND username IS NOT NULL AND username != '' GROUP BY username, source_ip ORDER BY sessions DESC"),

    ("Show the full RDP session timeline — user, source IP, event type, and timestamp.",
     "SELECT timestamp_utc, event_id, username, source_ip, computer FROM events WHERE event_id IN (21, 22, 23, 24, 25, 131) ORDER BY timestamp_utc"),

    ("Which external IPs accessed via RDP? Flag non-internal connections.",
     "SELECT DISTINCT source_ip, username, COUNT(*) as connections FROM events WHERE event_id IN (21, 22, 131) AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '172.16.%' GROUP BY source_ip, username ORDER BY connections DESC"),
]


# ── TACTIC_QA — 5Ws por táctica MITRE ATT&CK ─────────────────────────────────
# WHO · WHAT · WHEN · WHERE · HOW — una pregunta por W, por táctica

TACTIC_QA = [

    # ── TA0001 Initial Access ─────────────────────────────────────────────────
    ("WHO performed initial access? Which source IPs and accounts attempted entry? TA0001",
     "SELECT source_ip, username, COUNT(*) as attempts FROM events WHERE event_id IN (4625, 4771, 4776, 4768) AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip, username ORDER BY attempts DESC"),

    ("WHAT initial access events exist? All credential attack indicators for TA0001.",
     "SELECT event_id, COUNT(*) as count, COUNT(DISTINCT source_ip) as sources, CASE event_id WHEN 4625 THEN 'Password Guess' WHEN 4771 THEN 'Kerberos Fail' WHEN 4776 THEN 'NTLM Fail' WHEN 4768 THEN 'TGT Request' WHEN 4648 THEN 'Explicit Creds' END as type FROM events WHERE event_id IN (4625, 4771, 4776, 4768, 4648) GROUP BY event_id ORDER BY count DESC"),

    ("WHEN did initial access attempts first occur? Timeline of first and last attack for TA0001.",
     "SELECT MIN(timestamp_utc) as first_attempt, MAX(timestamp_utc) as last_attempt, COUNT(*) as total FROM events WHERE event_id IN (4625, 4771, 4776, 4768)"),

    ("WHERE were initial access attacks directed? Which systems were targeted? TA0001.",
     "SELECT computer, COUNT(*) as attempts, COUNT(DISTINCT source_ip) as sources FROM events WHERE event_id IN (4625, 4771, 4776, 4768) AND computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY attempts DESC"),

    ("HOW was initial access achieved? What technique: brute force, Kerberos spray, NTLM? TA0001.",
     "SELECT CASE event_id WHEN 4625 THEN 'T1110.001 Password Guessing' WHEN 4771 THEN 'T1110.003 Kerberos Spray' WHEN 4776 THEN 'T1110 NTLM Brute Force' WHEN 4648 THEN 'T1078 Valid Accounts' WHEN 4768 THEN 'T1558 Kerberos TGT' END as technique, COUNT(*) as count FROM events WHERE event_id IN (4625, 4771, 4776, 4648, 4768) GROUP BY event_id ORDER BY count DESC"),

    # ── TA0002 Execution ──────────────────────────────────────────────────────
    ("WHO executed code or commands? Which accounts ran processes? TA0002 Execution.",
     "SELECT username, computer, COUNT(*) as executions FROM events WHERE event_id IN (1, 4688, 4104, 800) AND username IS NOT NULL AND username != '' GROUP BY username, computer ORDER BY executions DESC"),

    ("WHAT execution events exist? Process creation, PowerShell, tasks, services. TA0002.",
     "SELECT event_id, COUNT(*) as count, CASE event_id WHEN 1 THEN 'T1059 Sysmon Process Create' WHEN 4688 THEN 'T1059 Windows Process Create' WHEN 4104 THEN 'T1059.001 PowerShell Script Block' WHEN 800 THEN 'T1059.001 PowerShell Pipeline' WHEN 4698 THEN 'T1053.005 Scheduled Task Created' WHEN 7045 THEN 'T1543.003 Service Installed' END as type FROM events WHERE event_id IN (1, 4688, 4104, 800, 4698, 7045) GROUP BY event_id ORDER BY count DESC"),

    ("WHEN did execution activity occur? Daily breakdown of process creation. TA0002.",
     "SELECT DATE(timestamp_utc) as date, COUNT(*) as exec_count FROM events WHERE event_id IN (1, 4688, 4104, 800) AND timestamp_utc IS NOT NULL GROUP BY DATE(timestamp_utc) ORDER BY date"),

    ("WHERE was code executed? Which systems have execution events? TA0002.",
     "SELECT computer, COUNT(*) as exec_events, COUNT(DISTINCT event_id) as techniques FROM events WHERE event_id IN (1, 4688, 4104, 800, 4698, 7045) AND computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY exec_events DESC"),

    ("HOW was code executed? Show LOLBins, PowerShell, WMI, scripting. TA0002.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1, 4688) AND (description LIKE '%powershell%' OR description LIKE '%wscript%' OR description LIKE '%cscript%' OR description LIKE '%mshta%' OR description LIKE '%rundll32%' OR description LIKE '%regsvr32%' OR description LIKE '%certutil%' OR description LIKE '%bitsadmin%') ORDER BY timestamp_utc LIMIT 20"),

    # ── TA0003 Persistence ────────────────────────────────────────────────────
    ("WHO established persistence? Which accounts created tasks, services, or AD changes? TA0003.",
     "SELECT username, computer, COUNT(*) as events FROM events WHERE event_id IN (4698, 4699, 4702, 7045, 4697, 5136, 4662) AND username IS NOT NULL AND username != '' GROUP BY username, computer ORDER BY events DESC"),

    ("WHAT persistence mechanisms were installed? Tasks, services, registry, AD. TA0003.",
     "SELECT event_id, COUNT(*) as count, CASE event_id WHEN 4698 THEN 'T1053.005 Scheduled Task Created' WHEN 4702 THEN 'T1053.005 Task Updated' WHEN 7045 THEN 'T1543.003 New Service' WHEN 4697 THEN 'T1543.003 Service Security' WHEN 5136 THEN 'T1484 Directory Modified' WHEN 4662 THEN 'T1003.006 AD Object Access' END as persistence_type FROM events WHERE event_id IN (4698, 4699, 4702, 7045, 4697, 5136, 4662) GROUP BY event_id ORDER BY count DESC"),

    ("WHEN was persistence established? Timeline of first and last persistence events. TA0003.",
     "SELECT MIN(timestamp_utc) as first_persistence, MAX(timestamp_utc) as last_persistence, COUNT(*) as total FROM events WHERE event_id IN (4698, 4699, 4702, 7045, 4697, 5136, 4662) AND timestamp_utc IS NOT NULL"),

    ("WHERE was persistence installed? Which systems have persistence events? TA0003.",
     "SELECT computer, event_id, COUNT(*) as count FROM events WHERE event_id IN (4698, 4702, 7045, 5136, 4662) AND computer IS NOT NULL AND computer != '' GROUP BY computer, event_id ORDER BY count DESC"),

    ("HOW did the attacker persist? Show details of each persistence mechanism. TA0003.",
     "SELECT timestamp_utc, event_id, username, computer, description FROM events WHERE event_id IN (4698, 4699, 4702, 7045, 5136, 4662) ORDER BY timestamp_utc"),

    # ── TA0004 Privilege Escalation ───────────────────────────────────────────
    ("WHO escalated privileges? Which accounts received special privileges? TA0004.",
     "SELECT username, computer, COUNT(*) as privesc_events FROM events WHERE event_id IN (4672, 4673, 4674, 4964) AND username IS NOT NULL AND username != '' GROUP BY username, computer ORDER BY privesc_events DESC"),

    ("WHAT privilege escalation events occurred? Special privilege and token events. TA0004.",
     "SELECT event_id, COUNT(*) as count, CASE event_id WHEN 4672 THEN 'T1134 Special Privileges Assigned' WHEN 4673 THEN 'T1134 Sensitive Privilege Used' WHEN 4674 THEN 'T1134 Privilege Object Operation' WHEN 4964 THEN 'T1078 Special Group Logon' END as type FROM events WHERE event_id IN (4672, 4673, 4674, 4964) GROUP BY event_id ORDER BY count DESC"),

    ("WHEN did privilege escalation occur? Timeline of special privilege events. TA0004.",
     "SELECT timestamp_utc, username, computer FROM events WHERE event_id IN (4672, 4673, 4674, 4964) ORDER BY timestamp_utc"),

    ("WHERE was privilege escalation performed? Systems with special privilege events. TA0004.",
     "SELECT computer, COUNT(*) as escalations, COUNT(DISTINCT username) as accounts FROM events WHERE event_id IN (4672, 4673, 4674) AND computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY escalations DESC"),

    ("HOW was privilege escalation achieved? Correlate privilege assignment with logon source. TA0004.",
     "SELECT e1.timestamp_utc, e1.username, e1.computer, e1.source_ip FROM events e1 WHERE e1.event_id = 4672 AND e1.source_ip IS NOT NULL AND e1.source_ip != '' ORDER BY e1.timestamp_utc"),

    # ── TA0005 Defense Evasion ────────────────────────────────────────────────
    ("WHO performed defense evasion? Accounts that cleared logs or changed audit policy. TA0005.",
     "SELECT username, computer, COUNT(*) as evasion_events FROM events WHERE event_id IN (1102, 4719) AND username IS NOT NULL AND username != '' GROUP BY username, computer ORDER BY evasion_events DESC"),

    ("WHAT defense evasion techniques were used? Log clearing and audit changes. TA0005.",
     "SELECT event_id, COUNT(*) as count, CASE event_id WHEN 1102 THEN 'T1070.001 Security Log Cleared' WHEN 4719 THEN 'T1562.002 Audit Policy Changed' END as technique FROM events WHERE event_id IN (1102, 4719) GROUP BY event_id ORDER BY count DESC"),

    ("WHEN did defense evasion occur? Timeline of log clearing. TA0005.",
     "SELECT timestamp_utc, event_id, username, computer FROM events WHERE event_id IN (1102, 4719) ORDER BY timestamp_utc"),

    ("WHERE were defense evasion actions performed? Systems with log clearing events. TA0005.",
     "SELECT computer, COUNT(*) as evasion_count FROM events WHERE event_id IN (1102, 4719) AND computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY evasion_count DESC"),

    ("HOW did the attacker evade defenses? Obfuscated commands and log clearing details. TA0005.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1102, 4719) UNION ALL SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1, 4688) AND (description LIKE '%EncodedCommand%' OR description LIKE '%wevtutil%' OR description LIKE '%clear-eventlog%') ORDER BY timestamp_utc LIMIT 20"),

    # ── TA0006 Credential Access ──────────────────────────────────────────────
    ("WHO was targeted for credential access? Which accounts received attack attempts? TA0006.",
     "SELECT username, COUNT(*) as attacks, COUNT(DISTINCT source_ip) as sources FROM events WHERE event_id IN (4625, 4771, 4776, 4768) AND username IS NOT NULL AND username != '' GROUP BY username ORDER BY attacks DESC"),

    ("WHAT credential access techniques were observed? Volume by technique. TA0006.",
     "SELECT event_id, COUNT(*) as count, COUNT(DISTINCT username) as targets, COUNT(DISTINCT source_ip) as sources FROM events WHERE event_id IN (4625, 4771, 4776, 4768, 4648) GROUP BY event_id ORDER BY count DESC"),

    ("WHEN did credential attacks peak? Hourly volume of authentication failures. TA0006.",
     "SELECT strftime('%Y-%m-%d %H:00', timestamp_utc) as hour, COUNT(*) as attempts FROM events WHERE event_id IN (4625, 4771, 4776, 4768) AND timestamp_utc IS NOT NULL GROUP BY strftime('%Y-%m-%d %H', timestamp_utc) ORDER BY attempts DESC LIMIT 10"),

    ("WHERE were credentials targeted? Systems with highest authentication failure rates. TA0006.",
     "SELECT computer, COUNT(*) as credential_attacks, COUNT(DISTINCT username) as accounts_targeted FROM events WHERE event_id IN (4625, 4771, 4776, 4768) AND computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY credential_attacks DESC"),

    ("HOW were credentials attacked? Rate of attempts per source IP — brute force vs. spray. TA0006.",
     "SELECT source_ip, COUNT(*) as total_attempts, COUNT(DISTINCT username) as accounts_targeted, MIN(timestamp_utc) as start, MAX(timestamp_utc) as end FROM events WHERE event_id IN (4625, 4771) AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY total_attempts DESC"),

    # ── TA0007 Discovery ──────────────────────────────────────────────────────
    ("WHO performed internal discovery or enumeration? TA0007.",
     "SELECT username, computer, COUNT(*) as enum_actions FROM events WHERE event_id IN (4798, 4799, 5140, 5145) AND username IS NOT NULL AND username != '' GROUP BY username, computer ORDER BY enum_actions DESC"),

    ("WHAT discovery activity occurred? User, group, and share enumeration. TA0007.",
     "SELECT event_id, COUNT(*) as count, CASE event_id WHEN 4798 THEN 'T1087 User Local Group Enum' WHEN 4799 THEN 'T1069 Security Group Enum' WHEN 5140 THEN 'T1135 Network Share Discovery' WHEN 5145 THEN 'T1135 Share Access Check' END as technique FROM events WHERE event_id IN (4798, 4799, 5140, 5145) GROUP BY event_id ORDER BY count DESC"),

    ("WHEN did discovery activity occur? Timeline of enumeration events. TA0007.",
     "SELECT timestamp_utc, event_id, username, computer FROM events WHERE event_id IN (4798, 4799, 5140, 5145) ORDER BY timestamp_utc"),

    ("WHERE was discovery performed? Systems that were enumerated. TA0007.",
     "SELECT computer, COUNT(*) as enum_count, COUNT(DISTINCT event_id) as techniques FROM events WHERE event_id IN (4798, 4799, 5140, 5145) AND computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY enum_count DESC"),

    ("HOW did the attacker enumerate the environment? Sequence of discovery actions. TA0007.",
     "SELECT timestamp_utc, event_id, username, source_ip, computer FROM events WHERE event_id IN (4798, 4799, 5140, 5145) ORDER BY timestamp_utc LIMIT 30"),

    # ── TA0008 Lateral Movement ───────────────────────────────────────────────
    ("WHO moved laterally between systems? Accounts used for lateral movement. TA0008.",
     "SELECT username, source_ip, computer, COUNT(*) as lateral_events FROM events WHERE event_id IN (4624, 4648, 5140, 5145, 21) AND source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '127.%' GROUP BY username, source_ip, computer ORDER BY lateral_events DESC"),

    ("WHAT lateral movement events occurred? Logons, shares, RDP by technique. TA0008.",
     "SELECT event_id, COUNT(*) as count, CASE event_id WHEN 4624 THEN 'T1078 Network Logon' WHEN 4648 THEN 'T1550.002 Explicit Credential Logon' WHEN 5140 THEN 'T1021.002 SMB Share Access' WHEN 5145 THEN 'T1021.002 Share Check' WHEN 21 THEN 'T1021.001 RDP Logon' END as technique FROM events WHERE event_id IN (4624, 4648, 5140, 5145, 21) GROUP BY event_id ORDER BY count DESC"),

    ("WHEN did lateral movement occur? Timeline of cross-system authentication. TA0008.",
     "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id IN (4624, 4648, 5140, 5145) AND source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '127.%' ORDER BY timestamp_utc LIMIT 30"),

    ("WHERE did lateral movement occur? Source and destination systems. TA0008.",
     "SELECT source_ip, computer, COUNT(*) as connections, COUNT(DISTINCT username) as accounts FROM events WHERE event_id IN (4624, 5140, 5145) AND source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '127.%' GROUP BY source_ip, computer ORDER BY connections DESC"),

    ("HOW did the attacker move laterally? SMB shares, explicit creds, RDP details. TA0008.",
     "SELECT timestamp_utc, event_id, username, source_ip, computer, description FROM events WHERE event_id IN (4648, 5140, 5145, 21, 22) ORDER BY timestamp_utc LIMIT 30"),

    # ── TA0011 Command and Control ────────────────────────────────────────────
    ("WHO established C2? Which processes made external connections? TA0011.",
     "SELECT description, COUNT(*) as c2_events FROM events WHERE event_id = 3 AND description IS NOT NULL AND description != '' GROUP BY description ORDER BY c2_events DESC LIMIT 10"),

    ("WHAT C2 connections were observed? Sysmon network events and netstat. TA0011.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id = 3 ORDER BY timestamp_utc LIMIT 30"),

    ("WHEN did C2 communication occur? Daily volume of outbound connections. TA0011.",
     "SELECT DATE(timestamp_utc) as date, COUNT(*) as c2_events FROM events WHERE event_id = 3 AND timestamp_utc IS NOT NULL GROUP BY DATE(timestamp_utc) ORDER BY date"),

    ("WHERE did C2 connect to? External IPs and ports used for command and control. TA0011.",
     "SELECT remote_address, remote_port, protocol, COUNT(*) as connections FROM network_connections WHERE state = 'ESTABLISHED' AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '172.16.%' AND remote_address NOT LIKE '127.%' AND remote_address IS NOT NULL GROUP BY remote_address, remote_port ORDER BY connections DESC"),

    ("HOW was C2 implemented? Process-to-connection attribution and protocol. TA0011.",
     "SELECT n.remote_address, n.remote_port, n.protocol, p.name, p.command_line FROM network_connections n JOIN processes p ON n.pid = p.pid WHERE n.state = 'ESTABLISHED' AND n.remote_address NOT LIKE '10.%' AND n.remote_address NOT LIKE '192.168.%' AND n.remote_address NOT LIKE '127.%' ORDER BY n.remote_address"),

    # ── TA0040 Impact ─────────────────────────────────────────────────────────
    ("WHO or WHAT caused impact? Accounts and processes in impact events. TA0040.",
     "SELECT timestamp_utc, username, computer, description FROM events WHERE event_id IN (1116, 1117) ORDER BY timestamp_utc"),

    ("WHAT impact events were detected? Defender alerts and malware detections. TA0040.",
     "SELECT event_id, COUNT(*) as count, CASE event_id WHEN 1116 THEN 'T1486 Malware Detected' WHEN 1117 THEN 'T1486 Defender Remediation' END as impact_type FROM events WHERE event_id IN (1116, 1117) GROUP BY event_id ORDER BY count DESC"),

    ("WHEN did impact occur? Timeline of Defender detections and ransomware indicators. TA0040.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1116, 1117) ORDER BY timestamp_utc"),

    ("WHERE was impact observed? Systems with Defender alerts. TA0040.",
     "SELECT computer, COUNT(*) as impact_events FROM events WHERE event_id IN (1116, 1117) AND computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY impact_events DESC"),

    ("HOW was impact achieved? Malware details from Defender detections. TA0040.",
     "SELECT timestamp_utc, computer, description FROM events WHERE channel LIKE '%Defender%' ORDER BY timestamp_utc"),
]


# ── TECHNIQUE_QA — 5Ws por técnica MITRE ATT&CK ──────────────────────────────
# Granularidad técnica: event IDs específicos por técnica

TECHNIQUE_QA = [

    # ── T1110 Brute Force ─────────────────────────────────────────────────────
    ("WHO initiated T1110 brute force? Source IPs and target accounts.",
     "SELECT source_ip, username, COUNT(*) as attempts FROM events WHERE event_id IN (4625, 4771, 4776) AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip, username ORDER BY attempts DESC LIMIT 15"),

    ("WHAT is the volume of T1110 brute force? Attempts per account per source IP.",
     "SELECT username, source_ip, COUNT(*) as failed_logons FROM events WHERE event_id = 4625 AND username IS NOT NULL AND username != '' GROUP BY username, source_ip ORDER BY failed_logons DESC LIMIT 20"),

    ("WHEN did T1110 brute force start and stop? Temporal profile of failed logon bursts.",
     "SELECT strftime('%Y-%m-%d %H:00', timestamp_utc) as hour, COUNT(*) as attempts FROM events WHERE event_id IN (4625, 4771) AND timestamp_utc IS NOT NULL GROUP BY strftime('%Y-%m-%d %H', timestamp_utc) ORDER BY hour"),

    ("WHERE were T1110 brute force attacks directed? Systems targeted.",
     "SELECT computer, COUNT(*) as attacks, COUNT(DISTINCT source_ip) as attacker_ips FROM events WHERE event_id IN (4625, 4771, 4776) AND computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY attacks DESC"),

    ("HOW many T1110 brute force attempts before success? Failure-to-success ratio per source IP.",
     "SELECT e1.source_ip, COUNT(DISTINCT CASE WHEN e1.event_id IN (4625,4771) THEN e1.timestamp_utc END) as failures, COUNT(DISTINCT CASE WHEN e1.event_id = 4624 THEN e1.timestamp_utc END) as successes FROM events e1 WHERE e1.source_ip IS NOT NULL AND e1.source_ip != '' AND e1.event_id IN (4625, 4771, 4624) GROUP BY e1.source_ip ORDER BY failures DESC"),

    # ── T1078 Valid Accounts ──────────────────────────────────────────────────
    ("WHO used valid accounts (T1078)? Accounts with successful logons from suspicious sources.",
     "SELECT username, source_ip, COUNT(*) as logons, MIN(timestamp_utc) as first_seen FROM events WHERE event_id = 4624 AND source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '127.%' GROUP BY username, source_ip ORDER BY logons DESC"),

    ("WHAT valid account (T1078) logon events are present? Successful auth summary.",
     "SELECT event_id, COUNT(*) as count FROM events WHERE event_id IN (4624, 4648, 4964) GROUP BY event_id ORDER BY count DESC"),

    ("WHEN were valid accounts (T1078) first used post-compromise? First logon timestamps per account.",
     "SELECT username, MIN(timestamp_utc) as first_logon, COUNT(*) as total_logons FROM events WHERE event_id = 4624 AND username IS NOT NULL AND username != '' AND username NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON') AND username NOT LIKE '%$' GROUP BY username ORDER BY first_logon"),

    ("WHERE did T1078 valid account logons originate? Source IPs per account.",
     "SELECT username, source_ip, computer, COUNT(*) as sessions FROM events WHERE event_id IN (4624, 4648) AND source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '127.%' GROUP BY username, source_ip, computer ORDER BY sessions DESC"),

    ("HOW were valid accounts used in T1078? Logon type distribution and explicit credential use.",
     "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id IN (4624, 4648) AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '127.%' AND source_ip IS NOT NULL AND source_ip != '' ORDER BY timestamp_utc LIMIT 20"),

    # ── T1059.001 PowerShell ──────────────────────────────────────────────────
    ("WHO executed T1059.001 PowerShell? Accounts and systems running PowerShell.",
     "SELECT username, computer, COUNT(*) as ps_events FROM events WHERE event_id IN (4104, 800) AND username IS NOT NULL AND username != '' GROUP BY username, computer ORDER BY ps_events DESC"),

    ("WHAT T1059.001 PowerShell scripts were executed? Script block content.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id = 4104 ORDER BY timestamp_utc LIMIT 20"),

    ("WHEN did T1059.001 PowerShell execution occur? Timeline of script events.",
     "SELECT timestamp_utc, computer FROM events WHERE event_id IN (4104, 800) ORDER BY timestamp_utc"),

    ("WHERE was T1059.001 PowerShell executed? Systems with script block logging.",
     "SELECT computer, COUNT(*) as ps_events FROM events WHERE event_id IN (4104, 800) AND computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY ps_events DESC"),

    ("HOW was T1059.001 PowerShell weaponized? Encoded commands, downloads, bypass flags.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1, 4688) AND (description LIKE '%EncodedCommand%' OR description LIKE '%-enc %' OR description LIKE '%IEX%' OR description LIKE '%Invoke-Expression%' OR description LIKE '%DownloadString%' OR description LIKE '%Bypass%') ORDER BY timestamp_utc LIMIT 20"),

    # ── T1053.005 Scheduled Task ──────────────────────────────────────────────
    ("WHO created T1053.005 scheduled tasks? Author and account per task.",
     "SELECT username, computer, COUNT(*) as tasks FROM events WHERE event_id IN (4698, 4702) AND username IS NOT NULL AND username != '' GROUP BY username, computer ORDER BY tasks DESC"),

    ("WHAT T1053.005 scheduled tasks were created? Task names and commands.",
     "SELECT timestamp_utc, username, computer, description FROM events WHERE event_id = 4698 ORDER BY timestamp_utc"),

    ("WHEN were T1053.005 scheduled tasks created? Timeline of task creation events.",
     "SELECT timestamp_utc, computer, username FROM events WHERE event_id IN (4698, 4699, 4702) ORDER BY timestamp_utc"),

    ("WHERE were T1053.005 scheduled tasks installed? Systems with task creation events.",
     "SELECT computer, COUNT(*) as task_events FROM events WHERE event_id IN (4698, 4699, 4702) AND computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY task_events DESC"),

    ("HOW were T1053.005 scheduled tasks used? Task details and execution commands.",
     "SELECT task_name, command, run_as, status FROM scheduled_tasks ORDER BY task_name"),

    # ── T1021.001 Remote Desktop Protocol ────────────────────────────────────
    ("WHO connected via T1021.001 RDP? Users and source IPs for all RDP sessions.",
     "SELECT username, source_ip, COUNT(*) as sessions, MIN(timestamp_utc) as first_seen, MAX(timestamp_utc) as last_seen FROM events WHERE event_id IN (21, 22) AND username IS NOT NULL AND username != '' GROUP BY username, source_ip ORDER BY sessions DESC"),

    ("WHAT T1021.001 RDP events occurred? Session logon, start, logoff, disconnect.",
     "SELECT event_id, COUNT(*) as count, CASE event_id WHEN 21 THEN 'RDP Session Logon' WHEN 22 THEN 'RDP Shell Start' WHEN 23 THEN 'RDP Session Logoff' WHEN 24 THEN 'RDP Session Disconnect' WHEN 25 THEN 'RDP Session Reconnect' END as type FROM events WHERE event_id IN (21, 22, 23, 24, 25) GROUP BY event_id ORDER BY count DESC"),

    ("WHEN did T1021.001 RDP sessions occur? Full session timeline.",
     "SELECT timestamp_utc, event_id, username, source_ip, computer FROM events WHERE event_id IN (21, 22, 23, 24, 25) ORDER BY timestamp_utc"),

    ("WHERE did T1021.001 RDP connections originate? External vs internal source IPs.",
     "SELECT source_ip, username, COUNT(*) as sessions FROM events WHERE event_id IN (21, 22) AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '172.16.%' AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip, username ORDER BY sessions DESC"),

    ("HOW many T1021.001 RDP sessions per user? Session count and duration indicators.",
     "SELECT username, COUNT(CASE WHEN event_id = 21 THEN 1 END) as logons, COUNT(CASE WHEN event_id = 23 THEN 1 END) as logoffs, COUNT(CASE WHEN event_id = 24 THEN 1 END) as disconnects FROM events WHERE event_id IN (21, 23, 24) AND username IS NOT NULL AND username != '' GROUP BY username ORDER BY logons DESC"),

    # ── T1021.002 SMB / Windows Admin Shares ─────────────────────────────────
    ("WHO accessed SMB shares for T1021.002 lateral movement? Accounts and source IPs.",
     "SELECT username, source_ip, computer, COUNT(*) as access_count FROM events WHERE event_id IN (5140, 5145) AND username IS NOT NULL AND username != '' GROUP BY username, source_ip, computer ORDER BY access_count DESC"),

    ("WHAT T1021.002 SMB share access events exist? Volume by account and share.",
     "SELECT event_id, COUNT(*) as count, CASE event_id WHEN 5140 THEN 'T1021.002 Network Share Accessed' WHEN 5145 THEN 'T1021.002 Share Object Check' END as type FROM events WHERE event_id IN (5140, 5145) GROUP BY event_id ORDER BY count DESC"),

    ("WHEN did T1021.002 SMB lateral movement occur? Timeline of share access.",
     "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id IN (5140, 5145) ORDER BY timestamp_utc LIMIT 30"),

    ("WHERE did T1021.002 SMB access originate? Source IP to destination system mapping.",
     "SELECT source_ip, computer, COUNT(*) as smb_events FROM events WHERE event_id IN (5140, 5145) AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip, computer ORDER BY smb_events DESC"),

    ("HOW was T1021.002 SMB used? Show full share access details including description.",
     "SELECT timestamp_utc, username, source_ip, computer, description FROM events WHERE event_id IN (5140, 5145) ORDER BY timestamp_utc LIMIT 20"),

    # ── T1003.006 DCSync / AD Object Access ──────────────────────────────────
    ("WHO performed T1003.006 DCSync or AD object operations? Accounts on directory.",
     "SELECT username, computer, COUNT(*) as ad_events FROM events WHERE event_id IN (5136, 4662, 4732, 4742) AND username IS NOT NULL AND username != '' GROUP BY username, computer ORDER BY ad_events DESC"),

    ("WHAT T1003.006 AD modifications were made? Directory service object operations.",
     "SELECT event_id, COUNT(*) as count, CASE event_id WHEN 5136 THEN 'T1484 Directory Object Modified' WHEN 4662 THEN 'T1003.006 AD Object Operation' WHEN 4732 THEN 'T1098 Member Added to Group' WHEN 4742 THEN 'T1098 Computer Account Changed' END as type FROM events WHERE event_id IN (5136, 4662, 4732, 4742) GROUP BY event_id ORDER BY count DESC"),

    ("WHEN did T1003.006 AD object operations occur? Timeline of directory changes.",
     "SELECT timestamp_utc, username, computer, description FROM events WHERE event_id IN (5136, 4662, 4732, 4742) ORDER BY timestamp_utc"),

    ("WHERE were T1003.006 AD changes made? Domain controllers involved.",
     "SELECT computer, event_id, COUNT(*) as changes FROM events WHERE event_id IN (5136, 4662, 4732, 4742) AND computer IS NOT NULL AND computer != '' GROUP BY computer, event_id ORDER BY changes DESC"),

    ("HOW were T1003.006 AD objects manipulated? Details of each directory operation.",
     "SELECT timestamp_utc, event_id, username, computer, description FROM events WHERE event_id IN (5136, 4662, 4732, 4742) ORDER BY timestamp_utc"),

    # ── T1070.001 Clear Windows Event Logs ───────────────────────────────────
    ("WHO performed T1070.001 log clearing? Account that cleared event logs.",
     "SELECT username, computer, timestamp_utc FROM events WHERE event_id = 1102 ORDER BY timestamp_utc"),

    ("WHAT T1070.001 log clearing events exist? Log cleared and audit policy changes.",
     "SELECT event_id, COUNT(*) as count, CASE event_id WHEN 1102 THEN 'T1070.001 Security Log Cleared' WHEN 4719 THEN 'T1562.002 Audit Policy Changed' END as type FROM events WHERE event_id IN (1102, 4719) GROUP BY event_id ORDER BY count DESC"),

    ("WHEN did T1070.001 log clearing occur? Was it after attack activity?",
     "SELECT timestamp_utc, username, computer, description FROM events WHERE event_id IN (1102, 4719) ORDER BY timestamp_utc"),

    ("WHERE was T1070.001 log clearing performed? Systems with cleared logs.",
     "SELECT computer, COUNT(*) as cleared FROM events WHERE event_id = 1102 AND computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY cleared DESC"),

    ("HOW was T1070.001 evasion timed relative to other attack events? Events before/after log clear.",
     "SELECT timestamp_utc, event_id, username, computer FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != '' ORDER BY timestamp_utc LIMIT 50"),

    # ── T1071 Command and Control / Application Layer Protocol ────────────────
    ("WHO initiated T1071 C2 connections? Processes with external network activity.",
     "SELECT p.name, p.pid, p.command_line, COUNT(*) as connections FROM network_connections n JOIN processes p ON n.pid = p.pid WHERE n.state = 'ESTABLISHED' AND n.remote_address NOT LIKE '10.%' AND n.remote_address NOT LIKE '192.168.%' AND n.remote_address NOT LIKE '127.%' GROUP BY p.name, p.pid ORDER BY connections DESC"),

    ("WHAT T1071 C2 network connections are active? External established connections.",
     "SELECT remote_address, remote_port, protocol, state FROM network_connections WHERE state = 'ESTABLISHED' AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '127.%' AND remote_address IS NOT NULL ORDER BY remote_port"),

    ("WHEN did T1071 C2 communication occur? Timeline of Sysmon network events.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id = 3 ORDER BY timestamp_utc LIMIT 30"),

    ("WHERE did T1071 C2 connect? External destination IPs and ports.",
     "SELECT remote_address, remote_port, protocol, COUNT(*) as connections FROM network_connections WHERE remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '127.%' AND remote_address IS NOT NULL GROUP BY remote_address, remote_port ORDER BY connections DESC"),

    ("HOW was T1071 C2 implemented? Process attribution and port/protocol used.",
     "SELECT n.remote_address, n.remote_port, n.protocol, p.name, p.command_line FROM network_connections n JOIN processes p ON n.pid = p.pid WHERE n.state = 'ESTABLISHED' AND n.remote_address NOT LIKE '10.%' AND n.remote_address NOT LIKE '192.168.%' AND n.remote_address NOT LIKE '127.%' ORDER BY n.remote_address"),
]


# ── PROCEDURE_QA — Patrones específicos de procedimiento de ataque ────────────
# Correlaciones, secuencias y firmas de herramientas concretas

PROCEDURE_QA = [

    # ── Brute force → success correlation ────────────────────────────────────
    ("Did brute force succeed? Show IPs with failed logons that also had successful logons.",
     "SELECT DISTINCT e1.source_ip, e1.username, e1.computer FROM events e1 WHERE e1.event_id = 4624 AND e1.source_ip IS NOT NULL AND e1.source_ip != '' AND EXISTS (SELECT 1 FROM events e2 WHERE e2.event_id IN (4625, 4771) AND e2.source_ip = e1.source_ip) ORDER BY e1.source_ip"),

    ("¿El brute force tuvo éxito? IPs con fallos que también tuvieron logon exitoso.",
     "SELECT DISTINCT e1.source_ip, e1.username, e1.computer FROM events e1 WHERE e1.event_id = 4624 AND e1.source_ip IS NOT NULL AND e1.source_ip != '' AND EXISTS (SELECT 1 FROM events e2 WHERE e2.event_id IN (4625, 4771) AND e2.source_ip = e1.source_ip) ORDER BY e1.source_ip"),

    ("Show the first successful logon after failed attempts — brute force success moment.",
     "SELECT e1.timestamp_utc, e1.username, e1.source_ip, e1.computer FROM events e1 WHERE e1.event_id = 4624 AND e1.source_ip IS NOT NULL AND e1.source_ip != '' AND EXISTS (SELECT 1 FROM events e2 WHERE e2.event_id IN (4625, 4771) AND e2.source_ip = e1.source_ip AND e2.timestamp_utc < e1.timestamp_utc) ORDER BY e1.timestamp_utc LIMIT 5"),

    # ── LOLBin detection ──────────────────────────────────────────────────────
    ("Which LOLBins (Living Off the Land Binaries) were executed?",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1, 4688) AND (description LIKE '%certutil%' OR description LIKE '%bitsadmin%' OR description LIKE '%mshta%' OR description LIKE '%regsvr32%' OR description LIKE '%rundll32%' OR description LIKE '%wscript%' OR description LIKE '%cscript%' OR description LIKE '%msiexec%' OR description LIKE '%installutil%') ORDER BY timestamp_utc"),

    ("¿Qué LOLBins se ejecutaron? Binarios del sistema usados para evasión.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1, 4688) AND (description LIKE '%certutil%' OR description LIKE '%bitsadmin%' OR description LIKE '%mshta%' OR description LIKE '%regsvr32%' OR description LIKE '%rundll32%' OR description LIKE '%installutil%') ORDER BY timestamp_utc"),

    # ── Encoded PowerShell ────────────────────────────────────────────────────
    ("Show encoded PowerShell commands — EncodedCommand, -enc, FromBase64String.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1, 4688, 4104) AND (description LIKE '%-EncodedCommand%' OR description LIKE '%-enc %' OR description LIKE '%FromBase64String%' OR description LIKE '%ToBase64String%') ORDER BY timestamp_utc"),

    ("¿Hay comandos PowerShell con encoding? Indicador de evasión de detección.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1, 4688, 4104) AND (description LIKE '%EncodedCommand%' OR description LIKE '%-enc %' OR description LIKE '%Base64%') ORDER BY timestamp_utc"),

    # ── Service installation as persistence ───────────────────────────────────
    ("Were new Windows services installed as persistence? Show service creation events.",
     "SELECT timestamp_utc, username, computer, description FROM events WHERE event_id IN (7045, 4697) ORDER BY timestamp_utc"),

    ("¿Se instalaron servicios nuevos para persistencia? Eventos de instalación de servicio.",
     "SELECT timestamp_utc, username, computer, description FROM events WHERE event_id IN (7045, 4697) ORDER BY timestamp_utc"),

    # ── Account creation and privilege group addition ─────────────────────────
    ("Were new user accounts created? Show account creation and group membership events.",
     "SELECT timestamp_utc, username, computer, description FROM events WHERE event_id IN (4720, 4728, 4732) ORDER BY timestamp_utc"),

    ("¿Se crearon cuentas nuevas o se añadieron a grupos privilegiados?",
     "SELECT timestamp_utc, event_id, username, computer, description FROM events WHERE event_id IN (4720, 4728, 4732) ORDER BY timestamp_utc"),

    # ── Kerberoasting / ticket requests ──────────────────────────────────────
    ("Show Kerberos service ticket requests — potential Kerberoasting activity.",
     "SELECT timestamp_utc, username, source_ip, computer, description FROM events WHERE event_id IN (4769, 4768) ORDER BY timestamp_utc LIMIT 30"),

    ("¿Hay solicitudes masivas de tickets Kerberos? Indicador de Kerberoasting.",
     "SELECT username, COUNT(*) as ticket_requests FROM events WHERE event_id = 4769 AND username IS NOT NULL AND username != '' GROUP BY username ORDER BY ticket_requests DESC"),

    # ── Pass-the-Hash indicators ──────────────────────────────────────────────
    ("Show explicit credential logons from external sources — possible pass-the-hash.",
     "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 4648 AND source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '127.%' ORDER BY timestamp_utc"),

    ("¿Hay indicadores de pass-the-hash? Logons con credenciales explícitas desde IPs externas.",
     "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 4648 AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '127.%' AND source_ip IS NOT NULL ORDER BY timestamp_utc"),

    # ── WMI execution indicators ──────────────────────────────────────────────
    ("Were there WMI execution events? WMI spawning child processes.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1, 4688) AND (description LIKE '%WmiPrvSE%' OR description LIKE '%wmiprvse%' OR description LIKE '%wmic%') ORDER BY timestamp_utc"),

    ("¿Hay ejecución remota vía WMI? Proceso wmiprvse lanzando hijos.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1, 4688) AND (description LIKE '%wmiprvse%' OR description LIKE '%wmic%') ORDER BY timestamp_utc"),

    # ── Suspicious parent-child process relationships ─────────────────────────
    ("Show cmd.exe or PowerShell spawned by Office or browser processes — phishing indicator.",
     "SELECT timestamp_utc, computer, description FROM events WHERE event_id IN (1, 4688) AND (description LIKE '%WINWORD%' OR description LIKE '%EXCEL%' OR description LIKE '%OUTLOOK%' OR description LIKE '%chrome%' OR description LIKE '%iexplore%') AND description LIKE '%powershell%' OR description LIKE '%cmd.exe%' ORDER BY timestamp_utc"),

    # ── Defense evasion: log clearing context ────────────────────────────────
    ("Show events immediately before log clearing — what was the attacker hiding?",
     "SELECT timestamp_utc, event_id, username, computer FROM events WHERE timestamp_utc < (SELECT MIN(timestamp_utc) FROM events WHERE event_id = 1102) ORDER BY timestamp_utc DESC LIMIT 20"),

    ("¿Qué ocurrió antes del borrado de logs? Actividad previa al evento 1102.",
     "SELECT timestamp_utc, event_id, username, computer FROM events WHERE timestamp_utc < (SELECT MIN(timestamp_utc) FROM events WHERE event_id = 1102) ORDER BY timestamp_utc DESC LIMIT 20"),

    # ── C2 beacon pattern ─────────────────────────────────────────────────────
    ("Does the same external IP appear repeatedly at regular intervals? C2 beacon pattern.",
     "SELECT remote_address, COUNT(*) as connection_count FROM network_connections WHERE state = 'ESTABLISHED' AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '127.%' AND remote_address IS NOT NULL GROUP BY remote_address ORDER BY connection_count DESC"),

    ("¿Hay un patrón de beacon C2? Misma IP externa con múltiples conexiones.",
     "SELECT remote_address, remote_port, COUNT(*) as hits FROM network_connections WHERE remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '127.%' AND remote_address IS NOT NULL GROUP BY remote_address, remote_port ORDER BY hits DESC"),

    # ── Lateral movement chain ────────────────────────────────────────────────
    ("Show the lateral movement chain — account pivoting across multiple systems over time.",
     "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id IN (4624, 4648) AND source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '127.%' ORDER BY username, timestamp_utc"),

    ("¿Cuál fue la cadena de movimiento lateral? Pivoting de cuenta entre sistemas.",
     "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id IN (4624, 4648, 5140, 5145) AND source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '127.%' ORDER BY timestamp_utc"),

    # ── RDP from external — first session ─────────────────────────────────────
    ("Show the first RDP session from an external IP — initial external access via RDP.",
     "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 21 AND source_ip IS NOT NULL AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '172.16.%' AND source_ip != '' ORDER BY timestamp_utc LIMIT 5"),

    ("¿Cuál fue la primera sesión RDP externa? Primera conexión desde IP no interna.",
     "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 21 AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '172.16.%' AND source_ip IS NOT NULL AND source_ip != '' ORDER BY timestamp_utc LIMIT 5"),

    # ── Incident scope summary ────────────────────────────────────────────────
    ("What is the full scope of this incident? Systems, accounts, timespan, techniques.",
     "SELECT COUNT(DISTINCT computer) as systems, COUNT(DISTINCT username) as accounts, MIN(timestamp_utc) as start, MAX(timestamp_utc) as end, COUNT(DISTINCT event_id) as unique_event_types, COUNT(*) as total_events FROM events WHERE computer IS NOT NULL"),

    ("¿Cuál es el alcance total del incidente? Resumen ejecutivo: sistemas, cuentas, tiempo.",
     "SELECT COUNT(DISTINCT computer) as sistemas, COUNT(DISTINCT username) as cuentas, MIN(timestamp_utc) as inicio, MAX(timestamp_utc) as fin, COUNT(*) as total_eventos FROM events WHERE computer IS NOT NULL"),

    # ── Attacker primary account ──────────────────────────────────────────────
    ("Which account is the primary threat actor? Appears in most attack phases.",
     "SELECT username, COUNT(DISTINCT event_id) as attack_phases, COUNT(*) as total_events FROM events WHERE username IS NOT NULL AND username != '' AND username NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON') AND username NOT LIKE 'NT AUTHORITY%' AND username NOT LIKE '%$' GROUP BY username ORDER BY attack_phases DESC, total_events DESC LIMIT 5"),

    ("¿Cuál es la cuenta principal del atacante? La que aparece en más fases del ataque.",
     "SELECT username, COUNT(DISTINCT event_id) as fases_ataque, COUNT(*) as total_eventos FROM events WHERE username IS NOT NULL AND username != '' AND username NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON') AND username NOT LIKE 'NT AUTHORITY%' AND username NOT LIKE '%$' GROUP BY username ORDER BY fases_ataque DESC LIMIT 5"),

    # ── All IoCs combined ─────────────────────────────────────────────────────
    ("Extract all IoCs: external IPs, attacker accounts, suspicious processes in one query.",
     "SELECT 'external_ip' as ioc_type, source_ip as ioc_value, COUNT(*) as hits FROM events WHERE source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '127.%' AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip UNION ALL SELECT 'attacker_account', username, COUNT(*) FROM events WHERE username NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON') AND username NOT LIKE '%$' AND username NOT LIKE 'NT AUTHORITY%' AND username IS NOT NULL AND username != '' GROUP BY username ORDER BY hits DESC"),

    ("¿Cuáles son todos los IoCs del incidente? IPs externas, cuentas, procesos.",
     "SELECT 'ip_externa' as tipo_ioc, source_ip as valor, COUNT(*) as ocurrencias FROM events WHERE source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '127.%' AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip UNION ALL SELECT 'cuenta_atacante', username, COUNT(*) FROM events WHERE username NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON') AND username NOT LIKE '%$' AND username NOT LIKE 'NT AUTHORITY%' AND username IS NOT NULL AND username != '' GROUP BY username ORDER BY ocurrencias DESC"),

    # ── Scheduled task with encoded command ────────────────────────────────────
    ("Are there scheduled tasks with encoded PowerShell commands — backdoor tasks?",
     "SELECT task_name, command, run_as, author FROM scheduled_tasks WHERE command LIKE '%EncodedCommand%' OR command LIKE '%-enc %' OR command LIKE '%IEX%' OR command LIKE '%Base64%' OR command LIKE '%Temp%' OR command LIKE '%AppData%'"),

    ("¿Hay tareas programadas con comandos codificados? Posible backdoor vía tarea.",
     "SELECT task_name, command, run_as FROM scheduled_tasks WHERE (command LIKE '%EncodedCommand%' OR command LIKE '%enc%' OR command LIKE '%IEX%') OR (command LIKE '%Temp%' OR command LIKE '%AppData%')"),

    # ── Dwell time and attack phases ──────────────────────────────────────────
    ("How long did each attack phase last? Time between first credential attack and impact.",
     "SELECT CASE WHEN event_id IN (4625,4771,4776) THEN 'TA0006_credential_access' WHEN event_id IN (4624,4648) THEN 'TA0001_initial_access' WHEN event_id IN (1,4688,4104) THEN 'TA0002_execution' WHEN event_id IN (4698,7045,5136) THEN 'TA0003_persistence' WHEN event_id IN (4672,4673) THEN 'TA0004_privesc' WHEN event_id IN (5140,5145,21) THEN 'TA0008_lateral' WHEN event_id IN (1102,4719) THEN 'TA0005_defense_evasion' WHEN event_id IN (1116,1117) THEN 'TA0040_impact' END as phase, MIN(timestamp_utc) as first_event, MAX(timestamp_utc) as last_event, COUNT(*) as events FROM events WHERE event_id IN (4625,4771,4776,4624,4648,1,4688,4104,4698,7045,5136,4672,4673,5140,5145,21,1102,4719,1116,1117) GROUP BY phase ORDER BY first_event"),

    ("¿Cuánto duró cada fase del ataque? Timeline completo por táctica MITRE.",
     "SELECT CASE WHEN event_id IN (4625,4771,4776) THEN 'TA0006_acceso_credenciales' WHEN event_id IN (4624,4648) THEN 'TA0001_acceso_inicial' WHEN event_id IN (1,4688,4104) THEN 'TA0002_ejecucion' WHEN event_id IN (4698,7045,5136) THEN 'TA0003_persistencia' WHEN event_id IN (4672,4673) THEN 'TA0004_privesc' WHEN event_id IN (5140,5145,21) THEN 'TA0008_movimiento_lateral' WHEN event_id IN (1102,4719) THEN 'TA0005_evasion' WHEN event_id IN (1116,1117) THEN 'TA0040_impacto' END as fase, MIN(timestamp_utc) as primer_evento, MAX(timestamp_utc) as ultimo_evento, COUNT(*) as total FROM events WHERE event_id IN (4625,4771,4776,4624,4648,1,4688,4104,4698,7045,5136,4672,4673,5140,5145,21,1102,4719,1116,1117) GROUP BY fase ORDER BY primer_evento"),
]


# ── TABLE_DOCS additions ──────────────────────────────────────────────────────
# Appended below in the TABLE_DOCS dict — loaded separately


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

        # 3. Pares Q-SQL relevantes — generic + tactic + technique + procedure
        print(f"  {CYAN}[3/3] Pares pregunta-SQL...{RESET}")
        active_event_ids = self._get_active_event_ids()
        all_qa = GENERIC_QA + TACTIC_QA + TECHNIQUE_QA + PROCEDURE_QA
        for question, sql in all_qa:
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

    def _call_llm(self, prompt: str, max_tokens: int = 256) -> str:
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
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content or ""

    def ask_with_explanation(self, question: str, verbose: bool = True) -> dict:
        """NL→SQL + interpretación forense del analista sobre los resultados."""
        result = self.ask(question, verbose=verbose)

        if result.get("error") or result.get("result") is None:
            return {**result, "explanation": None}

        df = result["result"]
        if len(df) == 0:
            data_summary = "(no rows returned)"
        elif len(df) <= 20:
            data_summary = df.to_string(index=False)
        else:
            data_summary = (
                df.head(15).to_string(index=False)
                + f"\n... ({len(df)} rows total, showing first 15)"
            )

        explain_prompt = (
            f"You are a senior DFIR analyst reviewing forensic evidence from a Windows environment.\n"
            f"The analyst asked: \"{question}\"\n\n"
            f"The forensic database returned ({len(df)} rows):\n{data_summary}\n\n"
            f"Answer in 2-3 concise sentences:\n"
            f"1. What specific attack technique or adversary behavior does this evidence indicate?\n"
            f"2. What is the attacker's likely goal or impact?\n"
            f"3. What artifact or pivot should the analyst examine next?\n"
            f"Be direct. Reference specific values from the data above."
        )

        if verbose:
            print(f"\n  {CYAN}[Análisis DFIR]...{RESET}", flush=True)

        explanation = self._call_llm(explain_prompt, max_tokens=384)

        if verbose:
            print(f"\n  {CYAN}{'─'*60}{RESET}")
            print(f"  {CYAN}{BOLD}  Interpretación del analista:{RESET}")
            for line in explanation.strip().splitlines():
                print(f"  {line}")
            print(f"  {CYAN}{'─'*60}{RESET}\n")

        return {**result, "explanation": explanation}

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
