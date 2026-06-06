"""
NexusRouter — enruta cada pregunta al tool correcto.

Tres rutas:
  threat_hunt → patrones MITRE ATT&CK en la DB (sin LLM, instantáneo)
  ioc         → correlación cross-tabla de un indicador (sin LLM, instantáneo)
  sql         → NL→SQL con Ollama (LLM, ~60-90s en CPU)

El analista solo escribe. El router decide.
"""

import re
import sqlite3
import time
from pathlib import Path

import pandas as pd

BOLD    = "\033[1m"
DIM     = "\033[2m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
RESET   = "\033[0m"

# ── Threat rules (MITRE ATT&CK mapped) ───────────────────────────────────────

THREAT_RULES = [
    {
        "id": "T1059.001", "severity": "HIGH",
        "name": "PowerShell Encoded Command",
        "table": "processes",
        "where": "command_line LIKE '%-EncodedCommand%' OR command_line LIKE '%-enc %' OR command_line LIKE '%FromBase64String%'",
        "cols": "pid, name, command_line, username",
    },
    {
        "id": "T1105", "severity": "HIGH",
        "name": "Ingress Tool Transfer",
        "table": "processes",
        "where": "command_line LIKE '%Invoke-WebRequest%' OR command_line LIKE '%DownloadString%' OR command_line LIKE '%certutil%url%' OR command_line LIKE '%bitsadmin%transfer%'",
        "cols": "pid, name, command_line",
    },
    {
        "id": "T1003", "severity": "CRITICAL",
        "name": "Credential Dumping Tools",
        "table": "processes",
        "where": "LOWER(name) IN ('mimikatz.exe','procdump.exe','wce.exe','fgdump.exe') OR command_line LIKE '%sekurlsa%' OR command_line LIKE '%lsadump%'",
        "cols": "pid, name, command_line",
    },
    {
        "id": "T1078", "severity": "CRITICAL",
        "name": "System Process Username Anomaly",
        "table": "processes",
        "where": "UPPER(username) NOT LIKE '%SYSTEM%' AND UPPER(username) NOT LIKE '%SERVICE%' AND UPPER(username) NOT LIKE '%LOCAL SERVICE%' AND UPPER(username) NOT LIKE '%NETWORK SERVICE%' AND name IN ('lsass.exe','services.exe','wininit.exe','csrss.exe','smss.exe')",
        "cols": "pid, name, username, exe_path",
    },
    {
        "id": "T1036", "severity": "MEDIUM",
        "name": "Masquerading — Suspicious Path",
        "table": "processes",
        "where": "(exe_path LIKE '%\\Temp\\%' OR exe_path LIKE '%\\AppData\\%' OR exe_path LIKE '%\\Users\\Public\\%') AND exe_path != ''",
        "cols": "pid, name, exe_path, username",
    },
    {
        "id": "T1053.005", "severity": "HIGH",
        "name": "Scheduled Task Persistence",
        "table": "scheduled_tasks",
        "where": "command LIKE '%Temp%' OR command LIKE '%AppData%' OR command LIKE '%-Enc%' OR command LIKE '%DownloadString%'",
        "cols": "task_name, command, author, run_as",
    },
    {
        "id": "T1547.001", "severity": "MEDIUM",
        "name": "Registry Run Key Persistence",
        "table": "registry_keys",
        "where": "key_path LIKE '%\\Run%' OR key_path LIKE '%\\RunOnce%'",
        "cols": "key_path, value_name, value_data",
    },
    {
        "id": "T1071.001", "severity": "HIGH",
        "name": "C2 over HTTP/HTTPS",
        "table": "network_connections",
        "where": "state='ESTABLISHED' AND remote_port IN (80,443,8080,8443) AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '127.%' AND remote_address IS NOT NULL AND remote_address != ''",
        "cols": "remote_address, remote_port, pid, state",
    },
    {
        "id": "T1049", "severity": "MEDIUM",
        "name": "Non-standard Outbound Port",
        "table": "network_connections",
        "where": "state='ESTABLISHED' AND remote_port NOT IN (80,443,22,21,25,53,3389,135,139,445) AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '127.%' AND remote_address IS NOT NULL AND remote_address != ''",
        "cols": "remote_address, remote_port, pid, state",
    },
    {
        "id": "T1110", "severity": "MEDIUM",
        "name": "Brute Force — Failed Logons",
        "table": "events",
        "where": "event_id = 4625",
        "cols": "COUNT(*) as failed_attempts, source_ip, username",
        "group_by": "source_ip, username",
        "having": "COUNT(*) > 5",
        "order_by": "failed_attempts DESC",
    },
    {
        "id": "T1078", "severity": "HIGH",
        "name": "Logon from External IP",
        "table": "events",
        "where": "event_id = 4624 AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '127.%' AND source_ip IS NOT NULL AND source_ip != ''",
        "cols": "timestamp_utc, username, source_ip, computer",
    },
    # ── Sysmon rules (events table, EID-based) ────────────────────────────────
    {
        "id": "T1059.001", "severity": "HIGH",
        "name": "Sysmon: PowerShell Encoded Command",
        "table": "events",
        "where": "event_id = 1 AND (description LIKE '%-EncodedCommand%' OR description LIKE '%FromBase64String%' OR description LIKE '%-enc %' OR description LIKE '%IEX%')",
        "cols": "timestamp_utc, computer, username, description",
    },
    {
        "id": "T1055", "severity": "CRITICAL",
        "name": "Sysmon: Process Injection (lsass access)",
        "table": "events",
        "where": "event_id = 10 AND description LIKE '%lsass%'",
        "cols": "timestamp_utc, computer, description",
    },
    {
        "id": "T1003.001", "severity": "CRITICAL",
        "name": "Sysmon: LSASS Memory Dump",
        "table": "events",
        "where": "event_id = 1 AND (description LIKE '%lsass%' OR description LIKE '%procdump%' OR description LIKE '%sekurlsa%')",
        "cols": "timestamp_utc, computer, username, description",
    },
    {
        "id": "T1071.001", "severity": "HIGH",
        "name": "Sysmon: Network Connection to External IP",
        "table": "events",
        "where": "event_id = 3 AND description NOT LIKE '%DestinationIp=10.%' AND description NOT LIKE '%DestinationIp=192.168.%' AND description NOT LIKE '%DestinationIp=127.%' AND description LIKE '%Initiated=true%'",
        "cols": "timestamp_utc, computer, username, description",
    },
    {
        "id": "T1547.001", "severity": "HIGH",
        "name": "Sysmon: Registry Run Key Write",
        "table": "events",
        "where": "event_id IN (12, 13, 14) AND (description LIKE '%CurrentVersion\\Run%' OR description LIKE '%CurrentVersion\\RunOnce%')",
        "cols": "timestamp_utc, computer, username, description",
    },
    {
        "id": "T1105", "severity": "HIGH",
        "name": "Sysmon: Suspicious Download (certutil/bitsadmin/curl)",
        "table": "events",
        "where": "event_id = 1 AND (description LIKE '%certutil%urlcache%' OR description LIKE '%bitsadmin%transfer%' OR description LIKE '%Invoke-WebRequest%' OR description LIKE '%DownloadString%')",
        "cols": "timestamp_utc, computer, username, description",
    },
    {
        "id": "T1053.005", "severity": "HIGH",
        "name": "Sysmon: Scheduled Task Created",
        "table": "events",
        "where": "event_id = 1 AND description LIKE '%schtasks%/create%'",
        "cols": "timestamp_utc, computer, username, description",
    },
    {
        "id": "T1218", "severity": "MEDIUM",
        "name": "Sysmon: LOLBin Execution (regsvr32/mshta/rundll32/certutil)",
        "table": "events",
        "where": "event_id = 1 AND (description LIKE '%regsvr32%scrobj%' OR description LIKE '%mshta%http%' OR description LIKE '%rundll32%javascript%' OR description LIKE '%wscript%http%')",
        "cols": "timestamp_utc, computer, username, description",
    },
]

_SEV_COLOR = {"CRITICAL": RED + BOLD, "HIGH": YELLOW + BOLD, "MEDIUM": CYAN, "LOW": DIM}


# ── Intent detection ──────────────────────────────────────────────────────────

def detect_intent(question: str) -> str:
    """Clasifica la pregunta en threat_hunt | ioc | sql. Sin LLM."""
    q = question.lower()

    # Threat hunt — palabras clave de malware/TTP
    if re.search(
        r"\b(malware|virus|infectad|infected|ransomware|trojan|"
        r"threat|amenaza|ttp|yara|hunting|caceria|"
        r"hay\s+malware|busca\s+malware|analiza\s+amenazas|"
        r"detecta|detection|patr[oó]n\s+sospec)\b",
        q
    ):
        return "threat_hunt"

    # IOC — IP literal en la pregunta O verbos de pivot
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", q):
        return "ioc"
    if re.search(r"[0-9a-f]{32,64}", q):   # hash MD5/SHA1/SHA256
        return "ioc"
    if re.search(
        r"\b(busca\s+\S|correlaciona|pivot|traza\s+|trace\s+|ioc\b|indicador\b)\b",
        q
    ):
        return "ioc"

    return "sql"


def extract_ioc(question: str) -> str | None:
    """Extrae el primer IOC de la pregunta."""
    m = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", question)
    if m:
        return m.group(0)
    m = re.search(r"[0-9a-fA-F]{32,64}", question)
    if m:
        return m.group(0)
    m = re.search(
        r"(?:busca|correlaciona|pivot|traza|trace)\s+(\S+)",
        question, re.IGNORECASE
    )
    if m:
        return m.group(1).strip("¿?.,;:")
    return None


# ── Tools ─────────────────────────────────────────────────────────────────────

def tool_threat_hunt(conn: sqlite3.Connection) -> list[dict]:
    """Aplica todas las reglas MITRE sobre la DB. Sin LLM."""
    hits = []
    for rule in THREAT_RULES:
        # Construir SQL dinámicamente según la regla
        cols    = rule["cols"]
        table   = rule["table"]
        where   = rule["where"]
        grp     = rule.get("group_by", "")
        having  = rule.get("having", "")
        order   = rule.get("order_by", "")

        sql = f"SELECT {cols} FROM {table} WHERE {where}"
        if grp:
            sql += f" GROUP BY {grp}"
        if having:
            sql += f" HAVING {having}"
        if order:
            sql += f" ORDER BY {order}"
        sql += " LIMIT 20"

        try:
            df = pd.read_sql(sql, conn)
            if not df.empty:
                hits.append({
                    "rule_id":   rule["id"],
                    "severity":  rule["severity"],
                    "name":      rule["name"],
                    "table":     table,
                    "rows":      df,
                    "count":     len(df),
                })
        except Exception:
            pass

    return hits


def tool_ioc_correlate(indicator: str, conn: sqlite3.Connection) -> dict:
    """Correlaciona un IOC en todas las tablas. Sin LLM."""
    results = {}

    searches = [
        # (tabla, columna_exacta, columnas_a_mostrar)
        ("events",              "source_ip",      "timestamp_utc, event_id, username, computer"),
        ("network_connections", "remote_address", "protocol, remote_address, remote_port, local_address, state, pid"),
    ]

    text_searches = {
        "processes":       ["name", "command_line", "exe_path"],
        "scheduled_tasks": ["task_name", "command", "author"],
        "registry_keys":   ["key_path", "value_name", "value_data"],
        "events":          ["username", "description"],
    }

    ind_lower = indicator.lower()

    for table, col, select_cols in searches:
        try:
            df = pd.read_sql(
                f"SELECT {select_cols} FROM {table} WHERE {col} = ? LIMIT 50",
                conn, params=(indicator,)
            )
            if not df.empty:
                results[f"{table} ({col})"] = df
        except Exception:
            pass

    for table, cols in text_searches.items():
        cond   = " OR ".join(f"LOWER({c}) LIKE ?" for c in cols)
        params = [f"%{ind_lower}%"] * len(cols)
        try:
            df = pd.read_sql(f"SELECT * FROM {table} WHERE {cond} LIMIT 20", conn, params=params)
            key = f"{table} (text)"
            if not df.empty and key not in results:
                results[key] = df
        except Exception:
            pass

    return results


# ── NexusRouter ───────────────────────────────────────────────────────────────

class NexusRouter:
    def __init__(self, case, model: str = "qwen2.5:7b-instruct"):
        self.case  = case
        self.model = model
        self._analyst = None
        self._conn    = sqlite3.connect(case.db_path)

    def _get_analyst(self):
        if self._analyst is None:
            from .analyst import NexusAnalyst
            self._analyst = NexusAnalyst(
                self.case.db_path,
                model=self.model,
                store_path=self.case.store_path,
            )
            self._analyst.train()
        return self._analyst

    def ask(self, question: str) -> dict:
        """Enruta la pregunta y ejecuta el tool correcto. Devuelve metadata."""
        intent = detect_intent(question)
        t0     = time.perf_counter()

        print(f"\n  {DIM}[{intent.upper()}]{RESET} {question}")

        if intent == "threat_hunt":
            result = self._run_threat_hunt()
        elif intent == "ioc":
            result = self._run_ioc(question)
        else:
            result = self._run_sql(question)

        elapsed = time.perf_counter() - t0
        print(f"\n  {DIM}↳ {elapsed:.1f}s{RESET}\n")

        result["intent"]  = intent
        result["elapsed"] = elapsed
        return result

    def _run_threat_hunt(self) -> dict:
        hits = tool_threat_hunt(self._conn)
        if not hits:
            print(f"  {GREEN}✓ Sin hallazgos — no se detectaron TTPs conocidos{RESET}")
            return {"hits": [], "error": None}

        total = sum(h["count"] for h in hits)
        print(f"  {RED}{BOLD}⚠ {len(hits)} reglas disparadas — {total} hallazgos totales{RESET}\n")

        for h in hits:
            sev_color = _SEV_COLOR.get(h["severity"], "")
            print(f"  {sev_color}[{h['severity']}] {h['rule_id']} — {h['name']}{RESET}")
            print(h["rows"].to_string(index=False))
            print()

        return {"hits": hits, "error": None}

    def _run_ioc(self, question: str) -> dict:
        indicator = extract_ioc(question)
        if not indicator:
            print(f"  {YELLOW}No pude extraer un IOC de la pregunta. Redirigiendo a SQL...{RESET}")
            return self._run_sql(question)

        print(f"  {CYAN}Correlacionando: {BOLD}{indicator}{RESET}")
        results = tool_ioc_correlate(indicator, self._conn)

        if not results:
            print(f"  {YELLOW}Sin resultados para '{indicator}'{RESET}")
            return {"indicator": indicator, "results": {}, "error": None}

        total = sum(len(df) for df in results.values())
        print(f"  {GREEN}✓ {total} referencias en {len(results)} tabla(s){RESET}\n")
        for label, df in results.items():
            print(f"  {BOLD}{label}{RESET} ({len(df)} filas)")
            print(df.to_string(index=False))
            print()

        return {"indicator": indicator, "results": results, "error": None}

    def _run_sql(self, question: str) -> dict:
        analyst = self._get_analyst()
        return analyst.ask(question)

    def close(self):
        self._conn.close()
        if self._analyst:
            self._analyst.close()
