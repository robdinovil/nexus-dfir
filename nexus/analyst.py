"""
Nexus Analyst — capa NL→SQL sobre cualquier caso Nexus.

No está hardcodeada a ningún caso. Lee el schema de la DB,
detecta qué tablas tienen datos, y construye el contexto
forense relevante para esas tablas.
"""

import re
import sqlite3
import json
import time
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


from .qa_corpus import GENERIC_QA, TACTIC_QA, TECHNIQUE_QA, PROCEDURE_QA


# ── TABLE_DOCS additions ──────────────────────────────────────────────────────
# Appended below in the TABLE_DOCS dict — loaded separately


_RE_SIMPLE_Q = re.compile(
    r'\b(how many|count|list all|distinct|cuántos|cuantos|lista|qué usuarios|'
    r'qué equipos|total de|muéstrame|muestra todos|show me|listar)\b',
    re.IGNORECASE,
)
_RE_COMPLEX_Q = re.compile(
    r'\b(correlat|timeline|lateral|kill chain|pivot|brute force|credential|'
    r'dump|también|also|asimismo|relaciona|relacionado)\b',
    re.IGNORECASE,
)


def _select_model(question: str, default_model: str) -> str:
    """Usa 3b para queries simples (count/list) — 2-3x más rápido."""
    if _RE_COMPLEX_Q.search(question):
        return default_model
    if len(question) < 80 and _RE_SIMPLE_Q.search(question):
        return default_model.replace("7b", "3b")
    return default_model


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

        self._prompt_base_cache: str | None = None
        self._session_history: list[dict] = []

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

    def _get_prompt_base(self) -> str:
        """Schema + reglas de sistema — cacheado por sesión (mismo para todas las queries)."""
        if self._prompt_base_cache is not None:
            return self._prompt_base_cache
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
        ddls = self._store.get_all_ddl()
        if ddls:
            parts.append("=== DATABASE SCHEMA ===")
            parts.extend(ddls[:10])
            parts.append("")
        self._prompt_base_cache = "\n".join(parts)
        return self._prompt_base_cache

    def ask(self, question: str, verbose: bool = True) -> dict:
        """Pregunta en lenguaje natural. Genera SQL, valida, y ejecuta con retry."""
        from .validator import validate, build_correction_hint

        if verbose:
            print(f"\n  {BOLD}Pregunta:{RESET} {question}")

        t0 = time.time()
        effective_model = _select_model(question, self.model)
        prompt = self._build_prompt(question)
        sql = _clean_sql(self._call_llm(prompt, model=effective_model))
        sql = _enforce_limit(sql)

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
            latency = round(time.time() - t0, 2)
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
            self._audit(question, sql, success=1, row_count=len(df),
                        hallucination=validation.hallucination_type,
                        autocorrected=int(self_corrected), latency_s=latency)
            # Actualizar historial de sesión (últimas 3 Q&A para contexto conversacional)
            summary = df.head(2).to_string(index=False)[:200] if len(df) > 0 else "(empty)"
            self._session_history.append({
                "question": question[:100],
                "row_count": len(df),
                "summary": summary,
            })
            self._session_history = self._session_history[-3:]
            return {
                "question": question, "sql": sql, "result": df, "error": None,
                "hallucination": validation.hallucination_type,
                "retried": retried,
                "self_corrected": self_corrected,
                "first_hallucination_type": first_hallucination_type,
            }
        except Exception as e:
            latency = round(time.time() - t0, 2)
            if verbose:
                print(f"  {RED}Error ejecutando SQL:{RESET} {e}")
            self._audit(question, sql, success=0, row_count=0,
                        hallucination=validation.hallucination_type,
                        autocorrected=int(self_corrected), latency_s=latency)
            return {
                "question": question, "sql": sql, "result": None, "error": str(e),
                "hallucination": validation.hallucination_type,
                "retried": retried,
                "self_corrected": self_corrected,
                "first_hallucination_type": first_hallucination_type,
            }

    def _build_prompt(self, question: str) -> str:
        """Schema cacheado + docs BM25 por query + historial de sesión + few-shot + pregunta."""
        parts = [self._get_prompt_base()]

        # Docs más relevantes (top 5 por BM25) — varía por pregunta
        all_docs = self._store.get_all_docs()
        if all_docs:
            relevant_docs = _bm25_top_k(question, all_docs, k=5)
            if relevant_docs:
                parts.append("=== CONTEXT ===")
                parts.extend(relevant_docs)
                parts.append("")

        # Contexto conversacional de la sesión (últimas 2 preguntas)
        if self._session_history:
            parts.append("=== SESSION CONTEXT (previous questions this session) ===")
            for h in self._session_history[-2:]:
                parts.append(f"Q: {h['question']}")
                parts.append(f"Result: {h['row_count']} rows. {h['summary']}")
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

    def _call_llm(self, prompt: str, max_tokens: int = 256, model: str = None) -> str:
        """Llama al LLM via Ollama. Fallback automático a 3b si 7b timeout."""
        import httpx
        from openai import OpenAI
        effective_model = model or self.model
        client = OpenAI(
            base_url=f"{self.ollama_url}/v1",
            api_key="ollama",
            timeout=httpx.Timeout(connect=10.0, read=600.0, write=10.0, pool=5.0),
            max_retries=0,
        )
        try:
            resp = client.chat.completions.create(
                model=effective_model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=max_tokens,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:
            err = str(e).lower()
            if "7b" in effective_model and ("timeout" in err or "read" in err or "connection" in err):
                fallback = effective_model.replace("7b", "3b")
                resp = client.chat.completions.create(
                    model=fallback,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.0,
                    max_tokens=max_tokens,
                )
                return resp.choices[0].message.content or ""
            raise

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

    def _audit(self, question: str, sql: str, success: int, row_count: int,
               hallucination: str | None, autocorrected: int, latency_s: float) -> None:
        try:
            self.conn.execute(
                "INSERT INTO audit_log "
                "(case_name, question, sql_generated, success, row_count, hallucination, autocorrected, latency_s) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (self.case_name, question, sql, success, row_count,
                 hallucination, autocorrected, latency_s)
            )
            self.conn.commit()
        except Exception:
            pass

    def close(self):
        self.conn.close()
        self._store.close()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _enforce_limit(sql: str, default: int = 500) -> str:
    """Añade LIMIT si el SQL no tiene uno — evita devolver millones de filas."""
    if sql and not re.search(r'\bLIMIT\b', sql, re.IGNORECASE):
        return sql + f'\nLIMIT {default}'
    return sql


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
