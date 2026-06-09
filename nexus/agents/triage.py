"""
TriageAgent — primer vistazo rápido a un caso forense.

Patrón DFIR-Chain (IEEE 2025):
  1. SQL determinista  → stats del caso
  2. MITRE ATT&CK     → tool_threat_hunt (sin LLM)
  3. qwen2.5:3b       → clasifica severidad + escribe resumen
  4. Guarda JSON      → ~/.nexus/cases/<name>/triage_<ts>.json

No usa ReAct — el LLM solo clasifica, no decide qué buscar.
Las decisiones las toma el SQL.
"""

import json
import re
import sqlite3
import time
from datetime import datetime
from pathlib import Path

import httpx
from openai import OpenAI

BOLD    = "\033[1m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
DIM     = "\033[2m"
RESET   = "\033[0m"

TRIAGE_MODEL = "qwen2.5:3b-instruct"
OLLAMA_URL   = "http://localhost:11434"
TIMEOUT      = httpx.Timeout(connect=10.0, read=180.0, write=10.0, pool=5.0)

SEV_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     YELLOW + BOLD,
    "MEDIUM":   CYAN,
    "LOW":      DIM,
}

PHASE_LABEL = {
    "initial_access":      "Acceso Inicial",
    "execution":           "Ejecución",
    "persistence":         "Persistencia",
    "privilege_escalation":"Escalación de Privilegios",
    "defense_evasion":     "Evasión de Defensa",
    "credential_access":   "Acceso a Credenciales",
    "lateral_movement":    "Movimiento Lateral",
    "collection":          "Recolección",
    "exfiltration":        "Exfiltración",
    "impact":              "Impacto",
    "unknown":             "Desconocida",
}


# ── Fase 1: recolección determinista ─────────────────────────────────────────

def _collect_stats(conn: sqlite3.Connection) -> dict:
    """SQL puro — cero LLM. Base de verdad para el clasificador."""
    from nexus.stats import collect_basic_stats
    s = collect_basic_stats(conn)

    def q(sql, params=()):
        try:
            return conn.execute(sql, params).fetchall()
        except Exception:
            return []

    def q1(sql, params=()):
        rows = q(sql, params)
        return rows[0][0] if rows else 0

    # Top event IDs
    rows = q("SELECT event_id, COUNT(*) n FROM events GROUP BY event_id ORDER BY n DESC LIMIT 8")
    s["top_event_ids"] = [{"event_id": r[0], "count": r[1]} for r in rows]

    # Señales de brute force (4625, 4771, 4776, 18456)
    bf_rows = q(
        "SELECT source_ip, COUNT(*) n FROM events "
        "WHERE event_id IN (4625,4771,4776,18456) AND source_ip IS NOT NULL AND source_ip != '' "
        "GROUP BY source_ip ORDER BY n DESC LIMIT 5"
    )
    s["brute_force_ips"] = [{"ip": r[0], "count": r[1]} for r in bf_rows]
    s["brute_force_total"] = q1(
        "SELECT COUNT(*) FROM events WHERE event_id IN (4625,4771,4776,18456)"
    )

    # Logons exitosos desde IPs externas
    ext_logon = q(
        "SELECT username, source_ip, COUNT(*) n FROM events "
        "WHERE event_id IN (4624, 21) "
        "AND source_ip IS NOT NULL AND source_ip != '' "
        "AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' "
        "AND source_ip NOT LIKE '127.%' AND source_ip NOT LIKE '172.1%' "
        "GROUP BY username, source_ip ORDER BY n DESC LIMIT 5"
    )
    s["external_logons"] = [{"user": r[0], "ip": r[1], "count": r[2]} for r in ext_logon]

    # Log clearing (evasión)
    s["log_clearing"] = q1("SELECT COUNT(*) FROM events WHERE event_id IN (1102, 104)")

    # Privilegios especiales asignados
    s["priv_assigned"] = q1("SELECT COUNT(*) FROM events WHERE event_id = 4672")

    # Procesos sospechosos (Temp/AppData)
    s["suspicious_procs"] = q1(
        "SELECT COUNT(*) FROM processes "
        "WHERE exe_path LIKE '%\\Temp\\%' OR exe_path LIKE '%\\AppData\\%' "
        "OR exe_path LIKE '%\\Users\\Public\\%'"
    )

    # Conexiones externas establecidas
    ext_conn = q(
        "SELECT remote_address, remote_port, process_name FROM network_connections "
        "WHERE state='ESTABLISHED' "
        "AND remote_address IS NOT NULL AND remote_address != '' "
        "AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' "
        "AND remote_address NOT LIKE '127.%' LIMIT 5"
    )
    s["external_connections"] = [{"ip": r[0], "port": r[1], "process": r[2]} for r in ext_conn]

    # Credenciales (mimikatz patterns, LSASS, 4776)
    s["credential_signals"] = q1(
        "SELECT COUNT(*) FROM processes "
        "WHERE LOWER(name) IN ('mimikatz.exe','procdump.exe','wce.exe') "
        "OR command_line LIKE '%sekurlsa%' OR command_line LIKE '%lsadump%'"
    )
    s["lsass_access"] = q1(
        "SELECT COUNT(*) FROM events WHERE event_id = 10 AND description LIKE '%lsass%'"
    )

    # Tareas programadas sospechosas
    s["suspicious_tasks"] = q1(
        "SELECT COUNT(*) FROM scheduled_tasks "
        "WHERE command LIKE '%Temp%' OR command LIKE '%AppData%' "
        "OR command LIKE '%-Enc%' OR command LIKE '%DownloadString%'"
    )

    # Run keys de registro
    s["run_keys"] = q1(
        "SELECT COUNT(*) FROM registry_keys "
        "WHERE key_path LIKE '%\\Run%' OR key_path LIKE '%\\RunOnce%'"
    )

    # Usuarios únicos (excluyendo cuentas de sistema)
    user_rows = q(
        "SELECT DISTINCT username FROM events "
        "WHERE username IS NOT NULL AND username != '' "
        "AND username NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON') "
        "AND username NOT LIKE '%$' AND username NOT LIKE 'NT AUTHORITY%' "
        "LIMIT 10"
    )
    s["human_users"] = [r[0] for r in user_rows]

    return s


# ── Fase 2: MITRE ATT&CK ─────────────────────────────────────────────────────

def _run_mitre(conn: sqlite3.Connection) -> list[dict]:
    from nexus.router import tool_threat_hunt
    from nexus.finding_validator import enrich_hits
    hits = tool_threat_hunt(conn)
    if hits:
        hits = enrich_hits(hits)
    return hits


# ── Fase 3: clasificación LLM ────────────────────────────────────────────────

def _build_triage_prompt(stats: dict, mitre_hits: list[dict]) -> str:
    lines = ["FORENSIC CASE STATISTICS:"]
    lines.append(f"  Events: {stats['total_events']:,} | Unique EIDs: {stats['unique_event_ids']} | Users: {stats['unique_users']} | IPs: {stats['unique_ips']} | Machines: {stats['unique_machines']}")
    lines.append(f"  Processes: {stats['processes']} | Network connections: {stats['net_connections']} | Scheduled tasks: {stats['sched_tasks']} | Registry keys: {stats['registry_keys']}")

    if stats["first_event"]:
        lines.append(f"  Time range: {stats['first_event'][:19]} → {stats['last_event'][:19]} ({stats['dwell_days']} days)")

    if stats["brute_force_total"] > 0:
        lines.append(f"  Brute force signals: {stats['brute_force_total']} failed auth events")
        for bf in stats["brute_force_ips"][:3]:
            lines.append(f"    • {bf['ip']}: {bf['count']} attempts")

    if stats["external_logons"]:
        lines.append("  External logons (successful):")
        for el in stats["external_logons"][:3]:
            lines.append(f"    • {el['user']} from {el['ip']} ({el['count']}x)")

    if stats["log_clearing"] > 0:
        lines.append(f"  Log clearing events: {stats['log_clearing']} (Defense Evasion indicator)")

    if stats["priv_assigned"] > 0:
        lines.append(f"  Special privileges assigned: {stats['priv_assigned']} events")

    if stats["suspicious_procs"] > 0:
        lines.append(f"  Processes from suspicious paths (Temp/AppData): {stats['suspicious_procs']}")

    if stats["credential_signals"] > 0:
        lines.append(f"  Credential dumping tools detected: {stats['credential_signals']}")

    if stats["lsass_access"] > 0:
        lines.append(f"  LSASS access events: {stats['lsass_access']}")

    if stats["external_connections"]:
        lines.append("  Established external connections:")
        for ec in stats["external_connections"][:3]:
            lines.append(f"    • {ec['ip']}:{ec['port']} ({ec['process'] or 'unknown'})")

    if stats["suspicious_tasks"] > 0:
        lines.append(f"  Suspicious scheduled tasks: {stats['suspicious_tasks']}")

    if stats["run_keys"] > 0:
        lines.append(f"  Registry Run keys: {stats['run_keys']}")

    if mitre_hits:
        lines.append(f"\nMITRE ATT&CK RULES TRIGGERED ({len(mitre_hits)}):")
        for h in mitre_hits:
            v = h.get("validation")
            conf = f" confidence:{v.confidence:.0%}" if v else ""
            lines.append(f"  [{h['severity']}] {h['rule_id']} — {h['name']}: {h['count']} hits{conf}")
    else:
        lines.append("\nMITRE ATT&CK: No rules triggered.")

    return "\n".join(lines)


TRIAGE_SYSTEM = """\
You are a DFIR triage analyst. Given forensic case statistics, output ONLY valid JSON.

Required JSON fields:
{
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "confidence": 0.0-1.0,
  "attack_phase": "initial_access" | "execution" | "persistence" | "privilege_escalation" | "defense_evasion" | "credential_access" | "lateral_movement" | "collection" | "exfiltration" | "impact" | "unknown",
  "top_indicators": ["string", "string", "string"],
  "recommendation": "one actionable sentence in Spanish",
  "needs_eil": true | false
}

Rules:
- severity CRITICAL if: ransomware/encryption signals, active C2, credential dumping tools found
- severity HIGH if: external logons successful, log clearing, brute force success, LSASS access
- severity MEDIUM if: brute force attempts only (no success), suspicious processes, run keys
- severity LOW if: only administrative activity, no attack signals
- needs_eil: true if severity is HIGH or CRITICAL
- top_indicators: the 3 most alarming findings, specific (include counts and IPs when available)
- Output ONLY the JSON object, no explanation, no markdown fences
"""


def _classify(prompt: str, model: str) -> dict:
    client = OpenAI(
        base_url=f"{OLLAMA_URL}/v1",
        api_key="ollama",
        timeout=TIMEOUT,
        max_retries=0,
    )
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": TRIAGE_SYSTEM},
            {"role": "user",   "content": prompt},
        ],
        temperature=0.0,
        max_tokens=300,
    )
    raw = resp.choices[0].message.content or "{}"
    # Limpiar markdown fences si el modelo las pone igual
    raw = re.sub(r"```json\s*|\s*```", "", raw).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Intentar extraer JSON con regex
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
        return {
            "severity": "UNKNOWN",
            "confidence": 0.0,
            "attack_phase": "unknown",
            "top_indicators": [raw[:200]],
            "recommendation": "Revisar manualmente — clasificación automática falló.",
            "needs_eil": True,
        }


# ── Display ───────────────────────────────────────────────────────────────────

def _display(case_name: str, stats: dict, mitre_hits: list, result: dict, elapsed: float):
    sev = result.get("severity", "UNKNOWN")
    sc  = SEV_COLOR.get(sev, BOLD)
    phase = PHASE_LABEL.get(result.get("attack_phase", "unknown"), result.get("attack_phase", "?"))
    conf = result.get("confidence", 0.0)

    print(f"\n{BOLD}{CYAN}{'═'*64}{RESET}")
    print(f"{BOLD}{CYAN}  NEXUS TRIAGE — {case_name}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*64}{RESET}")
    print()
    print(f"  Severidad  : {sc}{sev}{RESET}")
    print(f"  Confianza  : {conf:.0%}")
    print(f"  Fase ATT&CK: {phase}")
    print()

    indicators = result.get("top_indicators", [])
    if indicators:
        print(f"  {BOLD}Indicadores principales:{RESET}")
        for ind in indicators:
            print(f"    • {ind}")
        print()

    print(f"  {BOLD}Recomendación:{RESET}")
    print(f"    {result.get('recommendation','')}")
    print()

    # Stats rápidos
    print(f"  {DIM}Eventos: {stats['total_events']:,}  |  "
          f"Usuarios: {stats['unique_users']}  |  "
          f"IPs: {stats['unique_ips']}  |  "
          f"Máquinas: {stats['unique_machines']}{RESET}")

    mitre_count = len(mitre_hits)
    if mitre_count > 0:
        rule_ids = ", ".join(h["rule_id"] for h in mitre_hits)
        print(f"  {DIM}MITRE: {mitre_count} reglas → {rule_ids}{RESET}")
    else:
        print(f"  {DIM}MITRE: Sin reglas disparadas{RESET}")

    print(f"  {DIM}Tiempo de triage: {elapsed:.1f}s{RESET}")

    if result.get("needs_eil"):
        print()
        print(f"  {YELLOW}→ Investigación recomendada:{RESET}")
        print(f"  {YELLOW}  nexus investigate {case_name} \"¿Qué pasó en este incidente?\"{RESET}")

    print(f"\n{BOLD}{CYAN}{'═'*64}{RESET}\n")


# ── Punto de entrada ──────────────────────────────────────────────────────────

def triage(
    case_name: str,
    db_path: str,
    case_dir: str,
    model: str = TRIAGE_MODEL,
    verbose: bool = True,
) -> dict:
    """
    Ejecuta triage sobre un caso Nexus.
    Devuelve el dict de resultados y lo guarda en case_dir/triage_<ts>.json
    """
    t0 = time.time()
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    if verbose:
        print(f"\n  {DIM}[TRIAGE] Recopilando estadísticas...{RESET}", flush=True)

    stats = _collect_stats(conn)

    if verbose:
        print(f"  {DIM}[TRIAGE] Ejecutando reglas MITRE ATT&CK...{RESET}", flush=True)

    mitre_hits = _run_mitre(conn)
    conn.close()

    prompt = _build_triage_prompt(stats, mitre_hits)

    if verbose:
        print(f"  {DIM}[TRIAGE] Clasificando con {model}...{RESET}", flush=True)

    result = _classify(prompt, model)
    elapsed = time.time() - t0

    # Enriquecer con metadata
    result["case_name"]   = case_name
    result["model"]       = model
    result["elapsed_s"]   = round(elapsed, 1)
    result["timestamp"]   = datetime.now().isoformat()
    result["stats"]       = stats
    result["mitre_rules"] = [
        {"rule_id": h["rule_id"], "severity": h["severity"], "name": h["name"], "count": h["count"]}
        for h in mitre_hits
    ]

    # Guardar JSON
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(case_dir) / f"triage_{ts_str}.json"
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False, default=str))

    if verbose:
        _display(case_name, stats, mitre_hits, result, elapsed)
        print(f"  {DIM}Reporte guardado: {out_path}{RESET}\n")

    return result
