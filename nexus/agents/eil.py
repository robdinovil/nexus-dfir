"""
EIL — Evidence Interrogation Loop

ReAct agent que investiga un caso DFIR de forma autónoma.
Ciclo: THINK → ACT (tool) → OBSERVE → repeat → CONCLUSION
"""

import re
import sqlite3
import time

import httpx
from openai import OpenAI

BOLD    = "\033[1m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
DIM     = "\033[2m"
RESET   = "\033[0m"

MAX_STEPS    = 8
MAX_ROWS_OBS = 10
CTX_WINDOW   = 6   # últimos N turnos assistant+user que se mandan al LLM
OLLAMA_URL   = "http://localhost:11434"
TIMEOUT      = httpx.Timeout(connect=10.0, read=600.0, write=10.0, pool=5.0)

SYSTEM_PROMPT = """\
You are a DFIR analyst. Investigate a Windows forensic case using these tools:

  threat_hunt()              — MITRE ATT&CK detection (always start here)
  pivot_user("username")     — All events for a user (use real usernames from CASE DATA)
  pivot_ip("ip")             — All events for an IP (use real IPs from CASE DATA)
  pivot_process("name")      — All events for a process
  sql_query("NL question")   — Query the forensic database in natural language
  done("narrative")          — Finish: 4-5 sentence incident summary in Spanish

Rules:
- ONLY use usernames and IPs listed in CASE DATA. Never invent values.
- One THOUGHT + one ACTION per turn. No explanations outside this format.
- Call done() as soon as you can describe: initial access + what attacker did.
- NEVER query by specific date or time unless the CASE DATA shows timestamps.
- If a sql_query returns an ERROR, do NOT repeat the same query — try a different tool.
- If you have already called the same tool twice with no new findings, call done().

Output format (strict, no deviation):
THOUGHT: <one sentence reasoning>
ACTION: tool_name("argument")
"""


def _llm_call(model: str, messages: list[dict], max_tokens: int = 256) -> str:
    client = OpenAI(
        base_url=f"{OLLAMA_URL}/v1",
        api_key="ollama",
        timeout=TIMEOUT,
        max_retries=0,
    )
    resp = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0.0,
        max_tokens=max_tokens,
    )
    return resp.choices[0].message.content or ""


def _parse_action(text: str) -> tuple[str, str] | None:
    m = re.search(r'ACTION:\s*(\w+)\((["\']?)(.*?)\2\s*\)', text, re.DOTALL)
    if not m:
        m2 = re.search(r'ACTION:\s*(\w+)\(\)', text)
        if m2:
            return m2.group(1), ""
        return None
    return m.group(1), m.group(3).strip()


def _parse_thought(text: str) -> str:
    m = re.search(r'THOUGHT:\s*(.+?)(?=\nACTION:|$)', text, re.DOTALL)
    return m.group(1).strip() if m else ""


# ── Tools ─────────────────────────────────────────────────────────────────────

def _fmt_rows(rows: list, cols: list[str], limit: int = MAX_ROWS_OBS) -> str:
    header = " | ".join(cols)
    sep    = "-" * min(len(header), 72)
    lines  = [header, sep]
    for row in rows[:limit]:
        lines.append(" | ".join(str(row[c] or "")[:35] for c in cols))
    if len(rows) > limit:
        lines.append(f"... ({len(rows) - limit} more rows)")
    return "\n".join(lines)


def _tool_sql_query(analyst, question: str) -> str:
    result = analyst.ask(question, verbose=False)
    if result.get("error"):
        return f"ERROR: {result['error']}"
    df = result.get("result")
    if df is None or len(df) == 0:
        return "No rows returned."
    rows = min(len(df), MAX_ROWS_OBS)
    return f"{len(df)} rows (showing {rows}):\n" + df.head(rows).to_string(index=False)


def _tool_pivot_user(conn: sqlite3.Connection, username: str) -> str:
    parts = []
    try:
        cur = conn.execute(
            "SELECT event_id, timestamp_utc, username, source_ip, computer, channel "
            "FROM events WHERE LOWER(username) = LOWER(?) LIMIT ?",
            (username, MAX_ROWS_OBS)
        )
        rows = cur.fetchall()
        if rows:
            cols = [d[0] for d in cur.description]
            parts.append(f"[events] {len(rows)} rows:\n" + _fmt_rows(rows, cols))
    except Exception:
        pass
    try:
        cur = conn.execute(
            "SELECT pid, name, exe_path, username, command_line "
            "FROM processes WHERE LOWER(username) = LOWER(?) LIMIT ?",
            (username, MAX_ROWS_OBS)
        )
        rows = cur.fetchall()
        if rows:
            cols = [d[0] for d in cur.description]
            parts.append(f"[processes] {len(rows)} rows:\n" + _fmt_rows(rows, cols))
    except Exception:
        pass
    return "\n\n".join(parts) if parts else f"No activity found for user '{username}'."


def _tool_pivot_ip(conn: sqlite3.Connection, ip: str) -> str:
    parts = []
    try:
        cur = conn.execute(
            "SELECT event_id, timestamp_utc, username, source_ip, computer "
            "FROM events WHERE source_ip = ? LIMIT ?",
            (ip, MAX_ROWS_OBS)
        )
        rows = cur.fetchall()
        if rows:
            cols = [d[0] for d in cur.description]
            parts.append(f"[events] {len(rows)} rows:\n" + _fmt_rows(rows, cols))
    except Exception:
        pass
    try:
        cur = conn.execute(
            "SELECT protocol, remote_address, remote_port, state, process_name "
            "FROM network_connections WHERE remote_address = ? LIMIT ?",
            (ip, MAX_ROWS_OBS)
        )
        rows = cur.fetchall()
        if rows:
            cols = [d[0] for d in cur.description]
            parts.append(f"[network_connections] {len(rows)} rows:\n" + _fmt_rows(rows, cols))
    except Exception:
        pass
    return "\n\n".join(parts) if parts else f"No activity found for IP '{ip}'."


def _tool_pivot_process(conn: sqlite3.Connection, name: str) -> str:
    parts = []
    try:
        cur = conn.execute(
            "SELECT pid, name, exe_path, username, command_line "
            "FROM processes WHERE LOWER(name) LIKE LOWER(?) LIMIT ?",
            (f"%{name}%", MAX_ROWS_OBS)
        )
        rows = cur.fetchall()
        if rows:
            cols = [d[0] for d in cur.description]
            parts.append(f"[processes] {len(rows)} rows:\n" + _fmt_rows(rows, cols))
    except Exception:
        pass
    try:
        cur = conn.execute(
            "SELECT protocol, remote_address, remote_port, state, process_name "
            "FROM network_connections WHERE LOWER(process_name) LIKE LOWER(?) LIMIT ?",
            (f"%{name}%", MAX_ROWS_OBS)
        )
        rows = cur.fetchall()
        if rows:
            cols = [d[0] for d in cur.description]
            parts.append(f"[network_connections] {len(rows)} rows:\n" + _fmt_rows(rows, cols))
    except Exception:
        pass
    return "\n\n".join(parts) if parts else f"No activity found for process '{name}'."


def _tool_threat_hunt(conn: sqlite3.Connection) -> str:
    from nexus.router import tool_threat_hunt
    hits = tool_threat_hunt(conn)
    if not hits:
        return "No MITRE ATT&CK rules triggered."
    return "\n".join(
        f"[{h['severity']}] {h['rule_id']} — {h['name']}: {h['count']} hits"
        for h in hits
    )


def _tool_get_timeline(conn: sqlite3.Connection) -> str:
    try:
        cur = conn.execute(
            "SELECT timestamp_utc, event_id, username, source_ip, computer "
            "FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != '' "
            "ORDER BY timestamp_utc ASC LIMIT 20"
        )
        rows = cur.fetchall()
        if not rows:
            return "No timestamped events found."
        cols = [d[0] for d in cur.description]
        return f"First {len(rows)} events:\n" + _fmt_rows(rows, cols)
    except Exception as e:
        return f"ERROR: {e}"


# ── Case context ───────────────────────────────────────────────────────────────

def _get_case_context(conn: sqlite3.Connection) -> str:
    lines = ["CASE DATA (use ONLY these real values in pivot tools):"]
    try:
        rows = conn.execute(
            "SELECT username, COUNT(*) n FROM events "
            "WHERE username IS NOT NULL AND username != '' "
            "GROUP BY username ORDER BY n DESC LIMIT 8"
        ).fetchall()
        if rows:
            lines.append("Users: " + ", ".join(f"{r[0]}" for r in rows))
    except Exception:
        pass
    try:
        rows = conn.execute(
            "SELECT source_ip, COUNT(*) n FROM events "
            "WHERE source_ip IS NOT NULL AND source_ip != '' "
            "GROUP BY source_ip ORDER BY n DESC LIMIT 6"
        ).fetchall()
        if rows:
            lines.append("Source IPs: " + ", ".join(f"{r[0]}" for r in rows))
    except Exception:
        pass
    try:
        rows = conn.execute(
            "SELECT event_id, COUNT(*) n FROM events "
            "GROUP BY event_id ORDER BY n DESC LIMIT 10"
        ).fetchall()
        if rows:
            lines.append("Event IDs: " + ", ".join(str(r[0]) for r in rows))
    except Exception:
        pass
    try:
        rows = conn.execute(
            "SELECT remote_address, state, process_name FROM network_connections "
            "WHERE state='ESTABLISHED' LIMIT 3"
        ).fetchall()
        if rows:
            lines.append("Established connections: " + "; ".join(
                f"{r[0]}({r[2] or '?'})" for r in rows))
    except Exception:
        pass
    return "\n".join(lines)


# ── Dispatcher ────────────────────────────────────────────────────────────────

def _dispatch(tool: str, arg: str, analyst, conn: sqlite3.Connection) -> str:
    if tool == "sql_query":
        return _tool_sql_query(analyst, arg)
    elif tool == "pivot_user":
        return _tool_pivot_user(conn, arg)
    elif tool == "pivot_ip":
        return _tool_pivot_ip(conn, arg)
    elif tool == "pivot_process":
        return _tool_pivot_process(conn, arg)
    elif tool == "threat_hunt":
        return _tool_threat_hunt(conn)
    elif tool == "get_timeline":
        return _tool_get_timeline(conn)
    elif tool == "done":
        return arg
    else:
        return f"Unknown tool: {tool}"


# ── Main loop ─────────────────────────────────────────────────────────────────

def investigate(
    case_name: str,
    db_path: str,
    store_path: str,
    goal: str = "Determine what happened in this incident.",
    model: str = "qwen2.5:7b-instruct",
    max_steps: int = MAX_STEPS,
    verbose: bool = True,
) -> str:
    from nexus.analyst import NexusAnalyst

    analyst = NexusAnalyst(db_path, model=model, store_path=store_path)
    conn    = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    def _print(msg: str):
        if verbose:
            print(msg, flush=True)

    _print(f"\n{BOLD}{CYAN}{'═'*66}{RESET}")
    _print(f"{BOLD}{CYAN}  EIL — Evidence Interrogation Loop{RESET}")
    _print(f"{BOLD}{CYAN}  Caso : {case_name}{RESET}")
    _print(f"{BOLD}{CYAN}  Meta : {goal}{RESET}")
    _print(f"{BOLD}{CYAN}{'═'*66}{RESET}\n")

    # System prompt incluye el case context para no inflar el user message
    case_context = _get_case_context(conn)
    system = SYSTEM_PROMPT + f"\n{case_context}"

    messages: list[dict] = [
        {"role": "system", "content": system},
        {"role": "user",   "content": f"Case: {case_name}\nGoal: {goal}\n\nBegin."},
    ]

    conclusion  = None
    tools_used  = []   # para detectar loops

    for step in range(1, max_steps + 1):
        _print(f"{BOLD}{YELLOW}  Step {step}/{max_steps}{RESET}")

        # Último step: forzar done()
        if step == max_steps:
            messages.append({
                "role": "user",
                "content": (
                    "This is your LAST step. You MUST call done() now with a summary "
                    "of everything you found. Do not call any other tool."
                )
            })

        # Sliding window: system + first user + últimos CTX_WINDOW turnos
        ctx = [messages[0], messages[1]] + messages[2:][-CTX_WINDOW * 2:]

        try:
            raw = _llm_call(model, ctx, max_tokens=256)
        except Exception as e:
            _print(f"  {RED}[EIL] LLM timeout — reintentando con contexto reducido...{RESET}")
            # retry con contexto mínimo
            try:
                ctx_min = [messages[0], messages[-1]]
                raw = _llm_call(model, ctx_min, max_tokens=256)
            except Exception as e2:
                _print(f"  {RED}[EIL] LLM error: {e2} — abortando.{RESET}")
                break

        messages.append({"role": "assistant", "content": raw})

        thought = _parse_thought(raw)
        parsed  = _parse_action(raw)

        if thought:
            _print(f"  {DIM}THINK:{RESET} {thought}")

        if not parsed:
            _print(f"  {RED}[EIL] No ACTION encontrado — saltando step.{RESET}")
            messages.append({"role": "user", "content": "Please respond with THOUGHT and ACTION."})
            continue

        tool, arg = parsed
        _print(f"  {CYAN}ACT  :{RESET} {tool}({repr(arg) if arg else ''})")

        # Detectar loop: misma tool+arg dos veces seguidas
        tool_sig = f"{tool}:{arg}"
        if tools_used[-2:].count(tool_sig) >= 2:
            _print(f"  {YELLOW}[EIL] Loop detectado en {tool} — redirigiendo a sql_query.{RESET}")
            tool, arg = "sql_query", "¿Cuáles son los hallazgos más importantes de este caso?"
        tools_used.append(tool_sig)

        t0 = time.time()
        observation = _dispatch(tool, arg, analyst, conn)
        elapsed = time.time() - t0

        if tool == "done":
            conclusion = observation
            _print(f"\n{BOLD}{GREEN}{'─'*66}{RESET}")
            _print(f"{BOLD}{GREEN}  CONCLUSIÓN:{RESET}")
            for line in conclusion.splitlines():
                _print(f"  {line}")
            _print(f"{BOLD}{GREEN}{'─'*66}{RESET}\n")
            break

        # Mostrar observación (primeras 8 líneas)
        _print(f"  {DIM}OBS  ({elapsed:.1f}s):{RESET}")
        obs_lines = observation.splitlines()
        for line in obs_lines[:8]:
            _print(f"    {line}")
        if len(obs_lines) > 8:
            _print(f"    {DIM}... ({len(obs_lines) - 8} more lines){RESET}")
        _print("")

        messages.append({
            "role": "user",
            "content": f"OBSERVATION:\n{observation}\n\nContinue."
        })

    if not conclusion:
        _print(f"  {YELLOW}[EIL] Sin conclusión tras {max_steps} steps.{RESET}")
        conclusion = "Investigation incomplete."

    conn.close()
    return conclusion
