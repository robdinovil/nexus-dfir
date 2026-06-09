"""
Cross-case IOC search — busca un indicador en todos los casos de Nexus.

Soporta: IP, hash (MD5/SHA1/SHA256), username, hostname.
Resultado: lista de hits por caso, sin LLM.
"""

import re
import sqlite3
from pathlib import Path

from .case import CASES_DIR

BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"
RESET  = "\033[0m"

_RE_IP   = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$')
_RE_HASH = re.compile(r'^[0-9a-f]{32,64}$', re.IGNORECASE)
_RE_CIDR = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')


def _indicator_type(indicator: str) -> str:
    if _RE_HASH.match(indicator):
        return "hash"
    if _RE_IP.match(indicator):
        return "ip"
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', indicator):
        return "hostname"
    return "text"  # username, process name, etc.


def _search_db(db_path: str, indicator: str, ioc_type: str) -> list[dict]:
    """Busca el indicador en todas las tablas relevantes de un caso."""
    hits = []
    try:
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
    except Exception:
        return hits

    def q(sql, params=()):
        try:
            return conn.execute(sql, params).fetchall()
        except Exception:
            return []

    if ioc_type == "ip":
        # events.source_ip
        rows = q(
            "SELECT COUNT(*) n, MIN(timestamp_utc) first_seen, MAX(timestamp_utc) last_seen "
            "FROM events WHERE source_ip = ?", (indicator,)
        )
        if rows and rows[0]["n"]:
            hits.append({"table": "events.source_ip", "count": rows[0]["n"],
                         "first": (rows[0]["first_seen"] or "")[:19],
                         "last":  (rows[0]["last_seen"]  or "")[:19]})

        # network_connections.remote_address
        rows = q(
            "SELECT COUNT(*) n FROM network_connections WHERE remote_address = ?", (indicator,)
        )
        if rows and rows[0]["n"]:
            hits.append({"table": "network_connections.remote_address", "count": rows[0]["n"],
                         "first": "", "last": ""})

        # events.description LIKE (Sysmon DestinationIp)
        rows = q(
            "SELECT COUNT(*) n FROM events WHERE description LIKE ?", (f"%{indicator}%",)
        )
        if rows and rows[0]["n"]:
            hits.append({"table": "events.description", "count": rows[0]["n"],
                         "first": "", "last": ""})

    elif ioc_type == "hash":
        # evidence_files.sha256
        rows = q("SELECT COUNT(*) n FROM evidence_files WHERE sha256 = ?", (indicator,))
        if rows and rows[0]["n"]:
            hits.append({"table": "evidence_files.sha256", "count": rows[0]["n"],
                         "first": "", "last": ""})
        # description (hashes pueden aparecer en EventData)
        rows = q("SELECT COUNT(*) n FROM events WHERE description LIKE ?", (f"%{indicator}%",))
        if rows and rows[0]["n"]:
            hits.append({"table": "events.description", "count": rows[0]["n"],
                         "first": "", "last": ""})

    else:  # text: username, hostname, process name
        rows = q(
            "SELECT COUNT(*) n, MIN(timestamp_utc) first_seen, MAX(timestamp_utc) last_seen "
            "FROM events WHERE username LIKE ?", (f"%{indicator}%",)
        )
        if rows and rows[0]["n"]:
            hits.append({"table": "events.username", "count": rows[0]["n"],
                         "first": (rows[0]["first_seen"] or "")[:19],
                         "last":  (rows[0]["last_seen"]  or "")[:19]})

        rows = q(
            "SELECT COUNT(*) n FROM events WHERE computer LIKE ?", (f"%{indicator}%",)
        )
        if rows and rows[0]["n"]:
            hits.append({"table": "events.computer", "count": rows[0]["n"],
                         "first": "", "last": ""})

        rows = q(
            "SELECT COUNT(*) n FROM processes WHERE name LIKE ? OR command_line LIKE ?",
            (f"%{indicator}%", f"%{indicator}%")
        )
        if rows and rows[0]["n"]:
            hits.append({"table": "processes", "count": rows[0]["n"],
                         "first": "", "last": ""})

    conn.close()
    return hits


def search_ioc(indicator: str, cases_dir: Path = CASES_DIR) -> list[dict]:
    """
    Busca un indicador en todos los casos disponibles.
    Retorna lista de {case, hits, total} ordenada por total desc.
    """
    if not cases_dir.exists():
        return []

    ioc_type = _indicator_type(indicator)
    results = []

    for case_dir in sorted(cases_dir.iterdir()):
        if not case_dir.is_dir():
            continue
        db_path = case_dir / "case.db"
        if not db_path.exists():
            continue

        hits = _search_db(str(db_path), indicator, ioc_type)
        if hits:
            results.append({
                "case":  case_dir.name,
                "hits":  hits,
                "total": sum(h["count"] for h in hits),
            })

    return sorted(results, key=lambda x: x["total"], reverse=True)


def print_search_results(indicator: str, results: list[dict]) -> None:
    ioc_type = _indicator_type(indicator)
    print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  Cross-Case IOC Search{RESET}")
    print(f"{BOLD}{CYAN}  Indicador : {indicator} [{ioc_type}]{RESET}")
    print(f"{BOLD}{CYAN}  Casos con hits: {len(results)}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}\n")

    if not results:
        print(f"  {YELLOW}Sin resultados en ningún caso.{RESET}\n")
        return

    for r in results:
        print(f"  {GREEN}{BOLD}{r['case']}{RESET}  ({r['total']} hits total)")
        for h in r["hits"]:
            span = f"  {h['first']} → {h['last']}" if h.get("first") else ""
            print(f"    {DIM}├{RESET} {h['table']:<35} {BOLD}{h['count']:>5}{RESET}{span}")
        print()
