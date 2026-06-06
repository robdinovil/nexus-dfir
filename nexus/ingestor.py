"""
Ingestor — orquesta detección → parser → SQLite.
Punto de entrada para cargar evidencia a Nexus.
"""

import sqlite3
import time
from pathlib import Path

from .detector import detect, detect_directory, EvidenceFile, print_report
from .schema import SCHEMA_SQL
from .parsers import PARSER_REGISTRY

BOLD  = "\033[1m"
CYAN  = "\033[96m"
GREEN = "\033[92m"
YELLOW= "\033[93m"
RED   = "\033[91m"
RESET = "\033[0m"


class Ingestor:
    def __init__(self, db_path: str = "nexus_case.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    def ingest_file(self, filepath: str | Path) -> dict:
        """Detecta e ingesta un archivo de evidencia. Retorna resultado."""
        path = Path(filepath)
        t0 = time.time()

        ef = detect(path)
        result = {
            "file": path.name,
            "type": ef.evidence_type,
            "parser": ef.parser,
            "confidence": ef.confidence,
            "records": 0,
            "elapsed_s": 0.0,
            "error": None,
        }

        # Saltar si ya fue ingestado
        already = self.conn.execute(
            "SELECT id FROM evidence_files WHERE filepath = ?", (str(path),)
        ).fetchone()
        if already:
            print(f"  {YELLOW}~{RESET} {path.name:<35} [ya ingestado — omitiendo]")
            return result

        if ef.parser == "none":
            result["error"] = f"Sin parser para tipo '{ef.evidence_type}'"
            _print_skip(ef)
            return result

        parser_cls = PARSER_REGISTRY.get(ef.parser)
        if not parser_cls:
            result["error"] = f"Parser '{ef.parser}' no registrado"
            _print_skip(ef)
            return result

        try:
            _print_ingesting(ef)
            parser = parser_cls(self.conn)
            count = parser.parse(path, ef.encoding)
            result["records"] = count
            result["elapsed_s"] = round(time.time() - t0, 2)
            _print_done(ef, count, result["elapsed_s"])
        except Exception as e:
            result["error"] = str(e)
            print(f"  {RED}[✗]{RESET} {path.name}: {e}")

        return result

    def ingest_directory(self, dirpath: str | Path) -> list[dict]:
        """Ingesta todos los archivos detectables en un directorio."""
        files = detect_directory(dirpath)
        print_report(files)

        results = []
        for ef in files:
            results.append(self.ingest_file(ef.path))
        return results

    def summary(self) -> None:
        """Imprime resumen de lo que hay en la base de datos."""
        tables = {
            "events":               "Eventos de logs (EVTX)",
            "processes":            "Procesos",
            "network_connections":  "Conexiones de red",
            "scheduled_tasks":      "Tareas programadas",
            "registry_keys":        "Claves de registro",
            "sysinfo":              "Info del sistema",
            "evidence_files":       "Archivos ingestados",
        }
        print(f"\n{CYAN}{BOLD}{'─'*60}{RESET}")
        print(f"{CYAN}{BOLD}  Nexus — Caso: {self.db_path}{RESET}")
        print(f"{CYAN}{BOLD}{'─'*60}{RESET}")
        for table, label in tables.items():
            try:
                count = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                bar = "█" * min(count // 100, 30)
                print(f"  {label:<30} {BOLD}{count:>6,}{RESET}  {GREEN}{bar}{RESET}")
            except Exception:
                pass
        print()

    def close(self):
        self.conn.close()


def _print_ingesting(ef: EvidenceFile) -> None:
    size = f"{ef.size_kb:.0f}KB" if ef.size_kb < 1024 else f"{ef.size_kb/1024:.1f}MB"
    print(f"  {CYAN}►{RESET} {ef.filename:<35} [{ef.evidence_type}] {size}")


def _print_done(ef: EvidenceFile, count: int, elapsed: float) -> None:
    print(f"    {GREEN}✓{RESET} {count:,} registros en {elapsed}s")


def _print_skip(ef: EvidenceFile) -> None:
    print(f"  {YELLOW}~{RESET} {ef.filename:<35} [sin parser — {ef.evidence_type}]")
