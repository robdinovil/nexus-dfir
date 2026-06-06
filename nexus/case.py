"""Case management — casos viven en ~/.nexus/cases/<name>/"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

NEXUS_HOME = Path.home() / ".nexus"
CASES_DIR  = NEXUS_HOME / "cases"

BOLD  = "\033[1m"
DIM   = "\033[2m"
CYAN  = "\033[96m"
GREEN = "\033[92m"
YELLOW= "\033[93m"
RED   = "\033[91m"
RESET = "\033[0m"


class NexusCase:
    def __init__(self, name: str, path: Path, db_path: str, store_path: str):
        self.name       = name
        self.path       = path
        self.db_path    = db_path
        self.store_path = store_path

    # ── Constructores ──────────────────────────────────────────────────────────

    @classmethod
    def create(cls, name: str) -> "NexusCase":
        case = cls._from_name(name)
        if case.path.exists():
            raise FileExistsError(f"El caso '{name}' ya existe en {case.path}")
        case.path.mkdir(parents=True)
        _write_meta(case.path, name)
        return case

    @classmethod
    def open(cls, name: str) -> "NexusCase":
        case = cls._from_name(name)
        if not case.path.exists():
            raise FileNotFoundError(
                f"Caso '{name}' no encontrado.\n"
                f"  Crea uno con: nexus new {name}\n"
                f"  O lista los existentes: nexus cases"
            )
        return case

    @classmethod
    def resolve(cls, name_or_path: str) -> "NexusCase":
        """
        Acepta nombre de caso o path directo a un .db.
        Compat con el flujo antiguo --db.
        """
        p = Path(name_or_path)
        if p.suffix == ".db" and p.exists():
            return cls._from_db_file(p)
        return cls.open(name_or_path)

    # ── Helpers internos ───────────────────────────────────────────────────────

    @classmethod
    def _from_name(cls, name: str) -> "NexusCase":
        path = CASES_DIR / name
        return cls(
            name       = name,
            path       = path,
            db_path    = str(path / "case.db"),
            store_path = str(path / "store.db"),
        )

    @classmethod
    def _from_db_file(cls, db: Path) -> "NexusCase":
        return cls(
            name       = db.stem,
            path       = db.parent,
            db_path    = str(db),
            store_path = str(db.parent / f"nexus_store_{db.stem}.db"),
        )

    # ── Listado ────────────────────────────────────────────────────────────────

    @staticmethod
    def list_all() -> list[dict]:
        if not CASES_DIR.exists():
            return []
        out = []
        for p in sorted(CASES_DIR.iterdir()):
            if not p.is_dir():
                continue
            meta = _read_meta(p)
            out.append({
                "name"    : p.name,
                "created" : meta.get("created", "")[:10],
                "records" : _count_records(p / "case.db"),
                "has_db"  : (p / "case.db").exists(),
            })
        return out


def print_cases(cases: list[dict]) -> None:
    if not cases:
        print(f"\n  {YELLOW}Sin casos. Crea uno con: nexus new <nombre>{RESET}\n")
        return
    print(f"\n  {BOLD}{'Nombre':<28} {'Creado':<12} {'Registros':>12}{RESET}")
    print(f"  {'─'*28} {'─'*12} {'─'*12}")
    for c in cases:
        rec = f"{c['records']:>12,}" if c["has_db"] else f"{DIM}{'vacío':>12}{RESET}"
        print(f"  {GREEN}{c['name']:<28}{RESET} {c['created']:<12} {rec}")
    print()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _write_meta(path: Path, name: str) -> None:
    (path / "meta.json").write_text(
        json.dumps({"name": name, "created": datetime.now().isoformat()}, indent=2)
    )


def _read_meta(path: Path) -> dict:
    meta_file = path / "meta.json"
    if not meta_file.exists():
        return {}
    try:
        return json.loads(meta_file.read_text())
    except Exception:
        return {}


def _count_records(db_file: Path) -> int:
    if not db_file.exists():
        return 0
    total = 0
    try:
        conn = sqlite3.connect(str(db_file))
        for t in ("events", "processes", "network_connections", "scheduled_tasks", "registry_keys"):
            try:
                total += conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            except Exception:
                pass
        conn.close()
    except Exception:
        pass
    return total
