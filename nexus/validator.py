"""
SQL Validator — detecta y clasifica alucinaciones antes de ejecutar.

Tres tipos (igual que el hackathon):
  Structural  — columna que no existe en el schema
  Referential — event_id que no está en la DB
  Logical     — SQL válida pero semánticamente incorrecta (no detectable aquí)
"""

import re
import sqlite3
from dataclasses import dataclass, field


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    hallucination_type: str | None = None  # structural / referential / None

    @property
    def error_summary(self) -> str:
        return "; ".join(self.errors)


def validate(sql: str, conn: sqlite3.Connection) -> ValidationResult:
    """Valida una SQL contra el schema y datos reales de la DB."""
    errors = []
    htype = None

    # 1. Parse básico — debe ser SELECT
    sql_clean = sql.strip().rstrip(";")
    if not sql_clean.upper().startswith("SELECT"):
        return ValidationResult(False, ["SQL must be a SELECT statement"], "structural")

    # 1b. Validación sintáctica via EXPLAIN QUERY PLAN
    try:
        conn.execute(f"EXPLAIN QUERY PLAN {sql_clean}")
    except sqlite3.OperationalError as e:
        return ValidationResult(False, [f"SQL syntax error: {e}"], "structural")

    # 2. Extraer tablas referenciadas
    tables_in_sql = _extract_tables(sql_clean)
    real_tables = _get_real_tables(conn)

    for t in tables_in_sql:
        if t not in real_tables:
            errors.append(f"Table '{t}' does not exist. Available: {', '.join(sorted(real_tables))}")
            htype = "structural"

    if errors:
        return ValidationResult(False, errors, htype)

    # 3. Columnas referenciadas en WHERE y SELECT vs schema real
    col_errors = _check_columns(sql_clean, conn, tables_in_sql)
    if col_errors:
        errors.extend(col_errors)
        htype = "structural"

    if errors:
        return ValidationResult(False, errors, htype)

    # 4. Event IDs referenciados vs los que existen en la DB
    eid_errors = _check_event_ids(sql_clean, conn)
    if eid_errors:
        errors.extend(eid_errors)
        htype = "referential"

    return ValidationResult(len(errors) == 0, errors, htype if errors else None)


def build_correction_hint(result: ValidationResult, conn: sqlite3.Connection) -> str:
    """Genera un hint para el retry del LLM basado en el error."""
    hints = []

    for err in result.errors:
        if "does not exist" in err and "Column" in err:
            # Extraer el nombre de la columna del error
            m = re.search(r"Column '(\w+)'", err)
            if m:
                col = m.group(1)
                # Buscar columnas similares
                similar = _find_similar_columns(col, conn)
                hint = f"Column '{col}' does not exist."
                if similar:
                    hint += f" Did you mean: {', '.join(similar)}?"
                hints.append(hint)
        elif "event_id" in err.lower():
            hints.append(err)
        else:
            hints.append(err)

    return " | ".join(hints)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_tables(sql: str) -> list[str]:
    """Extrae nombres de tablas de FROM y JOIN."""
    pattern = r"(?:FROM|JOIN)\s+(\w+)"
    return list(set(re.findall(pattern, sql, re.IGNORECASE)))


def _get_real_tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    return {r[0].lower() for r in rows}


def _get_table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        cursor = conn.execute(f"SELECT * FROM {table} LIMIT 0")
        return {d[0].lower() for d in cursor.description}
    except Exception:
        return set()


def _check_columns(sql: str, conn: sqlite3.Connection, tables: list[str]) -> list[str]:
    """Detecta columnas en WHERE/SELECT que no existen en las tablas."""
    errors = []
    all_valid_cols: set[str] = set()
    for t in tables:
        all_valid_cols |= _get_table_columns(conn, t)

    if not all_valid_cols:
        return errors

    # Extraer referencias a columnas (palabras después de WHERE, AND, OR, =, >, <)
    # Excluir funciones SQL conocidas y keywords
    SQL_KEYWORDS = {
        "select", "from", "where", "and", "or", "not", "in", "like", "is",
        "null", "having", "group", "by", "order", "limit", "join", "on",
        "count", "sum", "avg", "min", "max", "distinct", "as", "case",
        "when", "then", "else", "end", "date", "strftime", "datetime",
        "upper", "lower", "trim", "length", "substr", "coalesce",
        "inner", "left", "right", "outer", "asc", "desc", "between",
        "exists", "union", "all", "true", "false",
    }

    # Encontrar patrones tipo "table.column" o standalone column en WHERE
    col_refs = re.findall(r"(?:WHERE|AND|OR|ON|,|\()\s+(?:\w+\.)?(\w+)\s*(?:=|!=|<|>|LIKE|IS|NOT|IN)", sql, re.IGNORECASE)
    for col in col_refs:
        col_lower = col.lower()
        if col_lower not in SQL_KEYWORDS and col_lower not in all_valid_cols:
            # Verificar que no sea un alias o literal
            if not col_lower.isdigit() and len(col_lower) > 2:
                errors.append(
                    f"Column '{col}' does not exist. "
                    f"Valid columns: {', '.join(sorted(all_valid_cols)[:15])}"
                )

    return list(set(errors))  # dedup


def _check_event_ids(sql: str, conn: sqlite3.Connection) -> list[str]:
    """Detecta event_ids en la SQL que no existen en la DB."""
    errors = []

    # Buscar "event_id = N" o "event_id IN (N, M)"
    single = re.findall(r"event_id\s*=\s*(\d+)", sql, re.IGNORECASE)
    multi  = re.findall(r"event_id\s+IN\s*\(([^)]+)\)", sql, re.IGNORECASE)

    referenced_ids = set(int(x) for x in single)
    for group in multi:
        for x in group.split(","):
            x = x.strip()
            if x.isdigit():
                referenced_ids.add(int(x))

    if not referenced_ids:
        return errors

    try:
        real_ids = {
            r[0] for r in conn.execute(
                "SELECT DISTINCT event_id FROM events WHERE event_id IS NOT NULL"
            ).fetchall()
        }
    except Exception:
        return errors

    if not real_ids:
        return errors

    for eid in referenced_ids:
        if eid not in real_ids:
            errors.append(
                f"event_id={eid} does not exist in this database. "
                f"Available event_ids: {', '.join(str(i) for i in sorted(real_ids))}"
            )

    return errors


def _find_similar_columns(col: str, conn: sqlite3.Connection) -> list[str]:
    """Encuentra columnas con nombres similares al col buscado."""
    all_cols: set[str] = set()
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    for (t,) in tables:
        all_cols |= _get_table_columns(conn, t)

    col_lower = col.lower()
    # Similitud simple: misma raíz o substring
    return [c for c in sorted(all_cols) if col_lower[:4] in c or c[:4] in col_lower][:3]
