"""Parser para CSV de Windows (tasklist, wmic, scheduled_tasks, drivers)."""

import re
import sqlite3
from pathlib import Path
import pandas as pd
from .base import BaseParser


# Mapeos de columnas en español/inglés a nombres normalizados
COL_MAP_PROCESS = {
    "nombre de imagen": "name", "image name": "name",
    "pid": "pid",
    "nombre de sesión": "session", "session name": "session",
    "núm. de sesión": "session_num", "session#": "session_num",
    "uso de memoria": "memory_raw", "mem usage": "memory_raw",
    "estado": "status", "status": "status",
    "nombre de usuario": "username", "user name": "username",
    "tiempo de cpu": "cpu_time", "cpu time": "cpu_time",
    "título de ventana": "window_title", "window title": "window_title",
}

COL_MAP_WMIC = {
    "node": "computer",
    "commandline": "command_line", "command line": "command_line",
    "executablepath": "exe_path", "executable path": "exe_path",
    "caption": "name", "name": "name",
    "parentprocessid": "ppid", "parent process id": "ppid",
    "processid": "pid", "process id": "pid",
}

COL_MAP_TASKS = {
    "taskname": "task_name", "task name": "task_name",
    "nombre de tarea": "task_name",
    "status": "status", "estado": "status",
    "lastruntime": "last_run", "last run time": "last_run",
    "último tiempo de ejecución": "last_run",
    "\xe9ltimo tiempo de ejecuci\xf3n": "last_run",
    "nextruntime": "next_run", "next run time": "next_run",
    "hora próxima ejecución": "next_run",
    "hora pr\xf3xima ejecuci\xf3n": "next_run",
    "author": "author", "autor": "author",
    "run as user": "run_as", "ejecutar como usuario": "run_as",
    "task to run": "command", "tarea para ejecutar": "command",
    "tarea que se ejecutar\xa0": "command",
}


class CsvParser(BaseParser):
    def parse(self, filepath: Path, encoding: str = "utf-8") -> int:
        df = None
        for enc in (encoding, "utf-16", "utf-8-sig", "latin-1", "cp1252"):
            try:
                df = pd.read_csv(filepath, encoding=enc, encoding_errors="replace",
                                 low_memory=False, on_bad_lines="skip")
                break
            except Exception:
                continue
        if df is None:
            raise RuntimeError(f"No se pudo leer CSV {filepath.name} con ningún encoding")

        df.columns = [str(c).strip().strip('"').lower() for c in df.columns]
        csv_type = _classify_df(df, filepath.stem.lower())

        if csv_type == "event_log":
            return self._load_event_log(df, filepath)
        if csv_type == "process":
            return self._load_processes(df, filepath)
        if csv_type == "tasks":
            return self._load_tasks(df, filepath)
        return self._load_generic(df, filepath, csv_type)

    def _load_processes(self, df: pd.DataFrame, filepath: Path) -> int:
        df = _rename_columns(df, {**COL_MAP_PROCESS, **COL_MAP_WMIC})
        records = []
        for _, row in df.iterrows():
            mem_kb = _parse_memory(str(row.get("memory_raw", "")))
            records.append((
                None,
                _safe_int(row.get("pid")),
                _safe_int(row.get("ppid")),
                str(row.get("name", ""))[:200],
                str(row.get("command_line", ""))[:500],
                str(row.get("exe_path", ""))[:500],
                str(row.get("username", ""))[:100],
                str(row.get("session", ""))[:50],
                mem_kb,
                str(row.get("cpu_time", ""))[:20],
                str(row.get("status", ""))[:50],
                filepath.name,
            ))
        self.conn.executemany(
            "INSERT INTO processes (timestamp_utc,pid,ppid,name,command_line,exe_path,username,session,memory_kb,cpu_time,status,source_file) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            records,
        )
        self.conn.commit()
        self._register_file(filepath, "csv_process", len(records))
        return len(records)

    def _load_tasks(self, df: pd.DataFrame, filepath: Path) -> int:
        df = _rename_columns(df, COL_MAP_TASKS)
        records = []
        for _, row in df.iterrows():
            enabled = 1 if str(row.get("status", "")).lower() in ("ready", "running", "listo") else 0
            records.append((
                str(row.get("task_name", ""))[:300],
                str(row.get("task_name", ""))[:300],
                str(row.get("status", ""))[:50],
                str(row.get("last_run", ""))[:30],
                str(row.get("next_run", ""))[:30],
                str(row.get("author", ""))[:100],
                str(row.get("run_as", ""))[:100],
                str(row.get("command", ""))[:500],
                "",
                enabled,
                filepath.name,
            ))
        self.conn.executemany(
            "INSERT INTO scheduled_tasks (task_name,task_path,status,last_run,next_run,author,run_as,command,arguments,enabled,source_file) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            records,
        )
        self.conn.commit()
        self._register_file(filepath, "csv_tasks", len(records))
        return len(records)

    def _load_event_log(self, df: pd.DataFrame, filepath: Path) -> int:
        """Carga CSVs de event logs (TSLSM, Sysmon, EvtxECmd) en la tabla events."""
        # Normalizar nombres de columna
        col_map = {
            "eventid": "event_id", "event_id": "event_id",
            "timecreated": "timestamp_utc", "time_created": "timestamp_utc",
            "mapdescription": "description",
            "username": "username",
            "remotehost": "source_ip",
            "computer": "computer",
            "channel": "channel",
            "level": "level",
            "payloaddata1": "payload1",
        }
        df = _rename_columns(df, col_map)

        records = []
        for _, row in df.iterrows():
            records.append((
                str(row.get("timestamp_utc", ""))[:30],
                _safe_int(row.get("event_id")),
                str(row.get("channel", ""))[:100],
                "",  # provider
                str(row.get("level", ""))[:20],
                str(row.get("computer", ""))[:100],
                str(row.get("username", ""))[:100],
                str(row.get("source_ip", ""))[:50],
                str(row.get("description", ""))[:500],
                filepath.name,
            ))

        self.conn.executemany(
            "INSERT INTO events (timestamp_utc,event_id,channel,provider,level,computer,username,source_ip,description,source_file) VALUES (?,?,?,?,?,?,?,?,?,?)",
            records,
        )
        self.conn.commit()
        self._register_file(filepath, "event_log_csv", len(records))
        return len(records)

    def _load_generic(self, df: pd.DataFrame, filepath: Path, csv_type: str) -> int:
        table = f"csv_{csv_type}"
        df["_source_file"] = filepath.name
        try:
            df.to_sql(table, self.conn, if_exists="append", index=False)
            self.conn.commit()
            self._register_file(filepath, csv_type, len(df))
            return len(df)
        except Exception as e:
            raise RuntimeError(f"No se pudo cargar {filepath.name} como tabla genérica: {e}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _classify_df(df: pd.DataFrame, stem: str) -> str:
    cols = set(df.columns)
    # Event log CSVs primero — EvtxECmd / TSLSM tienen MapDescription o Channel
    # que son señales fuertes de log de eventos, aunque también tengan ProcessId
    has_event_signal = any(c in cols for c in ("mapdescription", "channel", "eventrecordid"))
    has_eventid = any(c in cols for c in ("eventid", "event_id", "timecreated", "time_created"))
    if has_event_signal or (has_eventid and "commandline" not in cols):
        return "event_log"
    if any(c in cols for c in ("pid", "processid", "commandline", "command line",
                                "nombre de imagen", "image name")):
        return "process"
    if any(c in cols for c in ("taskname", "task name", "lastruntime", "nextruntime",
                                "nombre de tarea", "\xe9ltimo tiempo de ejecuci\xf3n")):
        return "tasks"
    if "driver" in stem:
        return "drivers"
    return stem.replace("-", "_").replace(" ", "_")[:30]


def _rename_columns(df: pd.DataFrame, mapping: dict) -> pd.DataFrame:
    rename = {}
    for col in df.columns:
        col_clean = col.strip().strip('"').lower()
        if col_clean in mapping:
            rename[col] = mapping[col_clean]
    return df.rename(columns=rename)


def _parse_memory(raw: str) -> float | None:
    raw = raw.replace(",", "").replace(".", "").replace("\xa0", "").strip()
    m = re.search(r"(\d+)", raw)
    if m:
        val = int(m.group(1))
        if "mb" in raw.lower():
            return val * 1024.0
        return float(val)
    return None


def _safe_int(val) -> int | None:
    try:
        return int(str(val).strip().replace(",", ""))
    except (TypeError, ValueError):
        return None
