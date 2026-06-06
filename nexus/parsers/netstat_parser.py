"""Parser para salida de netstat -ano (Windows, en inglés o español)."""

import re
import sqlite3
from pathlib import Path
from .base import BaseParser


# Regex que captura líneas tipo:
#   TCP    0.0.0.0:7    0.0.0.0:0    LISTENING    1556
#   TCP    10.0.0.5:50123  152.236.2.63:443  ESTABLISHED  9052
NETSTAT_LINE = re.compile(
    r"(TCP|UDP)\s+"
    r"([\d\.\[\]:]+):(\d+)\s+"
    r"([\d\.\[\]:*]+):(\d+|\*)\s+"
    r"(\w+)?\s*"
    r"(\d+)?",
    re.IGNORECASE,
)


class NetstatParser(BaseParser):
    def parse(self, filepath: Path, encoding: str = "utf-8") -> int:
        try:
            text = filepath.read_text(encoding=encoding, errors="replace")
        except Exception:
            text = filepath.read_text(encoding="utf-16", errors="replace")

        records = []
        for line in text.splitlines():
            m = NETSTAT_LINE.search(line)
            if not m:
                continue
            proto, local_addr, local_port, remote_addr, remote_port, state, pid = m.groups()
            records.append((
                None,
                proto.upper(),
                local_addr,
                _safe_int(local_port),
                remote_addr if remote_addr != "*" else None,
                _safe_int(remote_port) if remote_port != "*" else None,
                (state or "").upper(),
                _safe_int(pid),
                None,
                filepath.name,
            ))

        self.conn.executemany(
            "INSERT INTO network_connections (timestamp_utc,protocol,local_address,local_port,remote_address,remote_port,state,pid,process_name,source_file) VALUES (?,?,?,?,?,?,?,?,?,?)",
            records,
        )
        self.conn.commit()
        self._register_file(filepath, "netstat", len(records))
        return len(records)


def _safe_int(val) -> int | None:
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return None
