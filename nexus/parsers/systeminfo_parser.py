"""Parser para salida de systeminfo (Windows, en inglés o español)."""

import re
import sqlite3
from pathlib import Path
from .base import BaseParser


FIELD_MAP = {
    "host name": "hostname",           "nombre de host": "hostname",
    "os name": "os_name",              "nombre del sistema operativo": "os_name",
    "os version": "os_version",        "versión del sistema operativo": "os_version",
    "system type": "architecture",     "tipo del sistema": "architecture",
    "original install date": "install_date", "fecha de instalación original": "install_date",
    "system boot time": "last_boot",   "hora de inicio del sistema": "last_boot",
    "domain": "domain",                "dominio": "domain",
    "hotfix(s)": "hotfixes",           "revisión(es)": "hotfixes",
    "ip address(es)": "ip_addresses",  "dirección(es) ip": "ip_addresses",
}


class SysteminfoParser(BaseParser):
    def parse(self, filepath: Path, encoding: str = "utf-8") -> int:
        try:
            text = filepath.read_text(encoding=encoding, errors="replace")
        except Exception:
            text = filepath.read_text(encoding="utf-16", errors="replace")

        fields: dict[str, str] = {}
        current_key = None
        current_val_lines: list[str] = []

        for line in text.splitlines():
            if ":" in line:
                # Puede ser key: value
                m = re.match(r"^([^:]{3,45}):\s*(.*)", line)
                if m:
                    if current_key:
                        fields[current_key] = " ".join(current_val_lines).strip()
                    current_key = m.group(1).strip().lower()
                    current_val_lines = [m.group(2).strip()]
                    continue
            if current_key and line.startswith(" " * 4):
                current_val_lines.append(line.strip())

        if current_key:
            fields[current_key] = " ".join(current_val_lines).strip()

        row = {v: "" for v in FIELD_MAP.values()}
        for raw_key, norm_key in FIELD_MAP.items():
            if raw_key in fields:
                row[norm_key] = fields[raw_key][:500]

        self.conn.execute(
            "INSERT INTO sysinfo (hostname,os_name,os_version,architecture,install_date,last_boot,domain,ip_addresses,hotfixes,source_file) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (row["hostname"], row["os_name"], row["os_version"], row["architecture"],
             row["install_date"], row["last_boot"], row["domain"], row["ip_addresses"],
             row["hotfixes"], filepath.name),
        )
        self.conn.commit()
        self._register_file(filepath, "systeminfo", 1)
        return 1
