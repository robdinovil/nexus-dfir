"""Parser para exports de registro de Windows (.reg, texto UTF-16)."""

import re
import sqlite3
from pathlib import Path
from .base import BaseParser


# Regex para entradas de .reg
RE_KEY    = re.compile(r"^\[(.+)\]$")
RE_VALUE  = re.compile(r'^"(.+)"\s*=\s*(.+)$')
RE_DEFAULT = re.compile(r'^@\s*=\s*(.+)$')


class RegExportParser(BaseParser):
    def parse(self, filepath: Path, encoding: str = "utf-8") -> int:
        for enc in (encoding, "utf-16", "utf-16-le", "utf-8-sig", "latin-1"):
            try:
                text = filepath.read_text(encoding=enc, errors="replace")
                if "Windows Registry Editor" in text or "REGEDIT4" in text:
                    break
            except Exception:
                continue

        records = []
        current_key = ""
        hive = ""

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue

            m_key = RE_KEY.match(line)
            if m_key:
                current_key = m_key.group(1)
                hive = _extract_hive(current_key)
                continue

            m_val = RE_VALUE.match(line)
            if m_val and current_key:
                name = m_val.group(1)
                raw_val = m_val.group(2).strip()
                vtype, vdata = _parse_reg_value(raw_val)
                records.append((hive, current_key, name, vtype, vdata[:500], None, filepath.name))
                continue

            m_def = RE_DEFAULT.match(line)
            if m_def and current_key:
                raw_val = m_def.group(1).strip()
                vtype, vdata = _parse_reg_value(raw_val)
                records.append((hive, current_key, "(Default)", vtype, vdata[:500], None, filepath.name))

        self.conn.executemany(
            "INSERT INTO registry_keys (hive,key_path,value_name,value_type,value_data,modified_time,source_file) VALUES (?,?,?,?,?,?,?)",
            records,
        )
        self.conn.commit()
        self._register_file(filepath, "reg_export", len(records))
        return len(records)


def _extract_hive(key: str) -> str:
    for hive in ("HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_USERS",
                 "HKEY_CLASSES_ROOT", "HKEY_CURRENT_CONFIG"):
        if key.startswith(hive):
            return hive
    return key.split("\\")[0]


def _parse_reg_value(raw: str) -> tuple[str, str]:
    if raw.startswith('"') and raw.endswith('"'):
        return "REG_SZ", raw.strip('"')
    if raw.startswith("dword:"):
        return "REG_DWORD", raw[6:]
    if raw.startswith("hex(2):"):
        return "REG_EXPAND_SZ", raw[7:]
    if raw.startswith("hex:"):
        return "REG_BINARY", raw[4:]
    if raw.startswith("hex(7):"):
        return "REG_MULTI_SZ", raw[7:]
    return "REG_UNKNOWN", raw[:200]
