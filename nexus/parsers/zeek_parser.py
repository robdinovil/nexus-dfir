"""
Zeek log parser — soporta conn.log y dns.log (TSV con header #fields).

Zeek log format:
  - Líneas que empiezan con '#' son metadatos (#separator, #fields, #types, #path, etc.)
  - Resto son registros TSV
  - Campo '-' = null/unset, '(empty)' = empty set
"""

import csv
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .base import BaseParser

_CONN_STATE = {
    "SF":      "ESTABLISHED",
    "S1":      "ESTABLISHED",
    "S2":      "ESTABLISHED",
    "S3":      "ESTABLISHED",
    "S0":      "SYN_SENT",
    "SH":      "SYN_SENT",
    "SHR":     "SYN_SENT",
    "REJ":     "REJECTED",
    "RSTO":    "RESET",
    "RSTOS0":  "RESET",
    "RSTR":    "RESET",
    "RSTRH":   "RESET",
    "OTH":     "OTHER",
}


def _ts_to_utc(ts_str: str) -> str | None:
    """Convierte timestamp Zeek (epoch float) a ISO UTC."""
    if not ts_str or ts_str in ("-", "(empty)"):
        return None
    try:
        epoch = float(ts_str)
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, OSError):
        return None


def _val(v: str) -> str | None:
    """Retorna None para campos nulos de Zeek."""
    if v in ("-", "(empty)", ""):
        return None
    return v


class ZeekConnParser(BaseParser):
    """Parsea Zeek conn.log → network_connections."""

    SUPPORTED_TYPES = {"zeek_conn"}

    def parse(self, filepath: Path, conn: sqlite3.Connection) -> int:
        fields = []
        records = 0

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                if line.startswith("#"):
                    continue
                if not fields or not line.strip():
                    continue

                parts = line.split("\t")
                row = dict(zip(fields, parts))

                ts     = _ts_to_utc(row.get("ts", ""))
                proto  = (_val(row.get("proto", "")) or "tcp").upper()
                src_h  = _val(row.get("id.orig_h", ""))
                src_p  = row.get("id.orig_p", "")
                dst_h  = _val(row.get("id.resp_h", ""))
                dst_p  = row.get("id.resp_p", "")
                state  = _CONN_STATE.get(row.get("conn_state", ""), "OTHER")
                uid    = _val(row.get("uid", ""))

                try:
                    local_p = int(src_p) if src_p and src_p != "-" else None
                except ValueError:
                    local_p = None
                try:
                    remote_p = int(dst_p) if dst_p and dst_p != "-" else None
                except ValueError:
                    remote_p = None

                conn.execute(
                    "INSERT INTO network_connections "
                    "(timestamp_utc, protocol, local_address, local_port, "
                    " remote_address, remote_port, state, source_file) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (ts, proto, src_h, local_p, dst_h, remote_p, state,
                     filepath.name)
                )
                records += 1

        conn.commit()
        self._register_file(filepath, "zeek_conn", records)
        return records


class ZeekDnsParser(BaseParser):
    """Parsea Zeek dns.log → dns_cache."""

    SUPPORTED_TYPES = {"zeek_dns"}

    def parse(self, filepath: Path, conn: sqlite3.Connection) -> int:
        fields = []
        records = 0

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                if line.startswith("#"):
                    continue
                if not fields or not line.strip():
                    continue

                parts = line.split("\t")
                row = dict(zip(fields, parts))

                ts       = _ts_to_utc(row.get("ts", ""))
                hostname = _val(row.get("query", ""))
                qtype    = _val(row.get("qtype_name", ""))
                answers  = _val(row.get("answers", ""))
                # Zeek answers es una lista separada por comas
                data = answers.replace(",", " | ") if answers else None

                conn.execute(
                    "INSERT INTO dns_cache "
                    "(timestamp_utc, hostname, record_type, data, source_file) "
                    "VALUES (?,?,?,?,?)",
                    (ts, hostname, qtype, data, filepath.name)
                )
                records += 1

        conn.commit()
        self._register_file(filepath, "zeek_dns", records)
        return records
