"""Clase base para todos los parsers de Nexus."""

from abc import ABC, abstractmethod
from pathlib import Path
import sqlite3


class BaseParser(ABC):
    def __init__(self, db_conn: sqlite3.Connection):
        self.conn = db_conn

    @abstractmethod
    def parse(self, filepath: Path, encoding: str = "utf-8") -> int:
        """
        Parsea el archivo e inserta registros en SQLite.
        Retorna el número de registros insertados.
        """

    def _register_file(self, filepath: Path, evidence_type: str, record_count: int) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO evidence_files (filename, filepath, evidence_type, file_size_kb, record_count) VALUES (?,?,?,?,?)",
            (filepath.name, str(filepath), evidence_type, filepath.stat().st_size / 1024, record_count)
        )
        self.conn.commit()
