"""
Evidence Detector — identifica tipos de evidencia forense por magic bytes y estructura.
No confía en la extensión del archivo. Detecta por contenido.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


MAGIC_SIGNATURES = {
    # Windows Event Log
    b"\x45\x6c\x66\x46\x69\x6c\x65\x00": "evtx",
    # Expert Witness Format (E01 disk image)
    b"\x45\x56\x46\x09\x0d\x0a\xff\x00": "e01",
    # Raw PCAP (little-endian)
    b"\xd4\xc3\xb2\xa1": "pcap",
    # Raw PCAP (big-endian)
    b"\xa1\xb2\xc3\xd4": "pcap",
    # PCAPng
    b"\x0a\x0d\x0d\x0a": "pcapng",
    # Windows Registry hive (binary)
    b"\x72\x65\x67\x66": "reg_hive",
    # PE/EXE/DLL
    b"\x4d\x5a": "pe",
    # PDF
    b"\x25\x50\x44\x46": "pdf",
    # ZIP
    b"\x50\x4b\x03\x04": "zip",
    # RAR
    b"\x52\x61\x72\x21": "rar",
    # SQLite
    b"\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33": "sqlite",
    # Volatility memory image (various — handled separately)
}

# BOM markers
BOM_UTF16_LE = b"\xff\xfe"
BOM_UTF16_BE = b"\xfe\xff"
BOM_UTF8     = b"\xef\xbb\xbf"


@dataclass
class EvidenceFile:
    path: Path
    evidence_type: str
    encoding: str
    confidence: str       # high / medium / low
    parser: str           # which parser handles it
    description: str

    @property
    def filename(self) -> str:
        return self.path.name

    @property
    def size_kb(self) -> float:
        return self.path.stat().st_size / 1024


def detect(filepath: str | Path) -> EvidenceFile:
    """Identifica el tipo de evidencia forense de un archivo."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"No existe: {filepath}")
    if not path.is_file():
        raise ValueError(f"No es un archivo: {filepath}")

    raw = _read_header(path)
    encoding = _detect_encoding(raw)
    text_sample = _read_text_sample(path, encoding)

    # 1. Magic bytes primero (más confiable)
    for magic, etype in MAGIC_SIGNATURES.items():
        if raw.startswith(magic):
            return _build_result(path, etype, encoding, "high", raw, text_sample)

    # 2. UTF-16 con BOM — probablemente export de Windows
    if raw.startswith(BOM_UTF16_LE) or raw.startswith(BOM_UTF16_BE):
        return _detect_windows_export(path, encoding, text_sample, "high")

    # 3. UTF-8 BOM
    if raw.startswith(BOM_UTF8):
        text_sample = text_sample.lstrip("﻿")

    # 4. Detección por contenido de texto
    return _detect_by_content(path, encoding, text_sample, raw)


def detect_directory(dirpath: str | Path) -> list[EvidenceFile]:
    """Detecta todos los archivos de evidencia en un directorio."""
    results = []
    for f in sorted(Path(dirpath).rglob("*")):
        if f.is_file() and not f.name.startswith("."):
            try:
                results.append(detect(f))
            except Exception as e:
                results.append(EvidenceFile(
                    path=f,
                    evidence_type="unknown",
                    encoding="binary",
                    confidence="low",
                    parser="none",
                    description=f"Error detecting: {e}",
                ))
    return results


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read_header(path: Path, size: int = 512) -> bytes:
    with open(path, "rb") as f:
        return f.read(size)


def _detect_encoding(raw: bytes) -> str:
    if raw.startswith(BOM_UTF16_LE):
        return "utf-16-le"
    if raw.startswith(BOM_UTF16_BE):
        return "utf-16-be"
    if raw.startswith(BOM_UTF8):
        return "utf-8-sig"
    # Heurística: si hay muchos bytes nulos intercalados = UTF-16 sin BOM
    null_count = raw.count(b"\x00")
    if null_count > len(raw) * 0.3:
        return "utf-16-le"
    return "utf-8"


def _read_text_sample(path: Path, encoding: str, chars: int = 2000) -> str:
    try:
        with open(path, "r", encoding=encoding, errors="replace") as f:
            return f.read(chars)
    except Exception:
        return ""


def _detect_windows_export(path: Path, encoding: str, text: str, confidence: str) -> EvidenceFile:
    text_lower = text.lower()
    stem = path.stem.lower()

    if "windows registry editor" in text_lower or path.suffix.lower() == ".reg":
        return EvidenceFile(path=path, evidence_type="reg_export", encoding=encoding,
                            confidence=confidence, parser="reg_parser",
                            description="Windows Registry export (.reg text format)")

    if any(k in text_lower for k in ["node,command line", "processid", "parentprocessid", "commandline"]):
        return EvidenceFile(path=path, evidence_type="wmic_process", encoding=encoding,
                            confidence=confidence, parser="csv_parser",
                            description="WMIC process list (CSV)")

    if "nombre de imagen" in text_lower or "image name" in text_lower:
        return EvidenceFile(path=path, evidence_type="tasklist_csv", encoding=encoding,
                            confidence=confidence, parser="csv_parser",
                            description="Tasklist output (CSV)")

    # CSV genérico UTF-16
    if _looks_like_csv(text):
        return EvidenceFile(path=path, evidence_type="csv_generic", encoding=encoding,
                            confidence="medium", parser="csv_parser",
                            description="CSV genérico (UTF-16)")

    return EvidenceFile(path=path, evidence_type="text_windows", encoding=encoding,
                        confidence="low", parser="none",
                        description="Archivo de texto Windows (UTF-16)")


def _detect_by_content(path: Path, encoding: str, text: str, raw: bytes) -> EvidenceFile:
    text_lower = text.lower().strip()
    stem = path.stem.lower()
    ext = path.suffix.lower()

    # CSV por extensión + contenido
    if ext == ".csv" or _looks_like_csv(text):
        ctype, desc, parser = _classify_csv(text_lower, stem)
        return EvidenceFile(path=path, evidence_type=ctype, encoding=encoding,
                            confidence="high", parser=parser, description=desc)

    # Netstat
    if any(k in text_lower for k in ["conexiones activas", "active connections", "proto", "tcp", "udp"]) and \
       any(k in text_lower for k in ["listening", "established", "time_wait", "escuchando"]):
        return EvidenceFile(path=path, evidence_type="netstat", encoding=encoding,
                            confidence="high", parser="netstat_parser",
                            description="Netstat output (conexiones de red)")

    # Systeminfo
    if any(k in text_lower for k in ["host name", "nombre de host", "os name", "system boot"]):
        return EvidenceFile(path=path, evidence_type="systeminfo", encoding=encoding,
                            confidence="high", parser="systeminfo_parser",
                            description="Windows systeminfo output")

    # DNS cache
    if any(k in text_lower for k in ["in-addr.arpa", "dns", "record name", "nombre de registro"]):
        return EvidenceFile(path=path, evidence_type="dns_cache", encoding=encoding,
                            confidence="high", parser="dns_parser",
                            description="DNS cache dump")

    # Texto plano genérico
    if encoding in ("utf-8", "utf-8-sig") and len(text) > 10:
        return EvidenceFile(path=path, evidence_type="text_plain", encoding=encoding,
                            confidence="low", parser="none",
                            description="Texto plano (sin parser específico)")

    return EvidenceFile(path=path, evidence_type="unknown", encoding="binary",
                        confidence="low", parser="none",
                        description="Tipo desconocido")


def _classify_csv(text_lower: str, stem: str) -> tuple[str, str, str]:
    # Event logs primero — mapdescription y eventrecordid son señales fuertes
    if any(k in text_lower for k in ["mapdescription", "eventrecordid", "mapdescrip"]):
        return "event_log_csv", "Event log CSV (EvtxECmd/TSLSM)", "csv_parser"
    if any(k in text_lower for k in ["taskname", "task name", "nombre de tarea", "lastruntime"]):
        return "scheduled_tasks_csv", "Scheduled tasks (CSV)", "csv_parser"
    if any(k in text_lower for k in ["parentprocessid", "command line", "commandline"]):
        return "wmic_process", "WMIC process list (CSV)", "csv_parser"
    if any(k in text_lower for k in ["nombre de imagen", "image name", "pid", "mem usage"]):
        return "tasklist_csv", "Tasklist output (CSV)", "csv_parser"
    if "driver" in stem or any(k in text_lower for k in ["drivername", "driver name"]):
        return "drivers_csv", "Drivers list (CSV)", "csv_parser"
    return "csv_generic", "CSV genérico", "csv_parser"


def _looks_like_csv(text: str) -> bool:
    lines = [l for l in text.strip().splitlines() if l.strip()]
    if len(lines) < 2:
        return False
    commas = [l.count(",") for l in lines[:5]]
    return max(commas) >= 2 and min(commas) >= 1


def print_report(files: list[EvidenceFile]) -> None:
    """Imprime resumen de detección al terminal."""
    BOLD  = "\033[1m"
    CYAN  = "\033[96m"
    GREEN = "\033[92m"
    YELLOW= "\033[93m"
    RED   = "\033[91m"
    RESET = "\033[0m"

    print(f"\n{CYAN}{BOLD}{'─'*70}{RESET}")
    print(f"{CYAN}{BOLD}  Nexus — Evidence Detector{RESET}")
    print(f"{CYAN}{BOLD}{'─'*70}{RESET}")
    print(f"  {'Archivo':<30} {'Tipo':<22} {'Parser':<18} {'Conf'}")
    print(f"  {'─'*28} {'─'*20} {'─'*16} {'─'*6}")

    for ef in files:
        conf_color = GREEN if ef.confidence == "high" else YELLOW if ef.confidence == "medium" else RED
        size = f"{ef.size_kb:.1f}KB" if ef.size_kb < 1024 else f"{ef.size_kb/1024:.1f}MB"
        print(f"  {ef.filename:<30} {ef.evidence_type:<22} {ef.parser:<18} "
              f"{conf_color}{ef.confidence}{RESET}  {size}")
    print()


def _build_result(path, etype, encoding, confidence, raw, text):
    descriptions = {
        "evtx":     "Windows Event Log (EVTX)",
        "e01":      "Expert Witness disk image (E01)",
        "pcap":     "Packet capture (PCAP)",
        "pcapng":   "Packet capture (PCAPng)",
        "reg_hive": "Windows Registry hive (binary)",
        "pe":       "PE executable / DLL",
        "pdf":      "PDF document",
        "zip":      "ZIP archive",
        "rar":      "RAR archive",
        "sqlite":   "SQLite database",
    }
    parsers = {
        "evtx":     "evtx_parser",
        "reg_hive": "reg_hive_parser",
        "pcap":     "pcap_parser",
        "pcapng":   "pcap_parser",
    }
    return EvidenceFile(
        path=path,
        evidence_type=etype,
        encoding=encoding,
        confidence=confidence,
        parser=parsers.get(etype, "none"),
        description=descriptions.get(etype, etype),
    )
