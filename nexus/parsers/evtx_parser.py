"""Parser para archivos EVTX (Windows Event Log)."""

import re
import sqlite3
from pathlib import Path
from .base import BaseParser

try:
    from evtx import PyEvtxParser
    EVTX_BACKEND = "rust"
except ImportError:
    try:
        import Evtx.Evtx as evtx_lib
        EVTX_BACKEND = "python"
    except ImportError:
        EVTX_BACKEND = None


class EvtxParser(BaseParser):
    def parse(self, filepath: Path, encoding: str = "utf-8") -> int:
        if EVTX_BACKEND is None:
            raise RuntimeError("Instala: pip install evtx  (o python-evtx)")

        if EVTX_BACKEND == "rust":
            return self._parse_rust(filepath)
        return self._parse_python(filepath)

    def _parse_rust(self, filepath: Path) -> int:
        """Parser rápido via evtx (Rust bindings)."""
        from evtx import PyEvtxParser
        import json

        records = []
        parser = PyEvtxParser(str(filepath))

        for record in parser.records_json():
            try:
                data = json.loads(record["data"])
                sys = data.get("Event", {}).get("System", {})
                ed  = data.get("Event", {}).get("EventData", {}) or {}

                username  = _extract_username(ed, sys)
                source_ip = _extract_source_ip(ed)

                records.append((
                    sys.get("TimeCreated", {}).get("#attributes", {}).get("SystemTime", ""),
                    _safe_int(sys.get("EventID")),
                    sys.get("Channel", ""),
                    sys.get("Provider", {}).get("#attributes", {}).get("Name", ""),
                    sys.get("Level", ""),
                    sys.get("Computer", ""),
                    username,
                    source_ip,
                    _extract_description(ed),
                    str(filepath.name),
                ))
            except Exception:
                continue

        self.conn.executemany(
            "INSERT INTO events (timestamp_utc,event_id,channel,provider,level,computer,username,source_ip,description,source_file) VALUES (?,?,?,?,?,?,?,?,?,?)",
            records,
        )
        self.conn.commit()
        self._register_file(filepath, "evtx", len(records))
        return len(records)

    def _parse_python(self, filepath: Path) -> int:
        """Fallback con python-evtx."""
        import Evtx.Evtx as evtx_lib
        import Evtx.Views as evtx_views
        from lxml import etree

        records = []
        with evtx_lib.Evtx(str(filepath)) as log:
            for record in log.records():
                try:
                    xml = record.xml()
                    root = etree.fromstring(xml.encode())
                    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

                    sys_el = root.find("e:System", ns)
                    ed_el  = root.find("e:EventData", ns)

                    ts       = _xpath_text(sys_el, ".//e:TimeCreated/@SystemTime", ns)
                    event_id = _safe_int(_xpath_text(sys_el, "e:EventID", ns))
                    channel  = _xpath_text(sys_el, "e:Channel", ns)
                    provider = sys_el.find("e:Provider", ns).get("Name", "") if sys_el is not None else ""
                    level    = _xpath_text(sys_el, "e:Level", ns)
                    computer = _xpath_text(sys_el, "e:Computer", ns)

                    ed_dict = {}
                    if ed_el is not None:
                        for d in ed_el.findall("e:Data", ns):
                            name = d.get("Name", "")
                            if name:
                                ed_dict[name] = d.text or ""

                    username  = _extract_username(ed_dict, {})
                    source_ip = _extract_source_ip(ed_dict)

                    records.append((ts, event_id, channel, provider, level, computer,
                                    username, source_ip, str(ed_dict)[:500], str(filepath.name)))
                except Exception:
                    continue

        self.conn.executemany(
            "INSERT INTO events (timestamp_utc,event_id,channel,provider,level,computer,username,source_ip,description,source_file) VALUES (?,?,?,?,?,?,?,?,?,?)",
            records,
        )
        self.conn.commit()
        self._register_file(filepath, "evtx", len(records))
        return len(records)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_int(val) -> int | None:
    try:
        if isinstance(val, dict):
            val = val.get("#text", val.get("value", ""))
        return int(str(val).strip())
    except (TypeError, ValueError):
        return None


def _extract_username(ed: dict, sys: dict) -> str:
    for key in ("SubjectUserName", "TargetUserName", "UserName", "User"):
        if key in ed and ed[key] not in (None, "-", ""):
            return str(ed[key])
    sid = sys.get("Security", {})
    if isinstance(sid, dict):
        return sid.get("#attributes", {}).get("UserID", "")
    return ""


def _extract_source_ip(ed: dict) -> str:
    for key in ("IpAddress", "SourceAddress", "WorkstationName", "CallerIpAddress", "RemoteAddress"):
        if key in ed and ed[key] not in (None, "-", "::1", "127.0.0.1", ""):
            return str(ed[key])
    return ""


def _extract_description(ed: dict) -> str:
    parts = []
    for k, v in ed.items():
        if v and str(v).strip() not in ("-", ""):
            parts.append(f"{k}={v}")
    return "; ".join(parts[:10])


def _xpath_text(el, path: str, ns: dict) -> str:
    if el is None:
        return ""
    try:
        result = el.find(path.lstrip(".//").split("/")[0].split("@")[0].strip(), ns)
        if result is not None:
            return result.text or ""
    except Exception:
        pass
    return ""
