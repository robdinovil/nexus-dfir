from .evtx_parser import EvtxParser
from .csv_parser import CsvParser
from .netstat_parser import NetstatParser
from .systeminfo_parser import SysteminfoParser
from .reg_parser import RegExportParser

PARSER_REGISTRY = {
    "evtx_parser":      EvtxParser,
    "csv_parser":       CsvParser,
    "netstat_parser":   NetstatParser,
    "systeminfo_parser":SysteminfoParser,
    "reg_parser":       RegExportParser,
}
