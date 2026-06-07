"""Nexus CLI — entry point global."""

import argparse
import re
import sys
from pathlib import Path

BOLD   = "\033[1m"
DIM    = "\033[2m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
RESET  = "\033[0m"

DEFAULT_MODEL = "qwen2.5:7b-instruct"


def main():
    p = argparse.ArgumentParser(
        prog="nexus",
        add_help=False,  # manejamos help manualmente
    )
    p.add_argument("cmd", nargs="?", default=None)
    p.add_argument("args", nargs=argparse.REMAINDER)

    parsed, _ = p.parse_known_args()

    cmd = parsed.cmd

    # Sin argumento → modo conversacional
    if cmd is None:
        _cmd_chat()
        return

    # Subcomandos de power user / scripting
    if cmd == "new":
        _cmd_new(parsed.args[0] if parsed.args else _die("nexus new <nombre>"))

    elif cmd == "cases":
        _cmd_cases()

    elif cmd == "detect":
        _cmd_detect(parsed.args[0] if parsed.args else _die("nexus detect <path>"))

    elif cmd == "ingest":
        if len(parsed.args) < 2:
            _die("nexus ingest <caso> <path>")
        _cmd_ingest(parsed.args[0], parsed.args[1])

    elif cmd == "summary":
        _cmd_summary(parsed.args[0] if parsed.args else _die("nexus summary <caso>"))

    elif cmd == "train":
        ap = _sub_parser("train")
        ap.add_argument("case")
        ap.add_argument("--model", default=DEFAULT_MODEL)
        ap.add_argument("--force", action="store_true")
        a = ap.parse_args(parsed.args)
        _cmd_train(a.case, a.model, a.force)

    elif cmd == "ask":
        ap = _sub_parser("ask")
        ap.add_argument("case")
        ap.add_argument("question")
        ap.add_argument("--model", default=DEFAULT_MODEL)
        a = ap.parse_args(parsed.args)
        _cmd_ask(a.case, a.question, a.model)

    elif cmd == "shell":
        ap = _sub_parser("shell")
        ap.add_argument("case")
        ap.add_argument("--model", default=DEFAULT_MODEL)
        a = ap.parse_args(parsed.args)
        _cmd_shell(a.case, a.model)

    elif cmd == "benchmark":
        ap = _sub_parser("benchmark")
        ap.add_argument("case")
        ap.add_argument("--model", default=DEFAULT_MODEL)
        a = ap.parse_args(parsed.args)
        _cmd_benchmark(a.case, a.model)

    elif cmd == "results":
        _cmd_results(parsed.args[0] if parsed.args else _die("nexus results <caso>"))

    elif cmd == "test":
        _cmd_test()

    elif cmd in ("-h", "--help", "help"):
        _print_help()

    else:
        # Podría ser un nombre de caso directo: `nexus lockbit_ir`
        from .case import NexusCase
        try:
            case = NexusCase.resolve(cmd)
            _cmd_chat(preload=case)
        except FileNotFoundError:
            print(f"\n  {RED}Comando '{cmd}' no reconocido.{RESET}")
            _print_help()
            sys.exit(1)


# ── Modo conversacional ────────────────────────────────────────────────────────

def _cmd_chat(model: str = DEFAULT_MODEL, preload=None):
    from .case import NexusCase, print_cases
    from .router import NexusRouter
    from .ingestor import Ingestor

    _print_header()

    router   = None
    case     = preload

    # Si viene con caso precargado, mostrarlo
    if case:
        router = _load_case(case, model)

    while True:
        # Prompt dinámico
        prompt_case = f" [{BOLD}{case.name}{RESET}{CYAN}]" if case else ""
        try:
            raw = input(f"{CYAN}nexus{prompt_case}>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {DIM}Saliendo...{RESET}\n")
            break

        if not raw:
            continue

        low = raw.lower()

        # ── Salir ─────────────────────────────────────────────────────────────
        if low in ("exit", "quit", "q", "salir", "bye", "chao"):
            print(f"\n  {DIM}Saliendo...{RESET}\n")
            break

        # ── Listar casos ──────────────────────────────────────────────────────
        if low in ("casos", "cases", "lista", "ls"):
            cases = NexusCase.list_all()
            print_cases(cases)
            continue

        # ── Resumen del caso actual ───────────────────────────────────────────
        if low in ("resumen", "summary", "info", "status"):
            if not case:
                print(f"\n  {YELLOW}No hay caso cargado.{RESET}\n")
                continue
            ing = Ingestor(case.db_path)
            ing.summary()
            ing.close()
            continue

        # ── Cambiar/abrir caso: "abre X", "caso X", "cambia a X", "open X" ───
        switch = _parse_switch(raw)
        if switch:
            try:
                case   = NexusCase.resolve(switch)
                if router:
                    router.close()
                router = _load_case(case, model)
            except FileNotFoundError:
                print(f"\n  {RED}Caso '{switch}' no encontrado.{RESET}")
                _show_cases_hint()
            continue

        # ── Crear caso: "nuevo X", "new X", "crea X" ─────────────────────────
        create = _parse_create(raw)
        if create:
            try:
                case = NexusCase.create(create)
                print(f"\n  {GREEN}✓ Caso '{create}' creado{RESET}")
                print(f"  {DIM}Dame una ruta de evidencia para cargarlo.{RESET}\n")
                if router:
                    router.close()
                router = None
            except FileExistsError:
                print(f"\n  {YELLOW}El caso '{create}' ya existe.{RESET}")
                case   = NexusCase.open(create)
                if router:
                    router.close()
                router = _load_case(case, model)
            continue

        # ── Ruta de evidencia ─────────────────────────────────────────────────
        if _is_path(raw):
            target = Path(raw.replace("~", str(Path.home()))).expanduser().resolve()
            if not target.exists():
                print(f"\n  {RED}Ruta no encontrada: {target}{RESET}\n")
                continue

            # Sin caso activo: crear uno con el nombre de la carpeta
            if not case:
                name = target.stem if target.is_file() else target.name
                name = re.sub(r"[^\w\-]", "_", name)[:30]
                try:
                    case = NexusCase.create(name)
                    print(f"\n  {GREEN}✓ Caso '{name}' creado automáticamente{RESET}")
                except FileExistsError:
                    case = NexusCase.open(name)

            # Ingestar
            ing = Ingestor(case.db_path)
            if target.is_dir():
                ing.ingest_directory(target)
            else:
                ing.ingest_file(target)
            ing.close()

            # Cargar router con el caso actualizado
            if router:
                router.close()
            router = _load_case(case, model)
            continue

        # ── Nombre de caso sin verbo (si no hay caso activo) ──────────────────
        if not case:
            cases = NexusCase.list_all()
            names = {c["name"] for c in cases}
            if raw in names:
                case   = NexusCase.open(raw)
                router = _load_case(case, model)
            else:
                print(f"\n  {YELLOW}No hay caso cargado.{RESET}")
                if cases:
                    print(f"  Escribe el nombre de un caso, o una ruta de evidencia:\n")
                    for c in cases:
                        rec = f"{c['records']:,}" if c["has_db"] else "vacío"
                        print(f"    {GREEN}{c['name']}{RESET}  {DIM}({rec} registros){RESET}")
                    print()
                else:
                    print(f"  {DIM}Dame una ruta de evidencia para empezar.{RESET}\n")
            continue

        # ── Pregunta / análisis → router ──────────────────────────────────────
        router.ask(raw)

    if router:
        router.close()


# ── Helpers del chat ──────────────────────────────────────────────────────────

def _load_case(case, model: str):
    """Abre el router para un caso y muestra mini-resumen."""
    from .router import NexusRouter
    from .ingestor import Ingestor
    import sqlite3

    conn = sqlite3.connect(case.db_path)
    stats = {}
    for t, label in [("events","eventos"), ("processes","procesos"),
                     ("network_connections","conexiones"), ("scheduled_tasks","tareas")]:
        try:
            stats[label] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        except Exception:
            stats[label] = 0
    conn.close()

    parts = [f"{v:,} {k}" for k, v in stats.items() if v > 0]
    print(f"\n  {GREEN}✓ {BOLD}{case.name}{RESET}")
    if parts:
        print(f"  {DIM}{' · '.join(parts)}{RESET}")
    print()

    return NexusRouter(case, model=model)


def _parse_switch(text: str):
    """'abre X', 'caso X', 'cambia a X', 'open X', 'load X' → X"""
    m = re.match(
        r"(?:abre|open|caso|case|cambia\s+a|switch\s+to|load|usa|usar)\s+(\S+)",
        text, re.IGNORECASE
    )
    return m.group(1) if m else None


def _parse_create(text: str):
    """'nuevo X', 'new X', 'crea X', 'create X' → X"""
    m = re.match(
        r"(?:nuevo|new|crea|create|crear)\s+(\S+)",
        text, re.IGNORECASE
    )
    return m.group(1) if m else None


def _is_path(text: str) -> bool:
    """Detecta si el input parece una ruta de archivo/directorio."""
    if re.match(r"^[~/\.]", text):
        return True
    p = Path(text)
    return p.exists() and (p.is_file() or p.is_dir())


def _show_cases_hint():
    from .case import NexusCase
    cases = NexusCase.list_all()
    if cases:
        names = ", ".join(c["name"] for c in cases[:5])
        print(f"  {DIM}Casos disponibles: {names}{RESET}\n")


# ── Otros comandos (power user / scripting) ───────────────────────────────────

def _cmd_new(name: str):
    from .case import NexusCase
    try:
        case = NexusCase.create(name)
        print(f"\n  {GREEN}✓ Caso '{name}' creado en {case.path}{RESET}\n")
    except FileExistsError as e:
        print(f"\n  {YELLOW}{e}{RESET}\n")
        sys.exit(1)


def _cmd_cases():
    from .case import NexusCase, print_cases
    print_cases(NexusCase.list_all())


def _cmd_detect(path: str):
    from .detector import detect, detect_directory, print_report
    target = Path(path)
    files  = detect_directory(target) if target.is_dir() else [detect(target)]
    print_report(files)


def _cmd_ingest(case_ref: str, path: str):
    from .ingestor import Ingestor
    case   = _resolve(case_ref)
    target = Path(path)
    ing    = Ingestor(case.db_path)
    if target.is_dir():
        ing.ingest_directory(target)
    else:
        ing.ingest_file(target)
    ing.summary()
    ing.close()


def _cmd_summary(case_ref: str):
    from .ingestor import Ingestor
    case = _resolve(case_ref)
    ing  = Ingestor(case.db_path)
    ing.summary()
    ing.close()


def _cmd_train(case_ref: str, model: str, force: bool):
    from .analyst import NexusAnalyst
    case    = _resolve(case_ref)
    analyst = _make_analyst(case, model)
    analyst.describe_case()
    analyst.train(force=force)
    analyst.close()


def _cmd_ask(case_ref: str, question: str, model: str):
    from .router import NexusRouter
    case   = _resolve(case_ref)
    router = NexusRouter(case, model=model)
    router.ask(question)
    router.close()


def _cmd_shell(case_ref: str, model: str):
    case = _resolve(case_ref)
    _cmd_chat(model=model, preload=case)


def _cmd_test():
    """Corre el test suite con cobertura y muestra un resumen formateado."""
    import subprocess
    import sys

    pkg_root = Path(__file__).parent.parent

    print(f"\n{CYAN}{BOLD}{'─'*65}{RESET}")
    print(f"{CYAN}{BOLD}  Nexus — Test Suite{RESET}")
    print(f"{CYAN}{BOLD}{'─'*65}{RESET}\n")

    result = subprocess.run(
        [
            sys.executable, "-m", "pytest", "tests/", "-v",
            "--tb=short", "--no-header", "-q",
            "--cov=nexus", "--cov-report=term-missing",
        ],
        cwd=str(pkg_root),
        capture_output=False,
    )
    sys.exit(result.returncode)


def _cmd_benchmark(case_ref: str, model: str):
    from .benchmark import run
    from datetime import datetime
    case = _resolve(case_ref)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(case.path) / f"benchmark_{ts}.json"
    run(case.db_path, model=model, out_path=str(out_path), store_path=case.store_path)


def _cmd_results(case_ref: str):
    import json
    case = _resolve(case_ref)
    case_path = Path(case.path)

    jsons = sorted(case_path.glob("benchmark_*.json"))
    if not jsons:
        # fallback: legacy CWD file
        legacy = Path(f"{Path(case.db_path).stem}_benchmark.json")
        if legacy.exists():
            jsons = [legacy]

    if not jsons:
        print(f"\n  {YELLOW}Sin resultados. Corre primero: nexus benchmark {case.name}{RESET}\n")
        return

    latest = jsons[-1]
    with open(latest) as f:
        d = json.load(f)

    print(f"\n{CYAN}{BOLD}{'─'*70}{RESET}")
    print(f"{CYAN}{BOLD}  Benchmark Results — {case.name}  [{latest.name}]{RESET}")
    print(f"{CYAN}{BOLD}{'─'*70}{RESET}")
    print(f"  Model : {d.get('model', '?')}")
    print(f"  Score : {BOLD}{d.get('passed',0)}/{d.get('total',0)} ({d.get('score',0):.0%}){RESET}")
    print(f"  TUS   : {d.get('tus_avg', 'N/A')}")
    print(f"  RS    : {d.get('reliability_score', 'N/A')}")
    print(f"  CCR   : {d.get('context_recall_avg', 'N/A')}")
    h = d.get("hallucinations", {})
    print(f"  Halluc: {sum(h.values())}  "
          f"({h.get('structural',0)} struct / "
          f"{h.get('referential',0)} ref / "
          f"{h.get('syntax',0)} syntax)")
    print(f"  Self-correction rate: {d.get('self_correction_rate', 'N/A'):.0%}" if isinstance(d.get('self_correction_rate'), float) else "")
    print(f"  Latencia avg/p95: {d.get('avg_latency_s','?')}s / {d.get('p95_latency_s','?')}s\n")

    results = d.get("results", [])
    if not results:
        return

    print(f"  {BOLD}{'ID':<5} {'Cat':<14} {'Pass':<6} {'TUS':>5} {'CCR':>5}  Pregunta{RESET}")
    print(f"  {'─'*4} {'─'*12} {'─'*4} {'─'*5} {'─'*5}  {'─'*35}")
    for r in results:
        passed = r.get("passed", False)
        tus    = r.get("tus_score", 0.0)
        ccr    = r.get("context_recall", 1.0)
        htype  = r.get("hallucination_type") or ""
        sc     = r.get("self_corrected", False)
        p_col  = GREEN if passed else RED
        t_col  = GREEN if tus >= 0.8 else YELLOW if tus >= 0.5 else RED
        c_col  = GREEN if ccr >= 0.8 else YELLOW

        h_mark = ""
        if htype:
            h_mark = f" {YELLOW}[{htype[:3]}{'✓' if sc else ''}]{RESET}"

        q_short = r.get("question", "")[:42]
        print(f"  {r['id']:<5} {r['category']:<14} "
              f"{p_col}{'✓' if passed else '✗'}{RESET:<5} "
              f"{t_col}{tus:.2f}{RESET:>5} "
              f"{c_col}{ccr:.2f}{RESET:>5}"
              f"{h_mark}  {q_short}")

    if len(jsons) > 1:
        print(f"\n  {DIM}Historial: {len(jsons)} run(s) en {case_path}{RESET}")
    print()


# ── UI helpers ─────────────────────────────────────────────────────────────────

def _print_header():
    print(f"""
{CYAN}{BOLD}  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗{RESET}
{CYAN}{BOLD}  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝{RESET}
{CYAN}{BOLD}  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗{RESET}
{CYAN}{BOLD}  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║{RESET}
{CYAN}{BOLD}  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║{RESET}
{CYAN}{BOLD}  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝{RESET}
{DIM}  DFIR Evidence Intelligence — CPU-only · Air-gap ready{RESET}
""")

    from .case import NexusCase
    cases = NexusCase.list_all()
    if cases:
        print(f"  {BOLD}Casos disponibles:{RESET}")
        for c in cases:
            rec = f"{c['records']:,} registros" if c["has_db"] else "vacío"
            print(f"    {GREEN}•{RESET} {c['name']:<28} {DIM}{rec}{RESET}")
        print(f"\n  {DIM}Escribe el nombre de un caso, una ruta de evidencia,{RESET}")
        print(f"  {DIM}o haz una pregunta directamente.{RESET}\n")
    else:
        print(f"  {YELLOW}Sin casos aún.{RESET}")
        print(f"  {DIM}Dame una ruta de evidencia para empezar:{RESET}")
        print(f"  {DIM}  /media/usb/evidencia/  o  ~/Downloads/Security.evtx{RESET}\n")


def _print_help():
    print(f"""
{BOLD}Uso:{RESET}
  nexus                     modo conversacional (recomendado)
  nexus <caso>              abrir caso directamente
  nexus ingest <caso> <dir> ingestar desde script
  nexus ask <caso> "..."    pregunta desde script
  nexus benchmark <caso>    scorecard NL→SQL (guarda JSON en el caso)
  nexus results <caso>      ver último resultado con TUS/RS/CCR por pregunta
  nexus test                correr unit tests + cobertura
  nexus cases               listar casos

{BOLD}Dentro del chat:{RESET}
  <nombre-caso>             cargar caso
  <ruta>                    ingestar evidencia
  abre <caso>               cambiar de caso
  nuevo <nombre>            crear caso
  casos                     listar casos
  resumen                   ver estadísticas del caso activo
  exit                      salir
""")


# ── Helpers internos ──────────────────────────────────────────────────────────

def _resolve(name_or_path: str):
    from .case import NexusCase
    try:
        return NexusCase.resolve(name_or_path)
    except FileNotFoundError as e:
        print(f"\n  {RED}{e}{RESET}\n")
        sys.exit(1)


def _make_analyst(case, model: str):
    from .analyst import NexusAnalyst
    return NexusAnalyst(case.db_path, model=model, store_path=case.store_path)


def _sub_parser(name: str) -> argparse.ArgumentParser:
    return argparse.ArgumentParser(prog=f"nexus {name}")


def _die(msg: str):
    print(f"\n  {RED}Uso: {msg}{RESET}\n")
    sys.exit(1)


if __name__ == "__main__":
    main()
