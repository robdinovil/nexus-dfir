"""Nexus CLI — entry point global."""

import argparse
import sys
from pathlib import Path

BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
RESET  = "\033[0m"

DEFAULT_MODEL = "qwen2.5:7b-instruct"


def main():
    p = argparse.ArgumentParser(
        prog="nexus",
        description="Nexus — DFIR Evidence Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{BOLD}Flujo típico:{RESET}
  nexus new  <caso>               crear caso nuevo
  nexus ingest <caso> <dir>       ingestar evidencia
  nexus shell  <caso>             modo interactivo NL

{BOLD}Otros comandos:{RESET}
  nexus cases                     listar todos los casos
  nexus summary <caso>            resumen de evidencia cargada
  nexus ask <caso> "pregunta"     una sola pregunta
  nexus detect <path>             identificar tipos sin ingestar
  nexus train <caso>              entrenar vector store (manual)
  nexus benchmark <caso>          scorecard NL→SQL

{BOLD}Ejemplos:{RESET}
  nexus new lockbit2024
  nexus ingest lockbit2024 ~/evidencia/
  nexus shell lockbit2024
  nexus ask lockbit2024 "¿qué conexiones externas hay?"
        """,
    )
    sub = p.add_subparsers(dest="cmd", metavar="<comando>")

    # new
    c = sub.add_parser("new", help="Crear caso nuevo")
    c.add_argument("name", help="Nombre del caso")

    # cases
    sub.add_parser("cases", help="Listar todos los casos")

    # detect
    d = sub.add_parser("detect", help="Identificar tipos de evidencia sin ingestar")
    d.add_argument("path", help="Archivo o directorio")

    # ingest
    i = sub.add_parser("ingest", help="Ingestar evidencia en el caso")
    i.add_argument("case", help="Nombre del caso (o path a .db)")
    i.add_argument("path", help="Archivo o directorio de evidencia")

    # summary
    s = sub.add_parser("summary", help="Resumen de evidencia cargada")
    s.add_argument("case", help="Nombre del caso (o path a .db)")

    # train
    t = sub.add_parser("train", help="Entrenar vector store (normalmente automático)")
    t.add_argument("case", help="Nombre del caso (o path a .db)")
    t.add_argument("--model", default=DEFAULT_MODEL)
    t.add_argument("--force", action="store_true", help="Reentrenar desde cero")

    # ask
    a = sub.add_parser("ask", help="Una sola pregunta en lenguaje natural")
    a.add_argument("case", help="Nombre del caso (o path a .db)")
    a.add_argument("question", help="Pregunta forense")
    a.add_argument("--model", default=DEFAULT_MODEL)

    # shell
    sh = sub.add_parser("shell", help="Modo interactivo")
    sh.add_argument("case", help="Nombre del caso (o path a .db)")
    sh.add_argument("--model", default=DEFAULT_MODEL)

    # benchmark
    bm = sub.add_parser("benchmark", help="Scorecard NL→SQL")
    bm.add_argument("case", help="Nombre del caso (o path a .db)")
    bm.add_argument("--model", default=DEFAULT_MODEL)

    args = p.parse_args()

    # ── Dispatch ───────────────────────────────────────────────────────────────

    if args.cmd == "new":
        _cmd_new(args.name)

    elif args.cmd == "cases":
        _cmd_cases()

    elif args.cmd == "detect":
        _cmd_detect(args.path)

    elif args.cmd == "ingest":
        _cmd_ingest(args.case, args.path)

    elif args.cmd == "summary":
        _cmd_summary(args.case)

    elif args.cmd == "train":
        _cmd_train(args.case, args.model, args.force)

    elif args.cmd == "ask":
        _cmd_ask(args.case, args.question, args.model)

    elif args.cmd == "shell":
        _cmd_shell(args.case, args.model)

    elif args.cmd == "benchmark":
        _cmd_benchmark(args.case, args.model)

    else:
        p.print_help()
        sys.exit(1)


# ── Comandos ───────────────────────────────────────────────────────────────────

def _cmd_new(name: str):
    from .case import NexusCase
    try:
        case = NexusCase.create(name)
        print(f"\n  {GREEN}✓ Caso '{name}' creado{RESET}")
        print(f"  {CYAN}Ruta:{RESET} {case.path}")
        print(f"\n  Siguiente paso:")
        print(f"    nexus ingest {name} <directorio-de-evidencia>\n")
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
    from .case import NexusCase
    from .ingestor import Ingestor

    case   = _resolve(case_ref)
    target = Path(path)

    ing = Ingestor(case.db_path)
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
    from .router import NexusRouter
    from .ingestor import Ingestor

    case   = _resolve(case_ref)
    router = NexusRouter(case, model=model)

    # Mostrar resumen del caso al abrir
    ing = Ingestor(case.db_path)
    ing.summary()
    ing.close()

    print(f"  {CYAN}{BOLD}Nexus Shell — {case.name}{RESET}")
    print(f"  {CYAN}SQL · Threat Hunt · IOC Correlation — 'exit' para salir{RESET}\n")

    while True:
        try:
            q = input(f"{CYAN}nexus [{case.name}]>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Saliendo...")
            break
        if not q:
            continue
        if q.lower() in ("exit", "quit", "q", "salir"):
            break
        router.ask(q)

    router.close()


def _cmd_benchmark(case_ref: str, model: str):
    from .benchmark import run
    case = _resolve(case_ref)
    run(case.db_path, model=model)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _resolve(name_or_path: str):
    """Nombre de caso → NexusCase, o path .db → NexusCase (compat)."""
    from .case import NexusCase
    try:
        return NexusCase.resolve(name_or_path)
    except FileNotFoundError as e:
        print(f"\n  {RED}{e}{RESET}\n")
        sys.exit(1)


def _make_analyst(case, model: str):
    from .analyst import NexusAnalyst
    return NexusAnalyst(case.db_path, model=model, store_path=case.store_path)


if __name__ == "__main__":
    main()
