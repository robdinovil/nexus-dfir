"""
Nexus Benchmark — mide calidad de NL→SQL y tasa de alucinaciones.

Métricas implementadas:
  Score / Hallucination / Self-correction / Latency
    (propias de Nexus)

  TUS — Task-level Understanding Score [DFIR-Metric, arxiv 2505.19973]
    4 criterios por pregunta → 0.0-1.0 (vs binario PASS/FAIL)
    C1: tablas correctas  C2: columnas correctas
    C3: filtros correctos C4: resultado en rango esperado

  RS — Reliability Score [DFIR-Metric]
    +1 correcto / -2 incorrecto / 0 skip → normalizado 0.0-1.0

  CCR — Context Recall (NonLLM) [RAGAS adaptado, sin LLM]
    % de términos clave recuperados por BM25 antes de la generación
    Mide calidad del retriever independientemente del LLM

  Categorías: enumeration, user_activity, network, timeline, processes,
    cross_table, persistence, anomaly, attribution, meta
"""

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

# ── Ground truth questions ────────────────────────────────────────────────────
# Cada entrada tiene:
#   question          — pregunta en lenguaje natural
#   expected_cols     — columnas que DEBEN aparecer en el resultado
#   must_contain      — keywords que deben estar en la SQL generada
#   must_not_contain  — columnas/keywords que NO deben aparecer (alucinaciones conocidas)
#   min_rows/max_rows — rango esperado de filas (None = no verificar)
#   applies_to        — tipos de DB donde aplica esta pregunta
#   category          — para métricas por categoría

BENCHMARK_QUESTIONS = [
    # ── Logon / autenticación ──────────────────────────────────────────────
    {
        "id": "B01",
        "question": "¿Cuántos eventos hay por cada event_id?",
        "must_contain":     ["event_id", "count"],
        "must_not_contain": ["logon_type", "event_type"],
        "expected_cols":    ["event_id"],
        "min_rows": 1,
        "applies_to": ["events"],
        "category": "enumeration",
    },
    {
        "id": "B02",
        "question": "¿Desde qué IPs se conectó el usuario administrator?",
        "must_contain":     ["source_ip", "administrator"],
        "must_not_contain": ["logon_type", "event_type"],
        "expected_cols":    ["source_ip"],
        "min_rows": 0,
        "applies_to": ["events"],
        "category": "user_activity",
    },
    {
        "id": "B03",
        "question": "¿Qué IPs externas aparecen en los eventos?",
        "must_contain":     ["source_ip", "10."],
        "must_not_contain": ["logon_type", "event_type"],
        "expected_cols":    ["source_ip"],
        "min_rows": 0,
        "applies_to": ["events"],
        "category": "network",
    },
    {
        "id": "B04",
        "question": "¿Cuántos eventos hay por usuario?",
        "must_contain":     ["username", "count"],
        "must_not_contain": ["logon_type", "domain"],
        "expected_cols":    ["username"],
        "min_rows": 1,
        "applies_to": ["events"],
        "category": "enumeration",
    },
    {
        "id": "B05",
        "question": "Muestra los primeros 10 eventos ordenados por fecha",
        "must_contain":     ["timestamp_utc", "limit"],
        "must_not_contain": ["logon_type"],
        "expected_cols":    ["timestamp_utc"],
        "min_rows": 1,
        "max_rows": 10,
        "applies_to": ["events"],
        "category": "timeline",
    },
    {
        "id": "B06",
        "question": "¿Cuál es el rango de fechas de los eventos?",
        "must_contain":     ["timestamp_utc", "min", "max"],
        "must_not_contain": ["logon_type"],
        "expected_cols":    [],
        "min_rows": 1,
        "max_rows": 1,
        "applies_to": ["events"],
        "category": "timeline",
    },
    {
        "id": "B07",
        "question": "¿Qué usuarios únicos hay en los eventos?",
        "must_contain":     ["username", "distinct"],
        "must_not_contain": ["logon_type", "domain"],
        "expected_cols":    ["username"],
        "min_rows": 1,
        "applies_to": ["events"],
        "category": "enumeration",
    },
    {
        "id": "B08",
        "question": "¿Qué equipos aparecen en los logs?",
        "must_contain":     ["computer"],
        "must_not_contain": ["logon_type", "hostname"],
        "expected_cols":    ["computer"],
        "min_rows": 1,
        "applies_to": ["events"],
        "category": "enumeration",
    },
    # ── Procesos ───────────────────────────────────────────────────────────
    {
        "id": "B09",
        "question": "¿Qué procesos corrían como SYSTEM?",
        "must_contain":     ["username", "system", "processes"],
        "must_not_contain": ["logon_type", "event_type"],
        "expected_cols":    ["name"],
        "min_rows": 0,
        "applies_to": ["processes"],
        "category": "processes",
    },
    {
        "id": "B10",
        "question": "¿Qué proceso tiene el PID más alto?",
        "must_contain":     ["pid", "processes"],
        "must_not_contain": ["logon_type"],
        "expected_cols":    ["pid"],
        "min_rows": 1,
        "applies_to": ["processes"],
        "category": "processes",
    },
    # ── Red ───────────────────────────────────────────────────────────────
    {
        "id": "B11",
        "question": "¿Qué conexiones de red estaban activas?",
        "must_contain":     ["network_connections", "state"],
        "must_not_contain": ["logon_type", "event_type"],
        "expected_cols":    ["state"],
        "min_rows": 0,
        "applies_to": ["network_connections"],
        "category": "network",
    },
    {
        "id": "B12",
        "question": "¿Qué procesos tenían conexiones externas establecidas?",
        "must_contain":     ["established", "network_connections"],
        "must_not_contain": ["logon_type"],
        "expected_cols":    [],
        "min_rows": 0,
        "applies_to": ["network_connections", "processes"],
        "category": "network",
    },
    # ── Cross-table (el diferenciador de Nexus) ────────────────────────────
    {
        "id": "B13",
        "question": "¿Qué proceso corresponde a cada conexión de red activa?",
        "must_contain":     ["join", "network_connections", "processes", "pid"],
        "must_not_contain": ["logon_type"],
        "expected_cols":    [],
        "min_rows": 0,
        "applies_to": ["network_connections", "processes"],
        "category": "cross_table",
    },
    # ── Persistencia ──────────────────────────────────────────────────────
    {
        "id": "B14",
        "question": "¿Qué tareas programadas existen?",
        "must_contain":     ["scheduled_tasks"],
        "must_not_contain": ["logon_type"],
        "expected_cols":    ["task_name"],
        "min_rows": 0,
        "applies_to": ["scheduled_tasks"],
        "category": "persistence",
    },
    {
        "id": "B15",
        "question": "¿Qué claves de registro de autorun existen?",
        "must_contain":     ["registry_keys"],
        "must_not_contain": ["logon_type", "event_type"],
        "expected_cols":    [],
        "min_rows": 0,
        "applies_to": ["registry_keys"],
        "category": "persistence",
    },
    # ── Detección de anomalías ─────────────────────────────────────────────
    {
        "id": "B16",
        "question": "¿Hay actividad fuera de horario laboral (antes de 8am o después de 8pm)?",
        "must_contain":     ["timestamp_utc", "strftime"],
        "must_not_contain": ["logon_type", "business_hours"],
        "expected_cols":    [],
        "min_rows": 0,
        "applies_to": ["events"],
        "category": "anomaly",
    },
    {
        "id": "B17",
        "question": "¿Cuántos eventos hay por día?",
        "must_contain":     ["date", "timestamp_utc", "count"],
        "must_not_contain": ["logon_type"],
        "expected_cols":    [],
        "min_rows": 1,
        "applies_to": ["events"],
        "category": "timeline",
    },
    {
        "id": "B18",
        "question": "¿Qué usuario tiene más eventos en la base de datos?",
        "must_contain":     ["username", "count"],
        "must_not_contain": ["logon_type", "domain"],
        "expected_cols":    ["username"],
        "min_rows": 1,
        "max_rows": 1,
        "applies_to": ["events"],
        "category": "enumeration",
    },
    {
        "id": "B19",
        "question": "¿Desde qué IP hay más actividad?",
        "must_contain":     ["source_ip", "count", "limit"],
        "must_not_contain": ["logon_type"],
        "expected_cols":    ["source_ip"],
        "min_rows": 1,
        "max_rows": 1,
        "applies_to": ["events"],
        "category": "network",
    },
    {
        "id": "B20",
        "question": "Resume la evidencia disponible: cuántos archivos, qué tipos, cuántos registros",
        "must_contain":     ["evidence_files"],
        "must_not_contain": ["logon_type"],
        "expected_cols":    [],
        "min_rows": 1,
        "applies_to": [],  # siempre aplica
        "category": "meta",
    },
    # ── SANS FIND EVIL — preguntas de investigación de incidente ──────────
    # Estas reflejan el estilo del hackathon: preguntas concretas sobre
    # el ataque, no solo enumeración.
    {
        "id": "B21",
        "question": "¿Cuál fue el primer evento de logon exitoso registrado?",
        "must_contain":     ["timestamp_utc", "order", "limit"],
        "must_not_contain": ["logon_type"],
        "expected_cols":    ["timestamp_utc"],
        "min_rows": 1,
        "max_rows": 1,
        "applies_to": ["events"],
        "category": "timeline",
    },
    {
        "id": "B22",
        "question": "¿Qué proceso tiene más conexiones externas establecidas?",
        "must_contain":     ["join", "network_connections", "processes", "established"],
        "must_not_contain": ["logon_type"],
        "expected_cols":    [],
        "min_rows": 0,
        "applies_to": ["network_connections", "processes"],
        "category": "attribution",
    },
    {
        "id": "B23",
        "question": "¿Hay procesos corriendo desde directorios temporales o AppData?",
        "must_contain":     ["exe_path", "processes"],
        "must_not_contain": ["logon_type", "event_type"],
        "expected_cols":    ["name"],
        "min_rows": 0,
        "applies_to": ["processes"],
        "category": "anomaly",
    },
    {
        "id": "B24",
        "question": "¿Cuáles son los 5 usuarios con más eventos de autenticación fallida?",
        "must_contain":     ["username", "count", "limit"],
        "must_not_contain": ["logon_type"],
        "expected_cols":    ["username"],
        "min_rows": 0,
        "max_rows": 5,
        "applies_to": ["events"],
        "category": "user_activity",
    },
    {
        "id": "B25",
        "question": "¿Qué usuario se autenticó en horario nocturno (entre las 00:00 y las 06:00)?",
        "must_contain":     ["username", "timestamp_utc", "strftime"],
        "must_not_contain": ["logon_type"],
        "expected_cols":    ["username"],
        "min_rows": 0,
        "applies_to": ["events"],
        "category": "anomaly",
    },
]


@dataclass
class QuestionResult:
    id: str
    question: str
    category: str
    sql_generated: str | None
    rows_returned: int | None
    passed: bool
    hallucination_type: str | None       # tipo FINAL (después de retry si lo hubo)
    first_hallucination_type: str | None # tipo del PRIMER intento (None = limpio)
    self_corrected: bool                 # alucinó pero el validador lo arregló
    issues: list[str]
    elapsed_s: float
    tus_score: float = 0.0               # TUS: 0.0-1.0 (DFIR-Metric)
    context_recall: float = 1.0          # CCR: BM25 retrieval coverage (RAGAS NonLLM)


@dataclass
class BenchmarkReport:
    db_path: str
    model: str
    total: int
    passed: int
    failed: int
    hallucinations: dict          # {structural, referential, syntax} — alucinaciones NO resueltas
    self_corrections: int         # alucinaciones detectadas Y auto-corregidas
    by_category: dict
    results: list[QuestionResult]
    elapsed_total_s: float

    @property
    def score(self) -> float:
        return self.passed / self.total if self.total > 0 else 0.0

    @property
    def hallucination_rate(self) -> float:
        """Alucinaciones NO resueltas / total."""
        total_h = sum(self.hallucinations.values())
        return total_h / self.total if self.total > 0 else 0.0

    @property
    def self_correction_rate(self) -> float:
        """% de alucinaciones que el validador detectó y auto-corrigió."""
        total_triggered = self.self_corrections + sum(self.hallucinations.values())
        if total_triggered == 0:
            return 1.0
        return self.self_corrections / total_triggered

    @property
    def tus_avg(self) -> float:
        """TUS promedio — Task-level Understanding Score [DFIR-Metric]."""
        if not self.results:
            return 0.0
        return sum(r.tus_score for r in self.results) / len(self.results)

    @property
    def reliability_score(self) -> float:
        """RS normalizado 0-1: +1 correcto / -2 incorrecto [DFIR-Metric]."""
        if not self.results:
            return 0.0
        rs_raw = sum(1 if r.passed else -2 for r in self.results)
        # mapea [-2N, N] → [0, 1]
        return (rs_raw + 2 * len(self.results)) / (3 * len(self.results))

    @property
    def context_recall_avg(self) -> float:
        """CCR promedio — NonLLM Context Recall del retriever BM25 [RAGAS adaptado]."""
        if not self.results:
            return 0.0
        return sum(r.context_recall for r in self.results) / len(self.results)

    @property
    def avg_latency(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.elapsed_s for r in self.results) / len(self.results)

    @property
    def p95_latency(self) -> float:
        if not self.results:
            return 0.0
        times = sorted(r.elapsed_s for r in self.results)
        idx = int(len(times) * 0.95)
        return times[min(idx, len(times) - 1)]


# ── TUS / RS / CCR helpers ────────────────────────────────────────────────────

def _compute_tus(q: dict, sql_lower: str, rows: int | None) -> float:
    """
    Task-level Understanding Score — 4 criterios binarios, promedio → 0.0-1.0.
    Fuente: DFIR-Metric (arxiv 2505.19973), adaptado para NL→SQL.
    """
    scores: list[float] = []

    # C1: tablas correctas — applies_to tables presentes en FROM/JOIN
    tables = q.get("applies_to", [])
    if tables:
        scores.append(float(all(t in sql_lower for t in tables)))

    # C2: columnas objetivo — expected_cols en SELECT o WHERE
    cols = q.get("expected_cols", [])
    if cols:
        scores.append(float(all(c.lower() in sql_lower for c in cols)))

    # C3: filtros/keywords — fracción de must_contain presentes
    mc = q.get("must_contain", [])
    if mc:
        scores.append(sum(1 for kw in mc if kw.lower() in sql_lower) / len(mc))

    # C4: resultado en rango esperado
    min_r = q.get("min_rows")
    max_r = q.get("max_rows")
    if rows is not None and (min_r is not None or max_r is not None):
        c4 = (min_r is None or rows >= min_r) and (max_r is None or rows <= max_r)
        scores.append(float(c4))

    return sum(scores) / len(scores) if scores else 0.0


def _compute_context_recall(question: str, q: dict, analyst) -> float:
    """
    NonLLM Context Recall — % de términos clave presentes en top-5 docs BM25.
    Mide si el retriever recuperó lo necesario para responder la pregunta.
    Fuente: RAGAS NonLLMContextRecall, adaptado sin LLM judge.
    """
    from .vectorstore import _bm25_scores

    needed: set[str] = set()
    needed.update(q.get("applies_to", []))
    needed.update(c.lower() for c in q.get("expected_cols", []) if c)
    needed.update(kw.lower() for kw in q.get("must_contain", []))
    needed.discard("")

    if not needed:
        return 1.0

    all_docs = analyst._store.get_all_docs()
    if not all_docs:
        return 0.0

    scores = _bm25_scores(question, all_docs)
    ranked = sorted(zip(scores, all_docs), key=lambda x: x[0], reverse=True)
    top5 = " ".join(doc.lower() for _, doc in ranked[:5])

    return sum(1 for term in needed if term in top5) / len(needed)


def run(db_path: str, model: str = "qwen2.5:7b-instruct",
        save_json: bool = True) -> BenchmarkReport:
    from .analyst import NexusAnalyst
    from .validator import validate

    analyst = NexusAnalyst(db_path, model=model)
    analyst.train()

    active = set(analyst._active_tables)
    results = []
    t_start = time.time()

    BOLD   = "\033[1m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    RESET  = "\033[0m"

    print(f"\n{CYAN}{BOLD}{'─'*65}{RESET}")
    print(f"{CYAN}{BOLD}  Nexus Benchmark — {Path(db_path).stem}{RESET}")
    print(f"{CYAN}{BOLD}{'─'*65}{RESET}")
    print(f"  {'ID':<5} {'Categoría':<15} {'Estado':<12} {'Alucinación':<16} {'s':>5}  Pregunta")
    print(f"  {'─'*4} {'─'*13} {'─'*10} {'─'*14} {'─'*5}  {'─'*30}")

    for q in BENCHMARK_QUESTIONS:
        required = set(q["applies_to"])
        if required and not (required & active):
            continue

        t0 = time.time()
        try:
            result = analyst.ask(q["question"], verbose=False)
        except Exception as exc:
            elapsed = round(time.time() - t0, 1)
            issues = [f"exception: {type(exc).__name__}"]
            print(f"  {q['id']:<5} {q['category']:<15} {RED}ERROR{RESET:<16}  ─                      {elapsed:>5}s  {q['question'][:35]}")
            results.append(QuestionResult(
                id=q["id"], question=q["question"], category=q["category"],
                sql_generated=None, rows_returned=None, passed=False,
                hallucination_type=None, first_hallucination_type=None,
                self_corrected=False, issues=issues, elapsed_s=elapsed,
            ))
            continue
        elapsed = round(time.time() - t0, 1)

        sql              = result.get("sql") or ""
        df               = result.get("result")
        err              = result.get("error")
        h                = result.get("hallucination")
        first_h          = result.get("first_hallucination_type")
        self_corrected   = result.get("self_corrected", False)
        rows             = len(df) if df is not None else None

        issues = []

        sql_lower = sql.lower()
        for kw in q["must_contain"]:
            if kw.lower() not in sql_lower:
                issues.append(f"missing '{kw}'")

        for kw in q["must_not_contain"]:
            if kw.lower() in sql_lower:
                issues.append(f"hallucinated '{kw}'")

        if rows is not None:
            if q.get("min_rows") is not None and rows < q["min_rows"]:
                issues.append(f"too few rows: {rows} < {q['min_rows']}")
            if q.get("max_rows") is not None and rows > q["max_rows"]:
                issues.append(f"too many rows: {rows} > {q['max_rows']}")

        if err and "logon_type" in err:
            h = "structural"
            issues.append("column_logon_type")

        passed = len(issues) == 0 and err is None

        # Métricas adicionales (sin LLM)
        tus   = _compute_tus(q, sql_lower, rows)
        ccr   = _compute_context_recall(q["question"], q, analyst)

        status_str = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"

        # Alucinación display: mostrar first_h si se auto-corrigió (success story)
        display_h = first_h if self_corrected else h
        h_color = GREEN if self_corrected else YELLOW
        h_suffix = "✓" if self_corrected else ""
        h_str = f"{h_color}{display_h}{h_suffix}{RESET}" if display_h else "─"

        q_short = q["question"][:35]
        print(f"  {q['id']:<5} {q['category']:<15} {status_str:<20} {h_str:<30} {elapsed:>5}s  {q_short}")

        results.append(QuestionResult(
            id=q["id"], question=q["question"], category=q["category"],
            sql_generated=sql, rows_returned=rows, passed=passed,
            hallucination_type=h, first_hallucination_type=first_h,
            self_corrected=self_corrected, issues=issues, elapsed_s=elapsed,
            tus_score=tus, context_recall=ccr,
        ))

    analyst.close()
    elapsed_total = round(time.time() - t_start, 1)

    # Agregar resultados
    total   = len(results)
    passed  = sum(1 for r in results if r.passed)
    failed  = total - passed

    # Alucinaciones NO resueltas (final state tiene h_type)
    h_types = {"structural": 0, "referential": 0, "syntax": 0}
    for r in results:
        if r.hallucination_type in h_types:
            h_types[r.hallucination_type] += 1

    # Alucinaciones auto-corregidas
    self_corrections = sum(1 for r in results if r.self_corrected)

    by_cat: dict[str, dict] = {}
    for r in results:
        cat = r.category
        if cat not in by_cat:
            by_cat[cat] = {"total": 0, "passed": 0}
        by_cat[cat]["total"] += 1
        if r.passed:
            by_cat[cat]["passed"] += 1

    report = BenchmarkReport(
        db_path=db_path, model=model,
        total=total, passed=passed, failed=failed,
        hallucinations=h_types,
        self_corrections=self_corrections,
        by_category=by_cat,
        results=results,
        elapsed_total_s=elapsed_total,
    )

    _print_summary(report)

    if save_json:
        out = Path(db_path).stem + "_benchmark.json"
        _save_json(report, out)
        print(f"\n  Reporte guardado: {out}\n")

    return report


def _print_summary(r: BenchmarkReport) -> None:
    BOLD   = "\033[1m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    RESET  = "\033[0m"

    score_color = GREEN if r.score >= 0.8 else YELLOW if r.score >= 0.6 else RED
    sc_color    = GREEN if r.self_correction_rate >= 0.7 else YELLOW
    tus_color   = GREEN if r.tus_avg >= 0.8 else YELLOW if r.tus_avg >= 0.6 else RED
    rs_color    = GREEN if r.reliability_score >= 0.8 else YELLOW if r.reliability_score >= 0.6 else RED
    ccr_color   = GREEN if r.context_recall_avg >= 0.8 else YELLOW

    h_total = sum(r.hallucinations.values())

    print(f"\n{CYAN}{BOLD}{'─'*65}{RESET}")
    print(f"{CYAN}{BOLD}  RESUMEN{RESET}")
    print(f"  Score  (PASS/FAIL)  : {score_color}{BOLD}{r.passed}/{r.total} ({r.score:.0%}){RESET}")
    print(f"  TUS    (0-1.0)      : {tus_color}{BOLD}{r.tus_avg:.3f}{RESET}  ← partial credit [DFIR-Metric]")
    print(f"  RS     (0-1.0)      : {rs_color}{BOLD}{r.reliability_score:.3f}{RESET}  ← +1 correct / -2 wrong [DFIR-Metric]")
    print(f"  CCR    (0-1.0)      : {ccr_color}{BOLD}{r.context_recall_avg:.3f}{RESET}  ← BM25 retrieval coverage [RAGAS NonLLM]")
    print(f"  Halluc (no resuelto): {h_total}  "
          f"({r.hallucinations['structural']} struct / "
          f"{r.hallucinations['referential']} ref / "
          f"{r.hallucinations['syntax']} syntax)")
    print(f"  Auto-correcciones   : {sc_color}{r.self_corrections} "
          f"({r.self_correction_rate:.0%} de las detectadas){RESET}")
    print(f"  Latencia (avg/p95)  : {r.avg_latency:.1f}s / {r.p95_latency:.1f}s")
    print(f"  Tiempo total        : {r.elapsed_total_s:.0f}s")
    print()
    print(f"  {'Categoría':<18} {'Pass':<6} {'Total':<6} {'Score'}")
    print(f"  {'─'*16} {'─'*4} {'─'*4} {'─'*6}")
    for cat, stats in sorted(r.by_category.items()):
        s = stats["passed"] / stats["total"] if stats["total"] > 0 else 0
        color = GREEN if s >= 0.8 else YELLOW if s >= 0.5 else RED
        print(f"  {cat:<18} {stats['passed']:<6} {stats['total']:<6} {color}{s:.0%}{RESET}")

    # Issues más frecuentes
    all_issues: list[str] = []
    for res in r.results:
        all_issues.extend(res.issues)
    if all_issues:
        from collections import Counter
        top = Counter(all_issues).most_common(5)
        print(f"\n  Issues más frecuentes:")
        for issue, cnt in top:
            print(f"    {cnt}x  {issue}")
    print()


def _save_json(r: BenchmarkReport, path: str) -> None:
    data = {
        "db": r.db_path,
        "model": r.model,
        # ── Nexus métricas propias ─────────────────────────────────────────
        "score": round(r.score, 3),
        "hallucination_rate": round(r.hallucination_rate, 3),
        "self_correction_rate": round(r.self_correction_rate, 3),
        # ── DFIR-Metric (arxiv 2505.19973) ────────────────────────────────
        "tus_avg": round(r.tus_avg, 3),
        "reliability_score": round(r.reliability_score, 3),
        # ── RAGAS NonLLM Context Recall ────────────────────────────────────
        "context_recall_avg": round(r.context_recall_avg, 3),
        # ── Latencia ──────────────────────────────────────────────────────
        "avg_latency_s": round(r.avg_latency, 1),
        "p95_latency_s": round(r.p95_latency, 1),
        "elapsed_total_s": r.elapsed_total_s,
        "total": r.total, "passed": r.passed, "failed": r.failed,
        "hallucinations": r.hallucinations,
        "self_corrections": r.self_corrections,
        "by_category": r.by_category,
        "results": [
            {
                "id": res.id,
                "question": res.question,
                "category": res.category,
                "passed": res.passed,
                "tus_score": round(res.tus_score, 3),
                "context_recall": round(res.context_recall, 3),
                "hallucination_type": res.hallucination_type,
                "first_hallucination_type": res.first_hallucination_type,
                "self_corrected": res.self_corrected,
                "issues": res.issues,
                "elapsed_s": res.elapsed_s,
                "sql": res.sql_generated,
                "rows": res.rows_returned,
            }
            for res in r.results
        ],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
