"""Unit tests for benchmark metric calculations — TUS, RS, CCR, BenchmarkReport."""

import pytest
from nexus.benchmark import _compute_tus, _compute_context_recall, BenchmarkReport, QuestionResult


# ── Mock analyst for CCR tests ────────────────────────────────────────────────

class _MockStore:
    def __init__(self, docs):
        self._docs = docs

    def get_all_docs(self):
        return self._docs

    def get_similar_qa(self, query: str, top_k: int = 5) -> list[dict]:
        return [{"question": doc, "sql": doc, "score": 1.0} for doc in self._docs[:top_k]]


class _MockAnalyst:
    def __init__(self, docs):
        self._store = _MockStore(docs)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _result(passed, *, self_corrected=False, h_type=None, first_h=None,
            tus=0.8, ccr=0.9, category="test"):
    return QuestionResult(
        id="B00", question="test", category=category,
        sql_generated="SELECT 1", rows_returned=1,
        passed=passed,
        hallucination_type=h_type,
        first_hallucination_type=first_h,
        self_corrected=self_corrected,
        issues=[], elapsed_s=1.0,
        tus_score=tus, context_recall=ccr,
    )


def _report(*results):
    passed = sum(1 for r in results if r.passed)
    h_types = {"structural": 0, "referential": 0, "syntax": 0}
    for r in results:
        if r.hallucination_type in h_types:
            h_types[r.hallucination_type] += 1
    by_cat: dict = {}
    for r in results:
        c = r.category
        by_cat.setdefault(c, {"total": 0, "passed": 0})
        by_cat[c]["total"] += 1
        if r.passed:
            by_cat[c]["passed"] += 1
    return BenchmarkReport(
        db_path="test.db", model="test",
        total=len(results), passed=passed, failed=len(results) - passed,
        hallucinations=h_types,
        self_corrections=sum(1 for r in results if r.self_corrected),
        by_category=by_cat,
        results=list(results),
        elapsed_total_s=10.0,
    )


# ── _compute_tus ──────────────────────────────────────────────────────────────

def test_tus_all_criteria_pass():
    q = {
        "applies_to":   ["events"],
        "expected_cols": ["username"],
        "must_contain":  ["count", "group"],
        "min_rows": 1,
    }
    sql = "select count(*) as c, username from events group by username"
    assert _compute_tus(q, sql, rows=5) == 1.0


def test_tus_wrong_table():
    q = {"applies_to": ["processes"], "expected_cols": [], "must_contain": []}
    sql = "select * from events"
    assert _compute_tus(q, sql, rows=None) == 0.0


def test_tus_partial_must_contain():
    q = {"applies_to": [], "expected_cols": [], "must_contain": ["count", "join", "limit"]}
    sql = "select count(*) from events limit 10"
    tus = _compute_tus(q, sql, rows=None)
    assert abs(tus - 2 / 3) < 0.01


def test_tus_must_contain_all_present():
    q = {"applies_to": [], "expected_cols": [], "must_contain": ["count", "group"]}
    sql = "select count(*), event_id from events group by event_id"
    assert _compute_tus(q, sql, rows=None) == 1.0


def test_tus_row_bounds_pass():
    q = {"applies_to": [], "expected_cols": [], "must_contain": [], "min_rows": 1, "max_rows": 5}
    assert _compute_tus(q, "select *", rows=3) == 1.0


def test_tus_row_bounds_too_few():
    q = {"applies_to": [], "expected_cols": [], "must_contain": [], "min_rows": 1}
    assert _compute_tus(q, "select *", rows=0) == 0.0


def test_tus_row_bounds_too_many():
    q = {"applies_to": [], "expected_cols": [], "must_contain": [], "max_rows": 5}
    assert _compute_tus(q, "select *", rows=6) == 0.0


def test_tus_no_criteria():
    q = {"applies_to": [], "expected_cols": [], "must_contain": []}
    assert _compute_tus(q, "select *", rows=None) == 0.0


def test_tus_rows_none_skips_c4():
    q = {"applies_to": [], "expected_cols": [], "must_contain": ["count"], "min_rows": 1}
    sql = "select count(*) from events"
    tus = _compute_tus(q, sql, rows=None)
    assert tus == 1.0  # only C3 applies (rows=None skips C4)


def test_tus_expected_cols_missing():
    q = {"applies_to": [], "expected_cols": ["username", "source_ip"], "must_contain": []}
    sql = "select event_id from events"
    assert _compute_tus(q, sql, rows=None) == 0.0


# ── BenchmarkReport.score ─────────────────────────────────────────────────────

def test_score_all_pass():
    assert _report(_result(True), _result(True)).score == 1.0


def test_score_all_fail():
    assert _report(_result(False), _result(False)).score == 0.0


def test_score_mixed():
    r = _report(_result(True), _result(False), _result(True), _result(False))
    assert r.score == 0.5


def test_score_empty():
    assert _report().score == 0.0


# ── BenchmarkReport.hallucination_rate ───────────────────────────────────────

def test_hallucination_rate_zero():
    r = _report(_result(True), _result(True))
    assert r.hallucination_rate == 0.0


def test_hallucination_rate_partial():
    r = _report(
        _result(True),
        _result(False, h_type="structural"),
        _result(False, h_type="referential"),
    )
    assert r.hallucination_rate == pytest.approx(2 / 3)


def test_hallucination_rate_syntax_counted():
    r = _report(_result(False, h_type="syntax"), _result(True))
    assert r.hallucination_rate == pytest.approx(0.5)


# ── BenchmarkReport.self_correction_rate ─────────────────────────────────────

def test_self_correction_rate_no_hallucinations():
    # Nothing triggered → perfect rate
    r = _report(_result(True), _result(True))
    assert r.self_correction_rate == 1.0


def test_self_correction_rate_full():
    # 2 triggered, 2 corrected → 100%
    r = _report(
        _result(True, self_corrected=True, first_h="structural"),
        _result(True, self_corrected=True, first_h="structural"),
    )
    assert r.self_correction_rate == 1.0


def test_self_correction_rate_partial():
    # 1 corrected, 1 unresolved → 50%
    r = _report(
        _result(True,  self_corrected=True, first_h="structural"),
        _result(False, h_type="structural"),
    )
    assert r.self_correction_rate == pytest.approx(0.5)


def test_self_correction_rate_none_corrected():
    r = _report(_result(False, h_type="structural"), _result(False, h_type="referential"))
    assert r.self_correction_rate == 0.0


# ── BenchmarkReport.tus_avg ──────────────────────────────────────────────────

def test_tus_avg_uniform():
    r = _report(_result(True, tus=0.8), _result(True, tus=0.8))
    assert r.tus_avg == pytest.approx(0.8)


def test_tus_avg_mixed():
    r = _report(_result(True, tus=0.8), _result(False, tus=0.4))
    assert r.tus_avg == pytest.approx(0.6)


def test_tus_avg_empty():
    assert _report().tus_avg == 0.0


# ── BenchmarkReport.reliability_score (RS) ───────────────────────────────────

def test_rs_all_correct():
    # RS_raw = N, normalized = (N + 2N) / 3N = 1.0
    r = _report(_result(True), _result(True), _result(True))
    assert r.reliability_score == pytest.approx(1.0)


def test_rs_all_wrong():
    # RS_raw = -2N, normalized = (-2N + 2N) / 3N = 0.0
    r = _report(_result(False), _result(False))
    assert r.reliability_score == pytest.approx(0.0)


def test_rs_mixed():
    # 3 correct (+1 each) + 1 wrong (-2) = rs_raw = 1
    # normalized = (1 + 2*4) / (3*4) = 9/12 = 0.75
    r = _report(_result(True), _result(True), _result(True), _result(False))
    assert r.reliability_score == pytest.approx(0.75)


def test_rs_empty():
    assert _report().reliability_score == 0.0


# ── BenchmarkReport.context_recall_avg (CCR) ─────────────────────────────────

def test_ccr_avg_uniform():
    r = _report(_result(True, ccr=0.9), _result(True, ccr=0.9))
    assert r.context_recall_avg == pytest.approx(0.9)


def test_ccr_avg_mixed():
    r = _report(_result(True, ccr=1.0), _result(True, ccr=0.6))
    assert r.context_recall_avg == pytest.approx(0.8)


def test_ccr_avg_empty():
    assert _report().context_recall_avg == 0.0


# ── _compute_context_recall ───────────────────────────────────────────────────

def test_ccr_no_needed_terms():
    q = {"applies_to": [], "expected_cols": [], "must_contain": []}
    ccr = _compute_context_recall("test", q, _MockAnalyst(["some doc"]))
    assert ccr == 1.0


def test_ccr_empty_store():
    q = {"applies_to": ["events"], "expected_cols": ["username"], "must_contain": ["count"]}
    ccr = _compute_context_recall("how many events?", q, _MockAnalyst([]))
    assert ccr == 0.0


def test_ccr_full_coverage():
    q = {"applies_to": ["events"], "expected_cols": ["username"], "must_contain": ["count"]}
    docs = [
        "The events table contains Windows Event Log. Column username is the account name.",
        "Use count() to aggregate. GROUP BY username for per-user stats.",
        "Another events doc with count and username references.",
    ]
    ccr = _compute_context_recall("count events by username", q, _MockAnalyst(docs))
    assert ccr == 1.0


def test_ccr_partial_coverage():
    q = {"applies_to": ["processes"], "expected_cols": ["pid"], "must_contain": ["name"]}
    docs = [
        "The events table has timestamps and usernames.",
        "Source IP column for network analysis.",
    ]
    ccr = _compute_context_recall("list processes", q, _MockAnalyst(docs))
    assert ccr < 0.5


# ── BenchmarkReport.avg_latency / p95_latency ────────────────────────────────

def test_latency_avg():
    results = [_result(True) for _ in range(4)]
    for i, r in enumerate(results):
        r.elapsed_s = float(i + 1)  # 1, 2, 3, 4
    rep = _report(*results)
    assert rep.avg_latency == pytest.approx(2.5)


def test_latency_p95_single():
    r = _result(True)
    r.elapsed_s = 5.0
    rep = _report(r)
    assert rep.p95_latency == 5.0
