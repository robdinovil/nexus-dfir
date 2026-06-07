"""Tests para _save_json y _print_summary de benchmark.py."""

import json
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from nexus.benchmark import (
    BenchmarkReport, QuestionResult,
    _save_json, _print_summary,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _result(passed, *, h_type=None, first_h=None, sc=False,
            tus=0.9, ccr=0.95, cat="enumeration", elapsed=1.5):
    return QuestionResult(
        id="B01", question="¿cuántos eventos hay?", category=cat,
        sql_generated="SELECT COUNT(*) FROM events",
        rows_returned=5,
        passed=passed,
        hallucination_type=h_type,
        first_hallucination_type=first_h,
        self_corrected=sc,
        issues=[], elapsed_s=elapsed,
        tus_score=tus, context_recall=ccr,
    )


def _report(*results, model="qwen2.5:7b-instruct"):
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
        db_path="lockbit_case.db",
        model=model,
        total=len(results), passed=passed, failed=len(results) - passed,
        hallucinations=h_types,
        self_corrections=sum(1 for r in results if r.self_corrected),
        by_category=by_cat,
        results=list(results),
        elapsed_total_s=30.5,
    )


# ── _save_json ────────────────────────────────────────────────────────────────

def test_save_json_creates_file(tmp_path):
    report = _report(_result(True), _result(False, h_type="structural"))
    out = str(tmp_path / "bench.json")
    _save_json(report, out)
    assert Path(out).exists()


def test_save_json_valid_json(tmp_path):
    report = _report(_result(True))
    out = str(tmp_path / "bench.json")
    _save_json(report, out)
    with open(out) as f:
        data = json.load(f)
    assert isinstance(data, dict)


def test_save_json_contains_required_keys(tmp_path):
    report = _report(_result(True), _result(False))
    out = str(tmp_path / "bench.json")
    _save_json(report, out)
    with open(out) as f:
        d = json.load(f)
    for key in ("db", "model", "score", "tus_avg", "reliability_score",
                "context_recall_avg", "hallucination_rate", "self_correction_rate",
                "total", "passed", "failed", "hallucinations", "by_category", "results"):
        assert key in d, f"missing key: {key}"


def test_save_json_score_precision(tmp_path):
    report = _report(_result(True), _result(True), _result(False))
    out = str(tmp_path / "bench.json")
    _save_json(report, out)
    with open(out) as f:
        d = json.load(f)
    assert d["score"] == pytest.approx(2 / 3, abs=0.01)


def test_save_json_results_array(tmp_path):
    report = _report(_result(True), _result(False, h_type="referential"))
    out = str(tmp_path / "bench.json")
    _save_json(report, out)
    with open(out) as f:
        d = json.load(f)
    assert len(d["results"]) == 2
    r0 = d["results"][0]
    for key in ("id", "question", "category", "passed", "tus_score",
                "context_recall", "hallucination_type", "self_corrected",
                "issues", "elapsed_s", "sql", "rows"):
        assert key in r0, f"missing per-result key: {key}"


def test_save_json_hallucination_counts(tmp_path):
    report = _report(
        _result(False, h_type="structural"),
        _result(False, h_type="referential"),
        _result(False, h_type="syntax"),
        _result(True),
    )
    out = str(tmp_path / "bench.json")
    _save_json(report, out)
    with open(out) as f:
        d = json.load(f)
    assert d["hallucinations"]["structural"] == 1
    assert d["hallucinations"]["referential"] == 1
    assert d["hallucinations"]["syntax"] == 1


def test_save_json_tus_avg_in_range(tmp_path):
    report = _report(_result(True, tus=0.8), _result(True, tus=0.6))
    out = str(tmp_path / "bench.json")
    _save_json(report, out)
    with open(out) as f:
        d = json.load(f)
    assert 0.0 <= d["tus_avg"] <= 1.0
    assert d["tus_avg"] == pytest.approx(0.7)


def test_save_json_latency_fields(tmp_path):
    r1 = _result(True, elapsed=10.0)
    r2 = _result(True, elapsed=20.0)
    report = _report(r1, r2)
    out = str(tmp_path / "bench.json")
    _save_json(report, out)
    with open(out) as f:
        d = json.load(f)
    assert d["avg_latency_s"] == pytest.approx(15.0)
    assert "p95_latency_s" in d
    assert d["elapsed_total_s"] == 30.5


# ── _print_summary ────────────────────────────────────────────────────────────

def test_print_summary_no_crash():
    report = _report(_result(True), _result(False, h_type="structural"))
    _print_summary(report)  # solo verifica que no lanza excepción


def test_print_summary_contains_score(capsys):
    report = _report(_result(True), _result(True))
    _print_summary(report)
    out = capsys.readouterr().out
    assert "2/2" in out or "100%" in out


def test_print_summary_contains_categories(capsys):
    report = _report(
        _result(True, cat="enumeration"),
        _result(False, cat="user_activity"),
    )
    _print_summary(report)
    out = capsys.readouterr().out
    assert "enumeration" in out
    assert "user_activity" in out


def test_print_summary_shows_tus(capsys):
    report = _report(_result(True, tus=0.875))
    _print_summary(report)
    out = capsys.readouterr().out
    assert "TUS" in out


def test_print_summary_shows_issues(capsys):
    r = _result(False)
    r.issues = ["missing 'count'", "missing 'count'", "hallucinated 'logon_type'"]
    report = _report(r)
    _print_summary(report)
    out = capsys.readouterr().out
    assert "Issues" in out or "missing" in out
