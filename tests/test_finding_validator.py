"""Tests para FindingValidator — confianza y FP risk de threat hunt findings."""

import pytest
from nexus.finding_validator import validate_finding, enrich_hits, FindingValidation


# ── validate_finding ──────────────────────────────────────────────────────────

def test_zero_count_returns_zero_confidence():
    v = validate_finding("T1003", count=0)
    assert v.confidence == 0.0


def test_single_hit_low_confidence():
    v = validate_finding("T1071.001", count=1)
    assert v.confidence < 0.6
    assert any("single hit" in n for n in v.notes)


def test_high_count_raises_confidence():
    v = validate_finding("T1003", count=15)
    assert v.confidence >= 0.80


def test_low_fp_risk_boosts_confidence():
    v_low = validate_finding("T1003", count=3)      # fp_risk=low
    v_med = validate_finding("T1059.001", count=3)  # fp_risk=medium
    assert v_low.confidence > v_med.confidence


def test_high_fp_risk_reduces_confidence():
    v_high = validate_finding("T1547.001", count=3)  # fp_risk=high
    v_med  = validate_finding("T1059.001", count=3)  # fp_risk=medium
    assert v_high.confidence < v_med.confidence


def test_corroboration_boosts_confidence():
    v_no  = validate_finding("T1071.001", count=5, corroborated=False)
    v_yes = validate_finding("T1071.001", count=5, corroborated=True)
    assert v_yes.confidence > v_no.confidence
    assert any("cross-table" in n for n in v_yes.notes)


def test_confidence_capped_at_one():
    v = validate_finding("T1003", count=100, corroborated=True)
    assert v.confidence <= 1.0


def test_confidence_floored_at_zero():
    v = validate_finding("T1547.001", count=1)
    assert v.confidence >= 0.0


def test_fp_risk_populated():
    v = validate_finding("T1003", count=5)
    assert v.fp_risk == "low"

    v2 = validate_finding("T1547.001", count=5)
    assert v2.fp_risk == "high"


def test_unknown_rule_defaults_medium():
    v = validate_finding("T9999", count=5)
    assert v.fp_risk == "medium"


# ── risk_label property ───────────────────────────────────────────────────────

def test_risk_label_confirmed():
    v = FindingValidation(rule_id="T1003", confidence=0.85, fp_risk="low",
                          corroborated=False)
    assert v.risk_label == "CONFIRMED"


def test_risk_label_likely():
    v = FindingValidation(rule_id="T1003", confidence=0.65, fp_risk="low",
                          corroborated=False)
    assert v.risk_label == "LIKELY"


def test_risk_label_possible():
    v = FindingValidation(rule_id="T1003", confidence=0.45, fp_risk="medium",
                          corroborated=False)
    assert v.risk_label == "POSSIBLE"


def test_risk_label_weak():
    v = FindingValidation(rule_id="T1003", confidence=0.30, fp_risk="high",
                          corroborated=False)
    assert v.risk_label == "WEAK"


# ── enrich_hits ───────────────────────────────────────────────────────────────

def _make_hit(rule_id, table, count):
    import pandas as pd
    return {
        "rule_id":  rule_id,
        "severity": "HIGH",
        "name":     f"Rule {rule_id}",
        "table":    table,
        "rows":     pd.DataFrame({"col": range(count)}),
        "count":    count,
    }


def test_enrich_adds_validation_key():
    hits = [_make_hit("T1003", "processes", 3)]
    enriched = enrich_hits(hits)
    assert "validation" in enriched[0]
    assert isinstance(enriched[0]["validation"], FindingValidation)


def test_enrich_single_table_not_corroborated():
    hits = [
        _make_hit("T1003",    "processes", 3),
        _make_hit("T1059.001","processes", 2),
    ]
    enriched = enrich_hits(hits)
    for h in enriched:
        assert not h["validation"].corroborated


def test_enrich_multi_table_corroborated():
    hits = [
        _make_hit("T1003",    "processes",           3),
        _make_hit("T1071.001","network_connections",  2),
    ]
    enriched = enrich_hits(hits)
    for h in enriched:
        assert h["validation"].corroborated


def test_enrich_preserves_original_keys():
    hits = [_make_hit("T1003", "processes", 5)]
    enriched = enrich_hits(hits)
    for key in ("rule_id", "severity", "name", "table", "rows", "count"):
        assert key in enriched[0]


def test_enrich_empty_list():
    assert enrich_hits([]) == []
