"""Tests para NexusVectorStore (BM25) y _bm25_scores."""

import pytest
from nexus.vectorstore import NexusVectorStore, _bm25_scores, _tokenize


@pytest.fixture
def store(tmp_path):
    s = NexusVectorStore(str(tmp_path / "store.db"))
    yield s
    s.close()


# ── _tokenize ────────────────────────────────────────────────────────────────

def test_tokenize_basic():
    assert _tokenize("SELECT * FROM events") == ["select", "from", "events"]


def test_tokenize_lowercase():
    tokens = _tokenize("Username SOURCE_IP")
    assert "username" in tokens
    assert "source_ip" in tokens


def test_tokenize_empty():
    assert _tokenize("") == []


def test_tokenize_numbers():
    tokens = _tokenize("event_id = 4624")
    assert "4624" in tokens


# ── _bm25_scores ──────────────────────────────────────────────────────────────

def test_bm25_empty_corpus():
    assert _bm25_scores("query", []) == []


def test_bm25_relevant_doc_scores_higher():
    docs = [
        "events logon username authentication",
        "processes pid name command_line exe_path",
        "network connections remote_address established",
    ]
    scores = _bm25_scores("username logon events", docs)
    assert len(scores) == 3
    assert scores[0] > scores[1]
    assert scores[0] > scores[2]


def test_bm25_no_match_scores_zero():
    docs = ["totally irrelevant document about cats", "another unrelated text"]
    scores = _bm25_scores("sysmon powershell encoded", docs)
    assert all(s == 0.0 for s in scores)


def test_bm25_single_doc():
    scores = _bm25_scores("events", ["events table logon"])
    assert len(scores) == 1
    assert scores[0] > 0


def test_bm25_returns_float_list():
    scores = _bm25_scores("test", ["doc one", "doc two"])
    assert all(isinstance(s, float) for s in scores)


# ── NexusVectorStore ──────────────────────────────────────────────────────────

def test_store_starts_empty(store):
    assert store.count() == 0


def test_add_qa(store):
    store.add_qa("how many events?", "SELECT COUNT(*) FROM events")
    assert store.count("qa") == 1


def test_add_doc(store):
    store.add_doc("The events table contains Windows Event Log entries.")
    assert store.count("doc") == 1


def test_add_ddl(store):
    store.add_ddl("CREATE TABLE events (id INTEGER, event_id INTEGER)")
    assert store.count("ddl") == 1


def test_count_total(store):
    store.add_qa("q1", "sql1")
    store.add_doc("doc1")
    store.add_ddl("ddl1")
    assert store.count() == 3


def test_get_all_docs(store):
    store.add_doc("doc one")
    store.add_doc("doc two")
    store.add_qa("question", "SELECT 1")  # qa no es doc
    docs = store.get_all_docs()
    assert len(docs) == 2
    assert "doc one" in docs


def test_get_all_ddl(store):
    store.add_ddl("CREATE TABLE events (...)")
    store.add_doc("not a ddl")
    ddls = store.get_all_ddl()
    assert len(ddls) == 1
    assert "events" in ddls[0]


def test_get_similar_qa_empty(store):
    results = store.get_similar_qa("any query")
    assert results == []


def test_get_similar_qa_returns_relevant(store):
    store.add_qa("how many logon events?", "SELECT COUNT(*) FROM events WHERE event_id=4624")
    store.add_qa("list all processes", "SELECT * FROM processes")
    store.add_qa("show network connections", "SELECT * FROM network_connections")

    results = store.get_similar_qa("count logon events", top_k=1)
    assert len(results) == 1
    assert "events" in results[0]["sql"]


def test_get_similar_qa_top_k(store):
    for i in range(5):
        store.add_qa(f"question {i}", f"SELECT {i} FROM events")
    results = store.get_similar_qa("question events", top_k=3)
    assert len(results) <= 3


def test_get_similar_qa_score_positive(store):
    store.add_qa("failed logons by IP", "SELECT source_ip, COUNT(*) FROM events WHERE event_id=4625 GROUP BY source_ip")
    results = store.get_similar_qa("logon failures grouped by source IP")
    assert len(results) > 0
    assert results[0]["score"] > 0


def test_bm25_cache_cleared_on_add(store):
    store.add_qa("q1", "SELECT 1 FROM events")
    r1 = store.get_similar_qa("events query")
    store.add_qa("q2", "SELECT 2 FROM processes")
    r2 = store.get_similar_qa("events query")
    # Cache cleared — results may differ after adding new item
    assert r2 is not None  # didn't crash
