"""
NexusVectorStore — vector store minimalista para NL→SQL.

En lugar de ChromaDB (dependencias pesadas), usamos SQLite + BM25.
BM25 es el algoritmo de ranking de texto que usa Elasticsearch internamente.
Para nuestro caso (pocos miles de Q-SQL pairs) es más que suficiente y
no requiere GPU, embeddings, ni librerías externas.
"""

import sqlite3
import math
import re
from pathlib import Path


class NexusVectorStore:
    """
    Almacena pares (question, sql, doc) y recupera los más relevantes
    para una query usando BM25 (Okapi BM25).
    """

    def __init__(self, store_path: str):
        self.db = sqlite3.connect(store_path, check_same_thread=False)
        self._init_schema()
        self._bm25_cache = {}

    def _init_schema(self):
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS training_items (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                kind     TEXT NOT NULL,  -- 'qa', 'doc', 'ddl'
                question TEXT,
                sql      TEXT,
                content  TEXT NOT NULL,  -- texto indexable (question + sql o doc)
                added_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_kind ON training_items(kind);
        """)
        self.db.commit()

    def add_qa(self, question: str, sql: str) -> None:
        content = f"{question} {sql}"
        self.db.execute(
            "INSERT INTO training_items (kind, question, sql, content) VALUES ('qa',?,?,?)",
            (question, sql, content)
        )
        self.db.commit()
        self._bm25_cache.clear()

    def add_doc(self, doc: str) -> None:
        self.db.execute(
            "INSERT INTO training_items (kind, content) VALUES ('doc',?)",
            (doc,)
        )
        self.db.commit()
        self._bm25_cache.clear()

    def add_ddl(self, ddl: str) -> None:
        self.db.execute(
            "INSERT INTO training_items (kind, content) VALUES ('ddl',?)",
            (ddl,)
        )
        self.db.commit()

    def count(self, kind: str = None) -> int:
        if kind:
            return self.db.execute(
                "SELECT COUNT(*) FROM training_items WHERE kind=?", (kind,)
            ).fetchone()[0]
        return self.db.execute("SELECT COUNT(*) FROM training_items").fetchone()[0]

    def get_all_ddl(self) -> list[str]:
        rows = self.db.execute(
            "SELECT content FROM training_items WHERE kind='ddl'"
        ).fetchall()
        return [r[0] for r in rows]

    def get_all_docs(self) -> list[str]:
        rows = self.db.execute(
            "SELECT content FROM training_items WHERE kind='doc'"
        ).fetchall()
        return [r[0] for r in rows]

    def get_similar_qa(self, query: str, top_k: int = 5) -> list[dict]:
        """
        Recupera los top-k pares Q-SQL más similares a la query usando BM25.
        """
        rows = self.db.execute(
            "SELECT id, question, sql, content FROM training_items WHERE kind='qa'"
        ).fetchall()

        if not rows:
            return []

        corpus = [r[3] for r in rows]
        scores = _bm25_scores(query, corpus)

        ranked = sorted(zip(scores, rows), key=lambda x: x[0], reverse=True)
        results = []
        for score, row in ranked[:top_k]:
            if score > 0:
                results.append({"question": row[1], "sql": row[2], "score": score})
        return results

    def close(self):
        self.db.close()


# ── BM25 ──────────────────────────────────────────────────────────────────────

def _tokenize(text: str) -> list[str]:
    return re.findall(r"\w+", text.lower())


def _bm25_scores(query: str, corpus: list[str], k1: float = 1.5, b: float = 0.75) -> list[float]:
    """Okapi BM25 sobre una lista de documentos."""
    if not corpus:
        return []

    q_tokens = _tokenize(query)
    docs = [_tokenize(d) for d in corpus]
    n = len(docs)
    avg_dl = sum(len(d) for d in docs) / n

    # IDF por término
    idf: dict[str, float] = {}
    for term in set(q_tokens):
        df = sum(1 for d in docs if term in d)
        idf[term] = math.log((n - df + 0.5) / (df + 0.5) + 1)

    scores = []
    for doc in docs:
        dl = len(doc)
        score = 0.0
        term_freq: dict[str, int] = {}
        for t in doc:
            term_freq[t] = term_freq.get(t, 0) + 1

        for term in q_tokens:
            tf = term_freq.get(term, 0)
            if tf == 0:
                continue
            numerator = tf * (k1 + 1)
            denominator = tf + k1 * (1 - b + b * dl / avg_dl)
            score += idf.get(term, 0) * numerator / denominator

        scores.append(score)

    return scores
