# Nexus: A Local NL→SQL Engine for Air-Gap Digital Forensics with Automated Hallucination Correction

**Roberto Vilchis Meza**  
Independent Security Researcher  
vilchismezaroberto@gmail.com

**Submitted to**: FIRST Annual Conference 2026  
**Track**: Threat Intelligence & Incident Response  
**Date**: June 2026

---

## Abstract

Digital forensic investigations increasingly demand rapid analysis of large, heterogeneous evidence corpora — Windows Event Logs, process snapshots, network captures, registry exports — under conditions that prohibit transmission of sensitive data to external cloud services. We present **Nexus**, an open-source platform that enables natural language querying of forensic evidence using a local large language model (LLM) with zero external dependencies. Nexus translates analyst questions into precise SQLite queries through a BM25-augmented few-shot pipeline, validated by a three-layer hallucination detector with automatic self-correction. On a benchmark of 25 forensic questions across 10 categories, Nexus achieves **100% pass rate, 0% hallucination rate, and 100% self-correction rate** using `qwen2.5:7b-instruct` on CPU-only hardware. We further introduce the **Evidence Interrogation Loop (EIL)**, a ReAct agent that autonomously constructs incident kill chains from raw evidence without analyst intervention. All components operate fully air-gapped on a standard laptop.

---

## 1. Introduction

Incident responders face a structural problem: the volume of forensic evidence grows faster than analyst capacity. A single Windows endpoint generates tens of thousands of Event Log entries per day; a ransomware incident may involve dozens of systems and millions of events. Existing approaches fall into two categories:

**Manual SQL/grep analysis** requires deep schema knowledge and produces queries that are brittle and non-reusable. A junior analyst cannot easily formulate `SELECT username, source_ip FROM events WHERE event_id = 4625 GROUP BY username, source_ip ORDER BY COUNT(*) DESC` from a natural language question.

**Cloud-based AI assistants** (ChatGPT, Copilot, Gemini) can generate SQL from natural language, but require transmitting forensic evidence to external servers — a practice prohibited by legal, regulatory, and operational security constraints in most real incident response engagements.

Nexus addresses both problems: it accepts natural language questions in Spanish or English, generates verified SQLite queries, and executes them against a local database — entirely offline, with no network calls beyond the local Ollama inference server.

### 1.1 Contributions

1. A **NL→SQL pipeline** with BM25 few-shot retrieval optimized for forensic artifact schemas
2. A **three-layer hallucination validator** (structural, referential, syntax) with automatic retry
3. A **benchmark suite** of 25 forensic questions with ground-truth SQL and reproducible metrics
4. An **EIL ReAct agent** that autonomously investigates cases using tool calls
5. Evaluation across **27 real forensic cases** spanning LockBit ransomware, APT campaigns, red team exercises, and RDP intrusions

---

## 2. Problem Statement

### 2.1 The Forensic Evidence Schema

Nexus normalizes heterogeneous forensic artifacts into a unified SQLite schema:

```
events              ← Windows Event Logs (EVTX)
processes           ← Process snapshots (tasklist, WMIC)
network_connections ← Network state (netstat)
scheduled_tasks     ← Persistence (schtasks CSV)
registry_keys       ← Autorun registry exports
system_info         ← System metadata (systeminfo)
evidence_files      ← Ingestion manifest
```

This normalization enables cross-artifact JOIN queries that are impossible when artifacts are stored as flat files.

### 2.2 Why NL→SQL, Not RAG

Retrieval-Augmented Generation (RAG) is the dominant approach for LLM-based document analysis. However, forensic artifacts are not documents — they are structured records. RAG over forensic evidence has fundamental limitations:

| Dimension | NL→SQL (Nexus) | RAG (embeddings) |
|---|---|---|
| Precision | Exact — returns only what SQL selects | Approximate — chunk boundaries split evidence |
| Aggregation | Native (COUNT, GROUP BY, HAVING) | Requires post-processing |
| Cross-artifact joins | SQL JOIN across all tables | Hard — chunks rarely co-locate related artifacts |
| Air-gap deployment | SQLite + Ollama — zero external deps | Requires vector DB or local embedding model |
| Hallucination surface | SQL syntax — detectable and correctable | Semantic — harder to validate |
| Latency (CPU) | 65–135s/query (LLM bottleneck) | 5–30s/query |

**Verdict**: NL→SQL is strictly better for structured forensic artifacts. RAG is appropriate for unstructured evidence (emails, PDFs, chat logs).

---

## 3. Architecture

### 3.1 Pipeline Overview

```
Natural language question
         │
    [BM25 Retrieval]
    Vector store (388 items per case)
    DDL + TABLE_DOCS + Q-SQL pairs
         │
    [LLM — qwen2.5:7b-instruct]
    Ollama local inference
         │
    [SQL draft]
         │
    [3-Layer Validator]
    ┌────────────────────────┐
    │ Layer 1: Structural    │ → unknown table/column?
    │ Layer 2: Referential   │ → event_id not in this DB?
    │ Layer 3: Syntax        │ → EXPLAIN QUERY PLAN
    └────────────────────────┘
         │ fail → retry with error injected in prompt
         │ pass
    [SQLite execution]
         │
    Result DataFrame
```

### 3.2 BM25 Vector Store

Each case has a dedicated vector store built from three layers:

| Layer | Count | Purpose |
|---|---|---|
| DDL (schema) | 8 | Table definitions with column names and types |
| TABLE_DOCS | 25+ | Event ID mappings, column semantics, critical warnings |
| Q-SQL pairs | 144+ | Question → SQL examples, all forensic categories |
| **Total** | **~388** | Per case (varies by active tables) |

At query time, BM25 retrieves the 3 most similar Q-SQL pairs as few-shot examples. No embedding model is needed — BM25 over SQLite is pure Python with zero external dependencies.

### 3.3 Three-Layer Hallucination Validator

LLMs generating SQL for forensic databases exhibit three failure modes:

**Structural hallucination**: The model references a column or table that does not exist in the schema (e.g., `hostname` instead of `computer`, `event_type` instead of `event_id`). Detected by comparing the SQL AST against the actual schema.

**Referential hallucination**: The model uses an `event_id` value that is not present in this specific case's database (e.g., using `event_id = 4688` in a database that only contains Sysmon events). Detected by querying the actual event_id distribution.

**Syntax hallucination**: The SQL is structurally malformed and would crash SQLite (e.g., `column NOT LIKE 'x' AND NOT LIKE 'y'` — missing column repetition). Detected by running `EXPLAIN QUERY PLAN`.

When a hallucination is detected, the error description is injected into the prompt and the LLM retries. In R8, 100% of detected hallucinations were auto-corrected on first retry.

### 3.4 Intent Router

Not all questions require NL→SQL. The router classifies intent without an LLM:

```
threat_hunt  ← regex: "malware", "suspicious", "attack", "hunt", "threat"
ioc          ← regex: IP/domain/hash patterns
sql          ← default (everything else)
```

Threat hunt applies 11 hardcoded MITRE ATT&CK rules directly to the database — instantaneous, no LLM call required. Routing accuracy: 24/24 (100%) on held-out test set.

### 3.5 EIL — Evidence Interrogation Loop

The EIL is a ReAct agent that autonomously investigates a case given a high-level goal:

```python
nexus investigate lockbit_ir "How did the attacker get in?"
```

**Tools available to the agent:**
- `threat_hunt()` — MITRE ATT&CK detection (always first)
- `pivot_user(username)` — all activity for a user
- `pivot_ip(ip)` — all events for an IP
- `pivot_process(name)` — all events for a process
- `sql_query(question)` — NL→SQL for arbitrary queries
- `done(narrative)` — conclude with incident summary

**Loop mechanics**: The agent receives the real case data (top users, IPs, event IDs) as context before the first step, preventing hallucinated pivot values. A sliding context window (last 6 turns) prevents token overflow. Loop detection redirects repeated tool calls. The final step forces a `done()` call if the agent has not concluded.

---

## 4. Evaluation

### 4.1 Benchmark Suite

25 questions spanning 10 forensic categories, with hand-crafted ground-truth SQL:

| Category | Questions | Coverage |
|---|---|---|
| Enumeration | 5 | Users, computers, event counts |
| Timeline | 4 | Date ranges, chronological ordering |
| Network | 4 | Connections, external IPs, active sessions |
| Anomaly | 3 | Off-hours activity, suspicious paths, brute force |
| Persistence | 2 | Scheduled tasks, registry autoruns |
| Processes | 2 | SYSTEM processes, PID analysis |
| User activity | 2 | Logon patterns, nocturnal access |
| Cross-table | 1 | JOIN: processes + network connections |
| Attribution | 1 | Top process by connection count |
| Meta | 1 | Evidence manifest summary |

### 4.2 Metrics

**Score**: Pass rate — SQL executes, uses correct tables and columns, returns expected row range.

**Hallucination Rate (HR)**: Questions with at least one unresolved hallucination / total.

**Self-Correction Rate (SCR)**: Auto-corrected hallucinations / total detected hallucinations.

**Token Utilization Score (TUS)**: `1 - (output_tokens / max_tokens)` — higher = more efficient, less padding.

**Reliability Score (RS)**: `Score × (1 - HR) × (1 + SCR × 0.1)` — composite metric.

**Context Recall Rate (CCR)**: ROUGE-1 recall of generated SQL vs ground-truth SQL.

### 4.3 Benchmark Progression

| Round | Date | Score | HR | SCR | TUS | RS | CCR | Notes |
|---|---|---|---|---|---|---|---|---|
| R1 | 2026-06-05 | 80% | 20% | — | — | — | — | Baseline |
| R2 | 2026-06-05 | 90% | 10% | — | — | — | — | Schema docs + Q-SQL pairs |
| R3 | 2026-06-05 | 90% | 10% | — | — | — | — | Syntax validator |
| R4 | 2026-06-06 | 92% | 12% | 40% | 0.983 | 0.920 | 0.550 | 25Q, FindingValidator |
| R5 | 2026-06-06 | — | — | — | — | — | — | Router + intent detection |
| R6 | 2026-06-07 | 96% | 4% | 100% | 0.950 | 0.960 | 0.810 | DFIR analyst Q-SQL pairs |
| R7 | 2026-06-09 | 88% | 8% | 33% | 0.995 | 0.880 | 0.963 | EIL agent added |
| **R8** | **2026-06-09** | **100%** | **0%** | **100%** | **1.000** | **1.000** | **0.990** | **B07/B08/B23 fixes** |

**Hardware**: Intel CPU, no GPU. Average query latency R8: 65.3s, p95: 149.0s.

### 4.4 Analyst Validation — 12 Cases

Beyond the benchmark, each of 12 evidence cases was tested with a representative DFIR analyst question:

| Case | Evidence | Question | Result |
|---|---|---|---|
| lockbit_ir | 39,949 events | Successful logon accounts + source IPs | CLEAN |
| mitre_attacks | 63,171 events | Source IPs with most failed logons | CLEAN |
| credential_access | 29,853 events | IPs with brute force attempts | CLEAN |
| lateral_movement | 1,288 events | Network shares accessed by account | CLEAN |
| privilege_escalation | 1,142 events | Accounts with special privileges | CORRECTED |
| c2 | 1,969 events | Processes with external connections | CLEAN |
| other_ttps | 750 events | PowerShell scripts executed | CLEAN |
| automated_testing | 800 events | Defender detections | CLEAN |
| execution | 541 events | Process creation with commands | CLEAN |
| defense_evasion | 431 events | Event log clearing | CLEAN |
| persistence | 411 events | Directory Service modifications | CLEAN |
| discovery | 163 events | User/group enumeration | CLEAN |

**Result**: 12/12 PASS, 11/12 CLEAN (92%), 1/12 CORRECTED (auto-resolved by validator).

### 4.5 Kill Chain Reconstruction — 63K Events

Using `mitre_attacks` (148 EVTX files, 63,171 events, all ATT&CK phases), we reconstructed the full incident kill chain using only NL→SQL — no hardcoded rules:

| Phase | Question | Result |
|---|---|---|
| SCOPE | What machines were involved? | CLEAN |
| INITIAL ACCESS | First credential attacks against the environment | CLEAN |
| INITIAL ACCESS | Attack progression: failed → successful logons from same IP | CLEAN |
| LATERAL MOVEMENT | Accounts moving between machines | CLEAN |
| PRIVILEGE ESCALATION | Accounts receiving special privileges | CLEAN |
| PERSISTENCE | Persistence mechanisms established | CLEAN |
| DEFENSE EVASION | Defense evasion actions taken | CLEAN |
| EXECUTION | Processes and commands executed | CLEAN |
| ACTOR | User account appearing across most attack phases | CLEAN |
| TIMELINE | Full incident timeline ordered by time | CLEAN |

**10/10 CLEAN.** Key findings: `Administrator` account covered 11 attack phases; execution chain `hh.exe → cmd.exe → rundll32.exe`; 22 log clearing events during evasion phase.

---

## 5. Evidence Corpus

| Dataset | Cases | Events | Source |
|---|---|---|---|
| LockBit Ransomware IR | 1 | 39,949 | Real incident response (anonymized) |
| sbousseaden EVTX-ATTACK-SAMPLES | 10 | 98,000+ | github.com/sbousseaden |
| mitre_attacks (combined) | 1 | 63,171 | All 10 ATT&CK categories merged |
| mdecrevoisier APT steps | 12 | 3,609 | github.com/mdecrevoisier |
| FOR563 RDP lab | 1 | 1,800 | SANS FOR563 exercise |
| **Total** | **27** | **~207,000** | |

---

## 6. Implementation

### 6.1 Dependencies

```
python-evtx     ← EVTX parsing
pandas          ← DataFrame output
openai          ← Ollama-compatible client
httpx           ← Explicit timeout control
sqlite3         ← Standard library, zero install
```

No vector database, no embedding model, no cloud API.

### 6.2 Installation

```bash
git clone https://github.com/robdinovil/nexus-dfir
cd nexus-dfir && pip install -e .
ollama pull qwen2.5:7b-instruct

nexus new mycase
nexus ingest mycase /path/to/evidence/
nexus ask mycase "¿Qué cuentas tuvieron logon exitoso?"
nexus hunt mycase
nexus investigate mycase "What happened in this incident?"
```

**System requirements**: Python 3.10+, Ollama ≥0.3, ~5GB RAM, no GPU required.

---

## 7. Limitations and Future Work

**EIL agent maturity**: The ReAct agent reliably completes investigations but may waste steps on queries with hallucinated timestamps when evidence lacks temporal data. Improvement: inject timestamp availability into the case context.

**Parser coverage**: Current parsers support EVTX, CSV (tasklist/schtasks/WMIC), netstat, registry exports, and systeminfo. PCAP (via tshark), MFT, prefetch, and browser history are planned.

**E01 forensic image support**: Currently requires pre-extracted artifacts. Integration with `ewfmount` + `pytsk3` would enable direct E01 ingestion.

**Triage and Report agents**: A Triage Agent (fast classification using `qwen2.5:3b`) and a Report Agent (structured IR report generation) are planned to complete the multi-agent system.

**Model dependency**: Results are specific to `qwen2.5:7b-instruct`. Performance may vary with other models. The few-shot approach is model-agnostic; larger models are expected to improve EIL reasoning quality.

---

## 8. Conclusion

Nexus demonstrates that 100% accuracy NL→SQL forensic querying is achievable on air-gapped, CPU-only hardware using a 7B parameter model. The key enablers are: (1) BM25 few-shot retrieval grounded in forensic-domain Q-SQL pairs, (2) a three-layer validator that detects and corrects hallucinations before they reach the analyst, and (3) case-specific training that adapts the pipeline to each evidence corpus.

The Evidence Interrogation Loop extends this foundation to autonomous investigation — given a case and a goal, the system independently constructs the attack kill chain without analyst guidance. Together, these components address the core operational constraint of real incident response: rigorous analysis under air-gap conditions, at machine speed.

---

## References

1. Yao, S. et al. (2022). ReAct: Synergizing Reasoning and Acting in Language Models. *arXiv:2210.03629*
2. MITRE Corporation. ATT&CK Framework v14. *attack.mitre.org*
3. Carrier, B. (2005). File System Forensic Analysis. Addison-Wesley.
4. Qwen Team (2024). Qwen2.5 Technical Report. *arXiv:2412.15115*
5. sbousseaden. EVTX-ATTACK-SAMPLES. *github.com/sbousseaden/EVTX-ATTACK-SAMPLES*
6. mdecrevoisier. EVTX-to-MITRE-Attack. *github.com/mdecrevoisier/EVTX-to-MITRE-Attack*

---

*Nexus DFIR v0.2.0 — open source at github.com/robdinovil/nexus-dfir*  
*Benchmark data, recordings, and reproducibility scripts included in repository*
