# Nexus DFIR

**Evidence intelligence platform for digital forensics — CPU-only, air-gap ready, no cloud.**

Ask questions about forensic evidence in plain language. Nexus routes each question to the right tool automatically.

```
nexus shell lockbit2024

nexus [lockbit2024]> ¿hay malware?
  [THREAT_HUNT] ⚠ 5 reglas disparadas — 20 hallazgos
  [CRITICAL] T1078 — System Process Username Anomaly
  [HIGH]     T1071.001 — C2 over HTTPS → 152.236.2.63:443
  ...  ↳ 0.0s

nexus [lockbit2024]> correlaciona 152.236.2.63
  [IOC] ✓ 2 referencias en 1 tabla(s)
  network_connections: TCP 152.236.2.63:443 ESTABLISHED pid=9052
  ...  ↳ 0.0s

nexus [lockbit2024]> ¿cuántos logons fallidos por IP?
  [SQL] SELECT source_ip, COUNT(*) as failed ...
  10.1.1.45   45 intentos
  10.1.1.20   42 intentos
  ...  ↳ 87s
```

## How it works

Three routes — the system picks automatically:

| Route | When | LLM | Latency |
|---|---|---|---|
| **Threat Hunt** | "hay malware", "hunting", "TTPs" | No | ~0s |
| **IOC Correlation** | IP/hash literal, "correlaciona", "pivot" | No | ~0s |
| **NL→SQL** | Everything else | Yes (local Ollama) | ~60-90s CPU |

Threat hunt applies 19 MITRE ATT&CK-mapped rules across Security events, Sysmon, processes, network connections, scheduled tasks, and registry keys.

## Requirements

- Python 3.10+
- [Ollama](https://ollama.ai) running locally with any instruction-tuned model
- No GPU required — tested on i9 CPU only

```bash
ollama pull qwen2.5:7b-instruct   # or any model
```

## Install

```bash
git clone https://github.com/robdinovil/nexus-dfir
cd nexus-dfir
pip install -e .
```

## Usage

```bash
# Create a case
nexus new lockbit2024

# Ingest evidence directory (EVTX, CSV tasklist/netstat, .reg, systeminfo)
nexus ingest lockbit2024 /path/to/evidence/

# Interactive shell
nexus shell lockbit2024

# Single question
nexus ask lockbit2024 "¿qué procesos corren como SYSTEM?"

# List cases
nexus cases

# Threat hunt only
nexus ask lockbit2024 "¿hay malware?"
```

## Evidence formats supported

| Format | Parser | Example files |
|---|---|---|
| Windows Event Log | EVTX | Security.evtx, System.evtx, Sysmon.evtx |
| Process list | CSV | tasklist /v /fo csv, wmic process |
| Network connections | TXT | netstat -ano |
| System info | TXT | systeminfo |
| Registry export | REG | reg export HKLM\...\Run |

## NL→SQL benchmark (qwen2.5:7b-instruct, CPU-only)

| Round | Questions | Score | Halluc. rate | Self-correction rate |
|---|---|---|---|---|
| Round 1 | 20 | 16/20 (80%) | 10% | — |
| Round 2 | 20 | 18/20 (90%) | 5% | — |
| Round 3 | 20 | 18/20 (90%) | 5% | — |
| Round 4 | 20 | 19/20 (95%) | 5% | tracked |
| Round 5 | 25 | — | — | — |

Categories with 100% accuracy: cross_table, enumeration, meta, persistence, anomaly, processes, network.

## Hallucination measurement methodology

Nexus classifies LLM errors into three categories before execution:

| Type | Description | Detection method |
|---|---|---|
| **Structural** | Column or table that doesn't exist in the schema | Schema inspection after SQL parse |
| **Referential** | `event_id` value not present in this database | Live DB query against `events` |
| **Syntax** | Malformed SQL (parse error) | `EXPLAIN QUERY PLAN` |

### Three-layer validator pipeline

```
LLM generates SQL
       │
  [Layer 1] SELECT-only check (structural)
       │
  [Layer 2] Table + column existence (structural)
       │
  [Layer 3] event_id in DB check (referential)
       │
  valid? ── No ──→ inject error hint into prompt → RETRY once
       │                                                │
      Yes                                         re-validate
       │                                                │
  execute SQL ←──────────────────────── valid? ──Yes──┘
                                              │
                                             No → execute anyway, log unresolved hallucination
```

### Metrics

- **Score** — PASS rate on ground-truth question set (keyword checks + row count bounds)
- **Hallucination rate** — unresolved hallucinations / total questions (lower = better)
- **Self-correction rate** — (detected and fixed by validator) / (all triggered) — measures validator effectiveness
- **Latency** — avg and p95 per-question wall-clock time on CPU-only hardware

### Key finding

The validator's self-correction mechanism converts many structural hallucinations into
clean PASSes. A question that "hallucinated" but PASSed means the validator caught the
error and the retry succeeded — this is a feature, not a failure.

SANS FIND EVIL evaluation adds 5 attack-investigation questions (B21–B25) covering:
timeline anchoring, process attribution, anomaly detection, brute force ranking, and
off-hours authentication — matching the CTF challenge question style.

## Architecture

```
nexus/
├── router.py       — intent detection + tool dispatch (no LLM for hunt/IOC)
├── analyst.py      — NL→SQL with BM25 retrieval + Ollama
├── validator.py    — 3-layer SQL validation (structural + referential + syntax)
├── vectorstore.py  — BM25 over SQLite, zero external dependencies
├── ingestor.py     — evidence parser orchestrator (idempotent)
├── detector.py     — magic-byte file type detection
├── case.py         — case management (~/.nexus/cases/)
└── parsers/        — EVTX, CSV, netstat, systeminfo, registry
```

Cases are stored in `~/.nexus/cases/<name>/` — portable, no server required.

## Presented at FIRST 2026
