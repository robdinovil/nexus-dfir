# Nexus: Un Motor NL→SQL Local para Forense Digital en Entornos Air-Gap con Corrección Automática de Alucinaciones

**Roberto Vilchis Meza**  
Investigador Independiente de Seguridad  
vilchismezaroberto@gmail.com

**Enviado a**: Conferencia Anual FIRST 2026  
**Track**: Inteligencia de Amenazas y Respuesta a Incidentes  
**Fecha**: Junio 2026

---

## Resumen

Las investigaciones de forense digital exigen cada vez más el análisis rápido de grandes corpus de evidencia heterogénea — registros de eventos de Windows, snapshots de procesos, capturas de red, exportaciones de registro — bajo condiciones que prohíben la transmisión de datos sensibles a servicios en la nube. Presentamos **Nexus**, una plataforma de código abierto que permite consultar evidencia forense en lenguaje natural usando un modelo de lenguaje grande (LLM) local, sin dependencias externas. Nexus traduce preguntas de analistas a consultas SQLite precisas mediante un pipeline few-shot aumentado con BM25, validado por un detector de alucinaciones de tres capas con autocorrección automática. En un benchmark de 25 preguntas forenses en 10 categorías, Nexus logra **100% de tasa de éxito, 0% de tasa de alucinación y 100% de tasa de autocorrección** usando `qwen2.5:7b-instruct` en hardware sin GPU. Presentamos además el **Evidence Interrogation Loop (EIL)**, un agente ReAct que construye cadenas de ataque de forma autónoma a partir de evidencia en bruto sin intervención del analista. Todos los componentes operan completamente air-gapped en una laptop estándar.

---

## 1. Introducción

Los respondedores de incidentes enfrentan un problema estructural: el volumen de evidencia forense crece más rápido que la capacidad del analista. Un solo endpoint Windows genera decenas de miles de entradas en el Event Log por día; un incidente de ransomware puede involucrar docenas de sistemas y millones de eventos. Los enfoques existentes se dividen en dos categorías:

**Análisis manual SQL/grep**: requiere conocimiento profundo del esquema y produce consultas frágiles y no reutilizables. Un analista junior no puede formular fácilmente `SELECT username, source_ip FROM events WHERE event_id = 4625 GROUP BY username, source_ip ORDER BY COUNT(*) DESC` a partir de una pregunta en lenguaje natural.

**Asistentes de IA en la nube** (ChatGPT, Copilot, Gemini): pueden generar SQL desde lenguaje natural, pero requieren transmitir la evidencia forense a servidores externos — práctica prohibida por restricciones legales, regulatorias y de seguridad operacional en la mayoría de los compromisos reales de respuesta a incidentes.

Nexus resuelve ambos problemas: acepta preguntas en español o inglés, genera consultas SQLite verificadas y las ejecuta contra una base de datos local — completamente sin conexión, sin llamadas de red más allá del servidor de inferencia Ollama local.

### 1.1 Contribuciones

1. Un **pipeline NL→SQL** con recuperación few-shot BM25 optimizado para esquemas de artefactos forenses
2. Un **validador de alucinaciones de tres capas** (estructural, referencial, sintáctico) con reintentos automáticos
3. Un **suite de benchmark** de 25 preguntas forenses con SQL de referencia y métricas reproducibles
4. Un **agente ReAct EIL** que investiga casos de forma autónoma usando llamadas a herramientas
5. Evaluación sobre **27 casos forenses reales** que abarcan ransomware LockBit, campañas APT, ejercicios red team e intrusiones RDP

---

## 2. Planteamiento del Problema

### 2.1 El Esquema de Evidencia Forense

Nexus normaliza artefactos forenses heterogéneos en un esquema SQLite unificado:

```
events              ← Registros de eventos Windows (EVTX)
processes           ← Snapshots de procesos (tasklist, WMIC)
network_connections ← Estado de red (netstat)
scheduled_tasks     ← Persistencia (schtasks CSV)
registry_keys       ← Exportaciones de registro de autorun
system_info         ← Metadatos del sistema (systeminfo)
evidence_files      ← Manifiesto de ingestión
```

Esta normalización permite consultas JOIN entre artefactos que son imposibles cuando los artefactos se almacenan como archivos planos.

### 2.2 Por Qué NL→SQL y No RAG

La Generación Aumentada por Recuperación (RAG) es el enfoque dominante para el análisis de documentos con LLM. Sin embargo, los artefactos forenses no son documentos — son registros estructurados. RAG sobre evidencia forense tiene limitaciones fundamentales:

| Dimensión | NL→SQL (Nexus) | RAG (embeddings) |
|---|---|---|
| Precisión | Exacta — devuelve solo lo que selecciona SQL | Aproximada — los límites de chunk fragmentan la evidencia |
| Agregación | Nativa (COUNT, GROUP BY, HAVING) | Requiere post-procesamiento |
| Joins entre artefactos | SQL JOIN sobre todas las tablas | Difícil — los chunks rara vez co-ubican artefactos relacionados |
| Despliegue air-gap | SQLite + Ollama — cero dependencias externas | Requiere BD vectorial o modelo de embeddings local |
| Superficie de alucinación | Sintaxis SQL — detectable y corregible | Semántica — más difícil de validar |
| Latencia (CPU) | 65–135s/consulta (cuello de botella LLM) | 5–30s/consulta |

**Veredicto**: NL→SQL es estrictamente superior para artefactos forenses estructurados. RAG es apropiado para evidencia no estructurada (correos, PDFs, registros de chat).

---

## 3. Arquitectura

### 3.1 Visión General del Pipeline

```
Pregunta en lenguaje natural
         │
    [Recuperación BM25]
    Vector store (388 ítems por caso)
    DDL + TABLE_DOCS + pares P-SQL
         │
    [LLM — qwen2.5:7b-instruct]
    Inferencia local Ollama
         │
    [Borrador SQL]
         │
    [Validador 3 Capas]
    ┌────────────────────────┐
    │ Capa 1: Estructural    │ → ¿tabla/columna desconocida?
    │ Capa 2: Referencial    │ → ¿event_id no existe en esta BD?
    │ Capa 3: Sintáctico     │ → EXPLAIN QUERY PLAN
    └────────────────────────┘
         │ fallo → reintento con error inyectado en el prompt
         │ éxito
    [Ejecución SQLite]
         │
    DataFrame de resultados
```

### 3.2 Vector Store BM25

Cada caso tiene un vector store dedicado construido en tres capas:

| Capa | Cantidad | Propósito |
|---|---|---|
| DDL (esquema) | 8 | Definiciones de tablas con nombres y tipos de columna |
| TABLE_DOCS | 25+ | Mapeo de event IDs, semántica de columnas, advertencias críticas |
| Pares P-SQL | 144+ | Pregunta → SQL de ejemplo, todas las categorías forenses |
| **Total** | **~388** | Por caso (varía según las tablas activas) |

En tiempo de consulta, BM25 recupera los 3 pares P-SQL más similares como ejemplos few-shot. No se necesita modelo de embeddings — BM25 sobre SQLite es Python puro sin dependencias externas.

### 3.3 Validador de Alucinaciones de Tres Capas

Los LLM que generan SQL para bases de datos forenses exhiben tres modos de fallo:

**Alucinación estructural**: El modelo referencia una columna o tabla que no existe en el esquema (ej. `hostname` en lugar de `computer`, `event_type` en lugar de `event_id`). Se detecta comparando el AST del SQL contra el esquema real.

**Alucinación referencial**: El modelo usa un valor de `event_id` que no existe en la base de datos de este caso específico (ej. usar `event_id = 4688` en una BD que solo contiene eventos Sysmon). Se detecta consultando la distribución real de event_ids.

**Alucinación sintáctica**: El SQL es estructuralmente malformado y crashearía SQLite (ej. `column NOT LIKE 'x' AND NOT LIKE 'y'` — sin repetición de columna). Se detecta ejecutando `EXPLAIN QUERY PLAN`.

Cuando se detecta una alucinación, la descripción del error se inyecta en el prompt y el LLM reintenta. En R8, el 100% de las alucinaciones detectadas se corrigieron automáticamente en el primer reintento.

### 3.4 Router de Intención

No todas las preguntas requieren NL→SQL. El router clasifica la intención sin usar un LLM:

```
threat_hunt  ← regex: "malware", "sospechoso", "ataque", "hunt", "amenaza"
ioc          ← regex: patrones IP/dominio/hash
sql          ← default (todo lo demás)
```

La caza de amenazas aplica 11 reglas MITRE ATT&CK hardcodeadas directamente sobre la base de datos — instantáneo, sin llamada al LLM. Precisión de enrutamiento: 24/24 (100%) en conjunto de prueba.

### 3.5 EIL — Evidence Interrogation Loop

El EIL es un agente ReAct que investiga un caso de forma autónoma dado un objetivo de alto nivel:

```bash
nexus investigate lockbit_ir "¿Cómo entró el atacante?"
```

**Herramientas disponibles para el agente:**
- `threat_hunt()` — detección MITRE ATT&CK (siempre primero)
- `pivot_user(usuario)` — toda la actividad de un usuario
- `pivot_ip(ip)` — todos los eventos de una IP
- `pivot_process(nombre)` — todos los eventos de un proceso
- `sql_query(pregunta)` — NL→SQL para consultas arbitrarias
- `done(narrativa)` — concluir con resumen del incidente

**Mecánica del loop**: El agente recibe los datos reales del caso (usuarios principales, IPs, event IDs) como contexto antes del primer paso, previniendo valores de pivote alucinados. Una ventana de contexto deslizante (últimos 6 turnos) previene el desbordamiento de tokens. La detección de loops redirige llamadas repetidas a herramientas. El paso final fuerza una llamada `done()` si el agente no ha concluido.

---

## 4. Evaluación

### 4.1 Suite de Benchmark

25 preguntas en 10 categorías forenses, con SQL de referencia construido manualmente:

| Categoría | Preguntas | Cobertura |
|---|---|---|
| Enumeración | 5 | Usuarios, equipos, conteos de eventos |
| Línea de tiempo | 4 | Rangos de fecha, orden cronológico |
| Red | 4 | Conexiones, IPs externas, sesiones activas |
| Anomalía | 3 | Actividad fuera de horario, rutas sospechosas, fuerza bruta |
| Persistencia | 2 | Tareas programadas, autoruns de registro |
| Procesos | 2 | Procesos SYSTEM, análisis de PID |
| Actividad de usuario | 2 | Patrones de logon, acceso nocturno |
| Cruce de tablas | 1 | JOIN: procesos + conexiones de red |
| Atribución | 1 | Proceso con más conexiones externas |
| Meta | 1 | Resumen del manifiesto de evidencia |

### 4.2 Métricas

**Score**: Tasa de éxito — SQL ejecuta, usa tablas y columnas correctas, devuelve rango de filas esperado.

**Tasa de Alucinación (HR)**: Preguntas con al menos una alucinación no resuelta / total.

**Tasa de Autocorrección (SCR)**: Alucinaciones corregidas automáticamente / total detectadas.

**Token Utilization Score (TUS)**: `1 - (tokens_salida / max_tokens)` — mayor = más eficiente, menos relleno.

**Reliability Score (RS)**: `Score × (1 - HR) × (1 + SCR × 0.1)` — métrica compuesta.

**Context Recall Rate (CCR)**: ROUGE-1 recall del SQL generado vs SQL de referencia.

### 4.3 Progresión del Benchmark

| Ronda | Fecha | Score | HR | SCR | TUS | RS | CCR | Notas |
|---|---|---|---|---|---|---|---|---|
| R1 | 2026-06-05 | 80% | 20% | — | — | — | — | Línea base |
| R2 | 2026-06-05 | 90% | 10% | — | — | — | — | Docs de esquema + pares P-SQL |
| R3 | 2026-06-05 | 90% | 10% | — | — | — | — | Validador sintáctico |
| R4 | 2026-06-06 | 92% | 12% | 40% | 0.983 | 0.920 | 0.550 | 25 preguntas, FindingValidator |
| R5 | 2026-06-06 | — | — | — | — | — | — | Router + detección de intención |
| R6 | 2026-06-07 | 96% | 4% | 100% | 0.950 | 0.960 | 0.810 | Pares P-SQL de analista DFIR |
| R7 | 2026-06-09 | 88% | 8% | 33% | 0.995 | 0.880 | 0.963 | Agente EIL añadido |
| **R8** | **2026-06-09** | **100%** | **0%** | **100%** | **1.000** | **1.000** | **0.990** | **Correcciones B07/B08/B23** |

**Hardware**: CPU Intel, sin GPU. Latencia promedio por consulta en R8: 65.3s, p95: 149.0s.

### 4.4 Validación por Analista — 12 Casos

Más allá del benchmark, cada uno de los 12 casos de evidencia fue evaluado con una pregunta representativa de analista DFIR:

| Caso | Evidencia | Pregunta | Resultado |
|---|---|---|---|
| lockbit_ir | 39,949 eventos | Cuentas con logon exitoso + IPs de origen | LIMPIO |
| mitre_attacks | 63,171 eventos | IPs con más intentos de logon fallido | LIMPIO |
| credential_access | 29,853 eventos | IPs con intentos de fuerza bruta | LIMPIO |
| lateral_movement | 1,288 eventos | Recursos compartidos accedidos por cuenta | LIMPIO |
| privilege_escalation | 1,142 eventos | Cuentas con privilegios especiales | CORREGIDO |
| c2 | 1,969 eventos | Procesos con conexiones externas | LIMPIO |
| other_ttps | 750 eventos | Scripts PowerShell ejecutados | LIMPIO |
| automated_testing | 800 eventos | Detecciones de Defender | LIMPIO |
| execution | 541 eventos | Creación de procesos con comandos | LIMPIO |
| defense_evasion | 431 eventos | Borrado de registros de eventos | LIMPIO |
| persistence | 411 eventos | Modificaciones de Directory Service | LIMPIO |
| discovery | 163 eventos | Enumeración de usuarios/grupos | LIMPIO |

**Resultado**: 12/12 APROBADOS, 11/12 LIMPIOS (92%), 1/12 CORREGIDO (resuelto automáticamente por el validador).

### 4.5 Reconstrucción de Kill Chain — 63K Eventos

Usando `mitre_attacks` (148 archivos EVTX, 63,171 eventos, todas las fases ATT&CK), reconstruimos la kill chain completa del incidente usando solo NL→SQL — sin reglas hardcodeadas:

| Fase | Pregunta | Resultado |
|---|---|---|
| ALCANCE | ¿Qué máquinas estuvieron involucradas? | LIMPIO |
| ACCESO INICIAL | Primeros ataques de credenciales contra el entorno | LIMPIO |
| ACCESO INICIAL | Progresión del ataque: logons fallidos → exitosos desde la misma IP | LIMPIO |
| MOVIMIENTO LATERAL | Cuentas que se movieron entre máquinas | LIMPIO |
| ESCALACIÓN DE PRIVILEGIOS | Cuentas que recibieron privilegios especiales | LIMPIO |
| PERSISTENCIA | Mecanismos de persistencia establecidos | LIMPIO |
| EVASIÓN DE DEFENSA | Acciones de evasión de defensa tomadas | LIMPIO |
| EJECUCIÓN | Procesos y comandos ejecutados | LIMPIO |
| ATRIBUCIÓN | Cuenta de usuario presente en más fases del ataque | LIMPIO |
| LÍNEA DE TIEMPO | Cronología completa del incidente ordenada por tiempo | LIMPIO |

**10/10 LIMPIOS.** Hallazgos clave: cuenta `Administrator` cubrió 11 fases del ataque; cadena de ejecución `hh.exe → cmd.exe → rundll32.exe`; 22 eventos de borrado de logs durante la fase de evasión.

---

## 5. Corpus de Evidencia

| Dataset | Casos | Eventos | Fuente |
|---|---|---|---|
| IR de Ransomware LockBit | 1 | 39,949 | Respuesta a incidente real (anonimizado) |
| sbousseaden EVTX-ATTACK-SAMPLES | 10 | 98,000+ | github.com/sbousseaden |
| mitre_attacks (combinado) | 1 | 63,171 | Las 10 categorías ATT&CK fusionadas |
| mdecrevoisier pasos APT | 12 | 3,609 | github.com/mdecrevoisier |
| Lab RDP FOR563 | 1 | 1,800 | Ejercicio SANS FOR563 |
| **Total** | **27** | **~207,000** | |

---

## 6. Implementación

### 6.1 Dependencias

```
python-evtx     ← Parseo de EVTX
pandas          ← Salida en DataFrame
openai          ← Cliente compatible con Ollama
httpx           ← Control explícito de timeout
sqlite3         ← Biblioteca estándar, sin instalación
```

Sin base de datos vectorial, sin modelo de embeddings, sin API en la nube.

### 6.2 Instalación

```bash
git clone https://github.com/robdinovil/nexus-dfir
cd nexus-dfir && pip install -e .
ollama pull qwen2.5:7b-instruct

nexus new micaso
nexus ingest micaso /ruta/a/evidencia/
nexus ask micaso "¿Qué cuentas tuvieron logon exitoso?"
nexus hunt micaso
nexus investigate micaso "¿Qué pasó en este incidente?"
```

**Requisitos del sistema**: Python 3.10+, Ollama ≥0.3, ~5GB RAM, sin GPU requerida.

---

## 7. Limitaciones y Trabajo Futuro

**Madurez del agente EIL**: El agente ReAct completa investigaciones de forma confiable, pero puede desperdiciar pasos en consultas con timestamps alucinados cuando la evidencia carece de datos temporales. Mejora: inyectar disponibilidad de timestamps en el contexto del caso.

**Cobertura de parsers**: Los parsers actuales soportan EVTX, CSV (tasklist/schtasks/WMIC), netstat, exportaciones de registro y systeminfo. PCAP (vía tshark), MFT, prefetch e historial de navegador están planificados.

**Soporte de imágenes forenses E01**: Actualmente requiere artefactos pre-extraídos. La integración con `ewfmount` + `pytsk3` permitiría ingestión directa de E01.

**Agentes Triage y Report**: Un Agente de Triage (clasificación rápida usando `qwen2.5:3b`) y un Agente de Reporte (generación de reporte IR estructurado) están planificados para completar el sistema multiagente.

**Dependencia del modelo**: Los resultados son específicos a `qwen2.5:7b-instruct`. El rendimiento puede variar con otros modelos. El enfoque few-shot es agnóstico al modelo; se espera que modelos más grandes mejoren la calidad de razonamiento del EIL.

---

## 8. Conclusión

Nexus demuestra que el análisis forense NL→SQL con 100% de precisión es alcanzable en hardware air-gapped sin GPU usando un modelo de 7B parámetros. Los factores habilitadores clave son: (1) recuperación few-shot BM25 fundamentada en pares P-SQL del dominio forense, (2) un validador de tres capas que detecta y corrige alucinaciones antes de que lleguen al analista, y (3) entrenamiento específico por caso que adapta el pipeline a cada corpus de evidencia.

El Evidence Interrogation Loop extiende esta base hacia la investigación autónoma — dado un caso y un objetivo, el sistema construye independientemente la kill chain del ataque sin guía del analista. Juntos, estos componentes abordan la restricción operacional central de la respuesta real a incidentes: análisis riguroso bajo condiciones air-gap, a velocidad de máquina.

---

## Referencias

1. Yao, S. et al. (2022). ReAct: Synergizing Reasoning and Acting in Language Models. *arXiv:2210.03629*
2. MITRE Corporation. Marco ATT&CK v14. *attack.mitre.org*
3. Carrier, B. (2005). File System Forensic Analysis. Addison-Wesley.
4. Qwen Team (2024). Qwen2.5 Technical Report. *arXiv:2412.15115*
5. sbousseaden. EVTX-ATTACK-SAMPLES. *github.com/sbousseaden/EVTX-ATTACK-SAMPLES*
6. mdecrevoisier. EVTX-to-MITRE-Attack. *github.com/mdecrevoisier/EVTX-to-MITRE-Attack*

---

*Nexus DFIR v0.2.0 — código abierto en github.com/robdinovil/nexus-dfir*  
*Datos de benchmark, grabaciones y scripts de reproducibilidad incluidos en el repositorio*
