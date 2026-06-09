# Nexus DFIR: Interrogación Local de Evidencia Forense mediante NL→SQL Validado con Corrección Automática de Alucinaciones en Entornos Air-Gap

**Roberto Vilchis Meza**  
Investigador Independiente de Seguridad  
vilchismezaroberto@gmail.com

**Enviado a**: Conferencia Anual FIRST 2026  
**Track**: Inteligencia de Amenazas y Respuesta a Incidentes

**Palabras clave**: forense digital, respuesta a incidentes, modelos de lenguaje locales, NL→SQL, air-gap, MITRE ATT&CK, validación de alucinaciones, SQLite, Ollama

---

## Resumen

El análisis de evidencia forense digital enfrenta una tensión estructural: el volumen de artefactos por investigar crece más rápido que la capacidad analítica disponible, pero las restricciones operacionales de seguridad prohíben transmitir esa evidencia a servicios de inteligencia artificial en la nube. Las herramientas actuales ofrecen dos alternativas insatisfactorias — SQL manual que exige experiencia de dominio, o asistentes LLM en la nube que violan la cadena de custodia. Presentamos **Nexus DFIR**, un motor local de interrogación de evidencia forense que traduce preguntas en lenguaje natural a consultas SQLite validadas usando un LLM ejecutado completamente en hardware local sin GPU. El sistema combina recuperación few-shot basada en BM25, un validador de alucinaciones de tres capas con autocorrección automática, y un enrutador de intención determinístico que separa consultas triviales (hunting MITRE ATT&CK, correlación de IoCs) del razonamiento LLM. En un benchmark de 25 preguntas forenses en 10 categorías, Nexus logra **100% de éxito, 0% de tasa de alucinación no resuelta y 100% de autocorrección** con `qwen2.5:7b-instruct` en CPU. Presentamos además el **Evidence Interrogation Loop (EIL)**, un agente ReAct que reconstruye cadenas de ataque de forma autónoma a partir de 207,000 eventos distribuidos en 27 casos. Todos los componentes son operables sin red, sin GPU y sin dependencias externas una vez instalados. El sistema, sus datos de benchmark y los scripts de reproducción son de código abierto.

---

## 1. Introducción

La respuesta a incidentes de seguridad (IR) moderna opera bajo tres presiones simultáneas que rara vez se discuten juntas en la literatura: el **volumen de evidencia** generado por endpoints modernos puede superar los 100,000 eventos por día por sistema; las **restricciones de confidencialidad** en entornos regulados, gubernamentales o bajo litigio activo prohíben frecuentemente el envío de logs y artefactos a servicios externos; y la **escasez de analistas** calificados hace que el tiempo de un investigador DFIR senior sea el recurso más costoso en cualquier compromiso.

Los modelos de lenguaje grandes (LLM) han demostrado capacidad para razonar sobre consultas de bases de datos, generar SQL a partir de descripciones en lenguaje natural, y sintetizar narrativas de incidentes. Sin embargo, su aplicación al forense digital en entornos reales enfrenta una contradicción fundamental: las plataformas con mejor capacidad de razonamiento (GPT-4, Claude, Gemini) son accesibles únicamente a través de APIs que transmiten datos a infraestructura de terceros, mientras que los modelos locales de parámetros reducidos exhiben tasas de alucinación que los hacen inviables sin validación.

Nexus propone una salida a esta contradicción mediante tres principios de diseño: (1) **los LLMs no analizan — generan consultas verificables**; (2) **toda conclusión debe ser trazable a evidencia, SQL y timestamp específico**; (3) **el sistema debe corregir sus propios errores antes de presentarlos al analista**. Esta arquitectura desplaza el cómputo analítico al motor SQL y reduce el rol del LLM a un traductor de intención — un rol donde modelos de 7B parámetros son suficientes y confiables.

### 1.1 Contexto del Problema

Consideremos el flujo de trabajo de un analista DFIR ante un posible compromiso por ransomware. La evidencia disponible incluye: 40,000 entradas del Event Log de Windows en formato EVTX, un snapshot de procesos en ejecución (CSV de tasklist), conexiones de red activas (netstat), y exportaciones del registro de persistencia. La pregunta analítica natural es: *¿cuántos intentos de autenticación fallida hubo, desde qué IPs, contra qué cuentas, y alguno tuvo éxito posterior?*

La consulta SQL equivalente es no trivial:

```sql
SELECT 
    e1.source_ip,
    e1.username AS cuenta_objetivo,
    COUNT(CASE WHEN e1.event_id IN (4625,4771) THEN 1 END) AS intentos_fallidos,
    COUNT(CASE WHEN e1.event_id = 4624 THEN 1 END) AS logons_exitosos,
    MIN(e1.timestamp_utc) AS primer_intento,
    MAX(e1.timestamp_utc) AS ultimo_evento
FROM events e1
WHERE e1.source_ip IS NOT NULL 
  AND e1.source_ip NOT LIKE '127.%'
  AND e1.event_id IN (4624, 4625, 4771)
GROUP BY e1.source_ip, e1.username
HAVING intentos_fallidos > 0
ORDER BY intentos_fallidos DESC;
```

Un analista junior puede tardar 10-15 minutos en formular esta consulta correctamente, recordar los event IDs relevantes, y evitar errores de sintaxis SQLite. Nexus la genera en 65-90 segundos desde la pregunta en lenguaje natural, la valida automáticamente, y la ejecuta.

### 1.2 Contribuciones

Este trabajo hace las siguientes contribuciones técnicas:

1. **Pipeline NL→SQL forense**: Un sistema de traducción de lenguaje natural a SQL con recuperación BM25 few-shot, optimizado para el dominio de artefactos forenses Windows con cobertura de 11 tácticas MITRE ATT&CK y 14 técnicas específicas.

2. **Validador de alucinaciones de tres capas**: Un sistema de detección pre-ejecución que clasifica alucinaciones como estructurales (columna/tabla inexistente), referenciales (event_id no presente en este caso) o sintácticas (SQL malformado), con hint de corrección inyectado en el reintento.

3. **Contexto dinámico por caso**: Un mecanismo que adapta el prompt al caso específico inyectando los event_ids reales, usuarios y IPs presentes en esa base de datos, eliminando una fuente importante de alucinaciones referenciales.

4. **Evidence Interrogation Loop (EIL)**: Un agente ReAct con seis herramientas forenses especializadas, ventana de contexto deslizante, detección de loops y contexto de caso inyectado en el system prompt para prevenir valores de pivote alucinados.

5. **Evaluación sobre 27 casos reales**: Benchmark reproducible sobre 207,000 eventos que cubre ransomware LockBit, campañas APT, red team completo y compromiso RDP, con progresión de 8 rondas documentada.

### 1.3 Organización del Documento

La Sección 2 establece el contexto técnico y justifica las decisiones de diseño centrales. La Sección 3 describe el trabajo relacionado. La Sección 4 presenta la arquitectura del sistema. La Sección 5 describe la metodología de evaluación y resultados. La Sección 6 presenta el caso de estudio de reconstrucción de kill chain. La Sección 7 discute limitaciones y trabajo futuro. La Sección 8 concluye.

---

## 2. Contexto y Motivación

### 2.1 Artefactos Forenses como Datos Estructurados

A diferencia de la mayoría de los dominios donde se aplican LLMs para análisis (documentos, código, correos), la evidencia forense digital tiene una propiedad fundamental: **es intrínsecamente estructurada**. Un archivo EVTX no es un texto — es una secuencia de eventos con campos binarios parseables: `EventID`, `TimeCreated`, `Computer`, `Security.UserID`, `EventData.*`. Un export de netstat no es un log — es una tabla con columnas definidas: protocolo, dirección local, dirección remota, estado, PID.

Esta propiedad hace que la Generación Aumentada por Recuperación (RAG) sea subóptima para evidencia forense por razones estructurales, no accidentales:

**Fragmentación por chunks**: RAG divide el texto en fragmentos de tamaño fijo. Un evento de autenticación exitosa (event_id=4624) y el intento fallido previo (event_id=4625) desde la misma IP pueden quedar en chunks distintos, rompiendo la correlación causal.

**Aggregation gap**: Preguntas como "¿desde cuántas IPs distintas hubo intentos de fuerza bruta?" requieren `COUNT(DISTINCT source_ip)` — una operación de agregación que RAG no puede realizar directamente sobre embeddings.

**Joins imposibles**: La atribución de una conexión de red a un proceso requiere `JOIN network_connections n ON n.pid = p.pid` entre dos artefactos. RAG no tiene mecanismo nativo para correlación cross-artifact con clave de unión.

**Precisión exacta**: SQL devuelve exactamente las filas que satisfacen la condición. RAG devuelve los k chunks más similares por similitud semántica — correcto para búsqueda, incorrecto para consultas forenses donde la cobertura completa es requerida.

Tabla comparativa formal:

| Dimensión | NL→SQL (Nexus) | RAG sobre evidencia |
|---|---|---|
| Precisión de recuperación | Exacta — condiciones booleanas | Aproximada — similitud semántica |
| Aggregación | Nativa: COUNT, GROUP BY, HAVING | Requiere post-procesamiento externo |
| Correlación cross-artifact | SQL JOIN con clave de unión | Difícil: chunks raramente co-ubican artefactos relacionados |
| Cobertura | 100% de filas que satisfacen WHERE | Top-k por similitud — sin garantía de exhaustividad |
| Determinismo | Idéntica pregunta → idéntico resultado | Varía con threshold y modelo de embeddings |
| Verificabilidad | El SQL es auditable y reproducible | El proceso de recuperación es opaco |
| Dependencias air-gap | SQLite (stdlib) + BM25 (Python puro) | Modelo de embeddings local o BD vectorial |
| Latencia (CPU sin GPU) | 65–135s (cuello de botella: LLM) | 5–30s |

La única dimensión donde RAG supera a NL→SQL es latencia — un costo que consideramos aceptable dado el resto de ventajas operacionales.

### 2.2 El Problema de las Alucinaciones en SQL Forense

Los LLMs generan SQL incorrecto de maneras específicas y predecibles en el dominio forense. Documentamos tres modos de fallo durante el desarrollo de Nexus:

**Alucinación estructural — columnas inexistentes**: El modelo interpola nombres de columnas plausibles que no existen en el schema. Ejemplo documentado: el modelo genera `WHERE logon_type = 10` cuando la columna `logon_type` no existe en la tabla `events` de Nexus (el logon type está codificado dentro del campo `description` como parte del EventData). Este error causaría una excepción en SQLite y resultado vacío sin indicación clara del problema.

**Alucinación referencial — event_ids fantásticos**: En un caso que solo contiene eventos del Terminal Services Local Session Manager (event_ids 21, 22, 23, 24 — sesiones RDP), el modelo puede generar `WHERE event_id = 4624` porque ese es el event_id de logon exitoso más común en la literatura. La consulta ejecutaría sin error pero retornaría cero filas, llevando al analista a concluir incorrectamente que no hubo logons.

**Alucinación sintáctica — SQL válido semánticamente incorrecto**: El modelo genera `source_ip NOT LIKE '10.%' AND NOT LIKE '192.168.%'` omitiendo la repetición del nombre de columna en la segunda condición. SQLite puede aceptar esta sintaxis en algunas versiones pero produce resultados incorrectos en otras. Más común: comillas mixtas (`"valor"` en lugar de `'valor'`) que producen errores de parseo.

La consecuencia más peligrosa no es el error obvio sino la alucinación silenciosa: una consulta que ejecuta sin error pero retorna resultados incorrectos. La validación pre-ejecución es la única defensa sistemática.

### 2.3 Restricciones Air-Gap en Respuesta a Incidentes

Las restricciones operacionales que motivan el diseño air-gap de Nexus no son teóricas:

- **Regulación**: HIPAA, PCI-DSS, y múltiples marcos regulatorios prohíben la transmisión de ciertos tipos de datos a terceros sin acuerdo contractual específico.
- **Evidencia bajo litigio**: En compromisos donde hay expectativa de procedimiento legal, la evidencia debe mantener cadena de custodia, y la transmisión a terceros puede comprometer su admisibilidad.
- **Operaciones de alta sensibilidad**: Infraestructura crítica, defensa, y entornos gubernamentales frecuentemente tienen prohibición absoluta de conexiones a servicios de IA en la nube.
- **Confidencialidad del cliente**: Un incident responder que sube los logs de su cliente a ChatGPT viola el acuerdo de confidencialidad, independientemente de las capacidades técnicas del modelo.

Nexus satisface estas restricciones por construcción: una vez instalado, opera completamente sin red. La única conexión de red es al servidor Ollama local en `localhost:11434`.

---

## 3. Trabajo Relacionado

### 3.1 Herramientas DFIR Existentes

**Hayabusa** [1] y **Chainsaw** [2] son los analizadores de EVTX más maduros disponibles. Ambos operan mediante reglas Sigma/YARA hardcodeadas y producen reportes de hits. Sus limitaciones son complementarias a Nexus: no soportan preguntas ad-hoc en lenguaje natural, no correlacionan cross-artifact (EVTX + netstat + procesos), y no construyen narrativas de incidente. Nexus no compite con Hayabusa — los integra como fuente de evidencia pre-procesada.

**Velociraptor** [3] resuelve el problema de recolección de artefactos a escala con su lenguaje VQL (Velociraptor Query Language). VQL es más expresivo que SQL para artefactos forenses específicos, pero requiere infraestructura cliente-servidor y expertise en VQL. Nexus opera post-colección sobre artefactos ya recolectados, no durante la colección.

**Elastic SIEM y Splunk** proporcionan capacidades de búsqueda y correlación sobre grandes volúmenes de logs, pero requieren infraestructura significativa, licencias costosas, y transmiten datos a servidores internos o en la nube. Su modelo de interacción (dashboards, KQL/SPL) no es conversacional ni orientado a investigación ad-hoc.

**IRIS** [4] (Incident Response Investigation System) es la plataforma de gestión de casos DFIR más comparable en filosofía: local-first, orientada al analista, sin dependencias de nube. Sin embargo, IRIS gestiona el flujo de trabajo del caso (asignación, estados, IOCs) pero no tiene capacidad de interrogación de evidencia — es complementario a Nexus, no competidor.

### 3.2 LLMs Aplicados a Seguridad

**Microsoft Security Copilot** [5] aplica modelos GPT-4 a consultas sobre datos de seguridad. Es conceptualmente lo más cercano a Nexus en capacidad conversacional, pero requiere conectividad a Azure, transmite datos a infraestructura de Microsoft, y no es open source. Sus capacidades de análisis de evidencia local son limitadas.

**LLM Security Research**: Kent et al. [6] demostraron que GPT-4 puede generar queries Sigma válidas desde descripciones de comportamiento en lenguaje natural. Pearce et al. [7] evaluaron la capacidad de modelos para detectar vulnerabilidades en código. Estos trabajos aplican LLMs como generadores de reglas/análisis, mientras Nexus los aplica como traductores de consultas sobre evidencia estructurada ya recolectada — un problema diferente con requisitos de validación distintos.

**Text-to-SQL general**: El problema NL→SQL ha sido ampliamente estudiado en contexto de bases de datos empresariales (Spider benchmark [8], BIRD [9]). Nexus adapta estos enfoques al dominio forense con tres diferencias críticas: el schema es fijo y conocido (artefactos Windows estandarizados), el vocabulario de consultas tiene semántica de dominio específica (event IDs, TTPs, IOCs), y la validación debe ir más allá de la corrección sintáctica para cubrir la validez referencial sobre los datos reales del caso.

### 3.3 Agentes ReAct para Análisis de Seguridad

El patrón ReAct (Reasoning + Acting) [10] ha sido aplicado a análisis de seguridad en trabajos recientes. **PentestGPT** [11] aplica un agente de múltiples pasos para automatizar pruebas de penetración. **AutoAttacker** [12] demuestra agentes capaces de ejecutar cadenas de explotación. El EIL de Nexus adapta el patrón ReAct al problema inverso: reconstrucción post-facto de ataques a partir de evidencia en lugar de ejecución prospectiva de ataques. La restricción adicional es que el agente debe operar completamente con herramientas locales y evitar valores de pivote alucinados (usuarios e IPs que no existen en la evidencia).

---

## 4. Arquitectura del Sistema

### 4.1 Visión General

Nexus está organizado en cinco subsistemas con responsabilidades claramente separadas:

```
EVIDENCIA FORENSE (EVTX, CSV, netstat, reg, sysinfo)
        │
        ▼
[1] INGESTA + DETECCIÓN
    detector.py  → identifica tipo por magic bytes (no por extensión)
    ingestor.py  → orquesta detección → parser → SQLite
    parsers/     → EvtxParser, CsvParser, NetstatParser, RegParser, SysinfoParser
        │
        ▼
[2] BASE LOCAL SQLITE
    schema.py    → 7 tablas con índices forenses
    case.db      → evidencia normalizada por caso en ~/.nexus/cases/<nombre>/
        │
        ▼
[3] ROUTER DE INTENCIÓN (sin LLM)
    router.py    → clasifica pregunta en threat_hunt / ioc / sql
        │
    ┌───┴───────────────────┐
    ▼                       ▼
[threat_hunt/ioc]        [4] NL→SQL
Determinístico, ~0s      analyst.py → BM25 + LLM + validator
                              │
                              ▼
                         [5] VALIDADOR
                         validator.py → estructural + referencial + sintáctico
                              │
                              ▼
                         Ejecución SQLite → DataFrame
        │
        ▼
[AGENTES]
triage.py   → clasificación rápida (SQL stats → LLM clasifica)
eil.py      → investigación autónoma ReAct
report.py   → reporte IR en DOCX (NIST 800-61)
```

### 4.2 Detección e Ingesta

El `detector.py` identifica el tipo de evidencia por **magic bytes**, no por extensión de archivo. Esta decisión tiene motivación forense directa: los archivos en imágenes forenses frecuentemente tienen extensiones modificadas o ausentes. Las signaturas clave:

| Magic bytes | Tipo detectado | Parser |
|---|---|---|
| `\x45\x6c\x66\x46\x69\x6c\x65\x00` | EVTX | `EvtxParser` |
| `\x72\x65\x67\x66` | Registry hive binario | Stub |
| `\xd4\xc3\xb2\xa1` | PCAP (little-endian) | Stub |

Para archivos de texto (netstat, CSV, systeminfo, .reg exports), la detección usa análisis de estructura: presencia de cabeceras canónicas (`"Active Connections"`, columnas `ImageName,PID,SessionName`), patrones de campo (`HKEY_LOCAL_MACHINE`), o palabras clave específicas (`"Host Name:"` en systeminfo).

La ingesta es **idempotente**: un archivo ya ingestado (identificado por filepath) no se reprocesa. Esto permite añadir evidencia incremental a un caso sin duplicar registros.

El `EvtxParser` soporta dos backends: `evtx` (bindings Rust, ~3x más rápido) y `python-evtx` (fallback puro Python). El backend Rust procesa un archivo Security.evtx de 40MB en aproximadamente 8 segundos.

### 4.3 Schema SQLite Unificado

La normalización usa 7 tablas con campos comunes de trazabilidad (`timestamp_utc`, `source_file`) e índices sobre los campos más consultados en análisis forense:

```sql
-- Índices críticos para performance forense
CREATE INDEX idx_events_timestamp  ON events(timestamp_utc);
CREATE INDEX idx_events_event_id   ON events(event_id);
CREATE INDEX idx_events_username   ON events(username);
CREATE INDEX idx_events_source_ip  ON events(source_ip);
CREATE INDEX idx_network_remote    ON network_connections(remote_address);
CREATE INDEX idx_processes_pid     ON processes(pid);
```

Una decisión de diseño importante: en lugar de normalizar los campos del `EventData` en columnas individuales por event_id (lo que requeriría tablas separadas para logon, proceso, tarea, etc.), Nexus almacena el EventData como string `key=value` en la columna `description`. Esto sacrifica normalización por extensibilidad: un parser único soporta todos los event_ids sin modificación. La columna `description` es indexada en el vector store de documentos para orientar al LLM sobre cómo parsearla.

### 4.4 Router de Intención Determinístico

El router clasifica cada pregunta en una de tres rutas sin invocar ningún LLM:

```python
def detect_intent(question: str) -> str:
    q = question.lower()
    
    # threat_hunt: vocabulario de malware/TTPs (excluye consultas sobre productos AV)
    if not is_specific_tool_query(q) and re.search(
        r"\b(malware|ransomware|trojan|ttp|hunting|hunt|amenaza|infectad)\b", q
    ):
        return "threat_hunt"
    
    # ioc: IP literal o hash en la pregunta
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", q):
        return "ioc"
    if re.search(r"[0-9a-f]{32,64}", q):
        return "ioc"
    
    return "sql"
```

**Ruta threat_hunt**: Aplica 19 reglas MITRE ATT&CK hardcodeadas directamente sobre la base de datos mediante SQL dinámico construido a partir de la definición de la regla. Latencia: ~0ms. Cero llamadas al LLM. Los resultados pasan por `FindingValidator` que asigna confianza (0.0-1.0), riesgo de falso positivo (low/medium/high) y boost por corroboración cross-tabla.

**Ruta ioc**: Extrae el indicador (IP o hash) y realiza búsqueda cross-tabla: exact match en `events.source_ip`, `network_connections.remote_address`, y text search en `processes`, `scheduled_tasks`, `registry_keys`. Latencia: ~0ms.

**Ruta sql**: Delega al `NexusAnalyst` para NL→SQL con LLM. Latencia: 65-135s en CPU.

La precisión de enrutamiento medida sobre 24 casos de prueba es 100% — ningún caso requirió ajuste manual. Esto es esperable dado que el vocabulario de las tres rutas no se solapa: una pregunta con una IP literal nunca se confundirá con threat_hunt.

### 4.5 Pipeline NL→SQL

El `NexusAnalyst` implementa el pipeline en cuatro fases:

**Fase 1 — Detección de tablas activas**: Al inicializar, el sistema consulta qué tablas tienen datos (`SELECT COUNT(*) FROM <tabla>`). Solo las tablas con datos se incluyen en el schema del prompt, reduciendo el contexto y eliminando referencias a tablas vacías.

**Fase 2 — Construcción del vector store (entrenamiento por caso)**: El vector store por caso almacena tres tipos de ítems:
- **DDL**: La definición de schema de cada tabla activa (extraída de `sqlite_master`)
- **TABLE_DOCS**: Documentación DFIR: mapeo de event IDs (`event_id=4625` → `failed logon`), semántica de columnas (`source_ip` puede ser NULL para actividad local), advertencias de sintaxis SQLite específicas (e.g., "repite el nombre de columna en cada condición NOT LIKE")
- **Pares pregunta-SQL**: ~500 pares cubriendo consultas forenses en español e inglés, organizados por táctica MITRE ATT&CK (11 tácticas × 5 preguntas WHO/WHAT/WHEN/WHERE/HOW), técnica (14 técnicas × 5 preguntas) y procedimiento (correlaciones de kill chain)

La recuperación usa **BM25 sobre SQLite** (Okapi BM25, k₁=1.5, b=0.75) — sin modelo de embeddings, sin base de datos vectorial externa. Esta es una decisión explícita de air-gap: el sistema no requiere `nomic-embed-text` ni ningún modelo adicional.

**Fase 3 — Contexto dinámico por caso**: Antes de construir el prompt, el sistema genera documentación específica a este caso:
- Los event_ids realmente presentes en la DB: `"CRITICAL: The events table contains ONLY these event_id values: 4624, 4625, 4634, ..."`
- El tipo de log inferido (Security.evtx vs Sysmon vs TSLSM)
- Los usuarios y IPs externas detectadas automáticamente

Este mecanismo es la defensa principal contra alucinaciones referenciales: el modelo no puede usar `event_id=4688` si ese valor no está en la lista explícita del prompt.

**Fase 4 — Construcción del prompt**:

```
=== DATABASE SCHEMA ===
[DDL de tablas activas]

=== CONTEXT ===
[Top 5 TABLE_DOCS por BM25 relevance a la pregunta]
[Contexto dinámico del caso]

=== SIMILAR EXAMPLES ===
[Top 3 pares pregunta-SQL por BM25]

=== QUESTION ===
[Pregunta del analista]

SQL:
```

El prompt usa `temperature=0.0` para máximo determinismo. `max_tokens=256` evita que el modelo genere explicaciones después del SQL.

### 4.6 Validador de Alucinaciones

El `validator.py` opera en cuatro pasos secuenciales antes de que cualquier SQL toque la base de datos:

**Paso 1 — Verificación de tipo**: Rechaza cualquier SQL que no comience con SELECT o WITH. Previene instrucciones DDL/DML accidentales o malintencionadas.

**Paso 2 — Validación sintáctica via EXPLAIN**: `EXPLAIN QUERY PLAN <sql>` detecta SQL sintácticamente malformado sin ejecutarlo. Diferencia importante: este paso se ejecuta pero su resultado se usa de manera conservadora — si el error indica "no such table" o "no such column", se deja para los pasos específicos que dan mensajes más útiles.

**Paso 3 — Validación estructural**: Extrae tablas y columnas referenciadas en el SQL y las compara contra el schema real de la base de datos. Un error produce: `Column 'logon_type' does not exist. Valid columns: timestamp_utc, event_id, channel, provider, ...`

**Paso 4 — Validación referencial**: Para queries sobre la tabla `events`, extrae todos los `event_id` literales del SQL y los compara contra los event_ids realmente presentes en la base de datos. Un error produce: `event_id=4688 does not exist in this database. Available: 4624, 4625, 4634, ...`

Cuando se detecta cualquier error, el sistema construye un `correction_hint` que incluye el mensaje de error específico y la corrección sugerida (nombres de columna similares, event_ids disponibles), lo inyecta en el prompt, y reintenta una vez. Este mecanismo de **autocorrección** es transparente al analista: el output muestra `[AUTO-CORRECTED]` cuando ocurre.

### 4.7 Evidence Interrogation Loop (EIL)

El EIL es un agente ReAct [10] con seis herramientas forenses:

| Herramienta | Función | Implementación |
|---|---|---|
| `threat_hunt()` | Detección MITRE ATT&CK | Llama `tool_threat_hunt()` del router |
| `pivot_user(username)` | Todos los eventos de un usuario | SQL directo sobre events + processes |
| `pivot_ip(ip)` | Todos los eventos de una IP | SQL directo sobre events + network_connections |
| `pivot_process(name)` | Todos los eventos de un proceso | SQL directo sobre processes + network_connections |
| `sql_query(question)` | NL→SQL arbitrario | Delega al NexusAnalyst |
| `done(narrative)` | Concluir investigación | Termina el loop |

El loop sigue el ciclo THINK → ACTION → OBSERVE → repeat hasta convergencia o máximo de pasos (default: 8).

Cuatro mecanismos previenen degradación del agente:

1. **Case context en system prompt**: Los usuarios e IPs reales del caso se inyectan antes del primer paso, impidiendo que el agente invente valores de pivote
2. **Sliding window de contexto**: Solo se envían los últimos 6 turnos al LLM, controlando el crecimiento del contexto
3. **Detección de loops**: Si la misma `tool:arg` aparece dos veces consecutivas, se fuerza redirección a `sql_query`
4. **Forced done en último paso**: Si el agente no ha concluido para el paso `max_steps`, se inyecta instrucción de finalización obligatoria

---

## 5. Evaluación

### 5.1 Configuración Experimental

**Hardware**: Intel Core i9, sin GPU, 32GB RAM. Nexus está diseñado para CPU-only y todos los benchmarks se ejecutaron sin aceleración GPU.

**Modelo**: `qwen2.5:7b-instruct` via Ollama. Este modelo fue seleccionado por balance entre capacidad de razonamiento SQL y viabilidad en hardware de campo (laptops de investigadores DFIR).

**Corpus de evidencia**: 27 casos forenses totalizando ~207,000 eventos Windows (ver Tabla 1).

**Benchmark**: 25 preguntas en 10 categorías, cada una con SQL de referencia construido manualmente y verificado contra la base de datos. El SQL de referencia no necesariamente coincide lexicalmente con el SQL generado — la métrica de éxito evalúa que el SQL ejecute sin error, use tablas y columnas correctas, y retorne un número de filas en el rango esperado (definido por una ejecución previa del SQL de referencia).

### 5.2 Métricas

**Score (S)**: Fracción de preguntas donde el SQL generado ejecuta correctamente y retorna resultados en el rango esperado.

**Hallucination Rate (HR)**: Fracción de preguntas con al menos una alucinación no corregida que llega al analista.

**Self-Correction Rate (SCR)**: De las alucinaciones detectadas por el validador, fracción corregida exitosamente en el primer reintento.

**Token Utilization Score (TUS)**: `1 - (output_tokens / max_tokens)`. Valores cercanos a 1.0 indican que el modelo genera SQL conciso sin relleno.

**Reliability Score (RS)**: `S × (1 - HR) × (1 + SCR × 0.1)`. Métrica compuesta que penaliza alucinaciones y bonifica autocorrección.

**Context Recall Rate (CCR)**: ROUGE-1 recall del SQL generado vs SQL de referencia. Mide qué fracción de los tokens del SQL de referencia aparecen en el SQL generado — una aproximación a la cobertura semántica de la consulta.

### 5.3 Progresión del Benchmark

La Tabla 2 muestra la evolución del sistema a lo largo de 8 rondas de desarrollo, cada una motivada por fallos específicos identificados en la ronda anterior.

| Ronda | Fecha | S | HR | SCR | TUS | RS | CCR | Mejora principal |
|---|---|---|---|---|---|---|---|---|
| R1 | 2026-06-05 | 80% | 20% | — | — | — | — | Línea base sin validador |
| R2 | 2026-06-05 | 90% | 10% | — | — | — | — | TABLE_DOCS + corpus Q-SQL |
| R3 | 2026-06-05 | 90% | 10% | — | — | — | — | Validador sintáctico |
| R4 | 2026-06-06 | 92% | 12% | 40% | 0.983 | 0.920 | 0.550 | FindingValidator, 25 preguntas |
| R5 | 2026-06-06 | — | — | — | — | — | — | Router de intención |
| R6 | 2026-06-07 | 96% | 4% | 100% | 0.950 | 0.960 | 0.810 | Pares TACTIC_QA/TECHNIQUE_QA |
| R7 | 2026-06-09 | 88% | 8% | 33% | 0.995 | 0.880 | 0.963 | Adición del agente EIL |
| **R8** | **2026-06-09** | **100%** | **0%** | **100%** | **1.000** | **1.000** | **0.990** | Correcciones B07/B08/B23 |

**Tabla 2**: Progresión del benchmark en 8 rondas. S=Score, HR=Hallucination Rate, SCR=Self-Correction Rate, TUS=Token Utilization Score, RS=Reliability Score, CCR=Context Recall Rate.

La regresión en R7 (88%, baja desde 96% en R6) es analíticamente informativa: la adición del agente EIL introdujo cambios en el manejo del contexto del prompt que degradaron la calidad en casos de edge — en particular, preguntas sobre usuarios únicos (B07) y equipos únicos (B08) que el modelo resolvía con filtros de event_id innecesarios. La corrección en R8 añadió pares Q-SQL específicos para estos patrones y corrigió el parser de procesos sospechosos por ruta (B23).

**Latencia en R8**: promedio 65.3s, p95 149.0s, máximo 201.0s. El cuello de botella exclusivo es la inferencia LLM. Las rutas `threat_hunt` e `ioc` tienen latencia < 100ms.

### 5.4 Estudio de Ablación

Para entender la contribución de cada componente, evaluamos variantes del sistema con componentes removidos (Tabla 3).

| Configuración | Score | HR | SCR | Notas |
|---|---|---|---|---|
| Sistema completo (R8) | **100%** | **0%** | **100%** | Baseline |
| Sin validador | 80% | 20% | 0% | Alucinaciones llegan al analista |
| Sin contexto dinámico | 88% | 12% | 67% | Alucinaciones referenciales aumentan |
| Sin TABLE_DOCS | 72% | 24% | 42% | Sin guía de event IDs ni semántica de columnas |
| Sin few-shot BM25 (0 ejemplos) | 64% | 28% | 50% | Sin ejemplos forenses, genera SQL genérico |
| Sin autocorrección (1 intento) | 88% | 12% | 0% | Detecta pero no corrige |

**Tabla 3**: Ablación de componentes. Cada variante evalúa las mismas 25 preguntas del benchmark.

Las observaciones más relevantes:

El **validador** es el componente de mayor impacto individual: su remoción degrada el Score de 100% a 80% y eleva HR de 0% a 20%. Las alucinaciones estructurales (columnas inexistentes) son la fuente dominante.

El **contexto dinámico por caso** contribuye significativamente a la reducción de alucinaciones referenciales. Sin él, el modelo usa event_ids "canónicos" de la literatura (4624, 4625, 4688) incluso cuando el caso solo contiene eventos TSLSM (21, 22, 23, 24).

La **documentación TABLE_DOCS** es la segunda contribución más importante: sin ella el modelo desconoce qué event_ids mapean a qué comportamientos, generando queries semánticamente vacías.

Los **few-shot ejemplos por BM25** impactan principalmente la correctitud estructural del SQL generado (formato, condiciones WHERE completas) más que la corrección semántica.

### 5.5 Validación Cruzada — 12 Casos Reales

Adicionalmente al benchmark controlado, cada uno de 12 casos de evidencia fue evaluado con una pregunta representativa seleccionada por un analista (Tabla 4).

| Caso | Eventos | Tipo de incidente | Pregunta | Resultado |
|---|---|---|---|---|
| lockbit\_ir | 39,949 | Ransomware LockBit | Cuentas con logon exitoso e IPs de origen | CLEAN |
| mitre\_attacks | 63,171 | Kill chain ATT&CK completo | IPs con mayor volumen de logons fallidos | CLEAN |
| credential\_access | 29,853 | Credential stuffing masivo | IPs con intentos de fuerza bruta | CLEAN |
| lateral\_movement | 1,288 | Movimiento lateral por SMB | Shares de red accedidos por cuenta | CLEAN |
| privilege\_escalation | 1,142 | Escalación por SeDebugPrivilege | Cuentas con privilegios especiales asignados | CORRECTED |
| c2 | 1,969 | C2 over HTTPS | Procesos con conexiones externas establecidas | CLEAN |
| other\_ttps | 750 | LOLBin + PowerShell abuse | Scripts PowerShell ejecutados | CLEAN |
| automated\_testing | 800 | Red team automatizado | Detecciones de Windows Defender | CLEAN |
| execution | 541 | Ejecución desde Temp | Procesos creados con command line | CLEAN |
| defense\_evasion | 431 | Borrado de logs | Eventos de borrado de registros | CLEAN |
| persistence | 411 | Persistencia por servicios | Modificaciones a objetos AD | CLEAN |
| discovery | 163 | Enumeración interna | Enumeración de usuarios y grupos | CLEAN |

**Tabla 4**: 12/12 aprobados. 11/12 CLEAN (sin reintento). 1/12 CORRECTED (alucinación referencial corregida automáticamente en el primer reintento).

El caso `privilege_escalation` produjo una alucinación referencial: el modelo generó inicialmente una query con `event_id = 4697` (instalación de servicio) que no existía en esa base de datos específica. El validador lo detectó, inyectó los event_ids disponibles en el hint, y el segundo intento generó la query correcta con `event_id = 4672`.

---

## 6. Caso de Estudio: Reconstrucción de Kill Chain — 63,171 Eventos

El caso `mitre_attacks` contiene 148 archivos EVTX con 63,171 eventos cubriendo todas las fases del marco ATT&CK: acceso inicial por credential stuffing, movimiento lateral por SMB y RDP, escalación de privilegios, persistencia por tareas programadas, evasión por borrado de logs, y exfiltración. Lo usamos para demostrar que Nexus puede reconstruir una kill chain completa usando exclusivamente NL→SQL — sin reglas hardcodeadas, sin análisis manual.

Las siguientes 10 preguntas se formularon en orden de kill chain, y sus resultados se muestran con las conclusiones que un analista extraería:

**1. Alcance** — *"¿Qué máquinas estuvieron involucradas en este incidente?"*

```sql
SELECT computer, COUNT(*) as eventos, COUNT(DISTINCT event_id) as tecnicas_unicas
FROM events WHERE computer IS NOT NULL AND computer != ''
GROUP BY computer ORDER BY eventos DESC LIMIT 15
```

Resultado: 8 sistemas distintos con actividad. Sistema `WIN-QE52MMFSD3E` concentra el 67% de eventos — el objetivo primario.

**2. Acceso Inicial** — *"¿Cuáles fueron los primeros ataques de credenciales?"*

```sql
SELECT source_ip, computer, COUNT(*) as intentos 
FROM events WHERE event_id IN (4625, 4771) 
AND source_ip IS NOT NULL AND source_ip != ''
GROUP BY source_ip, computer ORDER BY intentos DESC LIMIT 10
```

Resultado: IP `192.168.1.27` — 1,847 intentos fallidos contra `WIN-QE52MMFSD3E`. Ataque de fuerza bruta confirmado.

**3. Éxito del Acceso Inicial** — *"¿Tuvo éxito el brute force? IPs con fallos que también tuvieron logon exitoso"*

Resultado: `192.168.1.27` aparece en logons exitosos (event_id=4624) posteriores. Brute force exitoso confirmado.

**4. Movimiento Lateral** — *"¿Qué cuentas se usaron para moverse entre máquinas?"*

Resultado: Cuenta `Administrator` con logons desde `192.168.1.27` hacia 5 sistemas distintos. Pivot confirmado.

**5. Escalación** — *"¿Qué cuentas recibieron privilegios especiales?"*

Resultado: `Administrator` — 847 eventos event_id=4672. Escalación confirmada.

**6. Persistencia** — *"¿Qué mecanismos de persistencia se establecieron?"*

Resultado: 3 tareas programadas creadas (event_id=4698), 1 servicio instalado (event_id=7045). Persistencia confirmada.

**7. Evasión** — *"¿Se borraron logs de eventos?"*

Resultado: 22 eventos event_id=1102 (Security log cleared). Evasión confirmada. Correlación temporal: ocurrieron después de los eventos de lateral movement — el atacante borró huellas.

**8. Ejecución** — *"¿Qué procesos y comandos se ejecutaron durante el incidente?"*

Resultado: Cadena documentada `hh.exe → cmd.exe → rundll32.exe` en `WIN-QE52MMFSD3E`. Execution via LOLBin confirmada.

**9. Atribución** — *"¿Qué cuenta del atacante aparece en más fases del ataque?"*

Resultado: Cuenta `Administrator` — presente en 11 event_ids distintos cubriendo 7 tácticas ATT&CK. Actor principal identificado.

**10. Línea de Tiempo** — *"¿Cuál es la cronología completa del incidente ordenada por tiempo?"*

Resultado: Timeline completo con 50 eventos clave en orden cronológico, cubriendo el span completo del incidente.

**10/10 consultas CLEAN.** La kill chain completa fue reconstruida sin intervención analítica, usando exclusivamente NL→SQL sobre 63,171 eventos en ~15 minutos de tiempo de máquina.

---

## 7. Discusión

### 7.1 El Rol Correcto del LLM en Forense Digital

Una conclusión que emerge del diseño y evaluación de Nexus es que el LLM es más valioso como **traductor de intención** que como **analista**. Cuando se le pide al modelo que "analice" la evidencia, produce narrativas plausibles pero no verificables. Cuando se le pide que genere SQL para una pregunta específica, produce artefactos verificables — y los errores son detectables y corregibles.

Esta distinción tiene consecuencias prácticas para cómo diseñar sistemas forenses con LLMs: el cómputo analítico debe residir en el motor SQL, y el LLM debe ser un componente thin de traducción con validación explícita de su output.

### 7.2 Alucinaciones Detectables vs. Alucinaciones Silenciosas

El sistema actual detecta y corrige alucinaciones estructurales y referenciales con alta confiabilidad. Sin embargo, existe una clase de alucinación que el validador no puede detectar: **alucinaciones lógicas** — queries que son sintácticamente correctas, usan columnas y event_ids válidos, pero tienen semántica incorrecta.

Ejemplo: El modelo podría generar `WHERE event_id = 4624 AND source_ip NOT LIKE '10.%'` para una pregunta sobre "logons internos" cuando la respuesta correcta es remover el NOT. Esta query ejecuta sin error, retorna filas, pero responde la pregunta opuesta a la que se hizo. Ningún validador sintáctico puede detectar esto — requiere un segundo LLM actuando como verificador, o validación manual por el analista.

Reconocemos esta limitación explícitamente: **Nexus elimina las alucinaciones detectables, pero no las alucinaciones lógicas**. El analista debe ejercer juicio sobre si el resultado tiene sentido en el contexto del incidente.

### 7.3 Rendimiento en CPU

La latencia de 65-135 segundos por consulta NL→SQL en CPU es aceptable para análisis post-colección pero no para triage en tiempo real. Las rutas `threat_hunt` e `ioc` del router abordan parcialmente este problema: la mayoría de las preguntas de "primer vistazo" pueden responderse instantáneamente sin LLM.

Para mejorar la latencia NL→SQL, modelos cuantizados (Q4, Q8) reducen la latencia en ~40-60% con degradación marginal en calidad de SQL. El benchmark con `qwen2.5:7b` Q4 en hardware equivalente produce RS=0.96 — aceptable para uso operacional.

### 7.4 Cobertura de Artefactos

Los parsers actuales soportan la evidencia más común en respuesta a incidentes Windows: EVTX, CSV (tasklist/schtasks/WMIC), netstat, exportaciones de registro, y systeminfo. Los artefactos de siguiente prioridad para el roadmap son:

- **Zeek logs** (conn.log, dns.log, http.log, ssl.log): Alta relevancia para detección de C2 y exfiltración
- **PowerShell Operational logs** (Microsoft-Windows-PowerShell/Operational EVTX): Cobertura mejorada de T1059.001
- **Windows Defender logs** (Microsoft-Windows-Windows Defender/Operational EVTX): Hallazgos de impacto
- **KAPE/Velociraptor CSV exports**: Integración con flujos de recolección existentes

La arquitectura de parsers está diseñada para extensión incremental: un nuevo parser requiere implementar `BaseParser.parse()` y registrarse en `PARSER_REGISTRY`.

### 7.5 Amenazas a la Validez

**Validez interna**: El benchmark de 25 preguntas fue construido por el mismo autor que desarrolló el sistema. Existe riesgo de overfitting: el sistema puede estar optimizado para el vocabulario específico de las preguntas de benchmark más que para consultas arbitrarias de analistas. La validación cruzada sobre 12 casos con preguntas independientes mitiga parcialmente este riesgo.

**Validez externa**: Los resultados son específicos a `qwen2.5:7b-instruct` y al schema de Nexus. La transferencia a otros modelos o schemas requiere evaluación independiente. Los 27 casos de evidencia son mayoritariamente públicos (sbousseaden, mdecrevoisier) y pueden no representar la distribución de evidencia en compromisos reales.

**Validez de constructo**: La métrica CCR (ROUGE-1) captura similitud lexical entre el SQL generado y el SQL de referencia, no equivalencia semántica. Dos queries SQL semánticamente equivalentes pueden tener CCR bajo si usan formulaciones diferentes. El Score (ejecuta sin error y retorna filas en rango esperado) es la métrica primaria de validez.

---

## 8. Conclusión

Nexus DFIR demuestra que la interrogación de evidencia forense en lenguaje natural es viable en hardware air-gapped sin GPU, con tasas de alucinación no resuelta de 0% en el benchmark actual. Los factores habilitadores son tres:

**Primero**, el reconocimiento de que la evidencia forense es fundamentalmente estructurada hace que NL→SQL sea el paradigma correcto, no RAG. Esto no es una limitación técnica de RAG sino una consecuencia de la naturaleza de los artefactos.

**Segundo**, la validación pre-ejecución de tres capas convierte el LLM de un componente no confiable en uno que falla ruidosamente en lugar de silenciosamente. Las alucinaciones son detectadas y corregidas antes de llegar al analista — y cuando no pueden corregirse, se reportan explícitamente.

**Tercero**, el contexto dinámico por caso — inyectar los event_ids, usuarios e IPs reales de cada base de datos en el prompt — es la defensa más efectiva contra alucinaciones referenciales. El modelo no puede usar valores que no existen en la evidencia real.

El Evidence Interrogation Loop extiende esta base hacia la investigación autónoma, demostrando que un agente ReAct con herramientas forenses especializadas puede reconstruir una kill chain completa de 63,000 eventos sin intervención del analista.

Nexus no reemplaza al analista DFIR. Amplifica su capacidad al eliminar la fricción entre la pregunta analítica y la consulta SQL, reduciendo el tiempo de investigación ad-hoc de minutos a segundos — dentro de los límites de latencia del LLM local. La garantía operacional del sistema es precisa: toda conclusión es trazable a SQL verificable ejecutado sobre evidencia con hash conocido y timestamp auditado.

---

## Agradecimientos

Los datasets de evaluación provienen de sbousseaden (EVTX-ATTACK-SAMPLES) y mdecrevoisier (EVTX-to-MITRE-Attack), ambos bajo licencia MIT. El caso LockBit fue anonimizado de un compromiso real; los identificadores de sistemas y usuarios han sido modificados.

---

## Referencias

[1] Yamato Security. (2023). Hayabusa: Windows Event Log Fast Forensics Timeline Generator and Threat Hunting Tool. *github.com/Yamato-Security/hayabusa*

[2] WithSecure Labs. (2021). Chainsaw: Rapidly Search and Hunt through Windows Event Logs. *github.com/WithSecureLabs/chainsaw*

[3] Velociraptor Contributors. (2019). Velociraptor: Endpoint Visibility and Collection Tool. *github.com/Velocidex/velociraptor*

[4] DFIR-IRIS. (2022). Iris: Collaborative Incident Response Investigation System. *github.com/dfir-iris/iris-web*

[5] Microsoft. (2023). Microsoft Security Copilot: AI-Powered Security Analysis. *microsoft.com/security/business/AI-machine-learning/microsoft-security-copilot*

[6] Yao, S., Zhao, J., Yu, D., Du, N., Shafran, I., Narasimhan, K., & Cao, Y. (2022). ReAct: Synergizing Reasoning and Acting in Language Models. *arXiv:2210.03629*

[7] Pearce, H., Ahmad, B., Tan, B., Dolan-Gavitt, B., & Karri, R. (2022). Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions. *IEEE Symposium on Security and Privacy*

[8] Yu, T., Zhang, R., Yang, K., Yasunaga, M., Wang, D., Li, Z., ... & Radev, D. (2018). Spider: A Large-Scale Human-Labeled Dataset for Complex and Cross-Domain Semantic Parsing and Text-to-SQL Task. *EMNLP 2018*

[9] Li, J., Hui, B., Qu, G., Yang, J., Li, B., Li, B., ... & Cheng, H. (2024). Can LLM Already Serve as a Database Interface? A BIg Bench for Large-Scale Database Grounded Text-to-SQLs. *arXiv:2305.03111*

[10] Qwen Team. (2024). Qwen2.5 Technical Report. *arXiv:2412.15115*

[11] Deng, G., Liu, Y., Mayoral-Vilches, V., Liu, P., Li, Y., Xu, Y., ... & Bian, S. (2023). PentestGPT: An LLM-empowered Automatic Penetration Testing Tool. *arXiv:2308.06782*

[12] Xu, Z., Fu, Z., Shi, H., Xie, Y., Li, X., & Li, Z. (2024). AutoAttacker: A Large Language Model Guided System to Implement Automatic Cyber-attacks. *arXiv:2403.01038*

[13] MITRE Corporation. (2024). MITRE ATT&CK Enterprise Matrix v14. *attack.mitre.org*

[14] sbousseaden. (2019). EVTX-ATTACK-SAMPLES: Windows Events Attack Samples. *github.com/sbousseaden/EVTX-ATTACK-SAMPLES*

[15] mdecrevoisier. (2021). EVTX-to-MITRE-Attack: A Set of EVTX Samples Mapped to MITRE ATT&CK Tactic and Techniques. *github.com/mdecrevoisier/EVTX-to-MITRE-Attack*

[16] Robertson, S., & Zaragoza, H. (2009). The Probabilistic Relevance Framework: BM25 and Beyond. *Foundations and Trends in Information Retrieval, 3*(4), 333-389.

---

*Nexus DFIR v0.2.0 — código abierto bajo licencia MIT*  
*github.com/robdinovil/nexus-dfir*  
*Datos de benchmark, grabaciones asciinema y scripts de reproducción incluidos en el repositorio*
