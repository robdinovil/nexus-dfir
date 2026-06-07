"""
NexusFindingValidator — confianza y FP risk para hallazgos de threat hunt.

Cada hit de tool_threat_hunt() pasa por aquí antes de mostrarse.
Output por finding: confidence (0-1), fp_risk (low/medium/high), notes.
"""

from dataclasses import dataclass, field


@dataclass
class FindingValidation:
    rule_id:      str
    confidence:   float       # 0.0–1.0
    fp_risk:      str         # low / medium / high
    corroborated: bool        # evidencia cross-tabla
    notes:        list[str] = field(default_factory=list)

    @property
    def risk_label(self) -> str:
        if self.confidence >= 0.80:
            return "CONFIRMED"
        if self.confidence >= 0.60:
            return "LIKELY"
        if self.confidence >= 0.40:
            return "POSSIBLE"
        return "WEAK"


# FP risk base por regla (ajuste de confianza por tipo de indicador)
_FP_RISK: dict[str, str] = {
    "T1003":      "low",    # credential dumping tools — nombres muy específicos
    "T1003.001":  "low",    # LSASS memory dump — patrón muy específico
    "T1055":      "low",    # process injection via lsass — alta especificidad
    "T1059.001":  "medium", # encoded PS — también scripts legítimos de admins
    "T1105":      "medium", # tool transfer — certutil tiene usos legítimos
    "T1036":      "medium", # masquerading — devs en AppData son comunes
    "T1053.005":  "medium", # scheduled task — muchas apps crean tareas
    "T1547.001":  "high",   # registry run keys — muy común en sw legítimo
    "T1071.001":  "medium", # C2 over HTTP/S — también tráfico legítimo
    "T1049":      "medium", # non-standard port — dev tools, etc.
    "T1110":      "low",    # brute force — COUNT > 5 es bastante claro
    "T1078":      "medium", # logon from external IP — puede ser VPN legítima
    "T1218":      "low",    # LOLBin execution — raramente legítimo en prod
}

# Delta de confianza según FP risk
_FP_DELTA: dict[str, float] = {
    "low":    +0.10,
    "medium":  0.00,
    "high":   -0.15,
}

_FP_NOTE: dict[str, str] = {
    "low":    "low FP risk — highly specific indicator",
    "high":   "high FP risk — common in legitimate software",
}


def validate_finding(rule_id: str, count: int,
                     corroborated: bool = False) -> FindingValidation:
    """
    Evalúa un threat hunt finding.

    rule_id:      identificador MITRE de la regla (e.g. "T1003")
    count:        número de rows que matchearon
    corroborated: True si hay hits en al menos otra tabla además de esta
    """
    notes: list[str] = []
    fp_risk = _FP_RISK.get(rule_id, "medium")

    # Confianza base por volumen de evidencia
    if count == 0:
        return FindingValidation(rule_id=rule_id, confidence=0.0,
                                 fp_risk=fp_risk, corroborated=False,
                                 notes=["no hits — rule skipped"])
    elif count == 1:
        confidence = 0.40
        notes.append("single hit — low evidence volume")
    elif count <= 3:
        confidence = 0.60
        notes.append(f"{count} hits")
    elif count <= 10:
        confidence = 0.75
    else:
        confidence = 0.85
        notes.append(f"{count} hits — high volume")

    # Ajuste por FP risk
    delta = _FP_DELTA[fp_risk]
    confidence += delta
    if fp_risk in _FP_NOTE:
        notes.append(_FP_NOTE[fp_risk])

    # Boost por corroboración cross-tabla
    if corroborated:
        confidence = min(1.0, confidence + 0.15)
        notes.append("cross-table corroboration")

    confidence = round(max(0.0, min(1.0, confidence)), 2)

    return FindingValidation(
        rule_id=rule_id,
        confidence=confidence,
        fp_risk=fp_risk,
        corroborated=corroborated,
        notes=notes,
    )


def enrich_hits(hits: list[dict]) -> list[dict]:
    """
    Agrega FindingValidation a cada hit de tool_threat_hunt().

    hits: lista de dicts con keys rule_id, severity, name, table, rows, count
    """
    tables_hit = {h["table"] for h in hits}
    enriched = []
    for hit in hits:
        corroborated = len(tables_hit) > 1
        v = validate_finding(hit["rule_id"], hit["count"], corroborated=corroborated)
        enriched.append({**hit, "validation": v})
    return enriched
