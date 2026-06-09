#!/usr/bin/env bash
# Nexus DFIR — Caso 03 v3: ATT&CK Red Team — 63K eventos, 10 máquinas
CASE="mitre_attacks"
BOLD="\033[1m"; CYAN="\033[96m"; YELLOW="\033[93m"; GREEN="\033[92m"; RESET="\033[0m"

_banner() {
  clear
  printf "${BOLD}${CYAN}"
  printf "╔══════════════════════════════════════════════════════════════╗\n"
  printf "║   NEXUS DFIR  —  Caso 03: ATT&CK Red Team Exercise          ║\n"
  printf "║   148 archivos EVTX  |  63,171 eventos  |  10 máquinas      ║\n"
  printf "║   Sin reporte del red team — reconstrucción pura desde logs  ║\n"
  printf "╚══════════════════════════════════════════════════════════════╝\n"
  printf "${RESET}\n"
  sleep 2
}

_q() {
  printf "\n${BOLD}${YELLOW}┌─ $1${RESET}\n"
  printf "${YELLOW}└▶ nexus ask $CASE \"$2\"${RESET}\n\n"
  sleep 1
  nexus ask "$CASE" "$2"
  sleep 2
}

_section() {
  printf "\n${BOLD}${CYAN}  ── $1 ──${RESET}\n"
  sleep 1
}

_banner

_section "TRIAGE — Escala del incidente"
nexus summary "$CASE"
sleep 2

_q "¿Qué está en scope?" \
   "¿Qué máquinas y dominios aparecen en los logs?"

_section "ACCESO INICIAL — ¿Por dónde entraron?"
_q "¿Hubo brute force?" \
   "¿Qué IPs tuvieron más intentos de autenticación fallida?"

_q "¿Primer acceso confirmado?" \
   "¿Cuál fue la primera autenticación exitosa registrada y desde dónde?"

_section "MOVIMIENTO LATERAL — ¿A cuántas máquinas llegaron?"
_q "¿Cuentas moviéndose entre sistemas?" \
   "¿Qué cuentas se autenticaron en múltiples equipos distintos?"

_section "PERSISTENCIA — ¿Qué dejaron?"
_q "¿Actividad del usuario bob?" \
   "¿Qué actividad registró el usuario bob en el dominio?"

_section "EVASIÓN — ¿Borraron evidencia?"
_q "¿Limpieza de logs?" \
   "¿Cuántos eventos de limpieza de log hay y cuándo ocurrieron?"

_section "EJECUCIÓN — ¿Qué corrieron?"
_q "¿Procesos sospechosos?" \
   "¿Qué procesos fueron ejecutados desde directorios temporales o AppData?"

_section "DETECCIÓN AUTOMÁTICA — MITRE ATT&CK"
printf "\n${BOLD}${YELLOW}└▶ nexus hunt $CASE${RESET}\n\n"
sleep 1
nexus hunt "$CASE"

printf "\n${BOLD}${GREEN}  Análisis completo. Caso: $CASE${RESET}\n\n"
