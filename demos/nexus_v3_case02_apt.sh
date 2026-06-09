#!/usr/bin/env bash
# Nexus DFIR — Caso 02 v3: APT Campaign — MS17-010 to Domain Dominance
CASE="apt_full_steps"
BOLD="\033[1m"; CYAN="\033[96m"; YELLOW="\033[93m"; GREEN="\033[92m"; RESET="\033[0m"

_banner() {
  clear
  printf "${BOLD}${CYAN}"
  printf "╔══════════════════════════════════════════════════════════════╗\n"
  printf "║   NEXUS DFIR  —  Caso 02: APT Campaign offsec.lan           ║\n"
  printf "║   Técnicas: EternalRomance / PrintNightmare / Mimikatz       ║\n"
  printf "║   Evidencia: 11 archivos EVTX  |  1,054 eventos             ║\n"
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

_section "TRIAGE — ¿Qué máquinas están involucradas?"
nexus summary "$CASE"
sleep 2

_q "¿Alcance del incidente?" \
   "¿Qué equipos aparecen en los logs y cuántos eventos tiene cada uno?"

_section "ACCESO INICIAL — EternalRomance via SMB"
_q "¿Tráfico SMB sospechoso?" \
   "¿Qué shares de red fueron accedidos y por quién?"

_q "¿Qué cuenta usó el atacante?" \
   "¿Qué actividad registró el usuario admmig en el dominio?"

_section "ESCALACIÓN — ¿Llegaron al Domain Controller?"
_q "¿Privilegios elevados?" \
   "¿Qué cuentas recibieron privilegios especiales durante el incidente?"

_q "¿Cuentas creadas por el atacante?" \
   "¿Se crearon o modificaron cuentas de usuario durante el incidente?"

_section "EVASIÓN — ¿Borraron sus huellas?"
_q "¿Limpieza de logs?" \
   "¿Se borraron logs de eventos durante el incidente?"

_section "PERSISTENCIA — ¿Cómo iban a volver?"
_q "¿Tareas programadas maliciosas?" \
   "¿Qué tareas programadas fueron creadas durante el incidente?"

_section "DETECCIÓN AUTOMÁTICA — MITRE ATT&CK"
printf "\n${BOLD}${YELLOW}└▶ nexus hunt $CASE${RESET}\n\n"
sleep 1
nexus hunt "$CASE"

printf "\n${BOLD}${GREEN}  Análisis completo. Caso: $CASE${RESET}\n\n"
