#!/usr/bin/env bash
# Nexus DFIR — Caso 04 v3: RDP Intrusion — SAMARANPRO
CASE="for563_rdp"
BOLD="\033[1m"; CYAN="\033[96m"; YELLOW="\033[93m"; GREEN="\033[92m"; RESET="\033[0m"

_banner() {
  clear
  printf "${BOLD}${CYAN}"
  printf "╔══════════════════════════════════════════════════════════════╗\n"
  printf "║   NEXUS DFIR  —  Caso 04: RDP Intrusion SAMARANPRO          ║\n"
  printf "║   Servidor: samaran-ts01.samaranpro.com                     ║\n"
  printf "║   1,800 eventos RDP  |  6 usuarios  |  7 IPs origen         ║\n"
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

_section "TRIAGE — ¿Qué tenemos?"
nexus summary "$CASE"
sleep 2

_section "RECONOCIMIENTO — ¿Quién se conectó?"
_q "¿Actividad por usuario?" \
   "¿Cuántas sesiones RDP tiene cada usuario?"

_q "¿Desde dónde?" \
   "¿Desde qué IPs se conectó cada usuario al servidor?"

_section "DETECCIÓN — ¿Hay acceso no autorizado?"
_q "¿IPs externas?" \
   "¿Qué usuarios se conectaron desde IPs externas, no de la red interna?"

_q "¿Horario sospechoso?" \
   "¿Hay sesiones RDP en horario nocturno entre las 00:00 y las 06:00?"

_section "ATRIBUCIÓN — ¿Quién es el sospechoso?"
_q "¿Timeline de jparker?" \
   "¿Cuál fue la primera y última sesión registrada del usuario jparker?"

_q "¿Sesiones concurrentes?" \
   "¿Qué usuarios tuvieron más de una sesión activa al mismo tiempo?"

_section "DETECCIÓN AUTOMÁTICA — MITRE ATT&CK"
printf "\n${BOLD}${YELLOW}└▶ nexus hunt $CASE${RESET}\n\n"
sleep 1
nexus hunt "$CASE"

printf "\n${BOLD}${GREEN}  Análisis completo. Caso: $CASE${RESET}\n\n"
