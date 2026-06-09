#!/usr/bin/env bash
# Nexus DFIR — Caso 01 v3: LockBit Ransomware IR
CASE="lockbit_ir"
BOLD="\033[1m"; CYAN="\033[96m"; YELLOW="\033[93m"; GREEN="\033[92m"; RESET="\033[0m"

_banner() {
  clear
  printf "${BOLD}${CYAN}"
  printf "╔══════════════════════════════════════════════════════════════╗\n"
  printf "║   NEXUS DFIR  —  Caso 01: LockBit Ransomware IR             ║\n"
  printf "║   Sistema comprometido: WIN-QE52MMFSD3E                     ║\n"
  printf "║   Evidencia: 8 archivos  |  39,641 eventos                  ║\n"
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

_section "ACCESO INICIAL — ¿Desde dónde atacaron?"
_q "¿Hubo brute force?" \
   "¿Cuántos intentos de autenticación fallida hubo por IP de origen?"

_q "¿Lograron entrar?" \
   "¿Qué cuentas tuvieron logon exitoso y desde qué IPs?"

_section "MOVIMIENTO LATERAL — ¿Qué hicieron dentro?"
_q "¿La cuenta quejas es sospechosa?" \
   "¿Qué actividad registró el usuario quejas en el sistema?"

_q "¿Qué actividad hubo por día?" \
   "¿Cuántos eventos hay por día? Muéstrame el timeline"

_section "COMANDO Y CONTROL — ¿Estaban conectados afuera?"
_q "¿Conexiones activas al momento del cifrado?" \
   "¿Qué conexiones de red estaban establecidas al capturar la evidencia?"

_q "¿Proceso con C2?" \
   "¿Qué proceso tenía conexión establecida con una IP externa?"

_section "PERSISTENCIA — ¿Dejaron una puerta trasera?"
_q "¿Tareas programadas sospechosas?" \
   "¿Qué tareas programadas existen y quién las creó?"

_section "DETECCIÓN AUTOMÁTICA — MITRE ATT&CK"
printf "\n${BOLD}${YELLOW}└▶ nexus hunt $CASE${RESET}\n\n"
sleep 1
nexus hunt "$CASE"

printf "\n${BOLD}${GREEN}  Análisis completo. Caso: $CASE${RESET}\n\n"
