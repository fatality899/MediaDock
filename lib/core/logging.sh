#!/usr/bin/env bash
# Module: logging — Logging, mode verbose, fichiers log
# Dependances: aucune
#
# Niveaux: ERROR, WARN, ACTION, INFO, DEBUG
# Mode normal: ERROR, WARN, ACTION → ecran
# Mode verbose (-v): tout → ecran
# Fichier log: tout, toujours (~/.mediadock/logs/)

# Variables globales initialisees par logging_init
MEDIADOCK_LOG_DIR=""
LOG_FILE=""

# Initialise le systeme de logging : cree le repertoire et le fichier log horodate
logging_init() {
  MEDIADOCK_LOG_DIR="${HOME}/.mediadock/logs"
  mkdir -p "${MEDIADOCK_LOG_DIR}"
  LOG_FILE="${MEDIADOCK_LOG_DIR}/mediadock-$(date '+%Y%m%d-%H%M%S').log"
  touch "${LOG_FILE}"
}

# Ecrit une ligne formatee dans le fichier log
# Arguments: $1 = niveau, $2 = message
_log_to_file() {
  [[ -n "${LOG_FILE}" ]] || return 0
  local level="${1}"
  local message="${2}"
  local timestamp
  timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
  printf '[%s] [%s] %s\n' "${timestamp}" "${level}" "${message}" >> "${LOG_FILE}"
}

# Affiche un message d'erreur (toujours visible, stderr)
log_error() {
  local message="${1}"
  printf '[ERREUR] %s\n' "${message}" >&2
  _log_to_file "ERROR" "${message}"
}

# Affiche un avertissement (toujours visible, stderr)
log_warn() {
  local message="${1}"
  printf '[ATTENTION] %s\n' "${message}" >&2
  _log_to_file "WARN" "${message}"
}

# Affiche une action en cours (toujours visible, stdout)
log_action() {
  local message="${1}"
  printf '>>> %s\n' "${message}"
  _log_to_file "ACTION" "${message}"
}

# Affiche une info detaillee (verbose uniquement, stdout)
log_info() {
  local message="${1}"
  if [[ "${VERBOSE:-0}" -eq 1 ]]; then
    printf '[INFO] %s\n' "${message}"
  fi
  _log_to_file "INFO" "${message}"
}

# Affiche un message de debug (verbose uniquement, stdout)
log_debug() {
  local message="${1}"
  if [[ "${VERBOSE:-0}" -eq 1 ]]; then
    printf '[DEBUG] %s\n' "${message}"
  fi
  _log_to_file "DEBUG" "${message}"
}
