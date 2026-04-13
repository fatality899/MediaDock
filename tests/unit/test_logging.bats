#!/usr/bin/env bats
# Tests unitaires — Module logging (lib/core/logging.sh)

setup() {
  TEST_HOME="$(mktemp -d)"
  export HOME="${TEST_HOME}"
  PROJECT_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  export VERBOSE=0
  source "${PROJECT_ROOT}/lib/core/logging.sh"
}

teardown() {
  rm -rf "${TEST_HOME}"
}

# --- logging_init ---

@test "logging_init cree le repertoire ~/.mediadock/logs/ s'il n'existe pas" {
  [ ! -d "${TEST_HOME}/.mediadock/logs" ]
  logging_init
  [ -d "${TEST_HOME}/.mediadock/logs" ]
}

@test "logging_init cree un fichier log horodate" {
  logging_init
  [ -f "${LOG_FILE}" ]
  local filename
  filename="$(basename "${LOG_FILE}")"
  [[ "${filename}" =~ ^mediadock-[0-9]{8}-[0-9]{6}\.log$ ]]
}

@test "logging_init est idempotent — peut etre appele plusieurs fois" {
  logging_init
  local first_log="${LOG_FILE}"
  sleep 1
  logging_init
  [ -f "${first_log}" ]
  [ -f "${LOG_FILE}" ]
}

# --- log_error ---

@test "log_error affiche toujours a l'ecran (stderr)" {
  logging_init
  run log_error "message erreur test"
  [[ "${output}" == *"message erreur test"* ]]
}

@test "log_error ecrit dans le fichier log" {
  logging_init
  log_error "erreur fichier test" 2>/dev/null
  grep -q "ERROR" "${LOG_FILE}"
  grep -q "erreur fichier test" "${LOG_FILE}"
}

@test "log_error affiche le prefixe ERREUR" {
  logging_init
  run log_error "msg test"
  [[ "${output}" == *"[ERREUR]"* ]]
}

# --- log_warn ---

@test "log_warn affiche toujours a l'ecran (stderr)" {
  logging_init
  run log_warn "message attention test"
  [[ "${output}" == *"message attention test"* ]]
}

@test "log_warn ecrit dans le fichier log" {
  logging_init
  log_warn "attention fichier test" 2>/dev/null
  grep -q "WARN" "${LOG_FILE}"
  grep -q "attention fichier test" "${LOG_FILE}"
}

@test "log_warn affiche le prefixe ATTENTION" {
  logging_init
  run log_warn "msg test"
  [[ "${output}" == *"[ATTENTION]"* ]]
}

# --- log_action ---

@test "log_action affiche toujours a l'ecran (stdout)" {
  logging_init
  run log_action "action test"
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"action test"* ]]
}

@test "log_action ecrit dans le fichier log" {
  logging_init
  log_action "action fichier test"
  grep -q "ACTION" "${LOG_FILE}"
  grep -q "action fichier test" "${LOG_FILE}"
}

@test "log_action affiche le prefixe >>>" {
  logging_init
  run log_action "msg test"
  [[ "${output}" == *">>>"* ]]
}

# --- log_info (mode normal) ---

@test "log_info n'affiche PAS a l'ecran en mode normal (VERBOSE=0)" {
  logging_init
  export VERBOSE=0
  run log_info "info cachee"
  [ -z "${output}" ]
}

@test "log_info ecrit dans le fichier log meme en mode normal" {
  logging_init
  export VERBOSE=0
  log_info "info dans fichier"
  grep -q "INFO" "${LOG_FILE}"
  grep -q "info dans fichier" "${LOG_FILE}"
}

# --- log_info (mode verbose) ---

@test "log_info affiche a l'ecran en mode verbose (VERBOSE=1)" {
  logging_init
  export VERBOSE=1
  run log_info "info visible"
  [[ "${output}" == *"info visible"* ]]
}

# --- log_debug (mode normal) ---

@test "log_debug n'affiche PAS a l'ecran en mode normal (VERBOSE=0)" {
  logging_init
  export VERBOSE=0
  run log_debug "debug cache"
  [ -z "${output}" ]
}

@test "log_debug ecrit dans le fichier log meme en mode normal" {
  logging_init
  export VERBOSE=0
  log_debug "debug dans fichier"
  grep -q "DEBUG" "${LOG_FILE}"
  grep -q "debug dans fichier" "${LOG_FILE}"
}

# --- log_debug (mode verbose) ---

@test "log_debug affiche a l'ecran en mode verbose (VERBOSE=1)" {
  logging_init
  export VERBOSE=1
  run log_debug "debug visible"
  [[ "${output}" == *"debug visible"* ]]
}

# --- Format du fichier log ---

@test "chaque ligne du fichier log contient un timestamp et le niveau" {
  logging_init
  log_action "test format"
  log_error "test format err" 2>/dev/null
  log_info "test format info"
  local line_count
  line_count="$(wc -l < "${LOG_FILE}")"
  [ "${line_count}" -ge 3 ]
  while IFS= read -r line; do
    [[ "${line}" =~ ^\[[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2}\]\ \[(ERROR|WARN|ACTION|INFO|DEBUG)\] ]]
  done < "${LOG_FILE}"
}
