#!/usr/bin/env bats
# Tests unitaires — Point d'entrée CLI et dispatch de commandes (Story 1.7)

setup() {
  TEST_HOME="$(mktemp -d)"
  export HOME="${TEST_HOME}"
  PROJECT_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  MEDIADOCK_BIN="${PROJECT_ROOT}/mediadock"
  export VERBOSE=0
}

teardown() {
  rm -rf "${TEST_HOME}"
  unset VERBOSE MEDIADOCK_DIR
}

# ---------------------------------------------------------------------------
# AC1 — Aide par défaut sans argument
# ---------------------------------------------------------------------------

@test "AC1 : mediadock sans argument affiche l'aide et retourne 0" {
  run "${MEDIADOCK_BIN}"
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Usage : mediadock"* ]]
  [[ "${output}" == *"install"* ]]
  [[ "${output}" == *"update"* ]]
  [[ "${output}" == *"backup"* ]]
  [[ "${output}" == *"restore"* ]]
  [[ "${output}" == *"-v"* ]]
  [[ "${output}" == *"--help"* ]]
  [[ "${output}" == *"--version"* ]]
}

# ---------------------------------------------------------------------------
# AC2 — Aide complète via --help / -h
# ---------------------------------------------------------------------------

@test "AC2 : mediadock --help affiche l'aide complete et retourne 0" {
  run "${MEDIADOCK_BIN}" --help
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Usage : mediadock"* ]]
  [[ "${output}" == *"Commandes"* ]]
  [[ "${output}" == *"Exemples"* ]]
}

@test "AC2 : mediadock -h (forme courte) affiche la meme aide" {
  run "${MEDIADOCK_BIN}" -h
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Usage : mediadock"* ]]
  [[ "${output}" == *"--version"* ]]
}

# ---------------------------------------------------------------------------
# AC3 — Affichage de la version
# ---------------------------------------------------------------------------

@test "AC3 : mediadock --version affiche la version au format attendu" {
  run "${MEDIADOCK_BIN}" --version
  [ "${status}" -eq 0 ]
  [[ "${output}" =~ ^MediaDock\ version\ [0-9]+\.[0-9]+\.[0-9]+$ ]]
}

# ---------------------------------------------------------------------------
# AC4 — Mode verbose et sourcing ordonné
# ---------------------------------------------------------------------------

@test "AC4 : mediadock install -v active VERBOSE et dispatche" {
  run "${MEDIADOCK_BIN}" install -v
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"[INFO] Mode verbose actif"* ]]
  [[ "${output}" == *"Commande install non encore implémentée"* ]]
}

@test "AC4 : mediadock -v install (option avant commande) active VERBOSE" {
  run "${MEDIADOCK_BIN}" -v install
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"[INFO] Mode verbose actif"* ]]
  [[ "${output}" == *"Commande install non encore implémentée"* ]]
}

@test "AC4 : mediadock --verbose install (forme longue) equivalente a -v" {
  run "${MEDIADOCK_BIN}" --verbose install
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"[INFO] Mode verbose actif"* ]]
}

@test "AC4 : mediadock install (sans -v) ne log pas en mode verbose" {
  run "${MEDIADOCK_BIN}" install
  [ "${status}" -eq 0 ]
  [[ "${output}" != *"[INFO]"* ]]
  [[ "${output}" == *"Commande install non encore implémentée"* ]]
}

@test "AC4 : sourcing ordonné — un fichier log est cree dans \$HOME/.mediadock/logs" {
  run "${MEDIADOCK_BIN}" install
  [ "${status}" -eq 0 ]
  [ -d "${HOME}/.mediadock/logs" ]
  # Au moins un fichier log horodate doit exister
  local log_count
  log_count="$(find "${HOME}/.mediadock/logs" -maxdepth 1 -type f -name 'mediadock-*.log' | wc -l)"
  [ "${log_count}" -ge 1 ]
}

@test "AC4 : le log contient l'action dispatchee (logging_init avant dispatch)" {
  run "${MEDIADOCK_BIN}" install
  [ "${status}" -eq 0 ]
  # Le fichier log doit contenir la ligne ACTION du stub
  grep -q "Commande install non encore" "${HOME}/.mediadock/logs/"mediadock-*.log
}

# ---------------------------------------------------------------------------
# AC5 — Commande inconnue
# ---------------------------------------------------------------------------

@test "AC5 : commande inconnue retourne code 1 et message d'erreur" {
  run "${MEDIADOCK_BIN}" foobar
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Commande inconnue"* ]]
  [[ "${output}" == *"foobar"* ]]
  [[ "${output}" == *"mediadock --help"* ]]
}

@test "AC5 : option longue inconnue retourne code 1" {
  run "${MEDIADOCK_BIN}" --invalid-option
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"option inconnue"* ]]
}

# ---------------------------------------------------------------------------
# AC6 — Dispatch des quatre commandes MVP
# ---------------------------------------------------------------------------

@test "AC6 : mediadock install dispatche hardening_run et retourne 0" {
  run "${MEDIADOCK_BIN}" install
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Commande install non encore implémentée (Epic 2)"* ]]
}

@test "AC6 : mediadock update dispatche update_run et retourne 0" {
  run "${MEDIADOCK_BIN}" update
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Commande update non encore implémentée (Epic 4)"* ]]
}

@test "AC6 : mediadock backup dispatche backup_run et retourne 0" {
  run "${MEDIADOCK_BIN}" backup
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Commande backup non encore implémentée (Epic 5)"* ]]
}

@test "AC6 : mediadock restore dispatche backup_restore et retourne 0" {
  run "${MEDIADOCK_BIN}" restore
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Commande restore non encore implémentée (Epic 5)"* ]]
}

# ---------------------------------------------------------------------------
# Cas combinés / priorité
# ---------------------------------------------------------------------------

@test "Options multiples : mediadock -v --help affiche l'aide (ne dispatche pas)" {
  run "${MEDIADOCK_BIN}" -v --help
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Usage : mediadock"* ]]
  [[ "${output}" != *"Commande install"* ]]
}

@test "Priorite : --help prime sur --version" {
  run "${MEDIADOCK_BIN}" --help --version
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Usage : mediadock"* ]]
  [[ "${output}" != *"MediaDock version 0"* ]]
}

# ---------------------------------------------------------------------------
# Contrat de structure (non régression)
# ---------------------------------------------------------------------------

@test "Structure : mediadock conserve shebang bash et set -euo pipefail" {
  head -1 "${MEDIADOCK_BIN}" | grep -q '#!/usr/bin/env bash'
  head -3 "${MEDIADOCK_BIN}" | grep -q 'set -euo pipefail'
}
