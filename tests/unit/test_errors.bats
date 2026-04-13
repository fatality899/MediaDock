#!/usr/bin/env bats
# Tests unitaires — Module errors (lib/core/errors.sh)

setup() {
  TEST_HOME="$(mktemp -d)"
  export HOME="${TEST_HOME}"
  PROJECT_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  export VERBOSE=0
  source "${PROJECT_ROOT}/lib/core/logging.sh"
  logging_init
  source "${PROJECT_ROOT}/lib/core/errors.sh"
}

teardown() {
  rm -rf "${TEST_HOME}"
}

# --- die ---

@test "die 1 affiche le message d'erreur et termine avec code 1" {
  run die 1 "message erreur test"
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"message erreur test"* ]]
}

@test "die 2 affiche le message ET la suggestion" {
  run die 2 "connexion SSH echouee" "Verifiez l'adresse IP et la cle SSH"
  [ "${status}" -eq 2 ]
  [[ "${output}" == *"connexion SSH echouee"* ]]
  [[ "${output}" == *"Verifiez l'adresse IP et la cle SSH"* ]]
}

@test "die sans suggestion n'affiche pas de ligne suggestion" {
  run die 1 "erreur simple"
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"erreur simple"* ]]
  [[ "${output}" != *"Suggestion"* ]]
}

@test "die avec code 0 termine avec code 0" {
  run die 0 "succes"
  [ "${status}" -eq 0 ]
}

@test "die avec code 2 termine avec code 2" {
  run die 2 "ssh erreur"
  [ "${status}" -eq 2 ]
}

@test "die avec code 3 termine avec code 3" {
  run die 3 "service erreur"
  [ "${status}" -eq 3 ]
}

@test "die ecrit dans le fichier log" {
  run die 1 "erreur log test"
  grep -q "ERROR" "${LOG_FILE}"
  grep -q "erreur log test" "${LOG_FILE}"
}

@test "die affiche le prefixe ERREUR" {
  run die 1 "msg test"
  [[ "${output}" == *"[ERREUR]"* ]]
}

# --- run_step ---

@test "run_step avec commande qui reussit ne produit pas d'erreur" {
  run run_step "Test reussi" 1 "suggestion" true
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Test reussi"* ]]
}

@test "run_step avec commande qui reussit affiche le message action" {
  run run_step "Installation Docker" 1 "suggestion" true
  [ "${status}" -eq 0 ]
  [[ "${output}" == *">>>"* ]]
  [[ "${output}" == *"Installation Docker"* ]]
}

@test "run_step avec commande qui echoue affiche l'erreur et la suggestion" {
  run run_step "Mise a jour apt" 1 "Verifiez la connectivite reseau" false
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Echec"* ]]
  [[ "${output}" == *"Mise a jour apt"* ]]
  [[ "${output}" == *"Verifiez la connectivite reseau"* ]]
}

@test "run_step avec commande qui echoue retourne le bon code" {
  run run_step "Test SSH" 2 "Verifiez la cle" false
  [ "${status}" -eq 2 ]
}

@test "run_step passe les arguments multiples a la commande" {
  run run_step "Test arguments" 1 "suggestion" echo "hello world"
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"hello world"* ]]
}

@test "run_step ecrit le succes dans le fichier log" {
  run run_step "Operation test" 1 "suggestion" true
  grep -q "Operation test" "${LOG_FILE}"
}

@test "run_step ecrit l'echec dans le fichier log" {
  run run_step "Operation echouee" 1 "suggestion" false
  grep -q "Operation echouee" "${LOG_FILE}"
}

# --- unexpected_error ---

@test "unexpected_error affiche le numero de ligne et le fichier source" {
  run unexpected_error "42" "test_script.sh" "commande_test"
  [[ "${output}" == *"42"* ]]
  [[ "${output}" == *"test_script.sh"* ]]
}

@test "unexpected_error affiche la commande qui a echoue" {
  run unexpected_error "10" "script.sh" "apt-get update"
  [[ "${output}" == *"apt-get update"* ]]
}

@test "unexpected_error ecrit la trace dans le fichier log" {
  run unexpected_error "42" "test_script.sh" "commande_test"
  grep -q "42" "${LOG_FILE}"
  grep -q "test_script.sh" "${LOG_FILE}"
  grep -q "commande_test" "${LOG_FILE}"
}

@test "unexpected_error via trap preserve le code de sortie de la commande echouee" {
  run bash -c '
    export HOME="'"${TEST_HOME}"'"
    export VERBOSE=0
    source "'"${PROJECT_ROOT}"'/lib/core/logging.sh"
    logging_init
    source "'"${PROJECT_ROOT}"'/lib/core/errors.sh"
    errors_init
    set -euo pipefail
    bash -c "exit 3"
  '
  [ "${status}" -eq 3 ]
  [[ "${output}" == *"Erreur inattendue"* ]]
}

# --- trap ERR ---

@test "trap ERR capture une commande qui echoue dans un script complet" {
  run bash -c '
    export HOME="'"${TEST_HOME}"'"
    export VERBOSE=0
    source "'"${PROJECT_ROOT}"'/lib/core/logging.sh"
    logging_init
    source "'"${PROJECT_ROOT}"'/lib/core/errors.sh"
    errors_init
    set -euo pipefail
    false
  '
  [ "${status}" -ne 0 ]
  [[ "${output}" == *"Erreur inattendue"* ]]
}

# Note : set -u (nounset) ne declenche PAS le trap ERR dans bash.
# L'erreur est geree directement par bash avec un message en anglais
# ("unbound variable"). C'est une limitation structurelle de bash,
# pas un bug de notre code. Le test verifie que le script se termine
# avec un code d'erreur, mais le message ne sera pas celui de
# unexpected_error.
@test "trap ERR capture une variable non definie" {
  run bash -c '
    export HOME="'"${TEST_HOME}"'"
    export VERBOSE=0
    source "'"${PROJECT_ROOT}"'/lib/core/logging.sh"
    logging_init
    source "'"${PROJECT_ROOT}"'/lib/core/errors.sh"
    errors_init
    set -euo pipefail
    echo "${VARIABLE_INEXISTANTE}"
  '
  [ "${status}" -ne 0 ]
}

# --- trap ERR avec pipefail ---

@test "trap ERR capture un pipe failure avec pipefail" {
  run bash -c '
    export HOME="'"${TEST_HOME}"'"
    export VERBOSE=0
    source "'"${PROJECT_ROOT}"'/lib/core/logging.sh"
    logging_init
    source "'"${PROJECT_ROOT}"'/lib/core/errors.sh"
    errors_init
    set -euo pipefail
    false | true
  '
  [ "${status}" -ne 0 ]
  [[ "${output}" == *"Erreur inattendue"* ]]
}

# --- errors_init ---

@test "errors_init ne produit pas d'erreur" {
  run errors_init
  [ "${status}" -eq 0 ]
}
