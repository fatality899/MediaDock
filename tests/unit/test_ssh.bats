#!/usr/bin/env bats
# Tests unitaires pour lib/core/ssh.sh

setup() {
  TEST_HOME="$(mktemp -d)"
  export HOME="${TEST_HOME}"
  PROJECT_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  export VERBOSE=0

  source "${PROJECT_ROOT}/lib/core/logging.sh"
  logging_init
  source "${PROJECT_ROOT}/lib/core/errors.sh"
  source "${PROJECT_ROOT}/tests/helpers/mocks.bash"
  source "${PROJECT_ROOT}/lib/core/ssh.sh"

  # Activer les mocks SSH
  mock_ssh_commands

  # Variables SSH par defaut pour les tests
  export SERVER_IP="192.168.1.100"
  export SSH_KEY_PATH="${TEST_HOME}/.ssh/test_key"
  mkdir -p "${TEST_HOME}/.ssh"
  touch "${SSH_KEY_PATH}"
}

teardown() {
  mock_ssh_cleanup
  rm -rf "${TEST_HOME}"
}

# ============================================================
# Tests ssh_init — validation des variables (AC: #1, #5)
# ============================================================

@test "ssh_init echoue si SERVER_IP est vide" {
  export SERVER_IP=""
  run ssh_init
  [[ "${status}" -eq 2 ]]
  [[ "${output}" == *"SERVER_IP non definie"* ]]
}

@test "ssh_init echoue si SERVER_IP n'est pas definie" {
  unset SERVER_IP
  run ssh_init
  [[ "${status}" -eq 2 ]]
  [[ "${output}" == *"SERVER_IP non definie"* ]]
}

@test "ssh_init echoue si SSH_KEY_PATH est vide" {
  export SSH_KEY_PATH=""
  run ssh_init
  [[ "${status}" -eq 2 ]]
  [[ "${output}" == *"SSH_KEY_PATH non definie"* ]]
}

@test "ssh_init echoue si SSH_KEY_PATH n'est pas definie" {
  unset SSH_KEY_PATH
  run ssh_init
  [[ "${status}" -eq 2 ]]
  [[ "${output}" == *"SSH_KEY_PATH non definie"* ]]
}

@test "ssh_init echoue si la cle SSH n'existe pas" {
  export SSH_KEY_PATH="${TEST_HOME}/.ssh/inexistant"
  run ssh_init
  [[ "${status}" -eq 2 ]]
  [[ "${output}" == *"Cle SSH introuvable"* ]]
}

# ============================================================
# Tests ssh_init — connexion avec mock (AC: #1)
# ============================================================

@test "ssh_init reussit avec des parametres valides" {
  run ssh_init
  [[ "${status}" -eq 0 ]]
  [[ "${output}" == *"Connexion SSH vers 192.168.1.100"* ]]
}

@test "ssh_init affiche le message de succes en mode verbose" {
  export VERBOSE=1
  run ssh_init
  [[ "${status}" -eq 0 ]]
  [[ "${output}" == *"Connexion SSH etablie (ControlMaster)"* ]]
}

@test "ssh_init echoue si la connexion SSH echoue" {
  export MOCK_SSH_FAIL=1
  run ssh_init
  [[ "${status}" -eq 2 ]]
  [[ "${output}" == *"Connexion SSH echouee vers 192.168.1.100"* ]]
  [[ "${output}" == *"Verifiez l'adresse IP et la cle SSH"* ]]
}

@test "ssh_init utilise SERVER_USER par defaut root" {
  run ssh_init
  [[ "${status}" -eq 0 ]]
}

@test "ssh_init accepte un SERVER_USER personnalise" {
  export SERVER_USER="mediadock"
  run ssh_init
  [[ "${status}" -eq 0 ]]
}

# ============================================================
# Tests ssh_init — guard re-entree (AC: #1, Task 5)
# ============================================================

@test "ssh_init ne se reconnecte pas si deja initialise" {
  # Simuler un etat initialise
  _SSH_INITIALIZED=1
  export VERBOSE=1
  run ssh_init
  [[ "${status}" -eq 0 ]]
  [[ "${output}" == *"SSH deja initialise"* ]]
}

# ============================================================
# Tests ssh_exec — sans initialisation (AC: #2, Task 5)
# ============================================================

@test "ssh_exec sans init echoue avec code 2" {
  run ssh_exec "ls"
  [[ "${status}" -eq 2 ]]
  [[ "${output}" == *"SSH non initialise"* ]]
}

# ============================================================
# Tests ssh_exec — avec mock (AC: #2)
# ============================================================

@test "ssh_exec execute une commande via le mock" {
  ssh_init
  run ssh_exec "ls -la"
  [[ "${status}" -eq 0 ]]
}

@test "ssh_exec log la commande en mode debug" {
  export VERBOSE=1
  ssh_init
  run ssh_exec "hostname"
  [[ "${status}" -eq 0 ]]
  [[ "${output}" == *"SSH exec: hostname"* ]]
}

# ============================================================
# Tests ssh_copy — sans initialisation (AC: #3, Task 5)
# ============================================================

@test "ssh_copy sans init echoue avec code 2" {
  run ssh_copy "/tmp/source" "/tmp/dest"
  [[ "${status}" -eq 2 ]]
  [[ "${output}" == *"SSH non initialise"* ]]
}

# ============================================================
# Tests ssh_copy — avec mock (AC: #3)
# ============================================================

@test "ssh_copy echoue si le fichier source n'existe pas" {
  ssh_init
  run ssh_copy "/tmp/fichier_inexistant_mediadock_test" "/tmp/dest"
  [[ "${status}" -eq 1 ]]
  [[ "${output}" == *"Fichier source introuvable"* ]]
}

@test "ssh_copy transfère un fichier existant" {
  ssh_init
  local test_file="${TEST_HOME}/test_transfer.txt"
  echo "contenu test" > "${test_file}"
  run ssh_copy "${test_file}" "/tmp/dest"
  [[ "${status}" -eq 0 ]]
}

@test "ssh_copy log le transfert en mode debug" {
  export VERBOSE=1
  ssh_init
  local test_file="${TEST_HOME}/test_transfer.txt"
  echo "contenu test" > "${test_file}"
  run ssh_copy "${test_file}" "/opt/mediadock/"
  [[ "${status}" -eq 0 ]]
  [[ "${output}" == *"SSH copy:"* ]]
}

# ============================================================
# Tests ssh_cleanup — idempotence (AC: #4)
# ============================================================

@test "ssh_cleanup sans connexion active ne crash pas" {
  run ssh_cleanup
  [[ "${status}" -eq 0 ]]
}

@test "ssh_cleanup sans connexion active log un message debug" {
  export VERBOSE=1
  run ssh_cleanup
  [[ "${status}" -eq 0 ]]
  [[ "${output}" == *"pas de connexion active"* ]]
}

@test "ssh_cleanup apres init ferme la connexion" {
  ssh_init
  export VERBOSE=1
  run ssh_cleanup
  [[ "${status}" -eq 0 ]]
  [[ "${output}" == *"Connexion SSH fermee"* ]]
}

@test "ssh_cleanup remet _SSH_INITIALIZED a 0" {
  ssh_init
  ssh_cleanup
  [[ "${_SSH_INITIALIZED}" -eq 0 ]]
}

@test "ssh_cleanup double appel apres init ne crash pas" {
  ssh_init
  ssh_cleanup
  run ssh_cleanup
  [[ "${status}" -eq 0 ]]
}

# ============================================================
# Tests cycle complet init/exec/copy/cleanup (AC: #1, #2, #3, #4)
# ============================================================

@test "cycle complet init exec copy cleanup" {
  # ssh_init sans run pour persister _SSH_INITIALIZED dans le shell courant
  ssh_init

  run ssh_exec "uname -a"
  [[ "${status}" -eq 0 ]]

  local test_file="${TEST_HOME}/cycle_test.txt"
  echo "test" > "${test_file}"
  run ssh_copy "${test_file}" "/tmp/"
  [[ "${status}" -eq 0 ]]

  run ssh_cleanup
  [[ "${status}" -eq 0 ]]
}
