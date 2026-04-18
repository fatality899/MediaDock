#!/usr/bin/env bats
# Tests unitaires — Point d'entree CLI et dispatch de commandes
# Stories 1.7 + 2.1 (orchestrateur install_run)

setup() {
  TEST_HOME="$(mktemp -d)"
  export HOME="${TEST_HOME}"
  PROJECT_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  MEDIADOCK_BIN="${PROJECT_ROOT}/mediadock"
  export VERBOSE=0

  # Fixture .env factice pour les tests utilisant `mediadock install` :
  # SERVER_IP=192.0.2.1 (TEST-NET-1, RFC 5737) non routable -> ssh_init echoue
  # rapidement (ConnectTimeout=10s) avec le code 2. Permet de tester le flux
  # install jusqu'a l'etape SSH sans serveur reel ni mock ssh.
  cat > "${TEST_HOME}/.env" <<EOF
SERVER_IP=192.0.2.1
SERVER_USER=root
SSH_KEY_PATH=${TEST_HOME}/fake_key
VPN_PROVIDER=nordvpn
VPN_TOKEN=fake
MEDIA_PLAYER=jellyfin
STORAGE_MODE=single_disk
LANGUAGE=fr
EOF
  touch "${TEST_HOME}/fake_key"
  chmod 600 "${TEST_HOME}/fake_key"
  cd "${TEST_HOME}"
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
# AC4 — Mode verbose et sourcing ordonné (adapte Story 2.1 : install_run)
# ---------------------------------------------------------------------------
# Note: depuis la Story 2.1, la commande `install` dispatche vers
# install_run qui charge la config puis tente ssh_init. Avec la fixture
# .env ci-dessus (IP TEST-NET-1), ssh_init echoue avec le code 2.
# Les tests verifient donc le dispatch + la propagation verbose + l'echec
# propre, plutot que l'ancien message stub `Commande install non encore...`.

@test "AC4 : mediadock install -v active VERBOSE et dispatche vers install_run" {
  run "${MEDIADOCK_BIN}" install -v
  [ "${status}" -eq 2 ]
  [[ "${output}" == *"[INFO] Mode verbose actif"* ]]
  [[ "${output}" == *"Demarrage de l'installation"* ]]
  [[ "${output}" == *"Connexion SSH echouee"* ]]
}

@test "AC4 : mediadock -v install (option avant commande) active VERBOSE" {
  run "${MEDIADOCK_BIN}" -v install
  [ "${status}" -eq 2 ]
  [[ "${output}" == *"[INFO] Mode verbose actif"* ]]
  [[ "${output}" == *"Demarrage de l'installation"* ]]
}

@test "AC4 : mediadock --verbose install (forme longue) equivalente a -v" {
  run "${MEDIADOCK_BIN}" --verbose install
  [ "${status}" -eq 2 ]
  [[ "${output}" == *"[INFO] Mode verbose actif"* ]]
}

@test "AC4 : mediadock install (sans -v) ne log pas en mode verbose" {
  run "${MEDIADOCK_BIN}" install
  [ "${status}" -eq 2 ]
  [[ "${output}" != *"[INFO]"* ]]
  [[ "${output}" == *"Demarrage de l'installation"* ]]
}

@test "AC4 : sourcing ordonné — un fichier log est cree dans \$HOME/.mediadock/logs" {
  run "${MEDIADOCK_BIN}" install
  # Le flux install echoue sur ssh_init (code 2) mais logging_init s'execute
  # avant dispatch : le fichier log doit donc exister quel que soit le statut.
  [ -d "${HOME}/.mediadock/logs" ]
  local log_count
  log_count="$(find "${HOME}/.mediadock/logs" -maxdepth 1 -type f -name 'mediadock-*.log' | wc -l)"
  [ "${log_count}" -ge 1 ]
}

@test "AC4 : le log contient l'action dispatchee (logging_init avant dispatch)" {
  run "${MEDIADOCK_BIN}" install
  # Le fichier log doit contenir l'action emise par install_run
  grep -q "Demarrage de l'installation" "${HOME}/.mediadock/logs/"mediadock-*.log
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

@test "AC6 : mediadock install dispatche install_run (echec SSH propre, code 2)" {
  run "${MEDIADOCK_BIN}" install
  [ "${status}" -eq 2 ]
  [[ "${output}" == *"Demarrage de l'installation"* ]]
  [[ "${output}" == *"Connexion SSH echouee"* ]]
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
  [[ "${output}" != *"Demarrage de l'installation"* ]]
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
