#!/usr/bin/env bats
# Tests unitaires — Orchestrateur install_run (Story 2.1)
#
# Strategie : sourcer install.sh en isolation avec des stubs locaux qui
# remplacent load_config, ssh_init, ssh_cleanup, hardening_run, storage_run,
# docker_run. Permet de valider l'ordre d'execution, la propagation d'erreur
# et le format du resume sans connexion SSH ni .env reels.

setup() {
  TEST_HOME="$(mktemp -d)"
  export HOME="${TEST_HOME}"
  PROJECT_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  export MEDIADOCK_DIR="${PROJECT_ROOT}"
  export VERBOSE=0

  # Fichier de trace pour reconstituer l'ordre des appels apres `run` (qui
  # execute en sous-shell : les variables ne survivent pas — un fichier oui).
  CALL_LOG="${TEST_HOME}/calls.log"
  : > "${CALL_LOG}"
  export CALL_LOG

  # Sourcing des dependances reelles : logging et errors
  # (die et log_* sont necessaires au fonctionnement d'install.sh).
  # shellcheck source=../../lib/core/logging.sh
  source "${PROJECT_ROOT}/lib/core/logging.sh"
  logging_init
  # shellcheck source=../../lib/core/errors.sh
  source "${PROJECT_ROOT}/lib/core/errors.sh"

  # Sourcing de l'orchestrateur : definit install_run, _install_run_step,
  # _install_print_summary, _install_source_submodule, _INSTALL_STEPS/STATUSES.
  # shellcheck source=../../lib/modules/install.sh
  source "${PROJECT_ROOT}/lib/modules/install.sh"

  # Override APRES le sourcing : les stubs remplacent les fonctions reelles.
  # _install_source_submodule devient un no-op : evite que install_run recharge
  # hardening.sh/storage.sh/docker.sh (qui redefiniraient les stubs ci-dessous).
  _install_source_submodule() { return 0; }
  load_config()   { echo "load_config"   >> "${CALL_LOG}"; }
  ssh_init()      { echo "ssh_init"      >> "${CALL_LOG}"; }
  ssh_cleanup()   { echo "ssh_cleanup"   >> "${CALL_LOG}"; }
  hardening_run() { echo "hardening_run" >> "${CALL_LOG}"; }
  storage_run()   { echo "storage_run"   >> "${CALL_LOG}"; }
  docker_run()    { echo "docker_run"    >> "${CALL_LOG}"; }
}

teardown() {
  rm -rf "${TEST_HOME}"
  unset MEDIADOCK_DIR VERBOSE CALL_LOG
}

# Helper : aplatit CALL_LOG en une chaine espace-separee pour comparaison.
_call_order() {
  tr '\n' ' ' < "${CALL_LOG}" | sed 's/ $//'
}

# ---------------------------------------------------------------------------
# AC1 — Flux complet : config → SSH → sous-modules → resume
# ---------------------------------------------------------------------------

@test "AC1 : install_run emet Demarrage, Hardening, Stockage, Docker et Resume dans l'ordre" {
  run install_run
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Demarrage de l'installation"*"Hardening"*"Stockage"*"Docker"*"Resume de l'installation"* ]]
}

@test "AC1 : install_run appelle load_config, ssh_init puis les trois sous-modules dans l'ordre" {
  run install_run
  [ "${status}" -eq 0 ]
  [ "$(_call_order)" = "load_config ssh_init hardening_run storage_run docker_run" ]
}

@test "AC1 : install_run n'appelle PAS ssh_cleanup (le trap EXIT du CLI s'en charge)" {
  run install_run
  [ "${status}" -eq 0 ]
  ! grep -q '^ssh_cleanup$' "${CALL_LOG}"
}

# ---------------------------------------------------------------------------
# AC3 — Echec d'une etape : arret propre + code + sous-modules suivants skippes
# ---------------------------------------------------------------------------

@test "AC3 : echec de hardening_run propage le code et stoppe avant storage/docker" {
  hardening_run() {
    echo "hardening_run" >> "${CALL_LOG}"
    die 1 "Echec hardening" "Consultez le fichier de log"
  }
  run install_run
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Echec hardening"* ]]
  # storage_run et docker_run NE doivent PAS avoir ete appeles
  ! grep -q '^storage_run$' "${CALL_LOG}"
  ! grep -q '^docker_run$' "${CALL_LOG}"
  # Le resume final ne doit pas s'afficher en cas d'erreur (die avant)
  [[ "${output}" != *"Resume de l'installation"* ]]
}

@test "AC3 : echec de ssh_init (code 2) propage le code et stoppe avant sous-modules" {
  ssh_init() {
    echo "ssh_init" >> "${CALL_LOG}"
    die 2 "Connexion SSH echouee" "Verifiez SERVER_IP"
  }
  run install_run
  [ "${status}" -eq 2 ]
  [[ "${output}" == *"Connexion SSH echouee"* ]]
  ! grep -q '^hardening_run$' "${CALL_LOG}"
  ! grep -q '^storage_run$' "${CALL_LOG}"
  ! grep -q '^docker_run$' "${CALL_LOG}"
}

@test "AC3 : echec de load_config (code 1) propage le code et stoppe avant ssh_init/sous-modules" {
  load_config() {
    echo "load_config" >> "${CALL_LOG}"
    die 1 "Configuration invalide" "Verifiez votre .env"
  }
  run install_run
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Configuration invalide"* ]]
  ! grep -q '^ssh_init$' "${CALL_LOG}"
  ! grep -q '^hardening_run$' "${CALL_LOG}"
  ! grep -q '^storage_run$' "${CALL_LOG}"
  ! grep -q '^docker_run$' "${CALL_LOG}"
  [[ "${output}" != *"Resume de l'installation"* ]]
}

# ---------------------------------------------------------------------------
# Garde arguments : install n'accepte aucun argument additionnel
# ---------------------------------------------------------------------------

@test "install_run refuse tout argument additionnel (code 1, message explicite)" {
  run install_run "un-argument-de-trop"
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Argument inattendu pour 'install' : un-argument-de-trop"* ]]
  # Rien ne doit avoir ete dispatche
  ! grep -q '^load_config$' "${CALL_LOG}"
  ! grep -q '^ssh_init$' "${CALL_LOG}"
}

# ---------------------------------------------------------------------------
# AC5 — Resume final lisible (ecran + fichier log)
# ---------------------------------------------------------------------------

@test "AC5 : le resume final liste Hardening, Stockage et Docker avec leur statut" {
  run install_run
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Resume de l'installation"* ]]
  [[ "${output}" == *"- Hardening : succes"* ]]
  [[ "${output}" == *"- Stockage : succes"* ]]
  [[ "${output}" == *"- Docker : succes"* ]]
  [[ "${output}" == *"Installation terminee"* ]]
}

@test "AC5 : le resume final est aussi ecrit dans le fichier log" {
  install_run
  # LOG_FILE a ete positionne par logging_init dans setup() ; grep persiste
  # dans le meme shell que le test (pas de run ici), donc LOG_FILE est visible.
  grep -q "Resume de l'installation" "${LOG_FILE}"
  grep -q -- "- Hardening : succes" "${LOG_FILE}"
  grep -q -- "- Stockage : succes" "${LOG_FILE}"
  grep -q -- "- Docker : succes" "${LOG_FILE}"
}

# ---------------------------------------------------------------------------
# AC6 — install.sh n'implemente AUCUNE logique metier
# ---------------------------------------------------------------------------

@test "AC6 : install.sh ne contient aucun appel direct a ssh_exec/scp/apt/systemctl/ensure_state" {
  local install_sh="${PROJECT_ROOT}/lib/modules/install.sh"
  # Grep strict : ces patterns ne doivent pas apparaitre dans le module
  # orchestrateur (ils appartiennent aux sous-modules 2.2 a 2.8).
  ! grep -E -q '\b(ssh_exec|ensure_state)\b' "${install_sh}"
  ! grep -E -q '\bscp\b' "${install_sh}"
  ! grep -E -q '\bapt(-get)?\b' "${install_sh}"
  ! grep -E -q '\bsystemctl\b' "${install_sh}"
}

@test "AC6 : install.sh respecte le contrat module (shebang, header, install_run defini)" {
  local install_sh="${PROJECT_ROOT}/lib/modules/install.sh"
  head -1 "${install_sh}" | grep -q '#!/usr/bin/env bash'
  grep -q '^# Module: install' "${install_sh}"
  # install_run doit etre defini et etre une fonction
  declare -F install_run >/dev/null
}

# ---------------------------------------------------------------------------
# AC4 — Marqueur verbose propage par install_run
# ---------------------------------------------------------------------------

@test "AC4 : install_run emet log_info 'Mode verbose actif' visible uniquement avec VERBOSE=1" {
  VERBOSE=1 run install_run
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"[INFO] Mode verbose actif"* ]]
}

@test "AC4 : sans VERBOSE, le marqueur 'Mode verbose actif' n'apparait pas a l'ecran" {
  VERBOSE=0 run install_run
  [ "${status}" -eq 0 ]
  [[ "${output}" != *"[INFO] Mode verbose actif"* ]]
}

# ---------------------------------------------------------------------------
# AC2 — Idempotence (appels multiples dans le meme process)
# ---------------------------------------------------------------------------

@test "AC2 : install_run reset les tableaux du resume entre deux appels dans le meme process" {
  # Invoquer install_run DANS LE SHELL DU TEST (pas `run` : les tableaux
  # globaux doivent survivre pour etre inspectes). Le reset au debut de
  # install_run doit empecher l'accumulation entre deux appels.
  install_run >/dev/null
  [ "${#_INSTALL_STEPS[@]}" -eq 3 ]
  [ "${#_INSTALL_STATUSES[@]}" -eq 3 ]

  install_run >/dev/null
  # Toujours 3 entrees (pas 6) : le reset a bien fonctionne.
  [ "${#_INSTALL_STEPS[@]}" -eq 3 ]
  [ "${#_INSTALL_STATUSES[@]}" -eq 3 ]
  [ "${_INSTALL_STEPS[0]}" = "Hardening" ]
  [ "${_INSTALL_STEPS[1]}" = "Stockage" ]
  [ "${_INSTALL_STEPS[2]}" = "Docker" ]
}
