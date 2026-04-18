#!/usr/bin/env bash
# Module: install — Orchestration du flux d'installation MediaDock
# Dependances: logging.sh, errors.sh, ssh.sh, config.sh, utils.sh,
#              modules/hardening.sh, modules/storage.sh, modules/docker.sh
#
# Point d'entree : install_run
# Helpers prives : _install_source_submodule, _install_run_step, _install_print_summary
#
# Orchestrateur : charge la configuration, etablit SSH, appelle hardening_run
# puis storage_run puis docker_run dans cet ordre strict, et affiche un resume.
# AUCUNE logique metier cote serveur ici — les sous-modules s'en chargent.

# Tableaux paralleles pour le resume final (indexed arrays, bash 3.2+ compatible).
# Prefixe underscore : usage interne au module, evite les collisions .env.
_INSTALL_STEPS=()
_INSTALL_STATUSES=()

# Source un sous-module depuis lib/modules/ avec message d'erreur lisible.
# Ne pas reutiliser _cli_source_module (prive au fichier mediadock).
_install_source_submodule() {
  local name="${1}"
  local path="${MEDIADOCK_DIR}/lib/modules/${name}.sh"
  if [[ ! -f "${path}" ]]; then
    die 1 "Module ${name} introuvable : ${path}" "Verifiez l'integrite de l'installation MediaDock"
  fi
  # shellcheck source=/dev/null
  source "${path}"
}

# Execute un sous-module et enregistre son statut pour le resume final.
# set -euo pipefail + trap ERR propagent automatiquement un echec : en cas
# de die dans la fonction appelee, _install_print_summary ne s'affiche pas
# (comportement attendu par AC3 : arret propre, pas d'etat incoherent).
_install_run_step() {
  local label="${1}"
  local fn="${2}"
  log_action "${label} : demarrage"
  "${fn}"
  _INSTALL_STEPS+=("${label}")
  _INSTALL_STATUSES+=("succes")
  log_action "${label} : OK"
}

# Affiche le resume final de l'installation : une ligne par etape avec son statut.
# Visible en mode normal ET verbose (log_action est toujours affiche).
_install_print_summary() {
  log_action "Resume de l'installation :"
  local i
  for (( i=0; i<${#_INSTALL_STEPS[@]}; i++ )); do
    log_action "  - ${_INSTALL_STEPS[i]} : ${_INSTALL_STATUSES[i]}"
  done
  log_action "Installation terminee"
}

# Point d'entree : orchestre le flux d'installation complet.
# 1. Marqueur verbose (observable via log_info si VERBOSE=1).
# 2. Sourcing des sous-modules (AVANT load_config : evite qu'un module absent
#    ne nous fasse ecrire un .env orphelin via interactive_setup avant de die).
# 3. Chargement de la configuration (.env ou interactif).
# 4. Connexion SSH ControlMaster persistante (die 2 si echec).
# 5. Execution sequentielle : hardening_run, storage_run, docker_run.
# 6. Resume final lisible (sortie ecran + fichier log).
#
# ssh_cleanup n'est PAS appele ici : le trap EXIT du CLI (pose dans cli_main
# au niveau top-level de mediadock) s'en charge de maniere idempotente,
# y compris en cas d'erreur.
install_run() {
  # Garde arguments : la commande install n'en accepte aucun (les flags
  # globaux -v/--verbose/-h/--help/--version sont deja consommes par
  # cli_parse_global_options avant dispatch).
  if [[ $# -gt 0 ]]; then
    die 1 "Argument inattendu pour 'install' : $*" "La commande 'install' n'accepte aucun argument additionnel. Utilisez 'mediadock --help' pour l'aide."
  fi

  log_info "Mode verbose actif"
  log_action "Demarrage de l'installation MediaDock"

  # Reset des tableaux de resume : permet un appel multiple dans le meme
  # process (tests notamment) sans accumuler les entrees des runs precedents.
  _INSTALL_STEPS=()
  _INSTALL_STATUSES=()

  # Sourcing AVANT load_config : un module manquant doit die AVANT qu'un
  # eventuel interactive_setup ecrive un .env qui serait alors orphelin.
  _install_source_submodule hardening
  _install_source_submodule storage
  _install_source_submodule docker

  load_config

  ssh_init

  _install_run_step "Hardening" hardening_run
  _install_run_step "Stockage"  storage_run
  _install_run_step "Docker"    docker_run

  _install_print_summary
}
