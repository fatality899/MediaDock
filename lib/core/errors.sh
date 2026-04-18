#!/usr/bin/env bash
# Module: errors — Gestion d'erreurs, codes retour
# Dependances: logging.sh
#
# Codes retour: 0=ok, 1=general, 2=SSH echoue, 3=service non demarre
# Fonctions: die(), run_step(), unexpected_error(), errors_init()

# Termine le script avec un message d'erreur lisible et un code de retour specifique
# Arguments: $1 = code de retour, $2 = message d'erreur, $3 = suggestion (optionnel)
die() {
  local code="${1}"
  local message="${2}"
  local suggestion="${3:-}"

  log_error "${message}"
  if [[ -n "${suggestion}" ]]; then
    log_error "Suggestion : ${suggestion}"
  fi
  exit "${code}"
}

# Execute une commande critique avec gestion d'erreur integree
# Arguments: $1 = description, $2 = code retour en cas d'echec, $3 = suggestion, $4+ = commande
run_step() {
  local description="${1}"
  local code="${2}"
  local suggestion="${3}"
  shift 3

  log_action "${description}"
  if ! "$@"; then
    die "${code}" "Echec : ${description}" "${suggestion}"
  fi
  log_info "${description} — termine avec succes"
}

# Handler pour les erreurs non anticipees (appele par le trap ERR)
# Arguments: $1 = numero de ligne, $2 = fichier source, $3 = commande
unexpected_error() {
  local exit_code=$?
  # Guard de re-entree : evite les boucles infinies si log_error echoue
  if [[ "${_UNEXPECTED_ERROR_IN_PROGRESS:-0}" -eq 1 ]]; then
    exit "${exit_code}"
  fi
  _UNEXPECTED_ERROR_IN_PROGRESS=1

  local line="${1}"
  local source="${2}"
  local command="${3}"

  log_error "Erreur inattendue a la ligne ${line} dans ${source}"
  log_error "Commande : ${command}"
  log_error "Consultez le fichier de log pour plus de details : ${LOG_FILE:-inconnu}"
  exit "${exit_code}"
}

# Initialise le trap ERR pour capturer les erreurs non anticipees.
# set -E (errtrace) permet au trap ERR d'etre herite par les fonctions et sous-shells.
# set -o pipefail garantit que les erreurs au milieu d'un pipeline remontent
# (sans pipefail, `false | true` passe silencieusement et le trap ne se declenche pas).
errors_init() {
  set -E
  set -o pipefail
  trap 'unexpected_error "${LINENO}" "${BASH_SOURCE[0]:-unknown}" "${BASH_COMMAND:-unknown}"' ERR
}
