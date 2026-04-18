#!/usr/bin/env bash
# Module: utils — Helpers d'idempotence et polling partages
# Dependances: logging.sh, errors.sh
#
# Fonctions publiques :
#   ensure_state <check_cmd> <action_cmd> <description>
#     - Pattern d'idempotence : execute action_cmd uniquement si check_cmd echoue.
#     - Retour 0 si etat deja en place ou action reussie, `die 1` sinon.
#
#   wait_for_http <url> [timeout_seconds=60] [expected_status=200]
#     - Poll HTTP toutes les 2s jusqu'a obtenir expected_status ou timeout.
#     - Retour 0 si URL repond, 1 si timeout. `die 1` sur usage invalide.
#
#   retry <max_attempts> <delay_seconds> <commande> [args...]
#     - Reessaie commande jusqu'a max_attempts fois avec delay entre tentatives.
#     - Retour 0 si succes, 1 si toutes tentatives ont echoue. `die 1` sur usage invalide.
#
# eval autorise UNIQUEMENT dans ensure_state (cf. architecture.md anti-patterns).

# Pattern d'idempotence : execute action_cmd uniquement si check_cmd echoue.
# Arguments: $1 = check_cmd (chaine bash), $2 = action_cmd (chaine bash), $3 = description
ensure_state() {
  if [[ "$#" -lt 3 ]]; then
    die 1 "ensure_state : usage : ensure_state <check_cmd> <action_cmd> <description>"
  fi

  local check_cmd="${1}"
  local action_cmd="${2}"
  local description="${3}"

  # check_cmd evalue dans un sous-shell pour isoler les effets de bord
  # et neutraliser un `set -e` actif (le test peut legitimement retourner != 0).
  # shellcheck disable=SC2294
  if ( eval "${check_cmd}" ) >/dev/null 2>&1; then
    log_info "${description} : deja en place"
    return 0
  fi

  log_action "${description}"

  # action_cmd evalue dans le shell courant : ses effets de bord sont voulus.
  # Le `if !` neutralise `set -e` localement.
  # shellcheck disable=SC2294
  if ! eval "${action_cmd}"; then
    die 1 "Echec : ${description}" "Consultez le fichier de log : ${LOG_FILE:-inconnu}"
  fi

  log_info "${description} : termine"
}

# Poll HTTP jusqu'a obtenir le code attendu ou atteindre le timeout.
# Arguments: $1 = url, $2 = timeout_seconds (defaut 60), $3 = expected_status (defaut 200)
wait_for_http() {
  if [[ "$#" -lt 1 ]]; then
    die 1 "wait_for_http : usage : wait_for_http <url> [timeout_seconds] [expected_status]"
  fi

  local url="${1}"
  local timeout_seconds="${2:-60}"
  local expected_status="${3:-200}"

  if [[ ! "${timeout_seconds}" =~ ^[0-9]+$ ]]; then
    die 1 "wait_for_http : timeout_seconds doit etre un entier >= 0, recu : ${timeout_seconds}"
  fi
  if [[ ! "${expected_status}" =~ ^[0-9]+$ ]]; then
    die 1 "wait_for_http : expected_status doit etre un entier, recu : ${expected_status}"
  fi

  local poll_interval=2
  local last_code=""
  local elapsed=0
  local start_time
  start_time="$(date +%s)"

  log_info "Attente de ${url} (timeout : ${timeout_seconds}s, attendu : HTTP ${expected_status})"

  while (( elapsed < timeout_seconds )); do
    last_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${url}" 2>/dev/null || echo "000")"
    if [[ "${last_code}" == "${expected_status}" ]]; then
      log_info "${url} repond (HTTP ${expected_status}) apres ${elapsed}s"
      return 0
    fi
    sleep "${poll_interval}"
    elapsed=$(( $(date +%s) - start_time ))
  done

  log_warn "${url} ne repond pas apres ${timeout_seconds}s (dernier code : ${last_code:-aucun})"
  return 1
}

# Reessaie une commande jusqu'a max_attempts fois avec un delai entre tentatives.
# Arguments: $1 = max_attempts (entier >= 1), $2 = delay_seconds (entier >= 0), $3+ = commande
retry() {
  if [[ "$#" -lt 3 ]]; then
    die 1 "retry : usage : retry <max_attempts> <delay> <commande> [args...]"
  fi

  local max_attempts="${1}"
  local delay="${2}"
  shift 2

  if [[ ! "${max_attempts}" =~ ^[1-9][0-9]*$ ]]; then
    die 1 "retry : max_attempts doit etre un entier >= 1, recu : ${max_attempts}"
  fi
  if [[ ! "${delay}" =~ ^[0-9]+$ ]]; then
    die 1 "retry : delay doit etre un entier >= 0, recu : ${delay}"
  fi

  local attempt
  for (( attempt=1; attempt<=max_attempts; attempt++ )); do
    if "$@"; then
      if (( attempt > 1 )); then
        log_info "Succes apres ${attempt} tentatives"
      fi
      return 0
    fi
    if (( attempt < max_attempts )); then
      log_warn "Tentative ${attempt}/${max_attempts} echouee, nouvelle tentative dans ${delay}s"
      sleep "${delay}"
    fi
  done

  log_error "Echec apres ${max_attempts} tentatives : $*"
  return 1
}
