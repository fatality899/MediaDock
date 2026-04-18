#!/usr/bin/env bash
# Module: config — Chargement .env, mode interactif
# Dependances: logging.sh, errors.sh
#
# Fonctions publiques :
#   load_config()         — charge un .env ou declenche le mode interactif
#   validate_config()     — valide les variables chargees (types, choix, defauts)
#   interactive_setup()   — genere un .env via questions guidees
#   require_var()         — echoue si une variable est absente ou vide
#   validate_choice()     — echoue si la valeur n'est pas dans une liste autorisee
#   validate_ip()         — echoue si la valeur n'est pas une IPv4 valide
#
# Codes retour : toutes les erreurs de configuration utilisent le code 1
# (le code 2 est reserve aux erreurs SSH, le code 3 aux services).

# ---------------------------------------------------------------------------
# Helpers de validation
# ---------------------------------------------------------------------------

# require_var <var_name> [example_value]
# Echoue (code 1) si la variable nommee est absente ou vide.
require_var() {
  local var_name="${1}"
  local example="${2:-}"
  local value="${!var_name:-}"

  if [[ -z "${value//[[:space:]]/}" ]]; then
    local suggestion="Ajoutez ${var_name}=<valeur> dans votre fichier .env"
    if [[ -n "${example}" ]]; then
      suggestion="Ajoutez ${var_name}=${example} dans votre fichier .env"
    fi
    die 1 "Variable obligatoire manquante : ${var_name}" "${suggestion}"
  fi
}

# validate_choice <var_name> <choice1> [<choice2> ...]
# Echoue (code 1) si la valeur de la variable n'est pas dans la liste.
validate_choice() {
  local var_name="${1}"
  shift
  local value="${!var_name:-}"
  local choices=("$@")
  local choice

  for choice in "${choices[@]}"; do
    if [[ "${value}" == "${choice}" ]]; then
      return 0
    fi
  done

  local choices_str
  choices_str="$(IFS='|'; echo "${choices[*]}")"
  die 1 "Valeur invalide pour ${var_name} : ${value}" "Valeurs autorisees : ${choices_str}"
}

# validate_ip <var_name>
# Echoue (code 1) si la valeur n'est pas une IPv4 (4 octets 0-255).
validate_ip() {
  local var_name="${1}"
  local value="${!var_name:-}"

  if [[ ! "${value}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    die 1 "Adresse IP invalide pour ${var_name} : ${value}" "Format attendu : X.X.X.X (0-255 par octet)"
  fi

  local IFS='.'
  local -a octets
  read -ra octets <<< "${value}"
  local octet
  for octet in "${octets[@]}"; do
    # Forcer la base 10 pour eviter l'interpretation octale des octets commencant par 0 (ex: 08, 09)
    if (( 10#${octet} > 255 )); then
      die 1 "Adresse IP invalide pour ${var_name} : ${value}" "Format attendu : X.X.X.X (0-255 par octet)"
    fi
  done
}

# ---------------------------------------------------------------------------
# Helpers de saisie interactive (prefixe _ : usage interne)
# ---------------------------------------------------------------------------

# _prompt <var_name> <question> [default] [hidden=0|1]
# Lit une ligne sur stdin et la stocke dans la variable globale <var_name>.
# Si la reponse est vide et qu'un defaut existe, utilise le defaut.
# Si la reponse est vide sans defaut, repose la question.
_prompt() {
  local var_name="${1}"
  local question="${2}"
  local default="${3:-}"
  local hidden="${4:-0}"
  local answer=""
  local prompt_str="${question}"

  if [[ -n "${default}" ]]; then
    prompt_str="${question} [${default}]"
  fi

  while true; do
    if [[ "${hidden}" -eq 1 ]]; then
      # Restaurer l'echo du terminal si Ctrl-C interrompt la saisie masquee
      trap 'stty echo 2>/dev/null || true' INT
      if ! read -r -s -p "${prompt_str} " answer; then
        trap - INT
        echo ""
        die 1 "Entree utilisateur impossible (EOF sur stdin)" "Utilisez le mode non-interactif avec un fichier .env"
      fi
      trap - INT
      echo ""
    else
      if ! read -r -p "${prompt_str} " answer; then
        die 1 "Entree utilisateur impossible (EOF sur stdin)" "Utilisez le mode non-interactif avec un fichier .env"
      fi
    fi

    if [[ -z "${answer}" && -n "${default}" ]]; then
      answer="${default}"
    fi

    if [[ -n "${answer}" ]]; then
      break
    fi
    log_warn "Reponse vide, veuillez repondre."
  done

  printf -v "${var_name}" '%s' "${answer}"
}

# _prompt_choice <var_name> <question> <default> <choice1> [<choice2> ...]
# Repose la question tant que la reponse n'est pas dans la liste des choix.
_prompt_choice() {
  local var_name="${1}"
  local question="${2}"
  local default="${3}"
  shift 3
  local choices=("$@")
  local choice valid

  while true; do
    _prompt "${var_name}" "${question}" "${default}"
    valid=0
    for choice in "${choices[@]}"; do
      if [[ "${!var_name}" == "${choice}" ]]; then
        valid=1
        break
      fi
    done
    if [[ "${valid}" -eq 1 ]]; then
      break
    fi
    local choices_str
    choices_str="$(IFS='|'; echo "${choices[*]}")"
    log_warn "Valeur invalide. Choix : ${choices_str}"
  done
}

# _prompt_ip <var_name> <question>
# Repose la question tant que la reponse n'est pas une IPv4 valide.
_prompt_ip() {
  local var_name="${1}"
  local question="${2}"

  while true; do
    _prompt "${var_name}" "${question}"
    local value="${!var_name}"
    if [[ "${value}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
      local IFS='.'
      local -a octets
      read -ra octets <<< "${value}"
      local ok=1 octet
      for octet in "${octets[@]}"; do
        # Forcer la base 10 pour eviter l'interpretation octale (ex: 08, 09)
        if (( 10#${octet} > 255 )); then
          ok=0
          break
        fi
      done
      if [[ "${ok}" -eq 1 ]]; then
        break
      fi
    fi
    log_warn "Adresse IP invalide (format : X.X.X.X, 0-255 par octet)."
  done
}

# ---------------------------------------------------------------------------
# validate_config : valide les variables chargees et applique les defauts
# ---------------------------------------------------------------------------
validate_config() {
  # Variables obligatoires
  require_var SERVER_IP "192.168.1.100"
  # shellcheck disable=SC2088 # le ~ est volontairement litteral dans le message utilisateur
  require_var SSH_KEY_PATH "~/.ssh/id_ed25519"
  require_var VPN_PROVIDER "nordvpn"
  require_var VPN_TOKEN "xxxxxxxxxxxx"
  require_var MEDIA_PLAYER "jellyfin"
  require_var STORAGE_MODE "dedicated_disk"
  require_var LANGUAGE "fr"

  # Defauts pour les variables optionnelles
  SERVER_USER="${SERVER_USER:-root}"
  QUALITY_PROFILE="${QUALITY_PROFILE:-default}"
  BACKUP_SCHEDULE="${BACKUP_SCHEDULE:-weekly}"
  BACKUP_PATH="${BACKUP_PATH:-/opt/mediadock/backups}"
  export SERVER_USER QUALITY_PROFILE BACKUP_SCHEDULE BACKUP_PATH

  # Validation des choix
  validate_choice MEDIA_PLAYER emby jellyfin plex
  validate_choice STORAGE_MODE dedicated_disk single_disk
  validate_choice QUALITY_PROFILE default anime custom
  validate_choice BACKUP_SCHEDULE daily weekly monthly

  # Validation de l'IP serveur
  validate_ip SERVER_IP

  # DATA_DISK obligatoire uniquement si STORAGE_MODE=dedicated_disk
  if [[ "${STORAGE_MODE}" == "dedicated_disk" ]]; then
    require_var DATA_DISK "/dev/sdb"
  fi

  # Expansion du ~ dans SSH_KEY_PATH, puis verification de l'existence du fichier
  SSH_KEY_PATH="${SSH_KEY_PATH/#\~/${HOME}}"
  export SSH_KEY_PATH
  if [[ ! -f "${SSH_KEY_PATH}" ]]; then
    die 1 "Cle SSH introuvable : ${SSH_KEY_PATH}" "Verifiez le chemin de votre cle SSH"
  fi
}

# ---------------------------------------------------------------------------
# interactive_setup : pose les questions et genere un .env
# ---------------------------------------------------------------------------
interactive_setup() {
  local env_file="${1:-.env}"

  log_action "Configuration interactive de MediaDock"
  log_info "Les reponses seront sauvegardees dans ${env_file} (permissions 600)."

  # Umask restrictif avant toute ecriture pour eviter une fenetre TOCTOU :
  # le fichier doit etre cree en 600 des le premier write (pas apres chmod).
  local _old_umask
  _old_umask="$(umask)"
  umask 077

  _prompt_ip     SERVER_IP     "Adresse IP du serveur distant :"
  _prompt        SERVER_USER   "Utilisateur SSH :"                                  "root"
  # shellcheck disable=SC2088 # le ~ est volontairement litteral : il sera saisi dans le .env puis expanse par validate_config
  _prompt        SSH_KEY_PATH  "Chemin vers la cle privee SSH :"                    "~/.ssh/id_ed25519"
  _prompt        VPN_PROVIDER  "Provider VPN (ex: nordvpn, mullvad, protonvpn) :"
  _prompt        VPN_TOKEN     "Token/credentials VPN :"                            ""   1
  _prompt_choice MEDIA_PLAYER  "Media player (emby|jellyfin|plex) :"                "jellyfin"        emby jellyfin plex
  _prompt_choice STORAGE_MODE  "Mode de stockage (dedicated_disk|single_disk) :"    "dedicated_disk"  dedicated_disk single_disk

  if [[ "${STORAGE_MODE}" == "dedicated_disk" ]]; then
    _prompt      DATA_DISK     "Disque data dedie (ex: /dev/sdb) :"                 "/dev/sdb"
  fi

  _prompt        LANGUAGE      "Langue preferee (ex: fr, en) :"                     "fr"

  # Generation du .env avec quoting shell-safe (printf %q) pour supporter
  # les valeurs contenant des espaces, #, $, backticks, quotes, etc.
  #
  # Ecriture atomique : toutes les sections sont ecrites dans un fichier
  # temporaire puis mv -f une seule fois. Evite de laisser un .env partiel
  # (missing LANGUAGE/QUALITY/BACKUP) si le processus est interrompu en cours.
  local generated_date tmp_env
  generated_date="$(date +%Y-%m-%d)"
  tmp_env="${env_file}.tmp.$$"

  {
    printf '# =============================================================================\n'
    printf '# MediaDock — Configuration\n'
    printf '# =============================================================================\n'
    printf '# Fichier genere automatiquement le %s par interactive_setup.\n' "${generated_date}"
    printf '# Permissions restrictives (600) — ce fichier contient des secrets.\n'
    printf '# =============================================================================\n'
    printf '\n'
    printf '# --- Serveur ---\n'
    printf 'SERVER_IP=%q\n' "${SERVER_IP}"
    printf 'SERVER_USER=%q\n' "${SERVER_USER}"
    printf 'SSH_KEY_PATH=%q\n' "${SSH_KEY_PATH}"
    printf '\n'
    printf '# --- VPN ---\n'
    printf 'VPN_PROVIDER=%q\n' "${VPN_PROVIDER}"
    printf 'VPN_TOKEN=%q\n' "${VPN_TOKEN}"
    printf '\n'
    printf '# --- Media Player ---\n'
    printf '# Choix : emby | jellyfin | plex\n'
    printf 'MEDIA_PLAYER=%q\n' "${MEDIA_PLAYER}"
    printf '\n'
    printf '# --- Stockage ---\n'
    printf '# Mode : dedicated_disk | single_disk\n'
    printf 'STORAGE_MODE=%q\n' "${STORAGE_MODE}"
    if [[ "${STORAGE_MODE}" == "dedicated_disk" ]]; then
      printf 'DATA_DISK=%q\n' "${DATA_DISK}"
    fi
    printf '\n'
    printf '# --- Langue et qualite ---\n'
    printf 'LANGUAGE=%q\n' "${LANGUAGE}"
    printf '# Profil : default | anime | custom\n'
    printf 'QUALITY_PROFILE=default\n'
    printf '\n'
    printf '# --- Backup ---\n'
    printf '# Frequence : daily | weekly | monthly\n'
    printf 'BACKUP_SCHEDULE=weekly\n'
    printf 'BACKUP_PATH=/opt/mediadock/backups\n'
  } > "${tmp_env}"

  # Commit atomique : si SIGINT intervient avant, tmp_env est orphelin mais
  # env_file existant (ou absent) reste coherent.
  mv -f "${tmp_env}" "${env_file}"

  # Belt-and-suspenders : le umask 077 a deja cree le fichier en 600.
  chmod 600 "${env_file}" 2>/dev/null || true
  umask "${_old_umask}"
  log_action "Fichier ${env_file} genere"
}

# ---------------------------------------------------------------------------
# _source_env_file <env_file>
# Source le .env apres avoir retire BOM UTF-8 + CRLF sur une copie temporaire.
# Supporte les .env edites sous Windows (Notepad, VSCode CRLF par defaut).
# ---------------------------------------------------------------------------
_source_env_file() {
  local env_file="${1}"
  local tmp
  tmp="$(mktemp 2>/dev/null || mktemp -t 'mediadock-env')"

  # Strip BOM UTF-8 (bytes EF BB BF en tete) + normaliser CRLF -> LF
  # Note: les 3 bytes du BOM sont ecrits litteralement (sequence ANSI-C pour sed).
  sed $'1s/^\xef\xbb\xbf//' "${env_file}" | tr -d '\r' > "${tmp}"

  set -a
  # shellcheck disable=SC1090
  source "${tmp}"
  set +a

  rm -f "${tmp}"
}

# ---------------------------------------------------------------------------
# load_config : point d'entree principal
# ---------------------------------------------------------------------------
load_config() {
  local env_file="${1:-.env}"

  if [[ -f "${env_file}" ]]; then
    log_action "Chargement de la configuration depuis ${env_file}"
    _source_env_file "${env_file}"
    validate_config
    log_info "Configuration chargee (mode non-interactif)"
  else
    log_action "Aucun fichier .env detecte, mode interactif active"
    interactive_setup "${env_file}"
    _source_env_file "${env_file}"
    validate_config
    log_info "Configuration chargee (mode interactif, .env genere)"
  fi
}
