#!/usr/bin/env bash
# Module: ssh — Connexion et exécution SSH
# Dépendances: logging.sh, errors.sh
#
# ControlMaster multiplexing, connexion persistante
# Fonctions: ssh_init(), ssh_exec(), ssh_copy(), ssh_cleanup()

# Variables internes du module
_SSH_INITIALIZED=0
_SSH_SOCKET_DIR=""
_SSH_SOCKET=""
_SSH_OPTS=()

# Etablit une connexion SSH ControlMaster persistante vers le serveur
# Prerequis: SERVER_IP et SSH_KEY_PATH doivent etre definies par le caller
# SERVER_USER est optionnel (defaut: root)
ssh_init() {
  if [[ "${_SSH_INITIALIZED}" -eq 1 ]]; then
    log_debug "SSH deja initialise"
    return 0
  fi

  # Validation des variables obligatoires
  if [[ -z "${SERVER_IP:-}" ]]; then
    die 2 "SERVER_IP non definie" "Configurez SERVER_IP dans votre fichier .env"
  fi
  if [[ -z "${SSH_KEY_PATH:-}" ]]; then
    die 2 "SSH_KEY_PATH non definie" "Configurez SSH_KEY_PATH dans votre fichier .env"
  fi
  if [[ ! -f "${SSH_KEY_PATH}" ]]; then
    die 2 "Cle SSH introuvable : ${SSH_KEY_PATH}" "Verifiez le chemin de votre cle SSH"
  fi

  local user="${SERVER_USER:-root}"
  _SSH_SOCKET_DIR="$(mktemp -d /tmp/mediadock-ssh-XXXX)"
  _SSH_SOCKET="${_SSH_SOCKET_DIR}/control"

  # Nettoyage preventif du repertoire de socket en cas d'interruption pendant
  # la phase de connexion (SIGINT/SIGTERM entre mktemp et le succes du probe).
  # Retire apres succes pour laisser ssh_cleanup gerer l'etat stable.
  # shellcheck disable=SC2064
  trap "rm -rf '${_SSH_SOCKET_DIR}'" INT TERM

  _SSH_OPTS=(
    -o "ControlMaster=auto"
    -o "ControlPath=${_SSH_SOCKET}"
    -o "ControlPersist=600"
    -o "ConnectTimeout=10"
    -o "StrictHostKeyChecking=accept-new"
    -o "BatchMode=yes"
    -i "${SSH_KEY_PATH}"
  )

  log_action "Connexion SSH vers ${SERVER_IP}"

  if ! ssh "${_SSH_OPTS[@]}" -o "ControlMaster=yes" "${user}@${SERVER_IP}" true 2>/dev/null; then
    rm -rf "${_SSH_SOCKET_DIR}"
    trap - INT TERM
    die 2 "Connexion SSH echouee vers ${SERVER_IP}" "Verifiez l'adresse IP et la cle SSH (${SSH_KEY_PATH})"
  fi

  trap - INT TERM
  _SSH_INITIALIZED=1
  log_info "Connexion SSH etablie (ControlMaster)"
}

# Execute une commande sur le serveur distant via la connexion ControlMaster
# Arguments: $@ = commande a executer (assemblee comme une chaine shell cote distant)
# Retourne: stdout de la commande distante, propage le code de retour
#
# Contrat de l'API :
#  - L'appelant passe la commande a executer ; les arguments sont concatenes
#    par ssh puis re-interpretes par le shell distant. L'appelant est
#    responsable du quoting multi-tokens (ex: ssh_exec "rm '/path with spaces'").
#  - Pour les arguments contenant des donnees utilisateur non fiables, utilisez
#    printf '%q' cote appelant avant de les inclure dans la commande.
ssh_exec() {
  if [[ "${_SSH_INITIALIZED}" -ne 1 ]]; then
    die 2 "SSH non initialise" "Appelez ssh_init avant ssh_exec"
  fi
  if [[ $# -eq 0 ]]; then
    die 2 "ssh_exec : commande manquante"
  fi

  # Ne logge que le nom de la commande (premier token), pas les arguments :
  # evite la fuite de secrets (tokens, mots de passe) dans ~/.mediadock/logs/.
  log_debug "SSH exec: ${1%% *}"

  local user="${SERVER_USER:-root}"
  # shellcheck disable=SC2029
  ssh "${_SSH_OPTS[@]}" -- "${user}@${SERVER_IP}" "$@"
}

# Copie un fichier local vers le serveur distant via scp
# Arguments: $1 = chemin source locale, $2 = chemin destination distante
ssh_copy() {
  if [[ "${_SSH_INITIALIZED}" -ne 1 ]]; then
    die 2 "SSH non initialise" "Appelez ssh_init avant ssh_copy"
  fi

  local source="${1:-}"
  local destination="${2:-}"

  if [[ -z "${source}" ]]; then
    die 1 "ssh_copy : chemin source manquant"
  fi
  if [[ -z "${destination}" ]]; then
    die 1 "ssh_copy : chemin destination manquant"
  fi

  if [[ ! -f "${source}" ]]; then
    die 1 "Fichier source introuvable : ${source}"
  fi

  # scp interprete la destination cote distant via le shell : rejeter les
  # metacaracteres qui permettraient une injection de commande (RCE via
  # `;`, `$()`, backticks, `|`, `<`, `>`, `&`, `(`, `)`, newlines).
  if [[ "${destination}" =~ [\;\$\`\|\<\>\&\(\)]|$'\n' ]]; then
    die 1 "ssh_copy : destination contient des caracteres dangereux : ${destination}"
  fi

  log_debug "SSH copy: ${source} -> ${destination}"

  local user="${SERVER_USER:-root}"
  scp -o "ControlPath=${_SSH_SOCKET}" -o "BatchMode=yes" -o "ConnectTimeout=10" -i "${SSH_KEY_PATH}" -- "${source}" "${user}@${SERVER_IP}:${destination}"
}

# Ferme la connexion ControlMaster et nettoie les fichiers temporaires
# Idempotent: ne fait rien si pas de connexion active
ssh_cleanup() {
  if [[ "${_SSH_INITIALIZED}" -ne 1 ]]; then
    log_debug "SSH cleanup: pas de connexion active"
    return 0
  fi

  local user="${SERVER_USER:-root}"
  ssh -o "ControlPath=${_SSH_SOCKET}" -O exit "${user}@${SERVER_IP}" 2>/dev/null || true

  if [[ -d "${_SSH_SOCKET_DIR:-}" ]]; then
    rm -rf "${_SSH_SOCKET_DIR}"
  fi

  _SSH_INITIALIZED=0
  log_info "Connexion SSH fermee"
}
