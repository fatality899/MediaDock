#!/usr/bin/env bats
# Tests unitaires pour lib/core/config.sh

setup() {
  TEST_HOME="$(mktemp -d)"
  export HOME="${TEST_HOME}"
  PROJECT_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  export VERBOSE=0

  # shellcheck disable=SC1091
  source "${PROJECT_ROOT}/lib/core/logging.sh"
  logging_init
  # shellcheck disable=SC1091
  source "${PROJECT_ROOT}/lib/core/errors.sh"
  # shellcheck disable=SC1091
  source "${PROJECT_ROOT}/lib/core/config.sh"

  TEST_ENV="${TEST_HOME}/.env"
  TEST_SSH_KEY="${TEST_HOME}/.ssh/id_ed25519"
  mkdir -p "${TEST_HOME}/.ssh"
  touch "${TEST_SSH_KEY}"

  cd "${TEST_HOME}"
}

teardown() {
  cd "${PROJECT_ROOT}"
  rm -rf "${TEST_HOME}"
  unset SERVER_IP SERVER_USER SSH_KEY_PATH VPN_PROVIDER VPN_TOKEN
  unset MEDIA_PLAYER STORAGE_MODE DATA_DISK LANGUAGE
  unset QUALITY_PROFILE BACKUP_SCHEDULE BACKUP_PATH
  unset FOO BAR
}

# Helper : ecrit un .env valide complet dans TEST_ENV
write_valid_env() {
  cat > "${TEST_ENV}" << EOF
SERVER_IP=192.168.1.100
SERVER_USER=root
SSH_KEY_PATH=${TEST_SSH_KEY}
VPN_PROVIDER=nordvpn
VPN_TOKEN=secret_token
MEDIA_PLAYER=jellyfin
STORAGE_MODE=dedicated_disk
DATA_DISK=/dev/sdb
LANGUAGE=fr
EOF
}

# ============================================================
# Tests require_var (AC: #1, #3)
# ============================================================

@test "require_var reussit si la variable est definie et non vide" {
  export FOO="valeur"
  run require_var FOO
  [[ "${status}" -eq 0 ]]
}

@test "require_var echoue si la variable n'est pas definie" {
  unset FOO
  run require_var FOO
  [[ "${status}" -eq 1 ]]
  [[ "${output}" == *"Variable obligatoire manquante : FOO"* ]]
}

@test "require_var echoue si la variable est vide" {
  export FOO=""
  run require_var FOO
  [[ "${status}" -eq 1 ]]
  [[ "${output}" == *"Variable obligatoire manquante : FOO"* ]]
}

@test "require_var affiche l'exemple dans la suggestion" {
  unset FOO
  run require_var FOO "exemple_valeur"
  [[ "${status}" -eq 1 ]]
  [[ "${output}" == *"FOO=exemple_valeur"* ]]
}

# ============================================================
# Tests validate_choice (AC: #1)
# ============================================================

@test "validate_choice reussit si la valeur est dans la liste" {
  export FOO="b"
  run validate_choice FOO a b c
  [[ "${status}" -eq 0 ]]
}

@test "validate_choice reussit pour la premiere valeur de la liste" {
  export FOO="a"
  run validate_choice FOO a b c
  [[ "${status}" -eq 0 ]]
}

@test "validate_choice echoue si la valeur n'est pas dans la liste" {
  export FOO="d"
  run validate_choice FOO a b c
  [[ "${status}" -eq 1 ]]
  [[ "${output}" == *"Valeur invalide pour FOO : d"* ]]
  [[ "${output}" == *"a|b|c"* ]]
}

@test "validate_choice echoue si la variable n'est pas definie" {
  unset FOO
  run validate_choice FOO a b c
  [[ "${status}" -eq 1 ]]
}

@test "validate_choice MEDIA_PLAYER accepte emby, jellyfin, plex" {
  export MEDIA_PLAYER="jellyfin"
  run validate_choice MEDIA_PLAYER emby jellyfin plex
  [[ "${status}" -eq 0 ]]
  export MEDIA_PLAYER="emby"
  run validate_choice MEDIA_PLAYER emby jellyfin plex
  [[ "${status}" -eq 0 ]]
  export MEDIA_PLAYER="plex"
  run validate_choice MEDIA_PLAYER emby jellyfin plex
  [[ "${status}" -eq 0 ]]
}

# ============================================================
# Tests validate_ip (AC: #1)
# ============================================================

@test "validate_ip reussit pour 192.168.1.1" {
  export FOO="192.168.1.1"
  run validate_ip FOO
  [[ "${status}" -eq 0 ]]
}

@test "validate_ip reussit pour 10.0.0.255" {
  export FOO="10.0.0.255"
  run validate_ip FOO
  [[ "${status}" -eq 0 ]]
}

@test "validate_ip reussit pour 0.0.0.0" {
  export FOO="0.0.0.0"
  run validate_ip FOO
  [[ "${status}" -eq 0 ]]
}

@test "validate_ip echoue pour octet superieur a 255" {
  export FOO="256.1.1.1"
  run validate_ip FOO
  [[ "${status}" -eq 1 ]]
  [[ "${output}" == *"Adresse IP invalide pour FOO"* ]]
}

@test "validate_ip echoue pour un octet largement hors plage" {
  export FOO="192.168.1.999"
  run validate_ip FOO
  [[ "${status}" -eq 1 ]]
}

@test "validate_ip echoue pour une chaine non IP" {
  export FOO="not.an.ip.address"
  run validate_ip FOO
  [[ "${status}" -eq 1 ]]
}

@test "validate_ip echoue pour moins de 4 octets" {
  export FOO="192.168.1"
  run validate_ip FOO
  [[ "${status}" -eq 1 ]]
}

@test "validate_ip echoue pour plus de 4 octets" {
  export FOO="192.168.1.1.1"
  run validate_ip FOO
  [[ "${status}" -eq 1 ]]
}

@test "validate_ip echoue si la variable n'est pas definie" {
  unset FOO
  run validate_ip FOO
  [[ "${status}" -eq 1 ]]
}

# ============================================================
# Tests load_config — mode non-interactif (AC: #1, #3)
# ============================================================

@test "load_config charge un .env valide sans erreur" {
  write_valid_env
  run load_config "${TEST_ENV}"
  [[ "${status}" -eq 0 ]]
}

@test "load_config positionne les variables attendues (sans run pour conserver l'etat)" {
  write_valid_env
  load_config "${TEST_ENV}"
  [[ "${SERVER_IP}" == "192.168.1.100" ]]
  [[ "${SERVER_USER}" == "root" ]]
  [[ "${VPN_PROVIDER}" == "nordvpn" ]]
  [[ "${MEDIA_PLAYER}" == "jellyfin" ]]
  [[ "${STORAGE_MODE}" == "dedicated_disk" ]]
  [[ "${DATA_DISK}" == "/dev/sdb" ]]
  [[ "${LANGUAGE}" == "fr" ]]
}

@test "load_config applique les defauts sur les variables optionnelles" {
  cat > "${TEST_ENV}" << EOF
SERVER_IP=192.168.1.100
SSH_KEY_PATH=${TEST_SSH_KEY}
VPN_PROVIDER=nordvpn
VPN_TOKEN=secret
MEDIA_PLAYER=jellyfin
STORAGE_MODE=single_disk
LANGUAGE=fr
EOF
  load_config "${TEST_ENV}"
  [[ "${SERVER_USER}" == "root" ]]
  [[ "${QUALITY_PROFILE}" == "default" ]]
  [[ "${BACKUP_SCHEDULE}" == "weekly" ]]
  [[ "${BACKUP_PATH}" == "/opt/mediadock/backups" ]]
}

@test "load_config echoue si MEDIA_PLAYER est invalide" {
  cat > "${TEST_ENV}" << EOF
SERVER_IP=192.168.1.100
SSH_KEY_PATH=${TEST_SSH_KEY}
VPN_PROVIDER=nordvpn
VPN_TOKEN=secret
MEDIA_PLAYER=kodi
STORAGE_MODE=single_disk
LANGUAGE=fr
EOF
  run load_config "${TEST_ENV}"
  [[ "${status}" -eq 1 ]]
  [[ "${output}" == *"Valeur invalide pour MEDIA_PLAYER"* ]]
  [[ "${output}" == *"emby|jellyfin|plex"* ]]
}

@test "load_config echoue si SERVER_IP est mal formee" {
  cat > "${TEST_ENV}" << EOF
SERVER_IP=not-an-ip
SSH_KEY_PATH=${TEST_SSH_KEY}
VPN_PROVIDER=nordvpn
VPN_TOKEN=secret
MEDIA_PLAYER=jellyfin
STORAGE_MODE=single_disk
LANGUAGE=fr
EOF
  run load_config "${TEST_ENV}"
  [[ "${status}" -eq 1 ]]
  [[ "${output}" == *"Adresse IP invalide"* ]]
}

@test "load_config echoue si VPN_TOKEN est manquante" {
  cat > "${TEST_ENV}" << EOF
SERVER_IP=192.168.1.100
SSH_KEY_PATH=${TEST_SSH_KEY}
VPN_PROVIDER=nordvpn
MEDIA_PLAYER=jellyfin
STORAGE_MODE=single_disk
LANGUAGE=fr
EOF
  run load_config "${TEST_ENV}"
  [[ "${status}" -eq 1 ]]
  [[ "${output}" == *"Variable obligatoire manquante : VPN_TOKEN"* ]]
}

@test "load_config echoue si STORAGE_MODE=dedicated_disk sans DATA_DISK" {
  cat > "${TEST_ENV}" << EOF
SERVER_IP=192.168.1.100
SSH_KEY_PATH=${TEST_SSH_KEY}
VPN_PROVIDER=nordvpn
VPN_TOKEN=secret
MEDIA_PLAYER=jellyfin
STORAGE_MODE=dedicated_disk
LANGUAGE=fr
EOF
  run load_config "${TEST_ENV}"
  [[ "${status}" -eq 1 ]]
  [[ "${output}" == *"Variable obligatoire manquante : DATA_DISK"* ]]
}

@test "load_config reussit si STORAGE_MODE=single_disk sans DATA_DISK" {
  cat > "${TEST_ENV}" << EOF
SERVER_IP=192.168.1.100
SSH_KEY_PATH=${TEST_SSH_KEY}
VPN_PROVIDER=nordvpn
VPN_TOKEN=secret
MEDIA_PLAYER=jellyfin
STORAGE_MODE=single_disk
LANGUAGE=fr
EOF
  run load_config "${TEST_ENV}"
  [[ "${status}" -eq 0 ]]
}

@test "load_config expanse le ~ dans SSH_KEY_PATH" {
  # Creer une cle dans HOME (TEST_HOME) a l'emplacement standard
  mkdir -p "${TEST_HOME}/.ssh"
  touch "${TEST_HOME}/.ssh/tilde_key"
  cat > "${TEST_ENV}" << 'EOF'
SERVER_IP=192.168.1.100
SSH_KEY_PATH=~/.ssh/tilde_key
VPN_PROVIDER=nordvpn
VPN_TOKEN=secret
MEDIA_PLAYER=jellyfin
STORAGE_MODE=single_disk
LANGUAGE=fr
EOF
  load_config "${TEST_ENV}"
  [[ "${SSH_KEY_PATH}" == "${TEST_HOME}/.ssh/tilde_key" ]]
}

@test "load_config echoue si la cle SSH n'existe pas apres expansion" {
  cat > "${TEST_ENV}" << EOF
SERVER_IP=192.168.1.100
SSH_KEY_PATH=${TEST_HOME}/.ssh/cle_inexistante
VPN_PROVIDER=nordvpn
VPN_TOKEN=secret
MEDIA_PLAYER=jellyfin
STORAGE_MODE=single_disk
LANGUAGE=fr
EOF
  run load_config "${TEST_ENV}"
  [[ "${status}" -eq 1 ]]
  [[ "${output}" == *"Cle SSH introuvable"* ]]
}

@test "load_config echoue si QUALITY_PROFILE est invalide" {
  cat > "${TEST_ENV}" << EOF
SERVER_IP=192.168.1.100
SSH_KEY_PATH=${TEST_SSH_KEY}
VPN_PROVIDER=nordvpn
VPN_TOKEN=secret
MEDIA_PLAYER=jellyfin
STORAGE_MODE=single_disk
LANGUAGE=fr
QUALITY_PROFILE=invalid
EOF
  run load_config "${TEST_ENV}"
  [[ "${status}" -eq 1 ]]
  [[ "${output}" == *"Valeur invalide pour QUALITY_PROFILE"* ]]
}

@test "load_config echoue si BACKUP_SCHEDULE est invalide" {
  cat > "${TEST_ENV}" << EOF
SERVER_IP=192.168.1.100
SSH_KEY_PATH=${TEST_SSH_KEY}
VPN_PROVIDER=nordvpn
VPN_TOKEN=secret
MEDIA_PLAYER=jellyfin
STORAGE_MODE=single_disk
LANGUAGE=fr
BACKUP_SCHEDULE=yearly
EOF
  run load_config "${TEST_ENV}"
  [[ "${status}" -eq 1 ]]
  [[ "${output}" == *"Valeur invalide pour BACKUP_SCHEDULE"* ]]
}

# ============================================================
# Tests load_config — mode interactif (AC: #2)
# ============================================================

@test "load_config mode interactif : genere .env a partir des reponses" {
  [[ ! -f "${TEST_ENV}" ]]
  load_config "${TEST_ENV}" << STDIN
192.168.1.100
root
${TEST_SSH_KEY}
nordvpn
secret_token
jellyfin
dedicated_disk
/dev/sdb
fr
STDIN
  [[ -f "${TEST_ENV}" ]]
  grep -q "^SERVER_IP=192.168.1.100$" "${TEST_ENV}"
  grep -q "^SERVER_USER=root$" "${TEST_ENV}"
  grep -q "^VPN_PROVIDER=nordvpn$" "${TEST_ENV}"
  grep -q "^VPN_TOKEN=secret_token$" "${TEST_ENV}"
  grep -q "^MEDIA_PLAYER=jellyfin$" "${TEST_ENV}"
  grep -q "^STORAGE_MODE=dedicated_disk$" "${TEST_ENV}"
  grep -q "^DATA_DISK=/dev/sdb$" "${TEST_ENV}"
  grep -q "^LANGUAGE=fr$" "${TEST_ENV}"
}

@test "load_config mode interactif : permissions 600 sur le .env genere" {
  # Skip sur Git Bash/NTFS : chmod n'a pas d'effet sur les permissions Unix reelles
  local probe="${TEST_HOME}/perm_probe"
  touch "${probe}"
  chmod 600 "${probe}"
  local probe_perm
  probe_perm="$(stat -c %a "${probe}" 2>/dev/null || stat -f %A "${probe}")"
  if [[ "${probe_perm}" != "600" ]]; then
    skip "chmod 600 non applicable sur ce systeme de fichiers (perm probe = ${probe_perm})"
  fi

  load_config "${TEST_ENV}" << STDIN
192.168.1.100
root
${TEST_SSH_KEY}
nordvpn
secret_token
jellyfin
single_disk
fr
STDIN
  local perm
  perm="$(stat -c %a "${TEST_ENV}" 2>/dev/null || stat -f %A "${TEST_ENV}")"
  [[ "${perm}" == "600" ]]
}

@test "load_config mode interactif : pas de question DATA_DISK si STORAGE_MODE=single_disk" {
  load_config "${TEST_ENV}" << STDIN
192.168.1.100
root
${TEST_SSH_KEY}
nordvpn
secret_token
jellyfin
single_disk
fr
STDIN
  [[ -f "${TEST_ENV}" ]]
  # DATA_DISK ne doit pas etre present dans le fichier genere
  ! grep -q "^DATA_DISK=" "${TEST_ENV}"
}

@test "load_config mode interactif : les variables sont positionnees apres generation" {
  load_config "${TEST_ENV}" << STDIN
192.168.1.100
root
${TEST_SSH_KEY}
nordvpn
secret_token
plex
single_disk
fr
STDIN
  [[ "${SERVER_IP}" == "192.168.1.100" ]]
  [[ "${MEDIA_PLAYER}" == "plex" ]]
  [[ "${STORAGE_MODE}" == "single_disk" ]]
}

# ============================================================
# Tests validate_config isole (AC: #1, #3)
# ============================================================

@test "validate_config echoue si aucune variable obligatoire n'est definie" {
  run validate_config
  [[ "${status}" -eq 1 ]]
  [[ "${output}" == *"Variable obligatoire manquante"* ]]
}

@test "validate_config reussit avec toutes les variables valides" {
  export SERVER_IP="192.168.1.100"
  export SSH_KEY_PATH="${TEST_SSH_KEY}"
  export VPN_PROVIDER="nordvpn"
  export VPN_TOKEN="secret"
  export MEDIA_PLAYER="jellyfin"
  export STORAGE_MODE="single_disk"
  export LANGUAGE="fr"
  run validate_config
  [[ "${status}" -eq 0 ]]
}
