#!/usr/bin/env bash
# Mocks SSH pour tests unitaires bats-core

# Repertoire contenant les faux binaires ssh/scp
MOCK_BIN_DIR=""

# Cree des faux binaires ssh et scp dans un repertoire temporaire
# et les met en tete de PATH pour intercepter les appels
mock_ssh_commands() {
  MOCK_BIN_DIR="$(mktemp -d)"

  # Faux ssh
  cat > "${MOCK_BIN_DIR}/ssh" << 'MOCK_SSH'
#!/usr/bin/env bash
# Simule ssh — analyse les arguments pour le comportement
if [[ "${MOCK_SSH_FAIL:-0}" -eq 1 ]]; then
  exit 255
fi
# -O check / -O exit : operations de controle ControlMaster
for arg in "$@"; do
  if [[ "${arg}" == "check" ]]; then exit 0; fi
  if [[ "${arg}" == "exit" ]]; then exit 0; fi
done
# Commande normale : retourne succes
# Si le dernier argument n'est pas "true" (test de connexion),
# echo la commande pour verification dans les tests
last_arg="${*: -1}"
if [[ "${last_arg}" != "true" ]]; then
  echo "MOCK_SSH_EXEC: ${last_arg}"
fi
exit 0
MOCK_SSH
  chmod +x "${MOCK_BIN_DIR}/ssh"

  # Faux scp
  cat > "${MOCK_BIN_DIR}/scp" << 'MOCK_SCP'
#!/usr/bin/env bash
if [[ "${MOCK_SSH_FAIL:-0}" -eq 1 ]]; then
  exit 1
fi
exit 0
MOCK_SCP
  chmod +x "${MOCK_BIN_DIR}/scp"

  export PATH="${MOCK_BIN_DIR}:${PATH}"
}

# Nettoie le repertoire des faux binaires
mock_ssh_cleanup() {
  if [[ -d "${MOCK_BIN_DIR:-}" ]]; then
    rm -rf "${MOCK_BIN_DIR}"
  fi
}
