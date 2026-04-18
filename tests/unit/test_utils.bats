#!/usr/bin/env bats
# Tests unitaires — Module utils (lib/core/utils.sh)

setup() {
  TEST_HOME="$(mktemp -d)"
  export HOME="${TEST_HOME}"
  PROJECT_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  # VERBOSE=1 pour que log_info soit visible sur stdout et testable via `output`
  export VERBOSE=1

  # shellcheck disable=SC1091
  source "${PROJECT_ROOT}/lib/core/logging.sh"
  logging_init
  # shellcheck disable=SC1091
  source "${PROJECT_ROOT}/lib/core/errors.sh"
  # shellcheck disable=SC1091
  source "${PROJECT_ROOT}/lib/core/utils.sh"

  ORIGINAL_PATH="${PATH}"
  MOCK_CURL_DIR=""
}

teardown() {
  rm -rf "${TEST_HOME}"
  unset POLLUTION POLLUTION_ACTION
  if [[ -n "${MOCK_CURL_DIR:-}" ]]; then
    rm -rf "${MOCK_CURL_DIR}"
  fi
  export PATH="${ORIGINAL_PATH}"
}

# Cree un faux curl qui retourne successivement les codes HTTP passes en arguments.
# Usage : mock_curl_responses 503 503 200
# Les appels au-dela du dernier code continuent de retourner le dernier code.
mock_curl_responses() {
  MOCK_CURL_DIR="$(mktemp -d)"

  local responses_file="${MOCK_CURL_DIR}/responses"
  printf '%s\n' "$@" > "${responses_file}"
  local counter_file="${MOCK_CURL_DIR}/counter"
  echo 0 > "${counter_file}"

  cat > "${MOCK_CURL_DIR}/curl" << MOCK_CURL
#!/usr/bin/env bash
# Mock curl — retourne le N-eme code de la liste, puis le dernier en boucle
counter=\$(cat "${counter_file}")
mapfile -t responses < "${responses_file}"
n=\${#responses[@]}
idx=\$counter
if (( idx >= n )); then idx=\$(( n - 1 )); fi
printf '%s' "\${responses[idx]}"
echo \$(( counter + 1 )) > "${counter_file}"
exit 0
MOCK_CURL
  chmod +x "${MOCK_CURL_DIR}/curl"
  export PATH="${MOCK_CURL_DIR}:${PATH}"
}

# --- ensure_state ---

@test "ensure_state : moins de 3 arguments -> die code 1" {
  run ensure_state "true" "true"
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"usage"* ]]
}

@test "ensure_state : aucun argument -> die code 1" {
  run ensure_state
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"usage"* ]]
}

@test "ensure_state : check_cmd succes -> action ignoree" {
  run ensure_state 'true' "touch ${TEST_HOME}/sentinel" "Test idempotence"
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"deja en place"* ]]
  [ ! -f "${TEST_HOME}/sentinel" ]
}

@test "ensure_state : check_cmd echec -> action executee" {
  run ensure_state 'false' "touch ${TEST_HOME}/sentinel" "Creation sentinel"
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Creation sentinel"* ]]
  [[ "${output}" == *"termine"* ]]
  [ -f "${TEST_HOME}/sentinel" ]
}

@test "ensure_state : action echec -> die code 1 avec message Echec" {
  run ensure_state 'false' 'false' "Action qui echoue"
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Echec"* ]]
  [[ "${output}" == *"Action qui echoue"* ]]
}

@test "ensure_state : description avec espaces et caracteres speciaux preservee" {
  run ensure_state 'false' 'true' "Configuration & verification"
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Configuration & verification"* ]]
}

@test "ensure_state : check_cmd complexe avec pipe fonctionne" {
  echo "foo bar baz" > "${TEST_HOME}/file"
  run ensure_state "grep -q foo ${TEST_HOME}/file" "touch ${TEST_HOME}/sentinel" "Test pipe"
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"deja en place"* ]]
  [ ! -f "${TEST_HOME}/sentinel" ]
}

@test "ensure_state : check_cmd avec code retour != 0 et != 1 -> action executee" {
  run ensure_state 'bash -c "exit 5"' "touch ${TEST_HOME}/sentinel" "Test code 5"
  [ "${status}" -eq 0 ]
  [ -f "${TEST_HOME}/sentinel" ]
}

@test "ensure_state : check_cmd ne pollue pas le shell courant" {
  unset POLLUTION
  # Appel direct (pas via run) pour verifier l'etat du shell de test
  ensure_state 'POLLUTION=oui ; true' 'true' "Test isolation" || true
  [ -z "${POLLUTION:-}" ]
}

@test "ensure_state : action_cmd pollue bien le shell courant (effets de bord voulus)" {
  # Contrepoint du test d'isolation : action_cmd s'execute hors sous-shell,
  # ses effets de bord doivent donc etre visibles apres retour.
  unset POLLUTION_ACTION
  ensure_state 'false' 'POLLUTION_ACTION=oui' "Test action pollue" || true
  [ "${POLLUTION_ACTION:-}" = "oui" ]
}

@test "ensure_state : action loggee en ACTION dans LOG_FILE" {
  run ensure_state 'false' 'true' "Action de test"
  grep -q "ACTION" "${LOG_FILE}"
  grep -q "Action de test" "${LOG_FILE}"
}

@test "ensure_state : etat deja present logge en INFO" {
  run ensure_state 'true' 'true' "Etat deja la"
  grep -q "INFO" "${LOG_FILE}"
  grep -q "deja en place" "${LOG_FILE}"
}

# --- wait_for_http ---

@test "wait_for_http : sans argument -> die code 1" {
  run wait_for_http
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"usage"* ]]
}

@test "wait_for_http : 200 immediat -> succes" {
  mock_curl_responses 200
  run wait_for_http "http://example.test"
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"repond (HTTP 200)"* ]]
}

@test "wait_for_http : 503 puis 200 -> succes apres retry" {
  mock_curl_responses 503 200
  run wait_for_http "http://example.test" 10
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"repond (HTTP 200)"* ]]
}

@test "wait_for_http : toujours 503 avec timeout 1s -> echec" {
  mock_curl_responses 503
  run wait_for_http "http://example.test" 1
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"ne repond pas"* ]]
  [[ "${output}" == *"503"* ]]
}

@test "wait_for_http : expected_status personnalise 204 -> succes" {
  mock_curl_responses 204
  run wait_for_http "http://example.test" 5 204
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"repond (HTTP 204)"* ]]
}

@test "wait_for_http : expected_status 200 mais serveur renvoie 204 -> echec" {
  mock_curl_responses 204
  run wait_for_http "http://example.test" 1
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"ne repond pas"* ]]
}

@test "wait_for_http : echec logge en WARN (pas en ERROR, pas de die)" {
  mock_curl_responses 503
  run wait_for_http "http://example.test" 1
  [ "${status}" -eq 1 ]
  grep -q "WARN" "${LOG_FILE}"
}

@test "wait_for_http : curl en echec -> fallback 000 dans le log de timeout" {
  # Mock curl qui echoue systematiquement (simulation refus de connexion / DNS down)
  MOCK_CURL_DIR="$(mktemp -d)"
  cat > "${MOCK_CURL_DIR}/curl" << 'MOCK_CURL'
#!/usr/bin/env bash
exit 7
MOCK_CURL
  chmod +x "${MOCK_CURL_DIR}/curl"
  export PATH="${MOCK_CURL_DIR}:${PATH}"

  run wait_for_http "http://example.test" 1
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"000"* ]]
}

@test "wait_for_http : URL correctement transmise a curl" {
  # Mock curl qui enregistre le dernier argument (l'URL) dans un fichier
  MOCK_CURL_DIR="$(mktemp -d)"
  local urls_file="${MOCK_CURL_DIR}/urls"
  cat > "${MOCK_CURL_DIR}/curl" << MOCK_CURL
#!/usr/bin/env bash
printf '%s\n' "\${@: -1}" >> "${urls_file}"
printf '200'
exit 0
MOCK_CURL
  chmod +x "${MOCK_CURL_DIR}/curl"
  export PATH="${MOCK_CURL_DIR}:${PATH}"

  run wait_for_http "http://example.test/health"
  [ "${status}" -eq 0 ]
  grep -q "http://example.test/health" "${urls_file}"
}

@test "wait_for_http : timeout non-numerique -> die code 1" {
  run wait_for_http "http://example.test" "abc"
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"timeout_seconds"* ]]
}

@test "wait_for_http : expected_status non-numerique -> die code 1" {
  run wait_for_http "http://example.test" 5 "OK"
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"expected_status"* ]]
}

# --- retry ---

@test "retry : moins de 3 arguments -> die code 1" {
  run retry 3 0
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"usage"* ]]
}

@test "retry : max_attempts=0 -> die code 1" {
  run retry 0 0 true
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"max_attempts"* ]]
}

@test "retry : max_attempts non-numerique -> die code 1" {
  run retry abc 0 true
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"max_attempts"* ]]
}

@test "retry : delay non-numerique -> die code 1" {
  run retry 3 xyz true
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"delay"* ]]
}

@test "retry : delay negatif rejete" {
  run retry 3 -5 true
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"delay"* ]]
}

@test "retry : commande qui reussit du premier coup -> 0" {
  run retry 3 0 true
  [ "${status}" -eq 0 ]
}

@test "retry : commande qui echoue toujours -> 1 apres N tentatives" {
  run retry 3 0 false
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Echec apres 3 tentatives"* ]]
}

@test "retry : message WARN intermediaire avec numero de tentative" {
  run retry 3 0 false
  [[ "${output}" == *"Tentative 1/3"* ]]
  [[ "${output}" == *"Tentative 2/3"* ]]
}

@test "retry : echoue 2 fois puis reussit -> 0 apres 3 appels" {
  COUNT_FILE="${TEST_HOME}/count"
  echo 0 > "${COUNT_FILE}"
  cat > "${TEST_HOME}/flaky" << FLAKY
#!/usr/bin/env bash
n=\$(cat "${COUNT_FILE}")
n=\$(( n + 1 ))
echo "\${n}" > "${COUNT_FILE}"
[[ "\${n}" -ge 3 ]]
FLAKY
  chmod +x "${TEST_HOME}/flaky"

  run retry 5 0 "${TEST_HOME}/flaky"
  [ "${status}" -eq 0 ]
  [[ "$(cat "${COUNT_FILE}")" -eq 3 ]]
  [[ "${output}" == *"Succes apres 3 tentatives"* ]]
}

@test "retry : succes du premier coup -> pas de log Succes apres N" {
  run retry 3 0 true
  [ "${status}" -eq 0 ]
  [[ "${output}" != *"Succes apres"* ]]
}

@test "retry : arguments multiples passes correctement a la commande" {
  run retry 1 0 echo "hello world"
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"hello world"* ]]
}

@test "retry : execute exactement max_attempts fois en cas d'echec persistant" {
  COUNT_FILE="${TEST_HOME}/count"
  echo 0 > "${COUNT_FILE}"
  cat > "${TEST_HOME}/always_fails" << FAILS
#!/usr/bin/env bash
n=\$(cat "${COUNT_FILE}")
echo \$(( n + 1 )) > "${COUNT_FILE}"
exit 1
FAILS
  chmod +x "${TEST_HOME}/always_fails"

  run retry 4 0 "${TEST_HOME}/always_fails"
  [ "${status}" -eq 1 ]
  [[ "$(cat "${COUNT_FILE}")" -eq 4 ]]
}
