#!/usr/bin/env bats
# Tests unitaires — Vérification de la structure projet MediaDock

setup() {
  PROJECT_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
}

@test "Point d'entrée mediadock existe et est exécutable" {
  [ -f "${PROJECT_ROOT}/mediadock" ]
  [ -x "${PROJECT_ROOT}/mediadock" ]
}

@test "mediadock contient le shebang correct" {
  head -1 "${PROJECT_ROOT}/mediadock" | grep -q '#!/usr/bin/env bash'
}

@test "mediadock --version affiche la version" {
  run "${PROJECT_ROOT}/mediadock" --version
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"MediaDock v"* ]]
}

@test "mediadock --help affiche l'aide" {
  run "${PROJECT_ROOT}/mediadock" --help
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Usage:"* ]]
}

@test "mediadock sans argument affiche l'aide" {
  run "${PROJECT_ROOT}/mediadock"
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Usage:"* ]]
}

@test "mediadock commande inconnue retourne erreur" {
  run "${PROJECT_ROOT}/mediadock" foobar
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"inconnue"* ]]
}

@test "lib/core/ contient les 5 modules core" {
  [ -f "${PROJECT_ROOT}/lib/core/logging.sh" ]
  [ -f "${PROJECT_ROOT}/lib/core/errors.sh" ]
  [ -f "${PROJECT_ROOT}/lib/core/ssh.sh" ]
  [ -f "${PROJECT_ROOT}/lib/core/config.sh" ]
  [ -f "${PROJECT_ROOT}/lib/core/utils.sh" ]
}

@test "lib/modules/ contient les 9 modules fonctionnels" {
  [ -f "${PROJECT_ROOT}/lib/modules/hardening.sh" ]
  [ -f "${PROJECT_ROOT}/lib/modules/storage.sh" ]
  [ -f "${PROJECT_ROOT}/lib/modules/docker.sh" ]
  [ -f "${PROJECT_ROOT}/lib/modules/deploy.sh" ]
  [ -f "${PROJECT_ROOT}/lib/modules/autoconfig.sh" ]
  [ -f "${PROJECT_ROOT}/lib/modules/vpn.sh" ]
  [ -f "${PROJECT_ROOT}/lib/modules/quality.sh" ]
  [ -f "${PROJECT_ROOT}/lib/modules/backup.sh" ]
  [ -f "${PROJECT_ROOT}/lib/modules/update.sh" ]
}

@test "lib/services/ contient les 12 services" {
  [ -f "${PROJECT_ROOT}/lib/services/radarr.sh" ]
  [ -f "${PROJECT_ROOT}/lib/services/sonarr.sh" ]
  [ -f "${PROJECT_ROOT}/lib/services/prowlarr.sh" ]
  [ -f "${PROJECT_ROOT}/lib/services/qbittorrent.sh" ]
  [ -f "${PROJECT_ROOT}/lib/services/jellyseerr.sh" ]
  [ -f "${PROJECT_ROOT}/lib/services/gluetun.sh" ]
  [ -f "${PROJECT_ROOT}/lib/services/recyclarr.sh" ]
  [ -f "${PROJECT_ROOT}/lib/services/flaresolverr.sh" ]
  [ -f "${PROJECT_ROOT}/lib/services/homarr.sh" ]
  [ -f "${PROJECT_ROOT}/lib/services/emby.sh" ]
  [ -f "${PROJECT_ROOT}/lib/services/jellyfin.sh" ]
  [ -f "${PROJECT_ROOT}/lib/services/plex.sh" ]
}

@test "Répertoires templates existent" {
  [ -d "${PROJECT_ROOT}/templates/services" ]
  [ -d "${PROJECT_ROOT}/templates/configs" ]
}

@test "Répertoires tests existent" {
  [ -d "${PROJECT_ROOT}/tests/unit" ]
  [ -d "${PROJECT_ROOT}/tests/integration" ]
  [ -d "${PROJECT_ROOT}/tests/helpers" ]
}

@test "Fichiers helpers de test existent" {
  [ -f "${PROJECT_ROOT}/tests/helpers/setup.bash" ]
  [ -f "${PROJECT_ROOT}/tests/helpers/mocks.bash" ]
}

@test "Fichiers de configuration projet existent" {
  [ -f "${PROJECT_ROOT}/.env.example" ]
  [ -f "${PROJECT_ROOT}/.shellcheckrc" ]
  [ -f "${PROJECT_ROOT}/.gitignore" ]
  [ -f "${PROJECT_ROOT}/LICENSE" ]
  [ -f "${PROJECT_ROOT}/CONTRIBUTING.md" ]
  [ -f "${PROJECT_ROOT}/README.md" ]
}

@test "Workflow CI GitHub Actions existe" {
  [ -f "${PROJECT_ROOT}/.github/workflows/ci.yml" ]
}

@test "Tous les .sh ont le shebang correct" {
  local bad_files=()
  while IFS= read -r f; do
    if ! head -1 "${f}" | grep -q '#!/usr/bin/env bash'; then
      bad_files+=("${f}")
    fi
  done < <(find "${PROJECT_ROOT}/lib" -name '*.sh')
  [ ${#bad_files[@]} -eq 0 ]
}
