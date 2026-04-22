#!/usr/bin/env bats
# Tests unitaires — Module hardening (Stories 2.2 + 2.3)
#
# Strategie : sourcer hardening.sh en isolation avec ssh_exec stube,
# pour valider hardening_configure_ssh (idempotence, ecriture + reload,
# rollback sur echec sshd -t, traces log) ET hardening_configure_fail2ban
# (idempotence effective, install + drop-in + enable + reload, die sans
# rollback sur echec reload, cablage hardening_run) sans serveur SSH reel.
#
# Persistance via fichier CALL_LOG : les tests avec `run` executent en
# sous-shell, les variables ne survivent pas mais un fichier si. Les
# codes de retour du stub sont configurables via variables d'env
# SSH_EXEC_*_RC (permet de simuler sshd -T conforme / non conforme,
# sshd -t valide / invalide, paquet fail2ban absent / valeurs non
# conformes, etc.).

setup() {
  _ORIG_HOME="${HOME:-}"
  TEST_HOME="$(mktemp -d)"
  export HOME="${TEST_HOME}"
  PROJECT_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  export MEDIADOCK_DIR="${PROJECT_ROOT}"
  export VERBOSE=0
  export SERVER_IP="192.0.2.1"

  CALL_LOG="${TEST_HOME}/calls.log"
  : > "${CALL_LOG}"
  export CALL_LOG

  # Dependances reelles : logging + errors + utils (ensure_state).
  # shellcheck source=../../lib/core/logging.sh
  source "${PROJECT_ROOT}/lib/core/logging.sh"
  logging_init
  # shellcheck source=../../lib/core/errors.sh
  source "${PROJECT_ROOT}/lib/core/errors.sh"
  # shellcheck source=../../lib/core/utils.sh
  source "${PROJECT_ROOT}/lib/core/utils.sh"
  # shellcheck source=../../lib/modules/hardening.sh
  source "${PROJECT_ROOT}/lib/modules/hardening.sh"

  # Codes de retour du stub par type de commande (defaut : check echoue
  # → declenche l'action ; toutes les autres operations reussissent).
  export SSH_EXEC_SSHD_T_RC=1           # sshd -T conforme ? 0=oui, 1=non
  export SSH_EXEC_SSHD_VALIDATE_RC=0    # sshd -t : 0=ok, 1=syntaxe invalide
  export SSH_EXEC_WRITE_RC=0            # cat > tmp && chmod && mv (SSH)
  export SSH_EXEC_RELOAD_RC=0           # systemctl reload ssh
  export SSH_EXEC_RM_RC=0               # rm -f drop-in (rollback SSH)

  # Stub fail2ban : defaut check echoue → action declenchee ; tout
  # le reste passe. Chaque RC pilote un sous-motif distinct.
  export SSH_EXEC_F2B_CHECK_RC=1        # dpkg -s fail2ban && ... (check chaine)
  export SSH_EXEC_F2B_UPDATE_RC=0       # apt-get update
  export SSH_EXEC_F2B_INSTALL_RC=0      # apt-get install -y ... fail2ban
  export SSH_EXEC_F2B_CAT_RC=0          # cat > /etc/fail2ban/...
  export SSH_EXEC_F2B_ENABLE_RC=0       # systemctl enable --now fail2ban
  export SSH_EXEC_F2B_TEST_RC=0         # fail2ban-client -t (pre-reload validation)
  export SSH_EXEC_F2B_RELOAD_RC=0       # fail2ban-client reload
  export SSH_EXEC_F2B_RM_RC=0           # rm -f tmp fail2ban (cleanup)

  # Stub ssh_exec : log la commande dans CALL_LOG et retourne un code
  # configurable selon le motif detecte. Les patterns fail2ban sont
  # testes AVANT les patterns SSH generiques (ex. cat > /etc/fail2ban/
  # doit matcher f2b, pas le cat SSH). `fail2ban-client -t` avant
  # `fail2ban-client reload` pour match le bon RC.
  ssh_exec() {
    local cmd="$*"
    printf 'ssh_exec: %s\n' "${cmd}" >> "${CALL_LOG}"
    case "${cmd}" in
      # --- Fail2ban (plus specifiques : ordre important) ---
      *"dpkg -s fail2ban"*)                 return "${SSH_EXEC_F2B_CHECK_RC}" ;;
      *"apt-get update"*)                   return "${SSH_EXEC_F2B_UPDATE_RC}" ;;
      *"apt-get install"*"fail2ban"*)       return "${SSH_EXEC_F2B_INSTALL_RC}" ;;
      *"systemctl enable --now fail2ban"*)  return "${SSH_EXEC_F2B_ENABLE_RC}" ;;
      *"fail2ban-client -t"*)               return "${SSH_EXEC_F2B_TEST_RC}" ;;
      *"fail2ban-client reload"*)           return "${SSH_EXEC_F2B_RELOAD_RC}" ;;
      *"cat > /etc/fail2ban/"*)             return "${SSH_EXEC_F2B_CAT_RC}" ;;
      *"rm -f /etc/fail2ban/"*)             return "${SSH_EXEC_F2B_RM_RC}" ;;

      # --- SSH hardening (existant) ---
      *"sshd -T"*)          return "${SSH_EXEC_SSHD_T_RC}" ;;
      *"sshd -t"*)          return "${SSH_EXEC_SSHD_VALIDATE_RC}" ;;
      *"systemctl reload"*) return "${SSH_EXEC_RELOAD_RC}" ;;
      *"cat > "*)          return "${SSH_EXEC_WRITE_RC}" ;;
      "rm -f "*)            return "${SSH_EXEC_RM_RC}" ;;
      *)                    return 0 ;;
    esac
  }
}

teardown() {
  rm -rf "${TEST_HOME}"
  export HOME="${_ORIG_HOME}"
  unset _ORIG_HOME MEDIADOCK_DIR VERBOSE CALL_LOG SERVER_IP
  unset SSH_EXEC_SSHD_T_RC SSH_EXEC_SSHD_VALIDATE_RC SSH_EXEC_WRITE_RC SSH_EXEC_RELOAD_RC SSH_EXEC_RM_RC
  unset SSH_EXEC_F2B_CHECK_RC SSH_EXEC_F2B_UPDATE_RC SSH_EXEC_F2B_INSTALL_RC
  unset SSH_EXEC_F2B_CAT_RC SSH_EXEC_F2B_ENABLE_RC SSH_EXEC_F2B_TEST_RC SSH_EXEC_F2B_RELOAD_RC SSH_EXEC_F2B_RM_RC
}

# ---------------------------------------------------------------------------
# AC1 — Cas nominal : check echoue → ecriture + sshd -t + reload
# ---------------------------------------------------------------------------

@test "AC1 : hardening_configure_ssh ecrit le drop-in, valide sshd -t puis reload" {
  export SSH_EXEC_SSHD_T_RC=1  # etat non conforme → action
  run hardening_configure_ssh
  [ "${status}" -eq 0 ]
  # Les 3 etapes attendues apparaissent dans CALL_LOG dans l'ordre :
  grep -q 'sshd -T' "${CALL_LOG}"
  grep -q 'ssh_exec: cat > /etc/ssh/sshd_config.d/50-mediadock-hardening.conf.tmp-' "${CALL_LOG}"
  grep -qE 'ssh_exec: sshd -t( |$)' "${CALL_LOG}"
  grep -q 'ssh_exec: systemctl reload ssh' "${CALL_LOG}"
}

@test "AC1 : le drop-in ecrit cible /etc/ssh/sshd_config.d/50-mediadock-hardening.conf avec chmod 644 puis mv atomique" {
  export SSH_EXEC_SSHD_T_RC=1
  run hardening_configure_ssh
  [ "${status}" -eq 0 ]
  # La commande d'ecriture contient : cat > tmp && chmod 644 tmp && mv -f tmp drop-in
  grep -qE 'ssh_exec: cat > /etc/ssh/sshd_config\.d/50-mediadock-hardening\.conf\.tmp-[0-9]+ && chmod 644 /etc/ssh/sshd_config\.d/50-mediadock-hardening\.conf\.tmp-[0-9]+ && mv -f /etc/ssh/sshd_config\.d/50-mediadock-hardening\.conf\.tmp-[0-9]+ /etc/ssh/sshd_config\.d/50-mediadock-hardening\.conf' "${CALL_LOG}"
}

# ---------------------------------------------------------------------------
# AC2 / AC3 — Idempotence : sshd -T conforme → aucune action
# ---------------------------------------------------------------------------

@test "AC2/AC3 : si sshd -T est deja conforme, aucune ecriture ni reload" {
  export SSH_EXEC_SSHD_T_RC=0  # etat deja conforme
  run hardening_configure_ssh
  [ "${status}" -eq 0 ]
  # Seule la commande de check doit avoir ete invoquee (contient sshd -T).
  grep -q 'sshd -T' "${CALL_LOG}"
  # AUCUNE ecriture du drop-in
  ! grep -q 'ssh_exec: cat > ' "${CALL_LOG}"
  # AUCUN sshd -t (validation de la nouvelle config).
  # Pattern : "sshd -t" suivi d'espace (futur `sshd -t -f`) ou fin de ligne.
  ! grep -qE 'ssh_exec: sshd -t( |$)' "${CALL_LOG}"
  # AUCUN systemctl reload
  ! grep -q 'ssh_exec: systemctl reload' "${CALL_LOG}"
}

# ---------------------------------------------------------------------------
# AC5 — Echec sshd -t : rollback du drop-in + die 1 (pas de reload)
# ---------------------------------------------------------------------------

@test "AC5 : si sshd -t echoue, le drop-in est supprime et die 1 est emis sans reload" {
  export SSH_EXEC_SSHD_T_RC=1         # check echoue → action
  export SSH_EXEC_SSHD_VALIDATE_RC=1  # sshd -t echoue → rollback
  run hardening_configure_ssh
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Validation sshd -t echouee"* ]]
  [[ "${output}" == *"Suggestion : Verifiez manuellement"* ]]
  # L'ecriture a eu lieu
  grep -q 'ssh_exec: cat > ' "${CALL_LOG}"
  # La validation a eu lieu
  grep -q 'ssh_exec: sshd -t' "${CALL_LOG}"
  # Le rollback (rm -f) a eu lieu
  grep -q 'ssh_exec: rm -f /etc/ssh/sshd_config.d/50-mediadock-hardening.conf' "${CALL_LOG}"
  # Aucun reload (die avant)
  ! grep -q 'ssh_exec: systemctl reload' "${CALL_LOG}"
}

# ---------------------------------------------------------------------------
# AC6 — Traces log : action + termine (cas modif) ; deja en place (idempotent)
# ---------------------------------------------------------------------------

@test "AC6 : cas modif ecrit [ACTION] Hardening SSH et [INFO] Hardening SSH : termine dans le fichier log" {
  export SSH_EXEC_SSHD_T_RC=1
  hardening_configure_ssh
  grep -q '\[ACTION\] Hardening SSH' "${LOG_FILE}"
  grep -q '\[INFO\] Hardening SSH : termine' "${LOG_FILE}"
}

@test "AC6 : cas idempotent ecrit [INFO] Hardening SSH : deja en place dans le fichier log" {
  export SSH_EXEC_SSHD_T_RC=0
  hardening_configure_ssh
  grep -q '\[INFO\] Hardening SSH : deja en place' "${LOG_FILE}"
  # En mode idempotent, pas de [ACTION] (action non emise par ensure_state)
  ! grep -q '\[ACTION\] Hardening SSH' "${LOG_FILE}"
}

@test "AC6 : en mode verbose le marqueur idempotent apparait aussi a l'ecran" {
  export SSH_EXEC_SSHD_T_RC=0
  VERBOSE=1 run hardening_configure_ssh
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"[INFO] Hardening SSH : deja en place"* ]]
}

@test "AC6 : messages sans accents (convention Epic 1)" {
  export SSH_EXEC_SSHD_T_RC=1
  export SSH_EXEC_SSHD_VALIDATE_RC=1
  run hardening_configure_ssh
  # Le message d'erreur doit etre sans accents : "echouee", pas "échouée"
  [[ "${output}" == *"echouee"* ]]
  [[ "${output}" != *"échouée"* ]]
}

# ---------------------------------------------------------------------------
# Story 2.2 AC4 + Story 2.3 AC4 — hardening_run orchestre ssh puis fail2ban
# ---------------------------------------------------------------------------

@test "Story 2.3 AC4 : hardening_run appelle ssh puis fail2ban, dans cet ordre" {
  # Stubbe les deux helpers pour tracer l'ordre d'invocation
  hardening_configure_ssh()      { echo "hardening_configure_ssh" >> "${CALL_LOG}"; }
  hardening_configure_fail2ban() { echo "hardening_configure_fail2ban" >> "${CALL_LOG}"; }
  run hardening_run
  [ "${status}" -eq 0 ]
  grep -q '^hardening_configure_ssh$' "${CALL_LOG}"
  grep -q '^hardening_configure_fail2ban$' "${CALL_LOG}"
  # Ordre : SSH en premier (ligne contenant ssh avant ligne contenant fail2ban)
  local ssh_line f2b_line
  ssh_line=$(grep -n '^hardening_configure_ssh$' "${CALL_LOG}" | cut -d: -f1)
  f2b_line=$(grep -n '^hardening_configure_fail2ban$' "${CALL_LOG}" | cut -d: -f1)
  [ "${ssh_line}" -lt "${f2b_line}" ]
  # Le message stub de 2.1 ne doit plus apparaitre
  [[ "${output}" != *"Hardening — stub"* ]]
}

# ---------------------------------------------------------------------------
# Story 2.3 AC1 — Cas nominal : check echoue → install + drop-in + enable + reload
# ---------------------------------------------------------------------------

@test "Story 2.3 AC1 : hardening_configure_fail2ban execute la sequence apt + drop-in + enable + test + reload" {
  export SSH_EXEC_F2B_CHECK_RC=1  # etat non conforme → action
  run hardening_configure_fail2ban
  [ "${status}" -eq 0 ]
  # Les 6 etapes d'action doivent apparaitre dans CALL_LOG (pas de -qq sur update)
  grep -qE 'ssh_exec: apt-get update( |$)' "${CALL_LOG}"
  grep -q 'ssh_exec: DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold fail2ban' "${CALL_LOG}"
  grep -q 'ssh_exec: cat > /etc/fail2ban/jail.d/50-mediadock.local.tmp-' "${CALL_LOG}"
  grep -q 'ssh_exec: systemctl enable --now fail2ban' "${CALL_LOG}"
  grep -qE 'ssh_exec: fail2ban-client -t( |$)' "${CALL_LOG}"
  grep -q 'ssh_exec: fail2ban-client reload' "${CALL_LOG}"
}

@test "Story 2.3 AC1 : apt-get update est invoque SANS -qq (conserve les warnings de depot)" {
  export SSH_EXEC_F2B_CHECK_RC=1
  run hardening_configure_fail2ban
  [ "${status}" -eq 0 ]
  ! grep -q 'ssh_exec: apt-get update -qq' "${CALL_LOG}"
  grep -qE 'ssh_exec: apt-get update( |$)' "${CALL_LOG}"
}

@test "Story 2.3 AC1 : fail2ban-client -t est invoque AVANT fail2ban-client reload" {
  export SSH_EXEC_F2B_CHECK_RC=1
  run hardening_configure_fail2ban
  [ "${status}" -eq 0 ]
  local test_line reload_line
  test_line=$(grep -n 'ssh_exec: fail2ban-client -t' "${CALL_LOG}" | cut -d: -f1)
  reload_line=$(grep -n 'ssh_exec: fail2ban-client reload' "${CALL_LOG}" | cut -d: -f1)
  [ -n "${test_line}" ] && [ -n "${reload_line}" ]
  [ "${test_line}" -lt "${reload_line}" ]
}

@test "Story 2.3 AC1 : le drop-in ecrit cible /etc/fail2ban/jail.d/50-mediadock.local avec chmod 644 et mv -f atomique" {
  export SSH_EXEC_F2B_CHECK_RC=1
  run hardening_configure_fail2ban
  [ "${status}" -eq 0 ]
  grep -qE 'ssh_exec: cat > /etc/fail2ban/jail\.d/50-mediadock\.local\.tmp-[0-9]+ && chmod 644 /etc/fail2ban/jail\.d/50-mediadock\.local\.tmp-[0-9]+ && mv -f /etc/fail2ban/jail\.d/50-mediadock\.local\.tmp-[0-9]+ /etc/fail2ban/jail\.d/50-mediadock\.local' "${CALL_LOG}"
}

# ---------------------------------------------------------------------------
# Story 2.3 AC2 / AC3 — Idempotence : check effectif conforme → aucune action
# ---------------------------------------------------------------------------

@test "Story 2.3 AC2/AC3 : si l'etat effectif est deja conforme, aucun apt/cat/enable/test/reload" {
  export SSH_EXEC_F2B_CHECK_RC=0  # paquet + service + jail + valeurs OK
  run hardening_configure_fail2ban
  [ "${status}" -eq 0 ]
  # La commande de check a eu lieu
  grep -q 'ssh_exec: dpkg -s fail2ban' "${CALL_LOG}"
  # AUCUNE action de modification
  ! grep -q 'ssh_exec: apt-get update' "${CALL_LOG}"
  ! grep -q 'ssh_exec: apt-get install' "${CALL_LOG}"
  ! grep -q 'ssh_exec: cat > /etc/fail2ban/' "${CALL_LOG}"
  ! grep -q 'ssh_exec: systemctl enable --now fail2ban' "${CALL_LOG}"
  ! grep -qE 'ssh_exec: fail2ban-client -t( |$)' "${CALL_LOG}"
  ! grep -q 'ssh_exec: fail2ban-client reload' "${CALL_LOG}"
}

@test "Story 2.3 AC3 : la commande de check combine paquet, service, jail et 3 valeurs effectives" {
  export SSH_EXEC_F2B_CHECK_RC=0
  run hardening_configure_fail2ban
  [ "${status}" -eq 0 ]
  # Un seul ssh_exec chaine couvre les 7 sous-checks (latence minimale)
  grep -qE 'ssh_exec: dpkg -s fail2ban.*systemctl is-active --quiet fail2ban.*systemctl is-enabled --quiet fail2ban.*fail2ban-client status sshd.*fail2ban-client get sshd maxretry.*fail2ban-client get sshd bantime.*fail2ban-client get sshd findtime' "${CALL_LOG}"
}

@test "Story 2.3 AC3 : check 1 (paquet absent) → l'action complete est declenchee" {
  export SSH_EXEC_F2B_CHECK_RC=1
  run hardening_configure_fail2ban
  [ "${status}" -eq 0 ]
  grep -qE 'ssh_exec: DEBIAN_FRONTEND=noninteractive apt-get install -y .*fail2ban' "${CALL_LOG}"
}

# ---------------------------------------------------------------------------
# Story 2.3 AC5 — Echecs : die 1 avec message + suggestion
# ---------------------------------------------------------------------------

@test "Story 2.3 AC5 : echec apt-get update → die 1 + suggestion reseau" {
  export SSH_EXEC_F2B_CHECK_RC=1
  export SSH_EXEC_F2B_UPDATE_RC=1
  run hardening_configure_fail2ban
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"apt-get update a echoue"* ]]
  [[ "${output}" == *"connectivite reseau"* ]]
  # L'install n'a pas eu lieu (die avant)
  ! grep -q 'ssh_exec: DEBIAN_FRONTEND=noninteractive apt-get install' "${CALL_LOG}"
}

@test "Story 2.3 AC5 : echec apt-get install → die 1 + suggestion apt-cache/journalctl" {
  export SSH_EXEC_F2B_CHECK_RC=1
  export SSH_EXEC_F2B_INSTALL_RC=1
  run hardening_configure_fail2ban
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Installation fail2ban echouee"* ]]
  [[ "${output}" == *"apt-cache policy fail2ban"* ]]
  [[ "${output}" == *"journalctl -xe"* ]]
  # Le cat > drop-in n'a pas eu lieu (die avant)
  ! grep -q 'ssh_exec: cat > /etc/fail2ban/' "${CALL_LOG}"
}

@test "Story 2.3 AC5 : echec ecriture drop-in → rm -f du tmp + die 1" {
  export SSH_EXEC_F2B_CHECK_RC=1
  export SSH_EXEC_F2B_CAT_RC=1
  run hardening_configure_fail2ban
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Ecriture du drop-in fail2ban echouee"* ]]
  # Nettoyage tmp tente (pas d'assertion stricte car best-effort : log_warn si rm echoue)
  grep -q 'ssh_exec: rm -f /etc/fail2ban/jail.d/50-mediadock.local.tmp-' "${CALL_LOG}"
  # Enable / reload non effectues
  ! grep -q 'ssh_exec: systemctl enable --now fail2ban' "${CALL_LOG}"
  ! grep -q 'ssh_exec: fail2ban-client reload' "${CALL_LOG}"
}

@test "Story 2.3 AC5 : echec systemctl enable → die 1 + suggestion journalctl -u fail2ban" {
  export SSH_EXEC_F2B_CHECK_RC=1
  export SSH_EXEC_F2B_ENABLE_RC=1
  run hardening_configure_fail2ban
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Activation fail2ban echouee"* ]]
  [[ "${output}" == *"systemctl status fail2ban"* ]]
  [[ "${output}" == *"journalctl -u fail2ban"* ]]
  # Le reload n'a pas eu lieu (die avant)
  ! grep -q 'ssh_exec: fail2ban-client reload' "${CALL_LOG}"
}

@test "Story 2.3 AC5 : echec fail2ban-client reload → die 1 sans rollback du drop-in" {
  export SSH_EXEC_F2B_CHECK_RC=1
  export SSH_EXEC_F2B_RELOAD_RC=1
  run hardening_configure_fail2ban
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"fail2ban-client reload a echoue"* ]]
  # Le chemin du drop-in doit etre cite dans le message ET la suggestion
  # pour guider l'admin vers le bon fichier a inspecter (§5 diagnostic).
  [[ "${output}" == *"/etc/fail2ban/jail.d/50-mediadock.local"* ]]
  [[ "${output}" == *"journalctl -u fail2ban"* ]]
  # Le drop-in a ete ecrit (mv -f vers la cible finale), enable est passe
  grep -q 'ssh_exec: cat > /etc/fail2ban/jail.d/50-mediadock.local.tmp-' "${CALL_LOG}"
  grep -q 'ssh_exec: systemctl enable --now fail2ban' "${CALL_LOG}"
  # PAS de rm -f du drop-in final (divergence volontaire vs SSH : cf. §5 story 2.3)
  ! grep -q 'ssh_exec: rm -f /etc/fail2ban/jail.d/50-mediadock.local$' "${CALL_LOG}"
}

@test "Story 2.3 AC5 : echec fail2ban-client -t → die 1 + chemin drop-in + pas de reload" {
  export SSH_EXEC_F2B_CHECK_RC=1
  export SSH_EXEC_F2B_TEST_RC=1
  run hardening_configure_fail2ban
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"fail2ban-client -t a detecte une config invalide"* ]]
  # Chemin du drop-in explicite (§5 diagnostic : garde le fichier + cite-le)
  [[ "${output}" == *"/etc/fail2ban/jail.d/50-mediadock.local"* ]]
  [[ "${output}" == *"journalctl -u fail2ban"* ]]
  # Le -t a bien eu lieu, mais le reload NON (die avant)
  grep -qE 'ssh_exec: fail2ban-client -t( |$)' "${CALL_LOG}"
  ! grep -q 'ssh_exec: fail2ban-client reload' "${CALL_LOG}"
  # Le drop-in reste en place (§5 : pas de rollback sur echec de test)
  ! grep -q 'ssh_exec: rm -f /etc/fail2ban/jail.d/50-mediadock.local$' "${CALL_LOG}"
}

@test "Story 2.3 AC5 : SERVER_IP non defini → message utilise le fallback 'serveur'" {
  unset SERVER_IP
  export SSH_EXEC_F2B_CHECK_RC=1
  export SSH_EXEC_F2B_RELOAD_RC=1
  run hardening_configure_fail2ban
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"sur serveur"* ]]
}

# ---------------------------------------------------------------------------
# Story 2.3 AC6 — Traces log et convention sans accents
# ---------------------------------------------------------------------------

@test "Story 2.3 AC6 : cas modif ecrit [ACTION] Hardening fail2ban et [INFO] termine" {
  export SSH_EXEC_F2B_CHECK_RC=1
  hardening_configure_fail2ban
  grep -q '\[ACTION\] Hardening fail2ban' "${LOG_FILE}"
  grep -q '\[INFO\] Hardening fail2ban : termine' "${LOG_FILE}"
}

@test "Story 2.3 AC6 : cas idempotent ecrit [INFO] Hardening fail2ban : deja en place" {
  export SSH_EXEC_F2B_CHECK_RC=0
  hardening_configure_fail2ban
  grep -q '\[INFO\] Hardening fail2ban : deja en place' "${LOG_FILE}"
  ! grep -q '\[ACTION\] Hardening fail2ban' "${LOG_FILE}"
}

@test "Story 2.3 AC6 : mode verbose affiche le marqueur idempotent a l'ecran" {
  export SSH_EXEC_F2B_CHECK_RC=0
  VERBOSE=1 run hardening_configure_fail2ban
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"[INFO] Hardening fail2ban : deja en place"* ]]
}

@test "Story 2.3 AC6 : mode verbose affiche le marqueur 'termine' du chemin modifiant a l'ecran" {
  export SSH_EXEC_F2B_CHECK_RC=1
  VERBOSE=1 run hardening_configure_fail2ban
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"[INFO] Hardening fail2ban : termine"* ]]
}

@test "Story 2.3 AC6 : messages sans accents (convention Epic 1)" {
  export SSH_EXEC_F2B_CHECK_RC=1
  export SSH_EXEC_F2B_INSTALL_RC=1
  run hardening_configure_fail2ban
  [[ "${output}" == *"echouee"* ]]
  [[ "${output}" != *"échouée"* ]]
  [[ "${output}" != *"échoué"* ]]
}

# ---------------------------------------------------------------------------
# Contrat module : shebang, header, pas d'eval/ssh direct hors helpers
# ---------------------------------------------------------------------------

@test "Contrat module : hardening.sh respecte shebang, header, definitions" {
  local hardening_sh="${PROJECT_ROOT}/lib/modules/hardening.sh"
  head -1 "${hardening_sh}" | grep -q '#!/usr/bin/env bash'
  grep -q '^# Module: hardening' "${hardening_sh}"
  declare -F hardening_run >/dev/null
  declare -F hardening_configure_ssh >/dev/null
  declare -F _hardening_check_ssh_hardened >/dev/null
  declare -F _hardening_write_ssh_drop_in >/dev/null
  # Story 2.3 : helpers fail2ban
  declare -F hardening_configure_fail2ban >/dev/null
  declare -F _hardening_check_fail2ban_active >/dev/null
  declare -F _hardening_install_and_configure_fail2ban >/dev/null
}

@test "Contrat module : hardening.sh n'appelle pas ssh/scp direct ni eval" {
  local hardening_sh="${PROJECT_ROOT}/lib/modules/hardening.sh"
  # Pas d'eval direct (reserve a ensure_state)
  ! grep -E -q '^[^#]*\beval\b' "${hardening_sh}"
  # Pas de `ssh ` ou `scp ` non-wrappe (ssh_exec / ssh_copy OK)
  ! grep -E -q '^[^#]*(^|[^_])\bssh\b[^_]' "${hardening_sh}"
  ! grep -E -q '^[^#]*\bscp\b' "${hardening_sh}"
}
