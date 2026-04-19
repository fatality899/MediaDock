#!/usr/bin/env bats
# Tests unitaires — Module hardening (Story 2.2)
#
# Strategie : sourcer hardening.sh en isolation avec ssh_exec stube,
# pour valider hardening_configure_ssh (idempotence, ecriture + reload,
# rollback sur echec sshd -t, traces log) sans serveur SSH reel.
#
# Persistance via fichier CALL_LOG : les tests avec `run` executent en
# sous-shell, les variables ne survivent pas mais un fichier si. Les
# codes de retour du stub sont configurables via variables d'env
# SSH_EXEC_*_RC (permet de simuler sshd -T conforme / non conforme,
# sshd -t valide / invalide, etc.).

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
  export SSH_EXEC_WRITE_RC=0            # cat > tmp && chmod && mv
  export SSH_EXEC_RELOAD_RC=0           # systemctl reload ssh
  export SSH_EXEC_RM_RC=0               # rm -f drop-in (rollback)

  # Stub ssh_exec : log la commande dans CALL_LOG et retourne un code
  # configurable selon le motif detecte. Prefixe les lignes pour grep.
  ssh_exec() {
    local cmd="$*"
    printf 'ssh_exec: %s\n' "${cmd}" >> "${CALL_LOG}"
    case "${cmd}" in
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
# AC4 — hardening_run appelle hardening_configure_ssh (plus de stub)
# ---------------------------------------------------------------------------

@test "AC4 : hardening_run appelle hardening_configure_ssh (plus de message stub)" {
  # Stubbe hardening_configure_ssh pour tracer l'appel depuis hardening_run
  hardening_configure_ssh() { echo "hardening_configure_ssh" >> "${CALL_LOG}"; }
  run hardening_run
  [ "${status}" -eq 0 ]
  grep -q '^hardening_configure_ssh$' "${CALL_LOG}"
  # Le message stub de 2.1 ne doit plus apparaitre
  [[ "${output}" != *"Hardening — stub"* ]]
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
}

@test "Contrat module : hardening.sh n'appelle pas ssh/scp direct ni eval" {
  local hardening_sh="${PROJECT_ROOT}/lib/modules/hardening.sh"
  # Pas d'eval direct (reserve a ensure_state)
  ! grep -E -q '^[^#]*\beval\b' "${hardening_sh}"
  # Pas de `ssh ` ou `scp ` non-wrappe (ssh_exec / ssh_copy OK)
  ! grep -E -q '^[^#]*(^|[^_])\bssh\b[^_]' "${hardening_sh}"
  ! grep -E -q '^[^#]*\bscp\b' "${hardening_sh}"
}
