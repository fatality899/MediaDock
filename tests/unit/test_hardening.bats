#!/usr/bin/env bats
# Tests unitaires — Module hardening (Stories 2.2 + 2.3 + 2.4 + 2.5)
#
# Strategie : sourcer hardening.sh en isolation avec ssh_exec stube,
# pour valider hardening_configure_ssh (idempotence, ecriture + reload,
# rollback sur echec sshd -t, traces log), hardening_configure_fail2ban
# (idempotence effective, install + drop-in + enable + reload, die sans
# rollback sur echec reload), hardening_configure_ufw (idempotence, 7
# etapes install + regles LAN, invariant allow 22/tcp AVANT --force enable)
# ET hardening_configure_auto_updates (idempotence via etat effectif, 5
# etapes install + drop-in + dry-run + enable timers, pas de rollback
# destructif, cablage hardening_run a 4 helpers), sans serveur SSH reel.
#
# Persistance via fichier CALL_LOG : les tests avec `run` executent en
# sous-shell, les variables ne survivent pas mais un fichier si. Les
# codes de retour du stub sont configurables via variables d'env
# SSH_EXEC_*_RC (permet de simuler sshd -T conforme / non conforme,
# sshd -t valide / invalide, paquet fail2ban absent / valeurs non
# conformes, paquet ufw absent / regles UFW en echec, paquet unattended
# absent / dry-run KO / enable timers KO, etc.). Capture de stdin du stub
# via CAT_STDIN_LOG pour verifier le contenu du drop-in UU (Story 2.5).

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

  # Story 2.5 : capture du stdin transmis au stub ssh_exec sur les commandes
  # `cat > ...`. Permet de verifier le contenu EXACT du drop-in UU envoye au
  # serveur (tests AC1 3.6 : littéral ${distro_codename} + 5 directives).
  CAT_STDIN_LOG="${TEST_HOME}/cat_stdin.log"
  : > "${CAT_STDIN_LOG}"
  export CAT_STDIN_LOG

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
  export SSH_EXEC_F2B_UPDATE_RC=0       # apt-get update (partage UFW/F2B - voir stub)
  export SSH_EXEC_F2B_INSTALL_RC=0      # apt-get install -y ... fail2ban
  export SSH_EXEC_F2B_CAT_RC=0          # cat > /etc/fail2ban/...
  export SSH_EXEC_F2B_ENABLE_RC=0       # systemctl enable --now fail2ban
  export SSH_EXEC_F2B_TEST_RC=0         # fail2ban-client -t (pre-reload validation)
  export SSH_EXEC_F2B_RELOAD_RC=0       # fail2ban-client reload
  export SSH_EXEC_F2B_RM_RC=0           # rm -f tmp fail2ban (cleanup)

  # Stub UFW (Story 2.4) : defaut check echoue → action declenchee.
  # Le check UFW commence par `dpkg -s ufw` (matche UFW_CHECK_RC avant f2b).
  # `apt-get update` est partage avec fail2ban (meme commande, meme pattern) :
  # le stub priorise UFW_UPDATE_RC si non-nul, sinon tombe sur F2B_UPDATE_RC.
  export SSH_EXEC_UFW_CHECK_RC=1        # dpkg -s ufw && ... (check chaine UFW)
  export SSH_EXEC_UFW_UPDATE_RC=0       # apt-get update (priorise sur F2B si !=0)
  export SSH_EXEC_UFW_INSTALL_RC=0      # apt-get install -y ... ufw
  export SSH_EXEC_UFW_DEFAULT_RC=0      # ufw default deny incoming && ... && deny routed
  export SSH_EXEC_UFW_ALLOW_SSH_RC=0    # ufw allow 22/tcp (invariant anti-lockout)
  export SSH_EXEC_UFW_ALLOW_LAN_RC=0    # set -e; ufw allow from <CIDR> ... (30 regles)
  export SSH_EXEC_UFW_ENABLE_RC=0       # ufw --force enable
  export SSH_EXEC_UFW_SYSTEMCTL_RC=0    # systemctl enable ufw

  # Stub unattended-upgrades (Story 2.5) : defaut check echoue → action.
  # Patterns UU places AVANT UFW dans le case pour eviter les collisions
  # (ex: `apt-get install ... unattended-upgrades` doit matcher UU avant
  # que `apt-get install ... ufw` ne fasse fallback sur UFW). Collision
  # `apt-get update` partagee UFW+F2B+UU : priorite UU_UPDATE_RC → UFW_UPDATE_RC
  # → F2B_UPDATE_RC (premier non-nul gagne).
  export SSH_EXEC_UU_CHECK_RC=1         # dpkg -s unattended-upgrades && ... (check chaine UU)
  export SSH_EXEC_UU_UPDATE_RC=0        # apt-get update (priorise sur UFW/F2B si !=0)
  export SSH_EXEC_UU_INSTALL_RC=0       # apt-get install -y ... unattended-upgrades
  export SSH_EXEC_UU_CAT_RC=0           # cat > /etc/apt/apt.conf.d/...tmp-$$ && chmod && mv
  export SSH_EXEC_UU_DRYRUN_RC=0        # unattended-upgrade --dry-run --debug
  export SSH_EXEC_UU_TIMERS_RC=0        # systemctl enable --now apt-daily.timer apt-daily-upgrade.timer
  export SSH_EXEC_UU_RM_RC=0            # rm -f /etc/apt/apt.conf.d/...tmp (cleanup echec etape 3)

  # Stub ssh_exec : log la commande dans CALL_LOG et retourne un code
  # configurable selon le motif detecte. Ordre de matching critique
  # (convention Story 2.5 §9.3) :
  #   1. UU d'abord (patterns specifiques unattended-upgrades)
  #   2. UFW
  #   3. Fail2ban
  #   4. SSH en dernier
  #   5. Fallback
  # Patterns UU places en tete pour eviter les collisions (ex:
  # `apt-get install ... unattended-upgrades` matche UU avant que UFW/F2B
  # ne prennent la main). Collision `apt-get update` partagee 3 modules :
  # priorite UU_UPDATE_RC → UFW_UPDATE_RC → F2B_UPDATE_RC (premier non-nul).
  #
  # Capture stdin : quand la commande matche `*"cat > "*`, on consomme
  # stdin et on le persiste dans CAT_STDIN_LOG pour verifier le contenu
  # du drop-in transmis au serveur (tests AC1 Story 2.5).
  ssh_exec() {
    local cmd="$*"
    printf 'ssh_exec: %s\n' "${cmd}" >> "${CALL_LOG}"

    # Capture stdin pour les commandes `cat > ...` (Story 2.5 AC1 3.6).
    # Meme si le test ne pipe rien, le `cat` consomme juste un stdin vide.
    if [[ "${cmd}" == *"cat > "* ]]; then
      cat >> "${CAT_STDIN_LOG}"
    fi

    case "${cmd}" in
      # --- unattended-upgrades (Story 2.5, places en tete) ---
      *"dpkg -s unattended-upgrades"*)        return "${SSH_EXEC_UU_CHECK_RC}" ;;
      *"apt-get install"*"unattended-upgrades"*) return "${SSH_EXEC_UU_INSTALL_RC}" ;;
      *"cat > /etc/apt/apt.conf.d/"*)         return "${SSH_EXEC_UU_CAT_RC}" ;;
      *"unattended-upgrade --dry-run"*)       return "${SSH_EXEC_UU_DRYRUN_RC}" ;;
      *"systemctl enable --now apt-daily"*)   return "${SSH_EXEC_UU_TIMERS_RC}" ;;
      *"rm -f /etc/apt/apt.conf.d/"*)         return "${SSH_EXEC_UU_RM_RC}" ;;

      # --- UFW (Story 2.4) ---
      *"dpkg -s ufw"*)                          return "${SSH_EXEC_UFW_CHECK_RC}" ;;
      *"apt-get install"*"ufw"*)                return "${SSH_EXEC_UFW_INSTALL_RC}" ;;
      *"ufw default"*)                          return "${SSH_EXEC_UFW_DEFAULT_RC}" ;;
      *"ufw allow 22/tcp"*)                     return "${SSH_EXEC_UFW_ALLOW_SSH_RC}" ;;
      *"ufw allow from"*)                       return "${SSH_EXEC_UFW_ALLOW_LAN_RC}" ;;
      *"ufw --force enable"*)                   return "${SSH_EXEC_UFW_ENABLE_RC}" ;;
      *"systemctl enable ufw"*)                 return "${SSH_EXEC_UFW_SYSTEMCTL_RC}" ;;

      # --- Fail2ban ---
      *"dpkg -s fail2ban"*)                 return "${SSH_EXEC_F2B_CHECK_RC}" ;;
      # apt-get update partage UU+UFW+F2B : priorite UU → UFW → F2B (premier non-nul).
      *"apt-get update"*)
        if [ "${SSH_EXEC_UU_UPDATE_RC:-0}" -ne 0 ]; then
          return "${SSH_EXEC_UU_UPDATE_RC}"
        fi
        if [ "${SSH_EXEC_UFW_UPDATE_RC:-0}" -ne 0 ]; then
          return "${SSH_EXEC_UFW_UPDATE_RC}"
        fi
        return "${SSH_EXEC_F2B_UPDATE_RC}"
        ;;
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
  unset _ORIG_HOME MEDIADOCK_DIR VERBOSE CALL_LOG CAT_STDIN_LOG SERVER_IP
  unset SSH_EXEC_SSHD_T_RC SSH_EXEC_SSHD_VALIDATE_RC SSH_EXEC_WRITE_RC SSH_EXEC_RELOAD_RC SSH_EXEC_RM_RC
  unset SSH_EXEC_F2B_CHECK_RC SSH_EXEC_F2B_UPDATE_RC SSH_EXEC_F2B_INSTALL_RC
  unset SSH_EXEC_F2B_CAT_RC SSH_EXEC_F2B_ENABLE_RC SSH_EXEC_F2B_TEST_RC SSH_EXEC_F2B_RELOAD_RC SSH_EXEC_F2B_RM_RC
  unset SSH_EXEC_UFW_CHECK_RC SSH_EXEC_UFW_UPDATE_RC SSH_EXEC_UFW_INSTALL_RC
  unset SSH_EXEC_UFW_DEFAULT_RC SSH_EXEC_UFW_ALLOW_SSH_RC SSH_EXEC_UFW_ALLOW_LAN_RC
  unset SSH_EXEC_UFW_ENABLE_RC SSH_EXEC_UFW_SYSTEMCTL_RC
  unset SSH_EXEC_UU_CHECK_RC SSH_EXEC_UU_UPDATE_RC SSH_EXEC_UU_INSTALL_RC
  unset SSH_EXEC_UU_CAT_RC SSH_EXEC_UU_DRYRUN_RC SSH_EXEC_UU_TIMERS_RC SSH_EXEC_UU_RM_RC
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
# Story 2.5 AC4 — hardening_run orchestre ssh -> fail2ban -> ufw -> auto_updates
# (etend le Story 2.4 AC4 a 4 helpers, clot l'epic hardening : aucun TODO 2.5)
# ---------------------------------------------------------------------------

@test "Story 2.5 AC4 : hardening_run appelle ssh puis fail2ban puis ufw puis auto_updates, dans cet ordre" {
  # Stubbe les quatre helpers pour tracer l'ordre d'invocation
  hardening_configure_ssh()          { echo "hardening_configure_ssh" >> "${CALL_LOG}"; }
  hardening_configure_fail2ban()     { echo "hardening_configure_fail2ban" >> "${CALL_LOG}"; }
  hardening_configure_ufw()          { echo "hardening_configure_ufw" >> "${CALL_LOG}"; }
  hardening_configure_auto_updates() { echo "hardening_configure_auto_updates" >> "${CALL_LOG}"; }
  run hardening_run
  [ "${status}" -eq 0 ]
  grep -q '^hardening_configure_ssh$' "${CALL_LOG}"
  grep -q '^hardening_configure_fail2ban$' "${CALL_LOG}"
  grep -q '^hardening_configure_ufw$' "${CALL_LOG}"
  grep -q '^hardening_configure_auto_updates$' "${CALL_LOG}"
  # Ordre strict : SSH -> fail2ban -> UFW -> auto_updates
  local ssh_line f2b_line ufw_line uu_line
  ssh_line=$(grep -n '^hardening_configure_ssh$' "${CALL_LOG}" | cut -d: -f1)
  f2b_line=$(grep -n '^hardening_configure_fail2ban$' "${CALL_LOG}" | cut -d: -f1)
  ufw_line=$(grep -n '^hardening_configure_ufw$' "${CALL_LOG}" | cut -d: -f1)
  uu_line=$(grep -n '^hardening_configure_auto_updates$' "${CALL_LOG}" | cut -d: -f1)
  [ "${ssh_line}" -lt "${f2b_line}" ]
  [ "${f2b_line}" -lt "${ufw_line}" ]
  [ "${ufw_line}" -lt "${uu_line}" ]
  # Le message stub de 2.1 ne doit plus apparaitre
  [[ "${output}" != *"Hardening — stub"* ]]
}

@test "Story 2.5 AC4 : aucun '# TODO Story 2.5' ne subsiste dans hardening.sh" {
  local hardening_sh="${PROJECT_ROOT}/lib/modules/hardening.sh"
  # Epic 2 hardening clos : plus de TODO 2.5 apres implementation.
  ! grep -qE '^[^#]*#[[:space:]]*TODO[[:space:]]+Story[[:space:]]+2\.5' "${hardening_sh}"
  ! grep -qE '#[[:space:]]*TODO[[:space:]]+Story[[:space:]]+2\.5[[:space:]]*:[[:space:]]*hardening_configure_auto_updates' "${hardening_sh}"
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

# ===========================================================================
# STORY 2.4 — Firewall UFW
# ===========================================================================

# ---------------------------------------------------------------------------
# Story 2.4 AC1 — Cas nominal : check echoue -> 7 etapes (update, install,
# default x3, allow 22/tcp, allow from CIDR x ports, --force enable,
# systemctl enable ufw) dans l'ordre
# ---------------------------------------------------------------------------

@test "Story 2.4 AC1 : hardening_configure_ufw execute les 7 etapes dans l'ordre" {
  export SSH_EXEC_UFW_CHECK_RC=1  # etat non conforme -> action
  run hardening_configure_ufw
  [ "${status}" -eq 0 ]
  # Les 7 etapes attendues apparaissent dans CALL_LOG
  grep -qE 'ssh_exec: apt-get update( |$)' "${CALL_LOG}"
  grep -q 'ssh_exec: DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold ufw' "${CALL_LOG}"
  grep -q 'ssh_exec: ufw default deny incoming && ufw default allow outgoing && ufw default deny routed' "${CALL_LOG}"
  grep -q 'ssh_exec: ufw allow 22/tcp' "${CALL_LOG}"
  grep -q 'ssh_exec: set -e; ufw allow from ' "${CALL_LOG}"
  grep -q 'ssh_exec: ufw --force enable' "${CALL_LOG}"
  grep -q 'ssh_exec: systemctl enable ufw' "${CALL_LOG}"
}

@test "Story 2.4 AC1 (INVARIANT ANTI-LOCKOUT) : ufw allow 22/tcp AVANT ufw --force enable" {
  export SSH_EXEC_UFW_CHECK_RC=1
  run hardening_configure_ufw
  [ "${status}" -eq 0 ]
  # Comparaison de numeros de lignes : allow SSH doit etre STRICTEMENT avant enable.
  local allow_ssh_line enable_line
  allow_ssh_line=$(grep -n 'ssh_exec: ufw allow 22/tcp' "${CALL_LOG}" | cut -d: -f1)
  enable_line=$(grep -n 'ssh_exec: ufw --force enable' "${CALL_LOG}" | cut -d: -f1)
  [ -n "${allow_ssh_line}" ] && [ -n "${enable_line}" ]
  [ "${allow_ssh_line}" -lt "${enable_line}" ]
}

@test "Story 2.4 AC1 : toutes les 30 regles LAN (3 CIDRs x 10 ports) sont presentes" {
  export SSH_EXEC_UFW_CHECK_RC=1
  run hardening_configure_ufw
  [ "${status}" -eq 0 ]
  # Les 30 regles sont concatenees dans UN seul ssh_exec (set -e; ufw allow ...).
  # On extrait la ligne CALL_LOG correspondante et on verifie chaque combinaison.
  local cidr port
  for cidr in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
    for port in 7878 8989 9696 8080 5055 8191 7575 8888 8096 32400; do
      grep -qF "ufw allow from ${cidr} to any port ${port} proto tcp" "${CALL_LOG}" \
        || { echo "Regle manquante : ${cidr}:${port}"; return 1; }
    done
  done
}

@test "Story 2.4 AC1 : apt-get install ufw utilise --force-conf{def,old} (heritage patch 2.3)" {
  export SSH_EXEC_UFW_CHECK_RC=1
  run hardening_configure_ufw
  [ "${status}" -eq 0 ]
  grep -q '\-o Dpkg::Options::=--force-confdef' "${CALL_LOG}"
  grep -q '\-o Dpkg::Options::=--force-confold' "${CALL_LOG}"
}

@test "Story 2.4 AC1 : apt-get update est invoque SANS -qq (heritage patch 2.3)" {
  export SSH_EXEC_UFW_CHECK_RC=1
  run hardening_configure_ufw
  [ "${status}" -eq 0 ]
  # Vu que -qq n'est jamais passe par UFW ni F2B (coherence patch 2.3)
  ! grep -q 'ssh_exec: apt-get update -qq' "${CALL_LOG}"
  grep -qE 'ssh_exec: apt-get update( |$)' "${CALL_LOG}"
}

# ---------------------------------------------------------------------------
# Story 2.4 AC2 / AC3 — Idempotence : check effectif conforme -> aucune action
# ---------------------------------------------------------------------------

@test "Story 2.4 AC2/AC3 : si l'etat effectif est deja conforme, aucune action (pas d'apt/ufw/systemctl)" {
  export SSH_EXEC_UFW_CHECK_RC=0  # paquet + service + statut + regles OK
  run hardening_configure_ufw
  [ "${status}" -eq 0 ]
  # Le check a eu lieu
  grep -q 'ssh_exec: dpkg -s ufw' "${CALL_LOG}"
  # AUCUNE action de modification
  ! grep -qE 'ssh_exec: apt-get update( |$)' "${CALL_LOG}"
  ! grep -q 'ssh_exec: DEBIAN_FRONTEND=noninteractive apt-get install' "${CALL_LOG}"
  ! grep -q 'ssh_exec: ufw default' "${CALL_LOG}"
  ! grep -q 'ssh_exec: ufw allow 22/tcp' "${CALL_LOG}"
  ! grep -q 'ssh_exec: ufw allow from' "${CALL_LOG}"
  ! grep -q 'ssh_exec: ufw --force enable' "${CALL_LOG}"
  ! grep -q 'ssh_exec: systemctl enable ufw' "${CALL_LOG}"
}

@test "Story 2.4 AC3 : la commande de check combine paquet + service + statut + default + allow SSH + regles LAN" {
  export SSH_EXEC_UFW_CHECK_RC=0
  run hardening_configure_ufw
  [ "${status}" -eq 0 ]
  # Un seul ssh_exec chaine couvre les 8 sous-categories + 30 regles LAN.
  # Assertion sur les elements critiques (pas les 30 regles LAN pour rester concis) :
  grep -qE 'ssh_exec: dpkg -s ufw.*systemctl is-active --quiet ufw.*systemctl is-enabled --quiet ufw.*ufw status verbose.*Status: active.*Default: deny.*incoming.*deny.*routed.*ufw status.*22/tcp' "${CALL_LOG}"
}

@test "Story 2.4 AC3 : la commande de check inclut les 30 regles LAN (port x CIDR)" {
  export SSH_EXEC_UFW_CHECK_RC=0
  run hardening_configure_ufw
  [ "${status}" -eq 0 ]
  # Le check chaine contient chaque combinaison port x CIDR. Sondage representatif :
  # 1er port (7878) x 1er CIDR (10.0.0.0/8), dernier port (32400) x dernier CIDR (192.168.0.0/16).
  grep -qE 'ssh_exec: dpkg -s ufw.*7878/tcp.*ALLOW.*10\\\.0\\\.0\\\.0/8' "${CALL_LOG}"
  grep -qE 'ssh_exec: dpkg -s ufw.*32400/tcp.*ALLOW.*192\\\.168\\\.0\\\.0/16' "${CALL_LOG}"
}

@test "Story 2.4 AC3 : check 1 (paquet absent) -> l'action complete est declenchee" {
  export SSH_EXEC_UFW_CHECK_RC=1
  run hardening_configure_ufw
  [ "${status}" -eq 0 ]
  grep -q 'ssh_exec: DEBIAN_FRONTEND=noninteractive apt-get install -y' "${CALL_LOG}"
  grep -q 'ssh_exec: ufw --force enable' "${CALL_LOG}"
}

# ---------------------------------------------------------------------------
# Story 2.4 AC5 — Echecs : die 1 + suggestion ciblee par etape
# ---------------------------------------------------------------------------

@test "Story 2.4 AC5 : echec apt-get update -> die 1 + suggestion reseau ; pas d'install" {
  export SSH_EXEC_UFW_CHECK_RC=1
  export SSH_EXEC_UFW_UPDATE_RC=1
  run hardening_configure_ufw
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"apt-get update a echoue avant installation ufw"* ]]
  [[ "${output}" == *"connectivite reseau"* ]]
  ! grep -q 'ssh_exec: DEBIAN_FRONTEND=noninteractive apt-get install' "${CALL_LOG}"
}

@test "Story 2.4 AC5 : echec apt-get install ufw -> die 1 + suggestion apt-cache/journalctl ; pas de ufw default" {
  export SSH_EXEC_UFW_CHECK_RC=1
  export SSH_EXEC_UFW_INSTALL_RC=1
  run hardening_configure_ufw
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Installation ufw echouee"* ]]
  [[ "${output}" == *"apt-cache policy ufw"* ]]
  [[ "${output}" == *"journalctl -xe"* ]]
  ! grep -q 'ssh_exec: ufw default' "${CALL_LOG}"
}

@test "Story 2.4 AC5 : echec ufw default -> die 1 ; pas d'allow 22/tcp" {
  export SSH_EXEC_UFW_CHECK_RC=1
  export SSH_EXEC_UFW_DEFAULT_RC=1
  run hardening_configure_ufw
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Configuration des politiques par defaut UFW echouee"* ]]
  [[ "${output}" == *"ufw status verbose"* ]]
  ! grep -q 'ssh_exec: ufw allow 22/tcp' "${CALL_LOG}"
}

@test "Story 2.4 AC5 (INVARIANT) : echec ufw allow 22/tcp -> die 1 ET PAS de ufw --force enable" {
  export SSH_EXEC_UFW_CHECK_RC=1
  export SSH_EXEC_UFW_ALLOW_SSH_RC=1
  run hardening_configure_ufw
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Autorisation SSH via UFW echouee"* ]]
  [[ "${output}" == *"ufw allow 22/tcp"* ]]
  # INVARIANT CRITIQUE ANTI-LOCKOUT : jamais d'enable sans allow 22/tcp
  grep -q 'ssh_exec: ufw allow 22/tcp' "${CALL_LOG}"
  ! grep -q 'ssh_exec: ufw --force enable' "${CALL_LOG}"
  ! grep -q 'ssh_exec: systemctl enable ufw' "${CALL_LOG}"
}

@test "Story 2.4 AC5 : echec regles LAN (set -e; ufw allow from ...) -> die 1 ; pas de --force enable" {
  export SSH_EXEC_UFW_CHECK_RC=1
  export SSH_EXEC_UFW_ALLOW_LAN_RC=1
  run hardening_configure_ufw
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Ajout des regles UFW LAN echoue"* ]]
  # L'allow SSH a eu lieu, mais l'enable non (die avant)
  grep -q 'ssh_exec: ufw allow 22/tcp' "${CALL_LOG}"
  ! grep -q 'ssh_exec: ufw --force enable' "${CALL_LOG}"
}

@test "Story 2.4 AC5 : echec ufw --force enable -> die 1 + suggestion journalctl/iptables" {
  export SSH_EXEC_UFW_CHECK_RC=1
  export SSH_EXEC_UFW_ENABLE_RC=1
  run hardening_configure_ufw
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"ufw --force enable a echoue"* ]]
  [[ "${output}" == *"journalctl -u ufw"* ]]
  [[ "${output}" == *"iptables -L -n -v"* ]]
  # SSH est autorise (etape 4 passee) : pas de coupure de session
  grep -q 'ssh_exec: ufw allow 22/tcp' "${CALL_LOG}"
  # Le systemctl enable ufw n'a pas eu lieu (die avant)
  ! grep -q 'ssh_exec: systemctl enable ufw' "${CALL_LOG}"
}

@test "Story 2.4 AC5 : echec systemctl enable ufw -> die 1 + suggestion systemctl status" {
  export SSH_EXEC_UFW_CHECK_RC=1
  export SSH_EXEC_UFW_SYSTEMCTL_RC=1
  run hardening_configure_ufw
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Activation persistance UFW au boot echouee"* ]]
  [[ "${output}" == *"systemctl status ufw"* ]]
  # UFW est deja actif (etape 6 passee) : pas de ufw disable pour revenir en arriere
  grep -q 'ssh_exec: ufw --force enable' "${CALL_LOG}"
}

@test "Story 2.4 AC5 : SERVER_IP non defini -> message utilise le fallback 'serveur'" {
  unset SERVER_IP
  export SSH_EXEC_UFW_CHECK_RC=1
  export SSH_EXEC_UFW_ENABLE_RC=1
  run hardening_configure_ufw
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"sur serveur"* ]]
}

# ---------------------------------------------------------------------------
# Story 2.4 AC6 — Traces log et convention sans accents
# ---------------------------------------------------------------------------

@test "Story 2.4 AC6 : cas modif ecrit [ACTION] Hardening UFW et [INFO] Hardening UFW : termine" {
  export SSH_EXEC_UFW_CHECK_RC=1
  hardening_configure_ufw
  grep -q '\[ACTION\] Hardening UFW' "${LOG_FILE}"
  grep -q '\[INFO\] Hardening UFW : termine' "${LOG_FILE}"
}

@test "Story 2.4 AC6 : cas idempotent ecrit [INFO] Hardening UFW : deja en place" {
  export SSH_EXEC_UFW_CHECK_RC=0
  hardening_configure_ufw
  grep -q '\[INFO\] Hardening UFW : deja en place' "${LOG_FILE}"
  ! grep -q '\[ACTION\] Hardening UFW' "${LOG_FILE}"
}

@test "Story 2.4 AC6 : mode verbose affiche le marqueur idempotent a l'ecran" {
  export SSH_EXEC_UFW_CHECK_RC=0
  VERBOSE=1 run hardening_configure_ufw
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"[INFO] Hardening UFW : deja en place"* ]]
}

@test "Story 2.4 AC6 : mode verbose affiche le marqueur 'termine' du chemin modifiant a l'ecran" {
  export SSH_EXEC_UFW_CHECK_RC=1
  VERBOSE=1 run hardening_configure_ufw
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"[INFO] Hardening UFW : termine"* ]]
}

@test "Story 2.4 AC6 : messages sans accents (convention Epic 1)" {
  export SSH_EXEC_UFW_CHECK_RC=1
  export SSH_EXEC_UFW_INSTALL_RC=1
  run hardening_configure_ufw
  [[ "${output}" == *"echouee"* ]]
  [[ "${output}" != *"échouée"* ]]
  [[ "${output}" != *"échoué"* ]]
}

# ===========================================================================
# STORY 2.5 — Mises a jour de securite automatiques (unattended-upgrades)
# ===========================================================================

# ---------------------------------------------------------------------------
# Story 2.5 AC1 — Cas nominal : check echoue -> 5 etapes (update, install,
# cat/chmod/mv drop-in, dry-run, enable --now timers) dans l'ordre
# ---------------------------------------------------------------------------

@test "Story 2.5 AC1 : hardening_configure_auto_updates execute les 5 etapes dans l'ordre" {
  export SSH_EXEC_UU_CHECK_RC=1  # etat non conforme -> action
  run hardening_configure_auto_updates
  [ "${status}" -eq 0 ]
  # Les 5 etapes attendues apparaissent dans CALL_LOG
  grep -qE 'ssh_exec: apt-get update( |$)' "${CALL_LOG}"
  grep -q 'ssh_exec: DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold unattended-upgrades' "${CALL_LOG}"
  grep -q 'ssh_exec: cat > /etc/apt/apt.conf.d/52mediadock-unattended-upgrades.tmp-' "${CALL_LOG}"
  grep -q 'ssh_exec: unattended-upgrade --dry-run --debug' "${CALL_LOG}"
  grep -q 'ssh_exec: systemctl enable --now apt-daily.timer apt-daily-upgrade.timer' "${CALL_LOG}"
  # Ordre strict : update < install < cat/mv < dry-run < enable timers
  local update_line install_line cat_line dryrun_line timers_line
  update_line=$(grep -nE 'ssh_exec: apt-get update( |$)' "${CALL_LOG}" | head -1 | cut -d: -f1)
  install_line=$(grep -n 'ssh_exec: DEBIAN_FRONTEND=noninteractive apt-get install -y .*unattended-upgrades' "${CALL_LOG}" | cut -d: -f1)
  cat_line=$(grep -n 'ssh_exec: cat > /etc/apt/apt.conf.d/52mediadock-unattended-upgrades.tmp-' "${CALL_LOG}" | cut -d: -f1)
  dryrun_line=$(grep -n 'ssh_exec: unattended-upgrade --dry-run --debug' "${CALL_LOG}" | cut -d: -f1)
  timers_line=$(grep -n 'ssh_exec: systemctl enable --now apt-daily.timer apt-daily-upgrade.timer' "${CALL_LOG}" | cut -d: -f1)
  [ "${update_line}" -lt "${install_line}" ]
  [ "${install_line}" -lt "${cat_line}" ]
  [ "${cat_line}" -lt "${dryrun_line}" ]
  [ "${dryrun_line}" -lt "${timers_line}" ]
}

@test "Story 2.5 AC1 : apt-get install utilise --force-conf{def,old} (heritage patch 2.3)" {
  export SSH_EXEC_UU_CHECK_RC=1
  run hardening_configure_auto_updates
  [ "${status}" -eq 0 ]
  grep -q '\-o Dpkg::Options::=--force-confdef' "${CALL_LOG}"
  grep -q '\-o Dpkg::Options::=--force-confold' "${CALL_LOG}"
}

@test "Story 2.5 AC1 : apt-get update est invoque SANS -qq (heritage patch 2.3)" {
  export SSH_EXEC_UU_CHECK_RC=1
  run hardening_configure_auto_updates
  [ "${status}" -eq 0 ]
  ! grep -q 'ssh_exec: apt-get update -qq' "${CALL_LOG}"
  grep -qE 'ssh_exec: apt-get update( |$)' "${CALL_LOG}"
}

@test "Story 2.5 AC1 : le drop-in cible /etc/apt/apt.conf.d/52mediadock-unattended-upgrades avec chmod 644 et mv -f atomique" {
  export SSH_EXEC_UU_CHECK_RC=1
  run hardening_configure_auto_updates
  [ "${status}" -eq 0 ]
  grep -qE 'ssh_exec: cat > /etc/apt/apt\.conf\.d/52mediadock-unattended-upgrades\.tmp-[0-9]+ && chmod 644 /etc/apt/apt\.conf\.d/52mediadock-unattended-upgrades\.tmp-[0-9]+ && mv -f /etc/apt/apt\.conf\.d/52mediadock-unattended-upgrades\.tmp-[0-9]+ /etc/apt/apt\.conf\.d/52mediadock-unattended-upgrades' "${CALL_LOG}"
}

@test "Story 2.5 AC1 : le contenu du drop-in transmis contient les 5 directives attendues" {
  export SSH_EXEC_UU_CHECK_RC=1
  run hardening_configure_auto_updates
  [ "${status}" -eq 0 ]
  # Les 5 directives (2 x APT::Periodic, 1 x Origins-Pattern avec 2 origines security, 2 x Remove-Unused-* false)
  grep -qF 'APT::Periodic::Update-Package-Lists "1";' "${CAT_STDIN_LOG}"
  grep -qF 'APT::Periodic::Unattended-Upgrade "1";' "${CAT_STDIN_LOG}"
  grep -qF 'origin=Debian,codename=${distro_codename},label=Debian-Security' "${CAT_STDIN_LOG}"
  grep -qF 'origin=Debian,codename=${distro_codename}-security,label=Debian-Security' "${CAT_STDIN_LOG}"
  grep -qF 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";' "${CAT_STDIN_LOG}"
  grep -qF 'Unattended-Upgrade::Remove-Unused-Dependencies "false";' "${CAT_STDIN_LOG}"
}

@test "Story 2.5 AC1 : le drop-in contient LITTERALEMENT \${distro_codename} (pas d'expansion cote client)" {
  export SSH_EXEC_UU_CHECK_RC=1
  run hardening_configure_auto_updates
  [ "${status}" -eq 0 ]
  # Le littéral ${distro_codename} DOIT apparaitre (expansion au runtime par python-apt cote serveur).
  grep -qF '${distro_codename}' "${CAT_STDIN_LOG}"
}

@test "Story 2.5 AC1 : activation timers en UN SEUL systemctl enable --now (pas 2 appels separes)" {
  export SSH_EXEC_UU_CHECK_RC=1
  run hardening_configure_auto_updates
  [ "${status}" -eq 0 ]
  # Un seul `systemctl enable --now` contient les DEUX timers.
  grep -qE 'ssh_exec: systemctl enable --now apt-daily\.timer apt-daily-upgrade\.timer' "${CALL_LOG}"
  # Compte : exactement 1 invocation de `systemctl enable --now apt-daily`.
  [ "$(grep -cE 'ssh_exec: systemctl enable --now apt-daily' "${CALL_LOG}")" -eq 1 ]
}

# ---------------------------------------------------------------------------
# Story 2.5 AC2 / AC3 — Idempotence : check effectif conforme -> aucune action
# ---------------------------------------------------------------------------

@test "Story 2.5 AC2/AC3 : si l'etat effectif est deja conforme, aucune action (pas d'apt/cat/dry-run/enable)" {
  export SSH_EXEC_UU_CHECK_RC=0  # paquet + timers + apt-config dump conformes
  run hardening_configure_auto_updates
  [ "${status}" -eq 0 ]
  # Le check a eu lieu
  grep -q 'ssh_exec: dpkg -s unattended-upgrades' "${CALL_LOG}"
  # AUCUNE action de modification
  ! grep -qE 'ssh_exec: apt-get update( |$)' "${CALL_LOG}"
  ! grep -q 'ssh_exec: DEBIAN_FRONTEND=noninteractive apt-get install' "${CALL_LOG}"
  ! grep -q 'ssh_exec: cat > /etc/apt/apt.conf.d/' "${CALL_LOG}"
  ! grep -q 'ssh_exec: unattended-upgrade --dry-run' "${CALL_LOG}"
  ! grep -q 'ssh_exec: systemctl enable --now apt-daily' "${CALL_LOG}"
}

@test "Story 2.5 AC3 : le check combine paquet + 2 timers actifs + 2 timers enable + 5 apt-config dump" {
  export SSH_EXEC_UU_CHECK_RC=0
  run hardening_configure_auto_updates
  [ "${status}" -eq 0 ]
  # UN SEUL ssh_exec chaine couvre les 10 sous-checks (latence minimale).
  grep -qE 'ssh_exec: dpkg -s unattended-upgrades.*systemctl is-active --quiet apt-daily\.timer.*systemctl is-enabled --quiet apt-daily\.timer.*systemctl is-active --quiet apt-daily-upgrade\.timer.*systemctl is-enabled --quiet apt-daily-upgrade\.timer.*apt-config dump APT::Periodic::Unattended-Upgrade.*apt-config dump APT::Periodic::Update-Package-Lists.*apt-config dump Unattended-Upgrade::Origins-Pattern.*label=Debian-Security.*apt-config dump Unattended-Upgrade::Remove-Unused-Kernel-Packages.*apt-config dump Unattended-Upgrade::Remove-Unused-Dependencies' "${CALL_LOG}"
  # Symetrie check/action : les 2 Remove-Unused-* ecrits par l'action sont verifies par le check avec valeur attendue "false".
  grep -qF '[ "$(apt-config dump Unattended-Upgrade::Remove-Unused-Kernel-Packages --format %v%n 2>/dev/null)" = "false" ]' "${CALL_LOG}"
  grep -qF '[ "$(apt-config dump Unattended-Upgrade::Remove-Unused-Dependencies --format %v%n 2>/dev/null)" = "false" ]' "${CALL_LOG}"
  # Exactement 1 seul ssh_exec pour le check (pas de check multi-appels).
  [ "$(grep -c 'ssh_exec: dpkg -s unattended-upgrades' "${CALL_LOG}")" -eq 1 ]
}

@test "Story 2.5 AC3 : check 1 (paquet absent) -> l'action complete est declenchee" {
  export SSH_EXEC_UU_CHECK_RC=1
  run hardening_configure_auto_updates
  [ "${status}" -eq 0 ]
  grep -q 'ssh_exec: DEBIAN_FRONTEND=noninteractive apt-get install -y .*unattended-upgrades' "${CALL_LOG}"
  grep -q 'ssh_exec: systemctl enable --now apt-daily.timer apt-daily-upgrade.timer' "${CALL_LOG}"
}

# ---------------------------------------------------------------------------
# Story 2.5 AC5 — Echecs : die 1 + suggestion ciblee par etape
# ---------------------------------------------------------------------------

@test "Story 2.5 AC5 : echec apt-get update -> die 1 + suggestion reseau ; pas d'install" {
  export SSH_EXEC_UU_CHECK_RC=1
  export SSH_EXEC_UU_UPDATE_RC=1
  run hardening_configure_auto_updates
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"apt-get update a echoue avant installation unattended-upgrades"* ]]
  [[ "${output}" == *"connectivite reseau"* ]]
  ! grep -q 'ssh_exec: DEBIAN_FRONTEND=noninteractive apt-get install' "${CALL_LOG}"
}

@test "Story 2.5 AC5 : echec apt-get install -> die 1 + suggestion apt-cache/journalctl ; pas de cat > drop-in" {
  export SSH_EXEC_UU_CHECK_RC=1
  export SSH_EXEC_UU_INSTALL_RC=1
  run hardening_configure_auto_updates
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Installation unattended-upgrades echouee"* ]]
  [[ "${output}" == *"apt-cache policy unattended-upgrades"* ]]
  [[ "${output}" == *"journalctl -xe"* ]]
  ! grep -q 'ssh_exec: cat > /etc/apt/apt.conf.d/' "${CALL_LOG}"
}

@test "Story 2.5 AC5 : echec ecriture drop-in -> rm -f du tmp + die 1 ; pas de dry-run" {
  export SSH_EXEC_UU_CHECK_RC=1
  export SSH_EXEC_UU_CAT_RC=1
  run hardening_configure_auto_updates
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Ecriture du drop-in unattended-upgrades echouee"* ]]
  # Nettoyage tmp (best-effort, pattern pid-suffix)
  grep -q 'ssh_exec: rm -f /etc/apt/apt.conf.d/52mediadock-unattended-upgrades.tmp-' "${CALL_LOG}"
  # Dry-run / enable timers non effectues
  ! grep -q 'ssh_exec: unattended-upgrade --dry-run' "${CALL_LOG}"
  ! grep -q 'ssh_exec: systemctl enable --now apt-daily' "${CALL_LOG}"
}

@test "Story 2.5 AC5 : echec unattended-upgrade --dry-run -> die 1 + chemin drop-in + drop-in conserve + pas de enable timers" {
  export SSH_EXEC_UU_CHECK_RC=1
  export SSH_EXEC_UU_DRYRUN_RC=1
  run hardening_configure_auto_updates
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"unattended-upgrade --dry-run --debug a detecte une config invalide"* ]]
  # Chemin du drop-in explicite (§5 diagnostic : garde le fichier + cite-le)
  [[ "${output}" == *"/etc/apt/apt.conf.d/52mediadock-unattended-upgrades"* ]]
  [[ "${output}" == *"journalctl -u unattended-upgrades"* ]]
  # Le dry-run a bien eu lieu, mais enable timers NON (die avant)
  grep -q 'ssh_exec: unattended-upgrade --dry-run --debug' "${CALL_LOG}"
  ! grep -q 'ssh_exec: systemctl enable --now apt-daily' "${CALL_LOG}"
  # Le drop-in reste en place (§5 : pas de rollback destructif sur echec dry-run)
  ! grep -qE 'ssh_exec: rm -f /etc/apt/apt\.conf\.d/52mediadock-unattended-upgrades$' "${CALL_LOG}"
}

@test "Story 2.5 AC5 : echec systemctl enable --now apt-daily* -> die 1 + suggestion systemctl status / journalctl" {
  export SSH_EXEC_UU_CHECK_RC=1
  export SSH_EXEC_UU_TIMERS_RC=1
  run hardening_configure_auto_updates
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"Activation des timers apt-daily* echouee"* ]]
  [[ "${output}" == *"systemctl status apt-daily.timer apt-daily-upgrade.timer"* ]]
  [[ "${output}" == *"journalctl -u apt-daily-upgrade"* ]]
  # Le dry-run est passe (etape 4), le drop-in est en place (§5 pas de rollback)
  grep -q 'ssh_exec: unattended-upgrade --dry-run --debug' "${CALL_LOG}"
  ! grep -qE 'ssh_exec: rm -f /etc/apt/apt\.conf\.d/52mediadock-unattended-upgrades$' "${CALL_LOG}"
}

@test "Story 2.5 AC5 : SERVER_IP non defini -> message utilise le fallback 'serveur'" {
  unset SERVER_IP
  export SSH_EXEC_UU_CHECK_RC=1
  export SSH_EXEC_UU_DRYRUN_RC=1
  run hardening_configure_auto_updates
  [ "${status}" -eq 1 ]
  [[ "${output}" == *"sur serveur"* ]]
}

# ---------------------------------------------------------------------------
# Story 2.5 AC6 — Traces log et convention sans accents
# ---------------------------------------------------------------------------

@test "Story 2.5 AC6 : cas modif ecrit [ACTION] Hardening auto-updates et [INFO] termine" {
  export SSH_EXEC_UU_CHECK_RC=1
  hardening_configure_auto_updates
  grep -q '\[ACTION\] Hardening auto-updates' "${LOG_FILE}"
  grep -q '\[INFO\] Hardening auto-updates : termine' "${LOG_FILE}"
}

@test "Story 2.5 AC6 : cas idempotent ecrit [INFO] Hardening auto-updates : deja en place" {
  export SSH_EXEC_UU_CHECK_RC=0
  hardening_configure_auto_updates
  grep -q '\[INFO\] Hardening auto-updates : deja en place' "${LOG_FILE}"
  ! grep -q '\[ACTION\] Hardening auto-updates' "${LOG_FILE}"
}

@test "Story 2.5 AC6 : mode verbose affiche le marqueur idempotent a l'ecran" {
  export SSH_EXEC_UU_CHECK_RC=0
  VERBOSE=1 run hardening_configure_auto_updates
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"[INFO] Hardening auto-updates : deja en place"* ]]
}

@test "Story 2.5 AC6 : mode verbose affiche le marqueur 'termine' du chemin modifiant a l'ecran" {
  export SSH_EXEC_UU_CHECK_RC=1
  VERBOSE=1 run hardening_configure_auto_updates
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"[INFO] Hardening auto-updates : termine"* ]]
}

@test "Story 2.5 AC6 : messages sans accents (convention Epic 1)" {
  export SSH_EXEC_UU_CHECK_RC=1
  export SSH_EXEC_UU_INSTALL_RC=1
  run hardening_configure_auto_updates
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
  # Story 2.4 : helpers UFW
  declare -F hardening_configure_ufw >/dev/null
  declare -F _hardening_check_ufw_active >/dev/null
  declare -F _hardening_install_and_configure_ufw >/dev/null
  # Story 2.5 : helpers unattended-upgrades
  declare -F hardening_configure_auto_updates >/dev/null
  declare -F _hardening_check_unattended_active >/dev/null
  declare -F _hardening_install_and_configure_unattended >/dev/null
}

@test "Contrat module : hardening.sh n'appelle pas ssh/scp direct ni eval" {
  local hardening_sh="${PROJECT_ROOT}/lib/modules/hardening.sh"
  # Pas d'eval direct (reserve a ensure_state)
  ! grep -E -q '^[^#]*\beval\b' "${hardening_sh}"
  # Pas de `ssh ` ou `scp ` non-wrappe (ssh_exec / ssh_copy OK)
  ! grep -E -q '^[^#]*(^|[^_])\bssh\b[^_]' "${hardening_sh}"
  ! grep -E -q '^[^#]*\bscp\b' "${hardening_sh}"
}
