#!/usr/bin/env bash
# Module: hardening - Durcissement SSH (cle only, PermitRootLogin) + helpers futurs
# Dependances: logging.sh, errors.sh, ssh.sh, utils.sh
#
# Point d'entree : hardening_run (appele par install_run via _install_run_step).
#
# Helpers publics :
#   hardening_configure_ssh
#     - Desactive PasswordAuthentication, KbdInteractiveAuthentication et
#       passe PermitRootLogin en prohibit-password via un drop-in dedie
#       /etc/ssh/sshd_config.d/50-mediadock-hardening.conf.
#     - Idempotent : source de verite = config effective `sshd -T`
#       (respecte un admin qui aurait pose les memes directives ailleurs).
#     - Valide avec `sshd -t` AVANT `systemctl reload ssh` ; rollback
#       (suppression du drop-in) + `die 1` en cas d'echec de validation,
#       afin de ne jamais recharger sshd avec une config invalide.
#
# Helpers prives : _hardening_check_ssh_hardened, _hardening_write_ssh_drop_in.
#
# Story 2.2 : voir _bmad-output/implementation-artifacts/2-2-hardening-*.md.

# Variables privees au module. Pas de `readonly` : casserait un second
# sourcing dans le meme process (cf. deferred-work.md, defer 2-1).
_HARDENING_SSHD_DROP_IN="/etc/ssh/sshd_config.d/50-mediadock-hardening.conf"

# Contenu du drop-in (libelles sans accents : lisible cote serveur via SSH).
_HARDENING_SSHD_CONFIG='# MediaDock hardening - genere par mediadock install (Story 2.2)
# Ne pas editer manuellement : ce fichier est gere par MediaDock.
PasswordAuthentication no
PermitRootLogin prohibit-password
KbdInteractiveAuthentication no'

# Commande de check : la source de verite est `sshd -T` (configuration
# effective), PAS la presence du drop-in (AC3). Accepte PermitRootLogin
# `no` ou `prohibit-password` - les deux satisfont le critere "pas de
# root login par mot de passe". Retour 0 = deja conforme, 1 = a faire.
# Un seul appel a sshd -T (stocke dans $out) pour eliminer la course
# theorique entre plusieurs invocations et diviser par 3 le cout reseau.
_hardening_check_ssh_hardened() {
  # shellcheck disable=SC2016 # $out est expanse cote serveur, pas cote client.
  ssh_exec 'out=$(sshd -T 2>/dev/null) && printf "%s\n" "$out" | grep -qxE "passwordauthentication no" && printf "%s\n" "$out" | grep -qxE "permitrootlogin (prohibit-password|no)" && printf "%s\n" "$out" | grep -qxE "kbdinteractiveauthentication no"'
}

# Ecriture atomique du drop-in + validation + reload gracieux.
#   1. printf | ssh_exec "cat > tmp && chmod 644 && mv -f" : creation puis
#      rename atomique sur /etc (meme filesystem) ; chmod AVANT mv evite
#      une fenetre courte avec des permissions laxistes. Detection
#      explicite de l'echec du pipeline (ne depend pas de pipefail).
#   2. `sshd -t` valide la syntaxe complete incluant le nouveau drop-in.
#      En cas d'echec : rollback (rm -f du drop-in) AVANT tout reload,
#      puis `die 1`. Le sshd en cours d'execution n'a pas encore
#      charge le drop-in (reload non effectue) : la config EFFECTIVE
#      du sshd tourne toujours sur l'etat pre-operation, donc la
#      connexion SSH courante reste saine.
#   3. `systemctl reload ssh` (pas restart) recharge via SIGHUP sans couper
#      les connexions existantes. Echec de reload = die 1 (sinon
#      ensure_state remonterait succes sans que la nouvelle config soit
#      appliquee).
_hardening_write_ssh_drop_in() {
  local tmp_path="${_HARDENING_SSHD_DROP_IN}.tmp-$$"
  if ! printf '%s\n' "${_HARDENING_SSHD_CONFIG}" \
      | ssh_exec "cat > ${tmp_path} && chmod 644 ${tmp_path} && mv -f ${tmp_path} ${_HARDENING_SSHD_DROP_IN}"; then
    ssh_exec "rm -f ${tmp_path}" \
      || log_warn "Nettoyage du tmp drop-in echoue sur ${SERVER_IP:-serveur}"
    die 1 "Ecriture du drop-in hardening SSH echouee" \
      "Verifiez les permissions ou la connectivite SSH vers ${SERVER_IP:-serveur}"
  fi
  if ! ssh_exec "sshd -t"; then
    ssh_exec "rm -f ${_HARDENING_SSHD_DROP_IN}" \
      || log_warn "Rollback rm echoue : drop-in potentiellement encore en place sur ${SERVER_IP:-serveur}"
    die 1 "Validation sshd -t echouee apres ecriture du drop-in" \
      "Verifiez manuellement /etc/ssh/sshd_config.d/ sur ${SERVER_IP:-serveur}"
  fi
  if ! ssh_exec "systemctl reload ssh"; then
    die 1 "systemctl reload ssh a echoue apres validation" \
      "Verifiez 'systemctl status ssh' sur ${SERVER_IP:-serveur}"
  fi
}

# Configure le durcissement SSH (PasswordAuthentication no, PermitRootLogin
# prohibit-password, KbdInteractiveAuthentication no). Idempotent via
# ensure_state qui controle la config effective avec `sshd -T`.
hardening_configure_ssh() {
  ensure_state \
    '_hardening_check_ssh_hardened' \
    '_hardening_write_ssh_drop_in' \
    'Hardening SSH'
}

# Orchestre le hardening : SSH d'abord (story 2.2). Les helpers fail2ban,
# UFW et auto-updates arrivent dans 2.3, 2.4 et 2.5 - leurs appels seront
# ajoutes ici au fil des stories. `_install_run_step` attend un return 0
# explicite : aucun traitement d'erreur supplementaire necessaire ici,
# `die` depuis les helpers fait exit avec code propage.
hardening_run() {
  hardening_configure_ssh
  # TODO Story 2.3 : hardening_configure_fail2ban
  # TODO Story 2.4 : hardening_configure_ufw
  # TODO Story 2.5 : hardening_configure_auto_updates
  return 0
}
